"""Root CLI for NDES enrollment through a materialized provider profile."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, TextIO

from haprion import cert_import, ndes, ndes_profiles, ui_interface
from haprion.cert_inventory import IMPORT_STORE, LETSENCRYPT_LIVE
from haprion.cert_publish import DEFAULT_LOCK_PATH, Deployer, Installer
from haprion.cli import cert_job
from haprion.cli.cert_import import result_envelope
from haprion.cli.cert_publish import default_deployer
from haprion.config import (
    CERTIFICATE_ID,
    DEFAULT_POLICY_PATH,
    ConfigError,
    load_policy,
    load_runtime_config,
)
from haprion.dns_profiles import ProfileError
from haprion.envelope import Message, envelope, failure, new_request_id
from haprion.helper_protocol import HelperProtocolError
from haprion.ndes_state import (
    request_formats,
    request_is_exportable,
    request_is_interface,
    request_record,
    request_targets,
    write_targets,
)

OPERATION = "cert_scep"


class ScepRefusal(Exception):
    """A refusal with the envelope's error code and the process exit code.

    One shape for both entrances: the terminal command writes it as its
    failure document, the stdin helper hands it to `Refuse`.
    """

    def __init__(self, code: str, message: str, exit_code: int) -> None:
        super().__init__(message)
        self.code = code
        self.exit_code = exit_code


def enroll(
    *,
    certificate_id: str,
    profile_id: str,
    domains: Sequence[str],
    clusters: Sequence[str],
    receivers: Sequence[str],
    resume: bool,
    request_id: str,
    formats: Mapping[str, str] | None = None,
    interface: bool = False,
    exportable: bool = False,
    policy_path: Path = DEFAULT_POLICY_PATH,
    require_secure: bool = True,
    deployer: Deployer,
    installer: Installer | None = None,
    live: Path = LETSENCRYPT_LIVE,
    store: Path = IMPORT_STORE,
    lock_path: Path = DEFAULT_LOCK_PATH,
) -> tuple[dict[str, Any], int]:
    """One enrollment, from profile to published certificate, as one document.

    The engine behind both `haprion-cert-scep` and its job helper: the same
    checks, the same Certmonger run, the same validation and the same import
    path, so what the terminal proved is what the interface gets. Raises
    `ScepRefusal` for everything that is a refusal rather than a result.
    """

    try:
        if not CERTIFICATE_ID.fullmatch(certificate_id):
            raise ScepRefusal("bad_input", "invalid certificate ID", 65)
        policy = load_policy(policy_path, require_secure=require_secure)
        if policy.ndes is None or policy.certificate_registry is None:
            raise ScepRefusal(
                "dependency_unavailable",
                "NDES policy and certificate registry must be configured",
                78,
            )
        if resume and not domains:
            #
            # A resume may name only the certificate: the request's record
            # already holds the profile and the names, and the engine refuses
            # a resume that disagrees with it anyway.
            #
            record = request_record(policy.ndes.state_root, certificate_id)
            recorded = record.get("domains") if record else None
            recorded_profile = record.get("profile") if record else None
            if not isinstance(recorded, list) or not isinstance(recorded_profile, str):
                raise ScepRefusal("bad_input", "no NDES request to resume for this ID", 65)
            domains = [str(name) for name in recorded]
            profile_id = profile_id or recorded_profile
        if resume and not clusters and not receivers:
            #
            # The targets too: kept beside the request rather than in the
            # registry, which names a certificate only once it exists.
            #
            clusters, receivers = request_targets(policy.ndes.state_root, certificate_id)
            formats = request_formats(policy.ndes.state_root, certificate_id)
        if resume:
            interface = interface or request_is_interface(policy.ndes.state_root, certificate_id)
            exportable = exportable or request_is_exportable(policy.ndes.state_root, certificate_id)
        if exportable and (clusters or receivers or interface):
            raise ScepRefusal(
                "bad_input",
                "an exportable certificate has no targets and does not serve the interface; "
                "name no cluster or receiver",
                65,
            )
        if exportable and any(name.startswith("*.") for name in domains):
            raise ScepRefusal(
                "bad_input", "an exportable certificate names one host; no wildcard", 65
            )
        if interface and (clusters or receivers):
            raise ScepRefusal(
                "bad_input",
                "the interface certificate has no targets; name no cluster or receiver",
                65,
            )
        if any(name not in receivers for name in formats or ()):
            raise ScepRefusal("bad_input", "a format names a receiver that is not targeted", 65)
        requested = ndes.names(domains)
        runtime = load_runtime_config(policy, require_secure=require_secure)
        if any(name not in runtime.clusters for name in clusters):
            raise ScepRefusal("bad_input", "unknown target cluster", 65)
        if runtime.registry is None or any(
            name not in runtime.registry.receivers for name in receivers
        ):
            raise ScepRefusal(
                "bad_input", "certificate registry or target receiver is unavailable", 65
            )
        existing = runtime.registry.certificates.get(certificate_id)
        if existing is not None and existing.source.kind != "import":
            raise ScepRefusal(
                "bad_input", "certificate ID already belongs to another source kind", 65
            )
        if (live / certificate_id).exists():
            raise ScepRefusal("bad_input", "certificate ID already belongs to an ACME lineage", 65)
        profile = ndes_profiles.resolve(policy.ndes, profile_id, require_secure=require_secure)
        with ndes.enroll(
            policy.ndes,
            certificate_id=certificate_id,
            profile=profile,
            domains=requested,
            resume=resume,
            require_secure=require_secure,
        ) as enrolled:
            if enrolled.state == "pending":
                #
                # Not registered: the registry's readers - the cluster's
                # certificate list, the deploy preflight - take every entry
                # to have a file, and an entry without one refused every
                # rollout to the clusters it named (review 2026-09-17,
                # finding 1). The targets wait beside the request, the
                # listing helper reads the request itself, and the registry
                # names the certificate once the CA has answered.
                #
                write_targets(
                    policy.ndes.state_root,
                    certificate_id,
                    clusters=tuple(clusters),
                    receivers=tuple(receivers),
                    formats=formats,
                    interface=interface,
                    exportable=exportable,
                )
                doc = envelope(
                    operation=OPERATION,
                    outcome="partial",
                    cluster=None,
                    request_id=request_id,
                    result={
                        "id": certificate_id,
                        "profile": profile.profile_id,
                        "domains": list(requested),
                        "state": "pending",
                    },
                    warnings=(
                        Message(
                            code="request_pending",
                            message="CA approval is pending; resume the same request to retain its key",
                        ),
                    ),
                )
                return doc, 0
            if enrolled.material is None:
                raise ndes.NdesError(
                    "scep_failed", "issued request has no certificate material", exit_code=1
                )
            #
            # Issued is the end of the request either way: a certificate that
            # fails validation is not going to pass it on a resume, and an
            # import that fails has its material in the store or a refusal
            # to fix first. The directory goes so the ID can be asked for
            # again; only a successful import kept it until now.
            #
            try:
                ndes.validate_certificate(enrolled.material, requested, enrolled.directory)
            except ndes.NdesError:
                shutil.rmtree(enrolled.directory, ignore_errors=True)
                raise
            imported = cert_import.import_certificate(
                certificate_id=certificate_id,
                material=enrolled.material,
                clusters=clusters,
                receivers=receivers,
                policy=policy,
                runtime=runtime,
                deployer=deployer,
                live=live,
                store=store,
                lock_path=lock_path,
                require_secure=require_secure,
                ndes_profile=profile.profile_id,
                formats=formats,
                interface=interface,
                installer=installer,
                exportable=exportable,
            )
            doc, exit_code = result_envelope(imported, request_id=request_id)
            doc["operation"] = OPERATION
            doc["result"] = {
                "id": certificate_id,
                "profile": profile.profile_id,
                "domains": list(requested),
                "state": "issued",
                "publication": doc["result"],
            }
            #
            # Imported and registered: the request is over whatever the
            # publication's exit code says, and `haprion-cert-publish` is
            # the way to finish that - not a resume of a request the CA has
            # already answered.
            #
            shutil.rmtree(enrolled.directory, ignore_errors=True)
            return doc, exit_code
    except ConfigError as exc:
        raise ScepRefusal("dependency_unavailable", str(exc), exc.exit_code) from exc
    except ProfileError as exc:
        raise ScepRefusal("profile_unavailable", str(exc), 78) from exc
    except (ndes.NdesError, cert_import.ImportError_) as exc:
        raise ScepRefusal(exc.code, str(exc), exc.exit_code) from exc


def abandon(
    *,
    certificate_id: str,
    request_id: str,
    policy_path: Path = DEFAULT_POLICY_PATH,
    require_secure: bool = True,
) -> tuple[dict[str, Any], int]:
    """Give up a request the CA has not answered: its key, its state, its targets.

    For the request that neither finished nor was rejected - the process died
    on it, or the approval is never coming. A rejected request removes itself.
    """

    try:
        if not CERTIFICATE_ID.fullmatch(certificate_id):
            raise ScepRefusal("bad_input", "invalid certificate ID", 65)
        policy = load_policy(policy_path, require_secure=require_secure)
        if policy.ndes is None:
            raise ScepRefusal("dependency_unavailable", "NDES policy must be configured", 78)
        removed = ndes.abandon(policy.ndes, certificate_id, require_secure=require_secure)
    except ConfigError as exc:
        raise ScepRefusal("dependency_unavailable", str(exc), exc.exit_code) from exc
    except ndes.NdesError as exc:
        raise ScepRefusal(exc.code, str(exc), exc.exit_code) from exc
    if not removed:
        raise ScepRefusal("bad_input", "no NDES request to abandon for this ID", 65)
    return envelope(
        operation=OPERATION,
        outcome="done",
        cluster=None,
        request_id=request_id,
        result={"id": certificate_id, "state": "abandoned"},
    ), 0


def main(
    argv: list[str] | None = None,
    *,
    policy_path: Path = DEFAULT_POLICY_PATH,
    output_stream: TextIO | None = None,
    error_stream: TextIO | None = None,
    require_secure: bool = True,
    require_root: bool = True,
    deployer: Deployer | None = None,
    installer: Installer | None = None,
    live: Path = LETSENCRYPT_LIVE,
    store: Path = IMPORT_STORE,
    lock_path: Path = DEFAULT_LOCK_PATH,
) -> int:
    writer = output_stream or sys.stdout
    errors = error_stream or sys.stderr
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--id", required=True)
    parser.add_argument("--profile", default="", help="required unless --resume")
    parser.add_argument(
        "--domain",
        action="append",
        default=[],
        help="primary CN first, then additional DNS SANs; taken from the request on --resume",
    )
    parser.add_argument("--cluster", action="append", default=[])
    parser.add_argument("--receiver", action="append", default=[])
    parser.add_argument(
        "--format",
        action="append",
        default=[],
        metavar="RECEIVER=FORMAT",
        help="how a --receiver is written: pem (default) or pkcs12",
    )
    parser.add_argument("--resume", action="store_true")
    parser.add_argument(
        "--abandon",
        action="store_true",
        help="give up a request the CA has not answered; its key is discarded",
    )
    parser.add_argument(
        "--interface",
        action="store_true",
        help="this manager's own interface certificate: no targets, installed with "
        "haprion-tls; takes the mark from the one that had it",
    )
    parser.add_argument(
        "--exportable",
        action="store_true",
        help="for a device never connected to this manager (B255): one name, no targets, "
        "a key that may be exported from the interface",
    )
    parser.add_argument("--json", action="store_true")
    try:
        args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    except SystemExit as exc:
        return int(exc.code or 0)
    request_id = new_request_id()

    def refuse(code: str, message: str, exit_code: int) -> int:
        errors.write(f"ERROR: [{code}] {message}\n")
        if args.json:
            writer.write(
                json.dumps(
                    failure(
                        operation=OPERATION,
                        cluster=None,
                        request_id=request_id,
                        code=code,
                        message=message,
                        exit_code=exit_code,
                    )
                )
                + "\n"
            )
        return exit_code

    if require_root and os.geteuid() != 0:
        return refuse("not_root", "haprion-cert-scep must run as root", 77)
    if args.abandon and (
        args.resume or args.profile or args.domain or args.cluster or args.receiver
    ):
        return refuse("bad_input", "--abandon takes only --id", 65)
    try:
        formats = cert_job.format_flags(args.format, args.receiver)
    except HelperProtocolError as exc:
        return refuse("bad_input", str(exc), 65)
    try:
        if args.abandon:
            doc, exit_code = abandon(
                certificate_id=args.id,
                request_id=request_id,
                policy_path=policy_path,
                require_secure=require_secure,
            )
        else:
            doc, exit_code = enroll(
                certificate_id=args.id,
                profile_id=args.profile,
                domains=args.domain,
                clusters=args.cluster,
                receivers=args.receiver,
                resume=args.resume,
                request_id=request_id,
                formats=formats,
                interface=args.interface,
                exportable=args.exportable,
                policy_path=policy_path,
                require_secure=require_secure,
                deployer=deployer or default_deployer(errors),
                # Root at a terminal, outside any sandbox: installed directly.
                installer=installer or ui_interface.install,
                live=live,
                store=store,
                lock_path=lock_path,
            )
    except ScepRefusal as exc:
        return refuse(exc.code, str(exc), exc.exit_code)
    if args.json:
        writer.write(json.dumps(doc, separators=(",", ":")) + "\n")
    else:
        writer.write(f"{args.id}: {doc['result']['state']}\n")
        if exit_code:
            errors.write(
                "ERROR: issued and imported, but publication or deployment did not finish\n"
            )
    return exit_code
