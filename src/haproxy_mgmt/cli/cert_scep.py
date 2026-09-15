"""Root CLI for NDES enrollment through a materialized provider profile."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any, TextIO

from haproxy_mgmt import cert_import, ndes, ndes_profiles
from haproxy_mgmt.cert_inventory import IMPORT_STORE, LETSENCRYPT_LIVE
from haproxy_mgmt.cert_publish import DEFAULT_LOCK_PATH, Deployer
from haproxy_mgmt.cli.cert_import import result_envelope
from haproxy_mgmt.cli.cert_publish import default_deployer
from haproxy_mgmt.config import (
    CERTIFICATE_ID,
    DEFAULT_POLICY_PATH,
    ConfigError,
    load_policy,
    load_runtime_config,
)
from haproxy_mgmt.dns_profiles import ProfileError
from haproxy_mgmt.envelope import Message, envelope, failure, new_request_id
from haproxy_mgmt.ndes_state import request_record

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
    policy_path: Path = DEFAULT_POLICY_PATH,
    require_secure: bool = True,
    deployer: Deployer,
    live: Path = LETSENCRYPT_LIVE,
    store: Path = IMPORT_STORE,
    lock_path: Path = DEFAULT_LOCK_PATH,
) -> tuple[dict[str, Any], int]:
    """One enrollment, from profile to published certificate, as one document.

    The engine behind both `haproxy-cert-scep` and its job helper: the same
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
                # Registered now, without material, so the listing shows the
                # request as pending and the targets are kept for the resume.
                # The publisher skips an entry whose source holds nothing.
                #
                cert_import.register(
                    policy.certificate_registry,
                    certificate_id,
                    runtime,
                    clusters=clusters,
                    receivers=receivers,
                    require_secure=require_secure,
                    ndes_profile=profile.profile_id,
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
            ndes.validate_certificate(enrolled.material, requested, enrolled.directory)
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
            if exit_code == 0:
                shutil.rmtree(enrolled.directory)
            return doc, exit_code
    except ConfigError as exc:
        raise ScepRefusal("dependency_unavailable", str(exc), exc.exit_code) from exc
    except ProfileError as exc:
        raise ScepRefusal("profile_unavailable", str(exc), 78) from exc
    except (ndes.NdesError, cert_import.ImportError_) as exc:
        raise ScepRefusal(exc.code, str(exc), exc.exit_code) from exc


def main(
    argv: list[str] | None = None,
    *,
    policy_path: Path = DEFAULT_POLICY_PATH,
    output_stream: TextIO | None = None,
    error_stream: TextIO | None = None,
    require_secure: bool = True,
    require_root: bool = True,
    deployer: Deployer | None = None,
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
    parser.add_argument("--resume", action="store_true")
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
        return refuse("not_root", "haproxy-cert-scep must run as root", 77)
    try:
        doc, exit_code = enroll(
            certificate_id=args.id,
            profile_id=args.profile,
            domains=args.domain,
            clusters=args.cluster,
            receivers=args.receiver,
            resume=args.resume,
            request_id=request_id,
            policy_path=policy_path,
            require_secure=require_secure,
            deployer=deployer or default_deployer(errors),
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
