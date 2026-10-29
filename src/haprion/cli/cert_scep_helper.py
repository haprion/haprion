"""The privileged half of `haprion-cert-scep` - one NDES enrollment, from a job.

Calls the same `enroll` the terminal command calls, so the two live
issuances proved from the terminal on 2026-09-15 are the code path the
interface uses. What this half adds is the boundary: a bounded request in,
one envelope out, and no way to name a file, a directory, a challenge or a
Certmonger flag. The challenge is never in the request: the helper opens the
root-only profile record by ID, the same way the terminal command does.

What the caller may decide: a certificate ID, a profile ID, the DNS names,
targets the registry already knows, and whether this is a resume of a request
the CA is still holding - or its abandon, which names the certificate alone
and runs the terminal command's own `--abandon` (B388).
"""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any, BinaryIO, TextIO

from haprion import exit_codes, ui_interface
from haprion.cert_inventory import IMPORT_STORE, LETSENCRYPT_LIVE
from haprion.cert_publish import DEFAULT_LOCK_PATH, Deployer, Installer
from haprion.cli import cert_job
from haprion.cli.cert_publish import default_deployer
from haprion.cli.cert_scep import OPERATION, ScepRefusal, abandon, enroll
from haprion.config import DEFAULT_POLICY_PATH
from haprion.dns_profiles import ProfileError, check_profile_id
from haprion.helper_protocol import HelperProtocolError, write_document

PARAMETERS = frozenset(
    {
        "id",
        "profile",
        "domains",
        "clusters",
        "receivers",
        "formats",
        "resume",
        "interface",
        "exportable",
        "abandon",
    }
)
HELPER = "/opt/haprion/current/bin/haprion-cert-scep-helper"
SUDO = "/usr/bin/sudo"
MAX_DOMAINS = 32
MAX_DOMAIN_BYTES = 255


def build_request(
    request_id: str,
    *,
    certificate_id: str,
    profile_id: str,
    domains: tuple[str, ...],
    clusters: tuple[str, ...] = (),
    receivers: tuple[str, ...] = (),
    resume: bool = False,
    formats: Mapping[str, str] | None = None,
    interface: bool = False,
    exportable: bool = False,
    abandon: bool = False,
) -> str:
    """The exact bounded request the worker sends. Null cluster, by contract."""

    if abandon:
        return json.dumps(
            {
                "schema_version": 1,
                "operation": OPERATION,
                "cluster": None,
                "request_id": request_id,
                "parameters": {"id": certificate_id, "abandon": True},
            },
            separators=(",", ":"),
        )
    parameters: dict[str, Any] = {
        "id": certificate_id,
        "profile": profile_id,
        "domains": list(domains),
        "clusters": list(clusters),
        "receivers": list(receivers),
        "resume": resume,
    }
    if formats:
        parameters["formats"] = dict(formats)
    if interface:
        parameters["interface"] = True
    if exportable:
        parameters["exportable"] = True
    return json.dumps(
        {
            "schema_version": 1,
            "operation": OPERATION,
            "cluster": None,
            "request_id": request_id,
            "parameters": parameters,
        },
        separators=(",", ":"),
    )


def main(
    argv: list[str] | None = None,
    *,
    policy_path: Path = DEFAULT_POLICY_PATH,
    input_stream: BinaryIO | None = None,
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
    argv = sys.argv[1:] if argv is None else argv
    writer: TextIO = output_stream or sys.stdout
    errors: TextIO = error_stream or sys.stderr

    try:
        request = cert_job.read_request(
            OPERATION,
            parameters=PARAMETERS,
            input_stream=input_stream,
            argv=argv,
            require_root=require_root,
            helper_name="haprion-cert-scep-helper",
        )
    except HelperProtocolError as exc:
        errors.write(f"ERROR: {exc}\n")
        return exc.exit_code

    refuse = cert_job.Refuse(OPERATION, request, writer, errors)
    if "abandon" in request.parameters:
        try:
            certificate_id = cert_job.certificate(request.parameters, "id")
            if request.parameters["abandon"] is not True or set(request.parameters) != {
                "id",
                "abandon",
            }:
                raise HelperProtocolError(
                    "parameters.abandon is true, beside the certificate ID alone",
                    exit_code=exit_codes.REFUSED,
                )
            document, exit_code = abandon(
                certificate_id=certificate_id,
                request_id=request.request_id,
                policy_path=policy_path,
                require_secure=require_secure,
            )
        except HelperProtocolError as exc:
            return refuse("bad_input", str(exc), exit_codes.REFUSED)
        except ScepRefusal as exc:
            return refuse(exc.code, str(exc), exc.exit_code)
        return write_document(writer, document, exit_code)
    try:
        certificate_id = cert_job.certificate(request.parameters, "id")
        resume = request.parameters.get("resume", False)
        if not isinstance(resume, bool):
            raise HelperProtocolError(
                "parameters.resume must be true or false", exit_code=exit_codes.REFUSED
            )
        raw_profile = request.parameters.get("profile", "")
        profile_id = "" if resume and raw_profile in ("", None) else check_profile_id(raw_profile)
        raw_domains = request.parameters.get("domains", [])
        if (
            not isinstance(raw_domains, list)
            or (not raw_domains and not resume)
            or len(raw_domains) > MAX_DOMAINS
            or not all(
                isinstance(name, str) and name and len(name.encode("utf-8")) <= MAX_DOMAIN_BYTES
                for name in raw_domains
            )
        ):
            raise HelperProtocolError(
                "parameters.domains must be a non-empty list of DNS names",
                exit_code=exit_codes.REFUSED,
            )
        domains = tuple(str(name) for name in raw_domains)
        clusters = cert_job.clusters(request.parameters)
        receivers = cert_job.receivers(request.parameters)
        formats = cert_job.formats(request.parameters, receivers)
        interface = cert_job.interface(request.parameters)
        exportable = cert_job.exportable(request.parameters)
    except (HelperProtocolError, ProfileError) as exc:
        return refuse("bad_input", str(exc), exit_codes.REFUSED)

    try:
        document, exit_code = enroll(
            certificate_id=certificate_id,
            profile_id=profile_id,
            domains=domains,
            clusters=clusters,
            receivers=receivers,
            resume=resume,
            request_id=request.request_id,
            formats=formats,
            interface=interface,
            exportable=exportable,
            policy_path=policy_path,
            require_secure=require_secure,
            deployer=deployer if deployer is not None else default_deployer(errors),
            # Inside the worker's sandbox: the root service installs it (B188).
            installer=installer if installer is not None else ui_interface.socket_installer(),
            live=live,
            store=store,
            lock_path=lock_path,
        )
    except ScepRefusal as exc:
        return refuse(exc.code, str(exc), exc.exit_code)
    return write_document(writer, document, exit_code)


if __name__ == "__main__":
    raise SystemExit(main())
