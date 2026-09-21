"""The privileged half of `haproxy-cert-request` - one key and one CSR, from a job (C9b).

Calls the same `request` the terminal command calls. What this half adds is
the boundary: a bounded request in, one envelope out, and no way to name a
file, a directory or an `openssl` flag. The key is made in the import
store and stays there; the envelope carries the CSR, which is public.

What the caller may decide: a certificate ID, the DNS names, the key type
from the short list, and targets the registry already knows.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any, BinaryIO, TextIO

from haproxy_mgmt.cert_inventory import IMPORT_STORE, LETSENCRYPT_LIVE
from haproxy_mgmt.cert_publish import DEFAULT_LOCK_PATH
from haproxy_mgmt.cert_request_state import DEFAULT_KEY_TYPE, KEY_TYPES
from haproxy_mgmt.cli import cert_job
from haproxy_mgmt.cli.cert_request import OPERATION, RequestRefusal, request
from haproxy_mgmt.config import DEFAULT_POLICY_PATH
from haproxy_mgmt.helper_protocol import HelperProtocolError, write_document

PARAMETERS = frozenset({"id", "domains", "key_type", "clusters", "receivers", "formats"})
HELPER = "/opt/haproxy-mgmt/current/bin/haproxy-cert-request-helper"
SUDO = "/usr/bin/sudo"
MAX_DOMAINS = 32
MAX_DOMAIN_BYTES = 255


def build_request(
    request_id: str,
    *,
    certificate_id: str,
    domains: tuple[str, ...],
    key_type: str = DEFAULT_KEY_TYPE,
    clusters: tuple[str, ...] = (),
    receivers: tuple[str, ...] = (),
    formats: Mapping[str, str] | None = None,
) -> str:
    """The exact bounded request the worker sends. Null cluster, by contract."""

    parameters: dict[str, Any] = {
        "id": certificate_id,
        "domains": list(domains),
        "key_type": key_type,
        "clusters": list(clusters),
        "receivers": list(receivers),
    }
    if formats:
        parameters["formats"] = dict(formats)
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
    live: Path = LETSENCRYPT_LIVE,
    store: Path = IMPORT_STORE,
    lock_path: Path = DEFAULT_LOCK_PATH,
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    writer: TextIO = output_stream or sys.stdout
    errors: TextIO = error_stream or sys.stderr

    try:
        job = cert_job.read_request(
            OPERATION,
            parameters=PARAMETERS,
            input_stream=input_stream,
            argv=argv,
            require_root=require_root,
            helper_name="haproxy-cert-request-helper",
        )
    except HelperProtocolError as exc:
        errors.write(f"ERROR: {exc}\n")
        return exc.exit_code

    refuse = cert_job.Refuse(OPERATION, job, writer, errors)
    try:
        certificate_id = cert_job.certificate(job.parameters, "id")
        raw_domains = job.parameters.get("domains", [])
        if (
            not isinstance(raw_domains, list)
            or not raw_domains
            or len(raw_domains) > MAX_DOMAINS
            or not all(
                isinstance(name, str) and name and len(name.encode("utf-8")) <= MAX_DOMAIN_BYTES
                for name in raw_domains
            )
        ):
            raise HelperProtocolError(
                "parameters.domains must be a non-empty list of DNS names", exit_code=65
            )
        domains = tuple(str(name) for name in raw_domains)
        key_type = job.parameters.get("key_type", DEFAULT_KEY_TYPE)
        if not isinstance(key_type, str) or key_type not in KEY_TYPES:
            raise HelperProtocolError(
                "parameters.key_type must be one of: " + ", ".join(KEY_TYPES), exit_code=65
            )
        clusters = cert_job.clusters(job.parameters)
        receivers = cert_job.receivers(job.parameters)
        formats = cert_job.formats(job.parameters, receivers)
    except HelperProtocolError as exc:
        return refuse("bad_input", str(exc), 65)

    try:
        document, exit_code = request(
            certificate_id=certificate_id,
            domains=domains,
            key_type=key_type,
            clusters=clusters,
            receivers=receivers,
            request_id=job.request_id,
            formats=formats,
            policy_path=policy_path,
            require_secure=require_secure,
            live=live,
            store=store,
            lock_path=lock_path,
        )
    except RequestRefusal as exc:
        return refuse(exc.code, str(exc), exc.exit_code)
    write_document(writer, document)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
