"""Root CLI for a signing request made on the manager (C9b).

    haproxy-cert-request --id shop.example --domain shop.example --domain '*.shop.example' \\
        --cluster alpha --receiver lb-01 [--key-type ec-p256|rsa-2048|rsa-4096] [--json]

The key is made under the ID in the import store and never leaves it; the
CSR is printed, for whoever signs it. The signed certificate comes back
through `haproxy-cert-import --certificate <file>` without `--key`, or the
interface's upload, and lands on the targets named here.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, TextIO

from haproxy_mgmt import cert_request
from haproxy_mgmt.cert_inventory import IMPORT_STORE, LETSENCRYPT_LIVE
from haproxy_mgmt.cert_publish import DEFAULT_LOCK_PATH
from haproxy_mgmt.cert_request_state import DEFAULT_KEY_TYPE, KEY_TYPES
from haproxy_mgmt.cli import cert_job
from haproxy_mgmt.config import DEFAULT_POLICY_PATH, ConfigError, load_policy, load_runtime_config
from haproxy_mgmt.envelope import envelope, failure, new_request_id
from haproxy_mgmt.helper_protocol import HelperProtocolError

OPERATION = cert_request.OPERATION


class RequestRefusal(Exception):
    """A refusal with the envelope's error code and the process exit code.

    One shape for both entrances, as `cert_scep.ScepRefusal` is: the terminal
    command writes it as its failure document, the stdin helper hands it to
    `Refuse`.
    """

    def __init__(self, code: str, message: str, exit_code: int) -> None:
        super().__init__(message)
        self.code = code
        self.exit_code = exit_code


def request(
    *,
    certificate_id: str,
    domains: Sequence[str],
    key_type: str,
    clusters: Sequence[str],
    receivers: Sequence[str],
    request_id: str,
    formats: Mapping[str, str] | None = None,
    policy_path: Path = DEFAULT_POLICY_PATH,
    require_secure: bool = True,
    live: Path = LETSENCRYPT_LIVE,
    store: Path = IMPORT_STORE,
    lock_path: Path = DEFAULT_LOCK_PATH,
) -> tuple[dict[str, Any], int]:
    """One request, from names to a CSR in the store, as one document.

    The engine behind both `haproxy-cert-request` and its job helper: the
    same checks and the same `openssl` run, so what the terminal makes is
    what the interface makes. Raises `RequestRefusal` for everything that is
    a refusal rather than a result.
    """

    try:
        policy = load_policy(policy_path, require_secure=require_secure)
        runtime = load_runtime_config(policy, require_secure=require_secure)
        ndes = getattr(policy, "ndes", None)
        result = cert_request.make_request(
            certificate_id=certificate_id,
            domains=domains,
            key_kind=key_type,
            clusters=clusters,
            receivers=receivers,
            formats=formats,
            policy=policy,
            runtime=runtime,
            live=live,
            store=store,
            lock_path=lock_path,
            request_root=ndes.state_root if ndes is not None else None,
        )
    except ConfigError as exc:
        raise RequestRefusal("dependency_unavailable", str(exc), exc.exit_code) from exc
    except cert_request.RequestError as exc:
        raise RequestRefusal(exc.code, str(exc), exc.exit_code) from exc
    return (
        envelope(
            operation=OPERATION,
            outcome="done",
            cluster=None,
            request_id=request_id,
            result=result.as_dict(),
        ),
        0,
    )


def main(
    argv: list[str] | None = None,
    *,
    policy_path: Path = DEFAULT_POLICY_PATH,
    output_stream: TextIO | None = None,
    error_stream: TextIO | None = None,
    require_secure: bool = True,
    require_root: bool = True,
    live: Path = LETSENCRYPT_LIVE,
    store: Path = IMPORT_STORE,
    lock_path: Path = DEFAULT_LOCK_PATH,
) -> int:
    writer = output_stream or sys.stdout
    errors = error_stream or sys.stderr
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--id", required=True, help="the certificate's name in the registry")
    parser.add_argument(
        "--domain",
        action="append",
        default=[],
        required=True,
        help="primary CN first, then additional DNS SANs; a wildcard is a SAN, never the CN",
    )
    parser.add_argument(
        "--key-type",
        default=DEFAULT_KEY_TYPE,
        choices=sorted(KEY_TYPES),
        help=f"the key to make (default {DEFAULT_KEY_TYPE})",
    )
    parser.add_argument("--cluster", action="append", default=[])
    parser.add_argument("--receiver", action="append", default=[])
    parser.add_argument(
        "--format",
        action="append",
        default=[],
        metavar="RECEIVER=FORMAT",
        help="how a --receiver is written once signed: pem (default) or pkcs12",
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
        return refuse("not_root", "haproxy-cert-request must run as root", 77)
    try:
        formats = cert_job.format_flags(args.format, args.receiver)
    except HelperProtocolError as exc:
        return refuse("bad_input", str(exc), 65)
    try:
        doc, exit_code = request(
            certificate_id=args.id,
            domains=args.domain,
            key_type=args.key_type,
            clusters=args.cluster,
            receivers=args.receiver,
            request_id=request_id,
            formats=formats,
            policy_path=policy_path,
            require_secure=require_secure,
            live=live,
            store=store,
            lock_path=lock_path,
        )
    except RequestRefusal as exc:
        return refuse(exc.code, str(exc), exc.exit_code)
    if args.json:
        writer.write(json.dumps(doc, separators=(",", ":")) + "\n")
    else:
        #
        # The CSR itself, and nothing about the key: what the reader does
        # next is paste this into a CA's form or hand it to whoever signs.
        #
        writer.write(f"{args.id}: pending; key {doc['result']['key_type']} made in the store\n")
        writer.write(doc["result"]["csr_pem"])
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
