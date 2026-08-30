"""``haproxy-cert-list`` - which certificates a cluster can be given, read-only.

Metadata only. The listing exists so an operator, and later the interface, can
answer three questions without opening a file: what is deployable to this
cluster, what does each certificate actually cover, and is anything renewing it.
"""

from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any, TextIO

from haproxy_mgmt.cli.caller import usage
from haproxy_mgmt.envelope import new_request_id
from haproxy_mgmt.helper_protocol import write_document

OPERATION = "cert_list"
HELPER = "/opt/haproxy-mgmt/current/bin/haproxy-cert-list-helper"
SUDO = "/usr/bin/sudo"
EXIT_UNAVAILABLE = 68
USAGE = "Usage:\n  haproxy-cert-list -c <cluster> [--json]\n"

type RunHelper = Callable[[str, str], subprocess.CompletedProcess[str]]


def run_cert_list_helper(cluster_id: str, request_id: str) -> subprocess.CompletedProcess[str]:
    """Ask the root helper which certificates one cluster can be given."""

    request = {
        "schema_version": 1,
        "operation": OPERATION,
        "cluster": cluster_id,
        "request_id": request_id,
        "parameters": {},
    }
    return subprocess.run(  # noqa: S603 - fixed helper path, no caller argv
        [SUDO, "-n", HELPER],
        input=json.dumps(request, separators=(",", ":")),
        capture_output=True,
        text=True,
        check=False,
    )


def _parse(argv: list[str]) -> tuple[str, bool]:
    if len(argv) not in (2, 3) or argv[0] not in ("-c", "--cluster"):
        usage(USAGE)
    if len(argv) == 3 and argv[2] != "--json":
        usage(USAGE)
    return argv[1], len(argv) == 3


class HelperFailure(ValueError):
    """The helper answered, and the answer is that it could not do the read."""


def _result(document: Mapping[str, Any]) -> Mapping[str, Any]:
    if document.get("operation") != OPERATION:
        raise ValueError("the certificate helper returned an invalid result")
    error = document.get("error")
    if isinstance(error, Mapping):
        raise HelperFailure(f"{error.get('code')}: {error.get('message')}")
    result = document.get("result")
    if not isinstance(result, Mapping):
        raise ValueError("the certificate helper returned an invalid result")
    return result


def _expiry(not_after: str, now: datetime) -> str:
    """Days left, which is the number an operator is actually reading for."""

    try:
        moment = datetime.fromisoformat(not_after.replace("Z", "+00:00"))
    except ValueError:
        return "unknown"
    days = (moment - now).days
    return f"{days}d" if days >= 0 else f"expired {-days}d ago"


def _render(document: Mapping[str, Any], writer: TextIO) -> None:
    result = _result(document)
    certificates = result.get("certificates")
    if not isinstance(certificates, list):
        raise ValueError("the certificate helper returned an invalid certificate list")
    writer.write(f"Cluster: {document.get('cluster')}\n\n")
    if not certificates:
        writer.write("No certificates in the distribution directory.\n")
        return

    now = datetime.now(UTC)
    writer.write(f"{'ID':<22}{'USE':<12}{'RENEWAL':<9}{'EXPIRES':<16}COVERS\n")
    writer.write(f"{'-' * 20:<22}{'-' * 10:<12}{'-' * 7:<9}{'-' * 14:<16}{'-' * 24}\n")
    for certificate in certificates:
        if not isinstance(certificate, Mapping):
            raise ValueError("the certificate helper returned an invalid certificate")
        use = "referenced" if certificate.get("referenced_by_cluster") else "available"
        if not certificate.get("deployable"):
            writer.write(
                f"{str(certificate.get('id', '')):<22}{use:<12}"
                f"UNUSABLE  {certificate.get('validation_error', '')}\n"
            )
            continue
        sans = certificate.get("sans")
        covers = ", ".join(sans) if isinstance(sans, list) and sans else "-"
        expires = _expiry(str(certificate.get("not_after", "")), now)
        if not certificate.get("valid"):
            expires = f"{expires} !"
        writer.write(
            f"{str(certificate.get('id', '')):<22}{use:<12}"
            f"{str(certificate.get('lifecycle', '')):<9}{expires:<16}{covers}\n"
        )
    writer.write(
        "\nRENEWAL is measured, not declared: acme means this certificate's leaf was\n"
        "found in certbot's archive on this host, so something is renewing it.\n"
    )


def main(
    argv: list[str] | None = None,
    *,
    stream_out: TextIO | None = None,
    stream_err: TextIO | None = None,
    run_helper: RunHelper = run_cert_list_helper,
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    writer: TextIO = stream_out or sys.stdout
    errors: TextIO = stream_err or sys.stderr
    cluster_id, json_mode = _parse(argv)
    completed = run_helper(cluster_id, new_request_id())

    try:
        document = json.loads(completed.stdout)
    except json.JSONDecodeError:
        errors.write(completed.stderr.strip() or "ERROR: the certificate helper returned no result")
        errors.write("\n")
        return completed.returncode or EXIT_UNAVAILABLE

    if json_mode:
        write_document(writer, document)
        return completed.returncode
    try:
        _render(document, writer)
    except ValueError as exc:
        errors.write(f"ERROR: {exc}\n")
        return completed.returncode or EXIT_UNAVAILABLE
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
