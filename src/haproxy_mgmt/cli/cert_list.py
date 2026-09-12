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
USAGE = "Usage:\n  haproxy-cert-list -c <cluster> [--registry] [--json]\n"

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


def _parse(argv: list[str]) -> tuple[str, bool, bool]:
    #
    # `--registry` still names a cluster, and that is not decoration: the
    # registry travels in the cluster listing's answer rather than in a helper
    # of its own, so `-c` says whose answer is being read. A clusterless listing
    # would need a helper, a wrapper and a sudoers rule of its own; the
    # implementation plan's C5 gate count says why that was not worth it.
    #
    if not argv or argv[0] not in ("-c", "--cluster") or len(argv) < 2:
        usage(USAGE)
    flags = argv[2:]
    if any(flag not in ("--json", "--registry") for flag in flags) or len(set(flags)) != len(flags):
        usage(USAGE)
    return argv[1], "--json" in flags, "--registry" in flags


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


def _targets(entry: Mapping[str, Any]) -> str:
    """Where one certificate goes, clusters and receivers in one column.

    Receivers are marked so the two kinds are not read as one list: a cluster
    is rolled out by this manager, and a receiver fetches on its own.
    """

    targets = entry.get("targets")
    if not isinstance(targets, Mapping):
        return "-"
    clusters = [str(name) for name in targets.get("clusters", []) if isinstance(name, str)]
    receivers = [
        f"{item.get('id')} (receiver)"
        for item in targets.get("receivers", [])
        if isinstance(item, Mapping)
    ]
    return ", ".join(clusters + receivers) or "nowhere"


def _render_registry(document: Mapping[str, Any], writer: TextIO) -> None:
    """Every certificate the manager holds, not one cluster's deployable set.

    Measured at each certificate's source, so a certificate that goes only to
    receivers - and therefore has no file in the distribution directory at all -
    is listed with real dates rather than missing.
    """

    registry = _result(document).get("registry")
    if not isinstance(registry, Mapping):
        raise ValueError(
            "this installation declares no certificate_registry, so there is nothing to list"
        )
    entries = registry.get("certificates")
    if not isinstance(entries, list):
        raise ValueError("the certificate helper returned an invalid registry")

    writer.write("The certificate registry\n\n")
    if not entries:
        writer.write("No certificates are registered.\n")
        return

    now = datetime.now(UTC)
    writer.write(f"{'ID':<26}{'SOURCE':<10}{'EXPIRES':<16}USED BY\n")
    writer.write(f"{'-' * 24:<26}{'-' * 8:<10}{'-' * 14:<16}{'-' * 30}\n")
    for entry in entries:
        if not isinstance(entry, Mapping):
            raise ValueError("the certificate helper returned an invalid registry entry")
        source = entry.get("source")
        kind = str(source.get("kind")) if isinstance(source, Mapping) else "unknown"
        if not entry.get("readable"):
            writer.write(
                f"{str(entry.get('id', '')):<26}{kind:<10}UNREADABLE      "
                f"{entry.get('validation_error', '')}\n"
            )
            continue
        expires = _expiry(str(entry.get("not_after", "")), now)
        if not entry.get("valid"):
            expires = f"{expires} !"
        writer.write(f"{str(entry.get('id', '')):<26}{kind:<10}{expires:<16}{_targets(entry)}\n")
    writer.write(
        "\nUSED BY is where the certificate is published. For a receiver that means\n"
        "the manager wrote the file; whether the receiver fetched it is not knowable\n"
        "here, because a receiver pulls on its own schedule and reports nothing back.\n"
    )


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
    cluster_id, json_mode, registry_mode = _parse(argv)
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
        _render_registry(document, writer) if registry_mode else _render(document, writer)
    except ValueError as exc:
        errors.write(f"ERROR: {exc}\n")
        return completed.returncode or EXIT_UNAVAILABLE
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
