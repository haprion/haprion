"""``haproxy-inventory`` - the published proxy configuration, read-only."""

from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Callable, Mapping
from typing import Any, TextIO

from haproxy_mgmt.cli.caller import usage
from haproxy_mgmt.envelope import new_request_id

OPERATION = "inventory"
HELPER = "/opt/haproxy-mgmt/current/bin/haproxy-inventory-helper"
SUDO = "/usr/bin/sudo"
EXIT_UNAVAILABLE = 68
USAGE = "Usage:\n  haproxy-inventory -c <cluster> [--json]\n"

type RunHelper = Callable[[str, str], subprocess.CompletedProcess[str]]


def run_inventory_helper(cluster_id: str, request_id: str) -> subprocess.CompletedProcess[str]:
    """Ask the root helper for the published inventory of one cluster."""

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


def _result(document: Mapping[str, Any]) -> Mapping[str, Any]:
    result = document.get("result")
    if document.get("operation") != OPERATION or not isinstance(result, Mapping):
        raise ValueError("the inventory helper returned an invalid result")
    return result


def _render(document: Mapping[str, Any], writer: TextIO) -> None:
    result = _result(document)
    version = result.get("version")
    writer.write(f"Cluster: {document.get('cluster')}\n")
    writer.write(f"Published: {'nothing published yet' if version is None else version}\n\n")
    proxies = result.get("proxies")
    if not isinstance(proxies, list) or not proxies:
        writer.write("No published proxies.\n")
        return
    writer.write("NAME                     TYPE   SOURCE    PORTS     BACKENDS\n")
    for proxy in proxies:
        if not isinstance(proxy, Mapping):
            raise ValueError("the inventory helper returned an invalid proxy")
        ports = ",".join(str(port) for port in proxy.get("bind_ports", [])) or "-"
        writer.write(
            f"{str(proxy.get('name', '')):<24} {str(proxy.get('protocol', '')):<6} "
            f"{str(proxy.get('source', '')):<9} {ports:<9} {proxy.get('backend_count', 0)}\n"
        )


def main(
    argv: list[str] | None = None,
    *,
    stream_out: TextIO | None = None,
    stream_err: TextIO | None = None,
    run_helper: RunHelper = run_inventory_helper,
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    writer: TextIO = stream_out or sys.stdout
    errors: TextIO = stream_err or sys.stderr
    cluster_id, json_mode = _parse(argv)
    completed = run_helper(cluster_id, new_request_id())

    try:
        document = json.loads(completed.stdout)
    except json.JSONDecodeError:
        errors.write(completed.stderr.strip() or "ERROR: the inventory helper returned no result")
        errors.write("\n")
        return completed.returncode or EXIT_UNAVAILABLE

    if json_mode:
        writer.write(json.dumps(document, separators=(",", ":"), sort_keys=True) + "\n")
        return completed.returncode
    try:
        _render(document, writer)
    except ValueError as exc:
        errors.write(f"ERROR: {exc}\n")
        return completed.returncode or EXIT_UNAVAILABLE
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
