"""``haproxy-list-backups`` - which state backups exist per node, read-only.

Replaces a shell implementation that read the backup directory directly with a
hardcoded node list. Two things change and one deliberately does not: the nodes
now come from cluster configuration, and the answer is a schema-checked
envelope. The CREATED column still shows the archive's modification time, which
is what the shell version showed - a reimplementation that quietly answered a
different question would be worse than no reimplementation.
"""

from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Callable, Mapping
from typing import Any, TextIO

from haproxy_mgmt.cli.caller import usage
from haproxy_mgmt.envelope import new_request_id

OPERATION = "list_backups"
HELPER = "/opt/haproxy-mgmt/current/bin/haproxy-list-backups-helper"
SUDO = "/usr/bin/sudo"
DEFAULT_LIMIT = 10
EXIT_UNAVAILABLE = 68
USAGE = (
    "Usage:\n"
    "  haproxy-list-backups -c <cluster> [--all] [--json]\n"
    "\n"
    "  --all   every retained backup, instead of the 10 most recent per node\n"
)

type RunHelper = Callable[[str, str, int | None], subprocess.CompletedProcess[str]]


def run_list_backups_helper(
    cluster_id: str, request_id: str, limit: int | None = DEFAULT_LIMIT
) -> subprocess.CompletedProcess[str]:
    """Ask the root helper which backups exist for one cluster's nodes."""

    request = {
        "schema_version": 1,
        "operation": OPERATION,
        "cluster": cluster_id,
        "request_id": request_id,
        "parameters": {"limit": limit},
    }
    return subprocess.run(  # noqa: S603 - fixed helper path, no caller argv
        [SUDO, "-n", HELPER],
        input=json.dumps(request, separators=(",", ":")),
        capture_output=True,
        text=True,
        check=False,
    )


def _parse(argv: list[str]) -> tuple[str, int | None, bool]:
    if len(argv) < 2 or argv[0] not in ("-c", "--cluster"):
        usage(USAGE)
    rest = argv[2:]
    if any(flag not in ("--all", "--json") for flag in rest) or len(set(rest)) != len(rest):
        usage(USAGE)
    return argv[1], None if "--all" in rest else DEFAULT_LIMIT, "--json" in rest


def _result(document: Mapping[str, Any]) -> Mapping[str, Any]:
    result = document.get("result")
    if document.get("operation") != OPERATION or not isinstance(result, Mapping):
        raise ValueError("the backup helper returned an invalid result")
    return result


def _size(size_bytes: int) -> str:
    #
    # Powers of 1024 with one unit per step, which is what `du -h` printed in
    # the shell version. Rendering is the operator's, so it stays where the
    # operator reads it and never reaches the JSON.
    #
    size = float(size_bytes)
    for unit in ("B", "K", "M"):
        if size < 1024:
            return f"{size:.0f}{unit}"
        size /= 1024
    return f"{size:.0f}G"


def _render(document: Mapping[str, Any], writer: TextIO) -> None:
    result = _result(document)
    nodes = result.get("nodes")
    if not isinstance(nodes, list):
        raise ValueError("the backup helper returned an invalid node list")
    writer.write(f"Cluster: {document.get('cluster')}\n")
    for node in nodes:
        if not isinstance(node, Mapping):
            raise ValueError("the backup helper returned an invalid node")
        writer.write(f"\n=== {node.get('name')} ===\n")
        if not node.get("available"):
            error = node.get("error")
            reason = error.get("code") if isinstance(error, Mapping) else "unavailable"
            writer.write(f"No backups could be read: {reason}\n")
            continue
        latest = node.get("latest_version")
        writer.write(f"latest -> {'MISSING' if latest is None else latest}\n\n")
        backups = node.get("backups")
        if not isinstance(backups, list) or not backups:
            writer.write("(no backups)\n")
            continue
        writer.write(f"{'CREATED':<22}{'SIZE':>8}  VERSION\n")
        for backup in backups:
            if not isinstance(backup, Mapping):
                raise ValueError("the backup helper returned an invalid backup")
            writer.write(
                f"{str(backup.get('created_at', '')):<22}"
                f"{_size(int(backup.get('size_bytes', 0))):>8}  {backup.get('version', '')}\n"
            )


def main(
    argv: list[str] | None = None,
    *,
    stream_out: TextIO | None = None,
    stream_err: TextIO | None = None,
    run_helper: RunHelper = run_list_backups_helper,
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    writer: TextIO = stream_out or sys.stdout
    errors: TextIO = stream_err or sys.stderr
    cluster_id, limit, json_mode = _parse(argv)
    completed = run_helper(cluster_id, new_request_id(), limit)

    try:
        document = json.loads(completed.stdout)
    except json.JSONDecodeError:
        errors.write(completed.stderr.strip() or "ERROR: the backup helper returned no result")
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
