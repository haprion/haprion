"""``haproxy-network`` - where a cluster's traffic arrives and leaves, read-only.

The addresses an object can be served on, the addresses it can leave from, and
the groups it can be restricted to. Read-only here on purpose: these tables are
changed by publishing to the cluster repository, the same way a proxy object is,
so that one path carries the lock, the history and the revert.
"""

from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Callable, Mapping
from typing import Any, TextIO

from haproxy_mgmt.cli.caller import usage
from haproxy_mgmt.envelope import new_request_id
from haproxy_mgmt.helper_protocol import write_document

OPERATION = "network"
HELPER = "/opt/haprion/current/bin/haproxy-network-helper"
SUDO = "/usr/bin/sudo"
EXIT_UNAVAILABLE = 68
USAGE = "Usage:\n  haproxy-network -c <cluster> [--json]\n"

type RunHelper = Callable[[str, str], subprocess.CompletedProcess[str]]


def run_network_helper(cluster_id: str, request_id: str) -> subprocess.CompletedProcess[str]:
    """Ask the root helper where one cluster's traffic arrives and leaves."""

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
        raise ValueError("the network helper returned an invalid result")
    error = document.get("error")
    if isinstance(error, Mapping):
        raise HelperFailure(f"{error.get('code')}: {error.get('message')}")
    result = document.get("result")
    if not isinstance(result, Mapping):
        raise ValueError("the network helper returned an invalid result")
    return result


def _rows(result: Mapping[str, Any], key: str) -> list[Mapping[str, Any]]:
    rows = result.get(key)
    if not isinstance(rows, list) or any(not isinstance(row, Mapping) for row in rows):
        raise ValueError(f"the network helper returned an invalid {key} table")
    return rows


def _render(document: Mapping[str, Any], writer: TextIO) -> None:
    result = _result(document)
    default_vip = str(result.get("default_vip", ""))
    writer.write(f"Cluster: {document.get('cluster')}\n\n")

    #
    # The TLS column is here for the same reason it is on the page: the policy
    # is part of what a VIP is, and a command line that could not show it left
    # the interface as the only way to read a value both of them can write.
    # A helper too old to report it says `-`, the same as a VIP that names none.
    #
    writer.write(f"{'VIP':<20}{'ADDRESS':<20}{'SOURCE':<20}{'TLS':<16}DEFAULT\n")
    writer.write(f"{'-' * 18:<20}{'-' * 18:<20}{'-' * 18:<20}{'-' * 14:<16}{'-' * 7}\n")
    for vip in _rows(result, "vips"):
        name = str(vip.get("name", ""))
        source = str(vip.get("source") or "-")
        policy = str(vip.get("tls") or "-")
        marker = "yes" if name == default_vip else ""
        writer.write(
            f"{name:<20}{str(vip.get('address', '')):<20}{source:<20}{policy:<16}{marker}\n"
        )

    sources = _rows(result, "sources")
    writer.write(f"\n{'SOURCE ADDRESS':<20}ADDRESS\n")
    writer.write(f"{'-' * 18:<20}{'-' * 18}\n")
    if not sources:
        writer.write("none; every object leaves from its VIP's default\n")
    for entry in sources:
        writer.write(f"{str(entry.get('name', '')):<20}{str(entry.get('address', ''))}\n")

    groups = _rows(result, "groups")
    writer.write(f"\n{'GROUP':<20}MEMBERS\n")
    writer.write(f"{'-' * 18:<20}{'-' * 24}\n")
    if not groups:
        writer.write("none defined\n")
    for group in groups:
        members = group.get("members")
        listed = ", ".join(str(member) for member in members) if isinstance(members, list) else "-"
        writer.write(f"{str(group.get('name', '')):<20}{listed}\n")

    #
    # Where the answer came from, and the one address that is not in any table
    # above. Both are reported because they decide what a reader may do next:
    # only a repository description can be edited by publishing, and the
    # ownership address is deliberately not editable at all.
    #
    origin = result.get("origin")
    where = (
        "managed/network.yaml in the cluster repository"
        if origin == "repository"
        else "the engine's cluster configuration (this cluster has no managed/network.yaml)"
    )
    writer.write(f"\nRead from {where}.\n")
    writer.write(
        f"Node ownership is checked against {result.get('ownership_vip')}, which is not one of "
        "these tables\nand cannot be changed by publishing.\n"
    )


def main(
    argv: list[str] | None = None,
    *,
    stream_out: TextIO | None = None,
    stream_err: TextIO | None = None,
    run_helper: RunHelper = run_network_helper,
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    writer: TextIO = stream_out or sys.stdout
    errors: TextIO = stream_err or sys.stderr
    cluster_id, json_mode = _parse(argv)
    completed = run_helper(cluster_id, new_request_id())

    try:
        document = json.loads(completed.stdout)
    except json.JSONDecodeError:
        errors.write(completed.stderr.strip() or "ERROR: the network helper returned no result")
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
