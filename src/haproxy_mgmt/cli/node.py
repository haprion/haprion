"""``haproxy-node`` - add a node to a cluster, or take one away (B211).

    haproxy-node add -c <cluster> --host <name> < block
    haproxy-node remove -c <cluster> <node>

The block is what `04-node-prepare` printed on the node. `--host` is the name
this management host reaches the node at; the block carries the node's own
suggestion, which is shown and may be wrong. Both go through the same root
helper the interface's Nodes card uses, so the terminal and the browser change
the same six files the same way - and a node that does not then answer as
itself is taken back out.

A new node has no release until the next `haproxy-deploy -c <cluster>`.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Callable, Mapping
from typing import Any, TextIO

from haproxy_mgmt.cli import node_helper
from haproxy_mgmt.cli.caller import usage
from haproxy_mgmt.envelope import new_request_id
from haproxy_mgmt.node_enrollment import MAX_BLOCK_BYTES

SUDO = "/usr/bin/sudo"
USAGE = (
    "Usage:\n"
    "  haproxy-node add -c <cluster> --host <name> < block\n"
    "  haproxy-node remove -c <cluster> <node>\n"
)

type RunHelper = Callable[[str], subprocess.CompletedProcess[str]]


def run_helper(request: str) -> subprocess.CompletedProcess[str]:
    """Through sudo, or directly when this already runs as root (F2, 2026-09-29)."""

    argv = [node_helper.HELPER] if os.geteuid() == 0 else [SUDO, "--", node_helper.HELPER]
    return subprocess.run(  # noqa: S603 - fixed helper path, no caller argv
        argv, input=request, capture_output=True, text=True, check=False
    )


def _parse(argv: list[str]) -> tuple[str, str, str]:
    """(action, cluster, host or node)."""

    if (
        len(argv) == 5
        and argv[0] == "add"
        and argv[1] in ("-c", "--cluster")
        and argv[3] == "--host"
    ):
        return "add", argv[2], argv[4]
    if len(argv) == 4 and argv[0] == "remove" and argv[1] in ("-c", "--cluster"):
        return "remove", argv[2], argv[3]
    usage(USAGE)


def _answer(completed: subprocess.CompletedProcess[str]) -> Mapping[str, Any]:
    try:
        document = json.loads(completed.stdout)
    except ValueError:
        raise ValueError(completed.stderr.strip() or "the helper gave no answer") from None
    if not isinstance(document, dict) or document.get("operation") != node_helper.OPERATION:
        raise ValueError("the helper returned an invalid result")
    error = document.get("error")
    if isinstance(error, Mapping):
        raise ValueError(str(error.get("message")))
    result = document.get("result")
    if not isinstance(result, Mapping):
        raise ValueError("the helper returned an invalid result")
    return result


def main(
    argv: list[str] | None = None,
    *,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
    run: RunHelper = run_helper,
) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    writer = stdout or sys.stdout
    errors = stderr or sys.stderr
    action, cluster, value = _parse(arguments)
    if action == "add":
        block = (stdin or sys.stdin).read(MAX_BLOCK_BYTES + 1)
        request = node_helper.build_request(
            cluster, new_request_id(), action="add", block=block, host=value
        )
    else:
        request = node_helper.build_request(cluster, new_request_id(), action="remove", node=value)

    try:
        result = _answer(run(request))
    except ValueError as exc:
        errors.write(f"ERROR: {exc}\n")
        return 1

    if result.get("action") == "added":
        writer.write(
            f"Added {result.get('node')} ({result.get('host')}) to {cluster}.\n"
            f"Host key: {result.get('host_key_fingerprint')}\n"
            f"Changed: {', '.join(str(item) for item in result.get('files', []))}\n"
            f"The node has no release yet: haproxy-deploy -c {cluster}\n"
        )
    else:
        writer.write(
            f"Removed {result.get('node')} from {cluster}.\n"
            f"Changed: {', '.join(str(item) for item in result.get('files', []))}\n"
            "The node itself is untouched: it keeps serving what it has until it is shut down.\n"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
