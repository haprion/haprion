"""``haprion-node`` - add a node to a cluster, or take one away (B211).

    haprion-node add -c <cluster> --host <name> [--json] < block
    haprion-node remove -c <cluster> <node> [--json]
    haprion-node host -c <cluster> <node> --host <new name> [--json]

`--json` prints the helper's envelope (`schemas/v1/haprion-cluster-node`) and
leaves with its exit code. The block is what `04-node-prepare` printed on the node. `--host` is the name
this management host reaches the node at; the block carries the node's own
suggestion, which is shown and may be wrong. Both go through the same root
helper the interface's Nodes card uses, so the terminal and the browser change
the same six files the same way - and a node that does not then answer as
itself is taken back out.

`host` reaches the same node at another name or address (B295): the host keys
pinned for it move to the new name, and the node must answer there with one
of them, as itself, or nothing is changed. Changing the machine is not this:
that is a restore, or a removal and an addition.

A new node has no certificates and no release until `haprion-cert-deploy -c <cluster>`
and then `haprion-deploy -c <cluster>`.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Callable, Mapping
from typing import Any, TextIO

from haprion.cli import node_helper
from haprion.cli.caller import usage
from haprion.envelope import new_request_id
from haprion.node_enrollment import MAX_BLOCK_BYTES

SUDO = "/usr/bin/sudo"
USAGE = (
    "Usage:\n"
    "  haprion-node add -c <cluster> --host <name> [--json] < block\n"
    "  haprion-node remove -c <cluster> <node> [--json]\n"
    "  haprion-node host -c <cluster> <node> --host <new name> [--json]\n"
)

type RunHelper = Callable[[str], subprocess.CompletedProcess[str]]


def run_helper(request: str) -> subprocess.CompletedProcess[str]:
    """Through sudo, or directly when this already runs as root (F2, 2026-09-29)."""

    argv = [node_helper.HELPER] if os.geteuid() == 0 else [SUDO, "--", node_helper.HELPER]
    return subprocess.run(  # noqa: S603 - fixed helper path, no caller argv
        argv, input=request, capture_output=True, text=True, check=False
    )


def _parse(argv: list[str]) -> tuple[str, str, str, str | None]:
    """(action, cluster, host or node, the new host for `host`)."""

    if (
        len(argv) == 5
        and argv[0] == "add"
        and argv[1] in ("-c", "--cluster")
        and argv[3] == "--host"
    ):
        return "add", argv[2], argv[4], None
    if len(argv) == 4 and argv[0] == "remove" and argv[1] in ("-c", "--cluster"):
        return "remove", argv[2], argv[3], None
    if (
        len(argv) == 6
        and argv[0] == "host"
        and argv[1] in ("-c", "--cluster")
        and argv[4] == "--host"
    ):
        return "host", argv[2], argv[3], argv[5]
    usage(USAGE)


def document_of(
    completed: subprocess.CompletedProcess[str], operation: str = node_helper.OPERATION
) -> dict[str, Any]:
    """The helper's envelope, or why there is none."""

    try:
        document = json.loads(completed.stdout)
    except ValueError:
        raise ValueError(completed.stderr.strip() or "the helper gave no answer") from None
    if not isinstance(document, dict) or document.get("operation") != operation:
        raise ValueError("the helper returned an invalid result")
    return document


def json_answer(
    completed: subprocess.CompletedProcess[str], operation: str, writer: TextIO, errors: TextIO
) -> int:
    """`--json`: the helper's envelope as it came, and its exit code."""

    try:
        document = document_of(completed, operation)
    except ValueError as exc:
        errors.write(f"ERROR: {exc}\n")
        return completed.returncode or 1
    writer.write(json.dumps(document, separators=(",", ":"), sort_keys=True) + "\n")
    return completed.returncode if document.get("ok") is not True else 0


def _answer(
    completed: subprocess.CompletedProcess[str], operation: str = node_helper.OPERATION
) -> Mapping[str, Any]:
    document = document_of(completed, operation)
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
    json_mode = "--json" in arguments
    action, cluster, value, new_host = _parse([item for item in arguments if item != "--json"])
    if action == "add":
        block = (stdin or sys.stdin).read(MAX_BLOCK_BYTES + 1)
        request = node_helper.build_request(
            cluster, new_request_id(), action="add", block=block, host=value
        )
    elif action == "host":
        request = node_helper.build_request(
            cluster, new_request_id(), action="host", node=value, host=new_host
        )
    else:
        request = node_helper.build_request(cluster, new_request_id(), action="remove", node=value)

    completed = run(request)
    if json_mode:
        return json_answer(completed, node_helper.OPERATION, writer, errors)
    try:
        result = _answer(completed)
    except ValueError as exc:
        errors.write(f"ERROR: {exc}\n")
        return 1

    if result.get("action") == "host_changed":
        writer.write(
            f"{result.get('node')} of {cluster} is now reached at {result.get('host')} "
            f"(was {result.get('previous_host')}).\n"
            f"Host key: {result.get('host_key_fingerprint')}\n"
            f"Changed: {', '.join(str(item) for item in result.get('files', []))}\n"
        )
        return 0
    if result.get("action") == "added":
        writer.write(
            f"Added {result.get('node')} ({result.get('host')}) to {cluster}.\n"
            f"Host key: {result.get('host_key_fingerprint')}\n"
            f"Changed: {', '.join(str(item) for item in result.get('files', []))}\n"
            f"The node has no certificates or release yet: haprion-cert-deploy -c {cluster}, "
            f"then haprion-deploy -c {cluster}\n"
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
