"""`haprion-server-state` - drain, maintenance or ready for an object's servers.

The thin half, as the calling user: it turns arguments into the request the
interface's worker sends too (`server_state_helper.build_request`), hands it to
the root helper through sudo, and prints what came back. Which nodes are asked,
with which key, and whether the servers exist is the helper's to decide.

    drain   out of load balancing; a visitor whose cookie names it still reaches
            it, and it is still checked
    maint   no new traffic at all, and no health checks
    ready   back in the pool

Requests already in flight finish in both (measured 2026-10-09); nothing is cut.

    unblock lifts the object's dynamic block on source addresses, on every node

The state is kept by each node across reloads and restarts until it is set to
ready again, so a deploy does not quietly put a drained server back.
"""

from __future__ import annotations

import json
import subprocess
import sys
from typing import Any, TextIO

from haprion.cli.caller import usage, without_answer
from haprion.cli.server_state_helper import HELPER, SUDO, build_request, build_unblock_request
from haprion.envelope import new_request_id
from haprion.helper_protocol import write_document
from haprion.server_state import OPERATION, STATES, UNBLOCK_OPERATION, UNBLOCK_VERB

USAGE = (
    "Usage:\n"
    "  haprion-server-state -c <cluster> -o <object> <ready|drain|maint> "
    "<host:port|pool/host:port>... [--json]\n"
    "  haprion-server-state -c <cluster> -o <object> unblock <address>... [--json]\n"
    "\n"
    "Examples:\n"
    "  haprion-server-state -c alpha -o shop drain 198.51.100.10:8080\n"
    "  haprion-server-state -c alpha -o shop ready 198.51.100.10:8080 198.51.100.11:8080\n"
    "  haprion-server-state -c alpha -o portal maint api/198.51.100.20:9000 --json\n"
    "  haprion-server-state -c alpha -o shop unblock 203.0.113.7 2001:db8::7\n"
)


def run_helper(request: str) -> subprocess.CompletedProcess[str]:
    """Through sudo without `-n`, as `haprion-probe`: a person has a terminal to answer it on."""

    return subprocess.run(  # noqa: S603 - fixed path, no caller-supplied arguments
        [SUDO, "--", HELPER],
        input=request,
        capture_output=True,
        text=True,
        check=False,
    )


def _parse(argv: list[str]) -> dict[str, Any]:
    options: dict[str, Any] = {"cluster": "", "object": "", "json": False, "words": []}
    index = 0
    while index < len(argv):
        argument = argv[index]
        if argument in ("-c", "--cluster") and index + 1 < len(argv):
            options["cluster"] = argv[index + 1]
            index += 2
        elif argument in ("-o", "--object") and index + 1 < len(argv):
            options["object"] = argv[index + 1]
            index += 2
        elif argument == "--json":
            options["json"] = True
            index += 1
        elif argument.startswith("-"):
            usage(USAGE)
        else:
            options["words"].append(argument)
            index += 1
    words = options["words"]
    if (
        not options["cluster"]
        or not options["object"]
        or len(words) < 2
        or words[0] not in (*STATES, UNBLOCK_VERB)
    ):
        usage(USAGE)
    return options


def _render_unblock(envelope: dict[str, Any], writer: TextIO) -> None:
    result = envelope.get("result") or {}
    writer.write(f"Cluster: {envelope.get('cluster')}\n")
    writer.write(f"Object:  {result.get('object')}\n\n")
    for node in result.get("nodes") or []:
        writer.write(f"{node.get('node')}   {node.get('message') or ''}".rstrip() + "\n")
        for entry in node.get("addresses") or []:
            verdict = "UNBLOCKED" if entry.get("outcome") == "done" else "STILL    "
            writer.write(f"  {verdict}  {entry.get('address')}\n")
        writer.write("\n")
    writer.write(f"RESULT: {str(envelope.get('outcome')).upper()}\n")


def _render(envelope: dict[str, Any], writer: TextIO) -> None:
    if envelope.get("operation") == "dynamic_unblock":
        _render_unblock(envelope, writer)
        return
    result = envelope.get("result") or {}
    writer.write(f"Cluster: {envelope.get('cluster')}\n")
    writer.write(f"Object:  {result.get('object')}\n")
    writer.write(f"State:   {result.get('state')}\n\n")
    for node in result.get("nodes") or []:
        writer.write(f"{node.get('node')}\n")
        for entry in node.get("servers") or []:
            verdict = {"done": "OK     ", "refused": "NOT RUN"}.get(entry.get("outcome"), "FAILED ")
            detail = entry.get("message") or ""
            writer.write(f"  {verdict}  {entry.get('server')}   {detail}\n".rstrip() + "\n")
        writer.write("\n")
    writer.write(f"RESULT: {str(envelope.get('outcome')).upper()}\n")


def main(argv: list[str] | None = None, *, writer: TextIO | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    out: TextIO = writer or sys.stdout
    options = _parse(argv)
    state, *servers = options["words"]

    if state == UNBLOCK_VERB:
        request = build_unblock_request(
            options["cluster"], new_request_id(), object_name=options["object"], addresses=servers
        )
    else:
        request = build_request(
            options["cluster"],
            new_request_id(),
            object_name=options["object"],
            servers=servers,
            state=state,
        )
    completed = run_helper(request)
    try:
        envelope = json.loads(completed.stdout)
    except ValueError:
        return without_answer(
            completed,
            operation=UNBLOCK_OPERATION if state == UNBLOCK_VERB else OPERATION,
            cluster=options["cluster"],
            json_mode=bool(options["json"]),
            writer=out,
            errors=sys.stderr,
            fallback="the helper produced no answer",
        )

    if options["json"]:
        return write_document(out, envelope, completed.returncode)
    if envelope.get("result") is None:
        error = envelope.get("error") or {}
        sys.stderr.write(f"ERROR: [{error.get('code')}] {error.get('message')}\n")
        return completed.returncode
    _render(envelope, out)
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
