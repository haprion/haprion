"""Carry one request from the worker to a root helper's socket, and its answer back.

Four helpers answer on sockets rather than through sudo - the receiver, the
node change, the backup job and the node restore - because each writes where
the worker's sandbox keeps it from writing (B163, B211). Their clients were
four near-copies; this is the one client, and each `*_ask` module names its
service (B335).

The shape is the one the worker runs every helper in: no arguments, the
request on stdin, the helper's document on stdout, passed through untouched.
This client's exit status says only whether an answer was obtained.

Every refusal it can tie to the request is a document as well (fynd 27): a
request this client turns away has asked nothing of anybody, and a job left
without a document reads as "may have acted". Only a request with no identity
to answer to - not an object, no request ID - is refused with a line alone,
and the worker never sends one.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Collection
from dataclasses import dataclass, field
from typing import Any, BinaryIO, TextIO

from haprion import helper_socket
from haprion.envelope import failure
from haprion.helper_protocol import MAX_REQUEST_BYTES, write_document

EXIT_USAGE = 64
EXIT_REFUSED = 1
EXIT_SILENT = 1
EXIT_BUSY = 75
EXIT_UNAVAILABLE = 78


@dataclass(frozen=True, slots=True)
class Service:
    """One helper behind a socket, as its client needs to know it."""

    command: str
    socket_path: str
    timeout: float
    what: str
    #
    # The sentence after "the socket is not there": which unit to install.
    #
    install: str
    #
    # The operations the helper answers; None leaves the judging to it.
    #
    operations: Collection[str] | None
    not_ours: str = "the request is not one this service answers"
    #
    # A receiver request names no cluster, and its refusal is filed under the
    # one operation the helper has.
    #
    cluster_bound: bool = True
    operation: str | None = None
    #
    # Questions that change nothing, answered "busy, ask again" when the
    # socket is held by a run still going (the restore's status).
    #
    busy_answers: Collection[str] = field(default_factory=frozenset)
    succeeded: Collection[str] = ("done", "partial")
    blocked_exit: int = EXIT_REFUSED


def _read(stream: BinaryIO) -> dict[str, Any] | None:
    raw = stream.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        return None
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return document if isinstance(document, dict) else None


def run(
    service: Service,
    argv: list[str] | None = None,
    *,
    input_stream: BinaryIO | None = None,
    output_stream: TextIO | None = None,
    error_stream: TextIO | None = None,
    socket_path: str | None = None,
    timeout: float | None = None,
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    writer: TextIO = output_stream or sys.stdout
    errors: TextIO = error_stream or sys.stderr
    if argv:
        errors.write(f"ERROR: {service.command} accepts no arguments\n")
        return EXIT_USAGE

    request = _read(input_stream or sys.stdin.buffer)
    if request is None:
        errors.write("ERROR: the request is not a JSON object of a request's size\n")
        return EXIT_USAGE
    sent = request.get("operation")
    operation = service.operation or sent
    request_id = request.get("request_id")
    cluster = request.get("cluster") if service.cluster_bound else None
    if (
        not isinstance(request_id, str)
        or not isinstance(operation, str)
        or (service.cluster_bound and not isinstance(cluster, str))
    ):
        errors.write("ERROR: the request carries no request identity\n")
        return EXIT_USAGE

    def answer(code: str, message: str, exit_code: int) -> int:
        errors.write(f"ERROR: [{code}] {message}\n")
        write_document(
            writer,
            failure(
                operation=operation,
                cluster=cluster,
                request_id=request_id,
                code=code,
                message=message,
                exit_code=exit_code,
            ),
        )
        return exit_code

    if service.operations is not None and sent not in service.operations:
        return answer("bad_input", f"{service.not_ours}; nothing was asked", EXIT_USAGE)

    try:
        reply = helper_socket.ask(
            request,
            path=socket_path or service.socket_path,
            timeout=timeout or service.timeout,
            what=service.what,
        )
    except helper_socket.HelperBusy as exc:
        if sent not in service.busy_answers:
            errors.write(
                f"ERROR: [helper_silent] {exc} It may still be working; its outcome is unknown.\n"
            )
            return EXIT_SILENT
        #
        # The socket takes one connection at a time, and a run still going
        # holds it. For a question that changes nothing, that is the answer.
        #
        return answer(
            "restore_busy",
            "A restore step is still running; ask again when it has finished.",
            EXIT_BUSY,
        )
    except helper_socket.HelperSilent as exc:
        #
        # Asked, then silent: the root service carries on without this client
        # and may have acted. No document - the worker records an answer that
        # never came as `unknown`, with this sentence as its reason.
        #
        errors.write(
            f"ERROR: [helper_silent] {exc} It may still be working; its outcome is unknown.\n"
        )
        return EXIT_SILENT
    except helper_socket.HelperUnavailable as exc:
        return answer("dependency_unavailable", f"{exc} {service.install}", EXIT_UNAVAILABLE)

    #
    # Passed through untouched: it is the helper's document, and the worker
    # judges it. Only the exit status is decided here, from what it says.
    #
    writer.write(reply + ("" if reply.endswith("\n") else "\n"))
    writer.flush()
    try:
        outcome = json.loads(reply).get("outcome")
    except (ValueError, AttributeError):
        return EXIT_REFUSED
    if outcome in service.succeeded:
        return 0
    return service.blocked_exit if outcome == "blocked" else EXIT_REFUSED
