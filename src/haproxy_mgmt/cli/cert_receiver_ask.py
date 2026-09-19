"""Carry one receiver request from the worker to the helper's socket (B163).

`haproxy-cert-receiver-helper` writes `/etc`: it runs `useradd`, and it
rewrites an sshd drop-in and an nginx snippet. The worker's unit has
`ProtectSystem=strict`, and a helper the worker starts through sudo inherits
that mount namespace - so the first registration from the interface failed
with a read-only `/etc/nginx/snippets`, and the one after it would have failed
at `useradd`. Opening `/etc` to a job runner is not an answer. So the helper
answers on a socket instead, from a unit of its own outside the sandbox, the
way the probe helper answers the web service, and this is the worker's side
of that: no arguments, the request on stdin, the answer on stdout, exactly the
shape the worker already runs every helper in. `execution.run`, the lease and
the output cap see nothing new.

What travels back is the helper's stdout and nothing else. Its stderr goes to
the journal, and its exit status stays with the unit - the envelope says what
happened, and that is what the job records. This command's own exit status
says only whether an answer was obtained: 0 when the helper answered, 1 when
it answered with a refusal, and 78 (EX_CONFIG) when there was nothing to ask -
which is then also an envelope, so the job reads "the service is not
installed" rather than "unknown".
"""

from __future__ import annotations

import json
import sys
from typing import Any, BinaryIO, TextIO

from haproxy_mgmt import helper_socket
from haproxy_mgmt.cli.cert_receiver_helper import OPERATION
from haproxy_mgmt.envelope import failure
from haproxy_mgmt.helper_protocol import MAX_REQUEST_BYTES, write_document

SOCKET_PATH = "/run/haproxy-mgmt/cert-receiver.sock"

# A registration resolves the receiver's name, runs useradd, checks and
# reloads sshd or nginx, and writes the registry. Seconds, not minutes; the
# bound exists so a unit that never answers becomes a sentence.
TIMEOUT_SECONDS = 120.0

EXIT_REFUSED = 1
EXIT_UNAVAILABLE = 78

__all__ = ["SOCKET_PATH", "TIMEOUT_SECONDS", "main"]


def _request(stream: BinaryIO) -> dict[str, Any]:
    """The worker's request, read whole. Its shape is the helper's to judge, not ours."""

    raw = stream.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        raise ValueError("the request is larger than a request")
    document = json.loads(raw.decode("utf-8"))
    if not isinstance(document, dict):
        raise ValueError("the request is not an object")
    return document


def main(
    argv: list[str] | None = None,
    *,
    input_stream: BinaryIO | None = None,
    output_stream: TextIO | None = None,
    error_stream: TextIO | None = None,
    socket_path: str = SOCKET_PATH,
    timeout: float = TIMEOUT_SECONDS,
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    writer: TextIO = output_stream or sys.stdout
    errors: TextIO = error_stream or sys.stderr
    if argv:
        errors.write("ERROR: haproxy-cert-receiver-ask accepts no command-line arguments\n")
        return 64

    try:
        request = _request(input_stream or sys.stdin.buffer)
    except (ValueError, UnicodeDecodeError) as exc:
        errors.write(f"ERROR: {exc}\n")
        return 64
    request_id = request.get("request_id")
    if not isinstance(request_id, str):
        errors.write("ERROR: the request carries no request_id\n")
        return 64

    try:
        answer = helper_socket.ask(
            request, path=socket_path, timeout=timeout, what="the receiver service"
        )
    except helper_socket.HelperUnavailable as exc:
        errors.write(f"ERROR: [dependency_unavailable] {exc}\n")
        write_document(
            writer,
            failure(
                operation=OPERATION,
                cluster=None,
                request_id=request_id,
                code="dependency_unavailable",
                message=f"{exc} Install haproxy-cert-receiver-helper.socket (07-platform-services).",
                exit_code=EXIT_UNAVAILABLE,
            ),
        )
        return EXIT_UNAVAILABLE

    #
    # Passed through untouched: it is the helper's document, and the worker
    # judges it. Only the exit status is decided here, from what it says.
    #
    writer.write(answer)
    if not answer.endswith("\n"):
        writer.write("\n")
    writer.flush()
    try:
        outcome = json.loads(answer).get("outcome")
    except (ValueError, AttributeError):
        return EXIT_REFUSED
    return 0 if outcome in {"done", "partial"} else EXIT_REFUSED


if __name__ == "__main__":
    raise SystemExit(main())
