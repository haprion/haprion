"""Carry a node change from the worker to the root helper socket (B211).

The same shape as the backup and receiver asks: no arguments, the request on
stdin, the helper's answer on stdout. Adding a node writes root's
`known_hosts` and the pull accounts' keys, which the worker's sandbox keeps
read-only for anything it starts; so the helper answers on a socket.
"""

from __future__ import annotations

import json
import sys
from typing import Any, BinaryIO, TextIO

from haproxy_mgmt import helper_socket
from haproxy_mgmt.cli.node_helper import OPERATION
from haproxy_mgmt.envelope import failure
from haproxy_mgmt.helper_protocol import MAX_REQUEST_BYTES, write_document

SOCKET_PATH = "/run/haproxy-mgmt/cluster-node.sock"
#
# Six small files and one status read of the node, whose own bound is sixty
# seconds. The margin is for a node that connects and then says nothing.
#
TIMEOUT_SECONDS = 120.0


def _request(stream: BinaryIO) -> dict[str, Any]:
    raw = stream.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        raise ValueError("the request is larger than a request")
    document = json.loads(raw.decode("utf-8"))
    if not isinstance(document, dict) or document.get("operation") != OPERATION:
        raise ValueError("the request is not a node change")
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
    writer = output_stream or sys.stdout
    errors = error_stream or sys.stderr
    if argv:
        errors.write("ERROR: haproxy-node-ask accepts no arguments\n")
        return 64
    try:
        request = _request(input_stream or sys.stdin.buffer)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        errors.write(f"ERROR: {exc}\n")
        return 64
    operation = str(request["operation"])
    request_id = request.get("request_id")
    cluster = request.get("cluster")
    if not isinstance(request_id, str) or not isinstance(cluster, str):
        errors.write("ERROR: the request carries no request identity\n")
        return 64
    try:
        answer = helper_socket.ask(
            request, path=socket_path, timeout=timeout, what="the node service"
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
        return 1
    except helper_socket.HelperUnavailable as exc:
        errors.write(f"ERROR: [dependency_unavailable] {exc}\n")
        write_document(
            writer,
            failure(
                operation=operation,
                cluster=cluster,
                request_id=request_id,
                code="dependency_unavailable",
                message=f"{exc} Install haproxy-node-helper.socket (07-platform-services).",
                exit_code=78,
            ),
        )
        return 78
    writer.write(answer + ("" if answer.endswith("\n") else "\n"))
    writer.flush()
    try:
        outcome = json.loads(answer).get("outcome")
    except (ValueError, AttributeError):
        return 1
    return 0 if outcome in {"done", "partial"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
