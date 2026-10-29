"""Carry a node or cluster change from the worker to its root helper socket (B211).

Adding a node writes root's `known_hosts` and the pull accounts' keys, which the
worker's sandbox keeps read-only for anything it starts; so the helper answers on
a socket. The client is `socket_ask`; this names the service.
"""

from __future__ import annotations

from typing import BinaryIO, TextIO

from haprion.cli.node_helper import PARAMETERS
from haprion.cli.socket_ask import Service, run

SERVICE = Service(
    command="haprion-node-ask",
    socket_path="/run/haprion/cluster-node.sock",
    #
    # Under the worker's 900 s, so a run that goes long is answered by this
    # client rather than cut off. A removal is six files and a status read of
    # sixty seconds; a join runs apt on the node, seconds or a few minutes
    # (`node_join.JOIN_TIMEOUT_SECONDS`), and a cluster has two. One that
    # outlasts this ends on the answer the helper keeps (26-10-29, O01).
    #
    timeout=840.0,
    what="the node service",
    install="Install haprion-node-helper.socket (07-platform-services).",
    #
    # Both operations the helper answers on this socket: a node of a cluster,
    # and a whole cluster.
    #
    operations=frozenset(PARAMETERS),
    not_ours="the request is not a node or cluster change",
)
SOCKET_PATH = SERVICE.socket_path
TIMEOUT_SECONDS = SERVICE.timeout

__all__ = [
    "SOCKET_PATH",
    "TIMEOUT_SECONDS",
    "main",
]


def main(
    argv: list[str] | None = None,
    *,
    input_stream: BinaryIO | None = None,
    output_stream: TextIO | None = None,
    error_stream: TextIO | None = None,
    socket_path: str = SOCKET_PATH,
    timeout: float = TIMEOUT_SECONDS,
) -> int:
    return run(
        SERVICE,
        argv,
        input_stream=input_stream,
        output_stream=output_stream,
        error_stream=error_stream,
        socket_path=socket_path,
        timeout=timeout,
    )


if __name__ == "__main__":
    raise SystemExit(main())
