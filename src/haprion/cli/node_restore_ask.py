"""Carry a node restore job from the worker to its root helper socket. The client is `socket_ask`."""

from __future__ import annotations

from typing import BinaryIO, TextIO

from haprion.cli.node_restore_helper import OPERATIONS, STATUS
from haprion.cli.socket_ask import Service, run

SERVICE = Service(
    command="haprion-node-restore-ask",
    socket_path="/run/haprion/node-restore.sock",
    #
    # Under the worker's 900 s, so a restore that runs long is answered by this
    # client rather than cut off by the worker without an answer. A restore is
    # expected to take about a minute; the headroom is for a slow mirror.
    #
    timeout=840.0,
    what="the node restore service",
    install="Install haprion-node-restore-helper.socket.",
    operations=frozenset(OPERATIONS),
    not_ours="the request is not a restore operation",
    busy_answers=frozenset({STATUS}),
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
