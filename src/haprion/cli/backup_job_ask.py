"""Carry a backup job from the worker to its root helper socket. The client is `socket_ask`."""

from __future__ import annotations

from typing import BinaryIO, TextIO

from haprion.cli.backup_job_helper import OPERATIONS
from haprion.cli.socket_ask import Service, run

SERVICE = Service(
    command="haprion-backup-job-ask",
    socket_path="/run/haprion/backup-job.sock",
    timeout=720.0,
    what="the backup job service",
    install="Install haprion-backup-job-helper.socket.",
    operations=frozenset(OPERATIONS),
    not_ours="the request is not a backup operation",
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
