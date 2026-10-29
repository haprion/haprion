"""Carry one receiver request from the worker to its helper's socket (B163).

`haprion-cert-receiver-helper` writes `/etc` - `useradd`, an sshd drop-in, an
nginx snippet - and a helper the worker starts through sudo inherits the
worker's read-only `/etc`. So it answers on a socket, from a unit of its own.
The client is `socket_ask`; this names the service. The request's shape is the
helper's to judge, and it names no cluster.
"""

from __future__ import annotations

from typing import BinaryIO, TextIO

from haprion.cli.cert_receiver_helper import OPERATION
from haprion.cli.socket_ask import Service, run

SERVICE = Service(
    command="haprion-cert-receiver-ask",
    socket_path="/run/haprion/cert-receiver.sock",
    #
    # A registration resolves the receiver's name, runs useradd and passwd,
    # checks and reloads sshd or nginx - thirty seconds each at most - and
    # writes the registry, which may first wait 120 s for the certificate
    # lock. Seconds as a rule; the bound exists so a unit that never answers
    # becomes a sentence, and one that outlasts it ends on the answer the
    # helper keeps (26-10-29, O06).
    #
    timeout=300.0,
    what="the receiver service",
    install="Install haprion-cert-receiver-helper.socket (07-platform-services).",
    operations=None,
    cluster_bound=False,
    operation=OPERATION,
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
