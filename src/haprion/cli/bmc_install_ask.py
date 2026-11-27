"""Carry one BMC install from the worker to its helper's socket (B526, B536).

`haprion-bmc-install-helper` opens the BMC account with the installation's
private key, which is root's, and reaches the BMC over the network, which the
worker's sudo helpers have no way to. So it answers on a socket, from a unit of
its own. The client is `socket_ask`; this names the service. The request's
shape is the helper's to judge, and it names no cluster.
"""

from __future__ import annotations

from typing import BinaryIO, TextIO

from haprion.cli.bmc_helper import INSTALL_OPERATION
from haprion.cli.socket_ask import Service, run

#
# The helper's unit ends at 600 s (`RuntimeMaxSec`): an upload is allowed
# 180 s and the restart 300 s. The client waits a little longer, so a unit
# that is stopped is said as such, and the worker's bound for the job
# (`operations.BMC_TIMEOUT_SECONDS`) is longer still.
#
TIMEOUT_SECONDS = 610.0

SERVICE = Service(
    command="haprion-bmc-install-ask",
    socket_path="/run/haprion/bmc-install.sock",
    timeout=TIMEOUT_SECONDS,
    what="the BMC install service",
    install="Install haprion-bmc-install-helper.socket (07-platform-services).",
    operations=None,
    cluster_bound=False,
    operation=INSTALL_OPERATION,
)
SOCKET_PATH = SERVICE.socket_path

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
