"""Processes a test starts, and how they are made to die with it.

A test that spawns a real program proves something a stub cannot - a generated
configuration is only proved by the program that reads it, and a probe that
declines an old backend is only proved by an old backend. The cost is a process
that outlives its test when teardown never runs, and teardown never runs when
the run is interrupted, times out, or is killed.

That cost was paid once: spawned HAProxys accumulated until 177 of them held
4.6 GB between them and the machine went to the OOM killer (B81). What is here
is the half of the fix teardown cannot provide, kept in one place so a second
kind of spawned process cannot quietly grow a second, weaker copy of it.
"""

from __future__ import annotations

import ctypes
import signal
import socket
import time

#
# What the kernel is asked to do to a spawned child when this process goes.
# `prctl(PR_SET_PDEATHSIG)`, which is Linux's own answer to exactly this: the
# child is signalled the moment its parent dies, whatever killed the parent.
#
_PR_SET_PDEATHSIG = 1


def die_with_the_test_run() -> None:
    """Ask the kernel to kill this child when the test process goes.

    Set in the child between fork and exec, so it holds for a parent that is
    given no chance to do anything. Pass it as `preexec_fn`.
    """

    ctypes.CDLL("libc.so.6", use_errno=True).prctl(_PR_SET_PDEATHSIG, signal.SIGKILL)


def wait_for(port: int, timeout: float = 5.0) -> None:
    """Return once something is listening on `port`, or raise.

    A spawned server is not ready when `Popen` returns, and a test that probes
    too early reports a connection failure as the verdict it was measuring.
    """

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise AssertionError(f"nothing came up on port {port} within {timeout}s")
