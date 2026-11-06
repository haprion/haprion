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
import errno
import functools
import shutil
import signal
import socket
import subprocess as sp
import tempfile
import time
from collections.abc import Callable
from pathlib import Path

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


def free_port() -> int:
    with socket.socket() as held:
        held.bind(("127.0.0.1", 0))
        return int(held.getsockname()[1])


#
# A port found free is free only until it is let go, and two things follow.
#
# Another test process can take it before the server we start binds it. For a
# Python server that is a loud `EADDRINUSE`. For HAProxy it was not: HAProxy
# binds with SO_REUSEPORT on Linux, so two HAProxys on one port both start and
# the kernel spreads connections between them. A test's HTTP request then
# reached another test's peers listener and read "501" as a status line
# (26-11-06, test_dynamic_block_live, full gate, eight processes).
#
# So every HAProxy a test starts has `noreuseport` in `global` - a port held by
# another process becomes a bind error - and a start that fails to bind is
# tried again on new ports.
#
NOREUSEPORT = "    noreuseport\n"


_TRIES = 5


class PortTaken(Exception):
    """A server the test started could not bind the port it was given."""


def retry_on_taken_port[**P, R](function: Callable[P, R]) -> Callable[P, R]:
    """Run a setup that picks ports again when one of them was taken meanwhile.

    The whole body runs again, so it picks every port afresh. Put it under
    `@classmethod`, on a `setUp`/`setUpClass` or a helper that starts servers.
    """

    @functools.wraps(function)
    def attempt(*args: P.args, **kwargs: P.kwargs) -> R:
        for _ in range(_TRIES - 1):
            try:
                return function(*args, **kwargs)
            except PortTaken:
                pass
            except OSError as error:
                if error.errno != errno.EADDRINUSE:
                    raise
        return function(*args, **kwargs)

    return attempt


def start_haproxy(binary: str, arguments: list[str], port: int) -> sp.Popen[bytes]:
    """One HAProxy, bound to this run's lifetime and proved to be listening.

    A start that never comes up is terminated here rather than left to a
    teardown that will not be called - `setUpClass` raising means the class
    never gets one. A start that dies because a port is held raises
    `PortTaken`, which `retry_on_taken_port` answers; any other death is an
    `AssertionError` carrying what HAProxy said.

    `-db` is what makes the process this returns the actual HAProxy. The core
    fixture says `daemon`, as a real one does, so without this HAProxy forks
    into the background and the child Python is holding exits at once. Every
    spawn leaked that way until the machine ran out of memory (B81). The flag is
    a harness concern, not a change to what is being tested.
    """

    with tempfile.TemporaryFile() as said:
        process = sp.Popen(
            [binary, "-db", *arguments],
            stderr=said,
            preexec_fn=die_with_the_test_run,
        )
        try:
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline and process.poll() is None:
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                        pass
                except OSError:
                    time.sleep(0.05)
                    continue
                #
                # Something answered; ours only if it is still there - a port
                # another process holds answers too, while this HAProxy has
                # already given up on it.
                #
                time.sleep(0.1)
                if process.poll() is None:
                    return process
            if process.poll() is None:
                raise AssertionError(f"nothing came up on port {port} within 5s")
            said.seek(0)
            output = said.read().decode(errors="replace")
            if "cannot bind" in output or "Address already in use" in output:
                raise PortTaken(output)
            raise AssertionError(f"haproxy exited before it listened on {port}:\n{output}")
        except BaseException:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=5)
            raise


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


def old_tls_server(certificate: Path, key: Path, version: str) -> tuple[sp.Popen[bytes], int]:
    """A backend that speaks `version` and nothing else, run by OpenSSL itself.

    Not a Python server. A `ssl.SSLContext` configured to offer TLS 1.1 is code
    in this repository that permits a deprecated protocol, and the security gate
    is right to say so - it cannot tell a fixture that must be old from a client
    that should not be. Handing the job to `openssl s_server` puts the old
    protocol in a tool rather than in our source, and makes the stand-in a real
    OpenSSL server, which is closer to the appliance this is about anyway.

    `SECLEVEL=0` because OpenSSL's own policy otherwise refuses to offer the old
    versions at all: the point is a backend that offers one and a probe that
    declines it, not a backend that could not be built. `-www` answers any GET
    with a status line, which is all the probe reads.

    The port is chosen here and returned. A free port is free only until it
    is let go, and in a full gate another test took one before `s_server`
    bound it (26-10-14): the server exited and the test waited five seconds
    for nothing. A server that is gone before it listens is started again on
    another port.
    """

    openssl = shutil.which("openssl")
    assert openssl is not None
    for _ in range(5):
        port = free_port()
        process = sp.Popen(
            [
                openssl,
                "s_server",
                "-accept",
                str(port),
                "-cert",
                str(certificate),
                "-key",
                str(key),
                version,
                "-cipher",
                "DEFAULT@SECLEVEL=0",
                "-www",
                "-quiet",
            ],
            stdout=sp.DEVNULL,
            stderr=sp.DEVNULL,
            preexec_fn=die_with_the_test_run,
        )
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and process.poll() is None:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    pass
            except OSError:
                time.sleep(0.05)
                continue
            #
            # Something answered; ours only if it is still there - a port
            # another test took answers too, while this server has exited.
            #
            time.sleep(0.05)
            if process.poll() is None:
                return process, port
        process.terminate()
        process.wait(timeout=5)
    raise AssertionError("openssl s_server did not come up on any of five ports")
