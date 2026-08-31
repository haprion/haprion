"""Running one operation, and stopping it when this worker is no longer allowed to.

Three things have to be true at once while a job runs, and each of them is a way
the naive version goes wrong:

The command must be stoppable as a whole. A deploy reaches nodes over SSH, so
killing the process the worker started can leave its children running - and a
child that keeps writing after the job has been handed to another worker is
exactly the double write the fencing token exists to prevent. The command is
therefore started in its own session, and stopped by signalling the group.

The lease must keep being renewed while the work goes on, because a lease that
expires under a healthy worker hands its job to a second one. Renewal happens
here, between checks, rather than in the operation's own code.

And a lost lease must end the run. Not finish it, not report it - end it. The
worker that lost the lease no longer owns the job, and the database will refuse
its writes anyway; continuing only burns the cluster's lock for longer.
"""

from __future__ import annotations

import logging
import os
import signal
import subprocess  # noqa: S404 - running one fixed command is this module's purpose
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from typing import BinaryIO, Literal, cast

from haproxy_ui import diagnostics

logger = logging.getLogger("haproxy_ui.execution")

type Ending = Literal["finished", "timeout", "lease_lost"]
type OutputError = Literal["too_large", "invalid_utf8"]

#
# How often the loop wakes to renew the lease and look at the process. Short
# enough that a lost lease is noticed while the operation is still running, long
# enough that a slow deploy does not spend its time asking the database how it
# is doing.
#
TICK_SECONDS = 5.0

#
# The grace between asking the process group to stop and insisting. A deploy
# that is interrupted mid-step should get the chance to leave the node in a
# state it chose rather than one the kernel chose.
#
GRACE_SECONDS = 10.0

#
# Everything the command is allowed to inherit. Passed explicitly rather than
# filtered, so a variable that appears in the worker's environment later does not
# silently become part of an operation's.
#
ENVIRONMENT_KEYS = ("PATH", "LANG", "LC_ALL", "TZ")

#
# stdout is a result, not a log. Retaining more than the largest document the
# contract permits would let a broken privileged helper grow the worker without
# bound before the JSON parser ever gets a say.
#
STDOUT_LIMIT = 4 * 1024 * 1024
STDERR_EDGE_BYTES = 32 * 1024
READ_CHUNK_BYTES = 64 * 1024


@dataclass(frozen=True, slots=True)
class Completed:
    """How the run ended, and what it said.

    `ending` is deliberately separate from `exit_code`. A command killed for a
    lost lease may still exit 0 on its way out, and reading that as success would
    record a result this worker is not entitled to record.
    """

    ending: Ending
    exit_code: int | None
    stdout: str
    stderr: str
    stdout_error: OutputError | None = None


class _PrefixCapture:
    """Drain everything while retaining only one bounded prefix."""

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.total = 0
        self.value = bytearray()

    def add(self, chunk: bytes) -> None:
        self.total += len(chunk)
        remaining = self.limit - len(self.value)
        if remaining > 0:
            self.value.extend(chunk[:remaining])


class _EdgeCapture:
    """Drain everything while retaining bounded beginning and ending edges."""

    def __init__(self, edge_bytes: int) -> None:
        self.edge_bytes = edge_bytes
        self.total = 0
        self.first = bytearray()
        self.last = bytearray()

    def add(self, chunk: bytes) -> None:
        self.total += len(chunk)
        remaining = self.edge_bytes - len(self.first)
        if remaining > 0:
            self.first.extend(chunk[:remaining])
            chunk = chunk[remaining:]
        if chunk:
            self.last.extend(chunk)
            if len(self.last) > self.edge_bytes:
                del self.last[: len(self.last) - self.edge_bytes]

    def value(self) -> bytes:
        if self.total <= self.edge_bytes:
            return bytes(self.first)
        if self.total <= self.edge_bytes * 2:
            return bytes(self.first + self.last)
        marker = diagnostics.TRUNCATION_MARKER.encode("utf-8")
        return bytes(self.first) + marker + bytes(self.last)


def _environment() -> dict[str, str]:
    return {key: os.environ[key] for key in ENVIRONMENT_KEYS if key in os.environ}


def _group_exists(group: int) -> bool:
    """Whether anything is still in the group - not whether we may signal it.

    `EPERM` is not absence. The helper runs as root through sudo, so once the
    members this worker was allowed to signal have gone, the kernel answers
    `EPERM` for what is left rather than `ESRCH`. Reading that as "the group is
    gone" was how this crashed the worker on 2026-08-31; reading it as "there is
    something there" is what it actually means.
    """

    try:
        os.killpg(group, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _stop(process: subprocess.Popen[bytes], group: int) -> None:
    """Stop the whole group, politely and then not.

    `os.killpg` on the child's own group, which exists because the process was
    started in a new session. Signalling the process alone would leave an SSH
    child holding the far end of the operation.
    """

    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(group, sig)
        except ProcessLookupError:  # pragma: no cover - the group is already gone
            return
        except PermissionError:
            #
            # The remaining members are root's, and this worker holds no
            # CAP_KILL. Stopping them is not available here, so the honest thing
            # is to say so and stop pretending: the job is already heading for
            # `unknown`, and the cluster lock the privileged half holds is what
            # actually prevents a second operation from overlapping this one.
            #
            logger.error(
                "the operation group is beyond this worker's privilege; it was not stopped"
            )
            return
        try:
            process.wait(timeout=GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            logger.warning("the operation did not stop on %s; escalating", sig.name)
            continue
        if sig == signal.SIGTERM:
            # The leader may exit before one of its children. Give the group one
            # scheduler turn, then send SIGKILL if anything still answers. A
            # zombie can keep the group ID visible, so waiting for killpg(...,
            # 0) to fail would burn the whole grace period after every stop.
            time.sleep(0.05)
            if _group_exists(group):
                logger.warning("the operation group survived SIGTERM; escalating")
                continue
        return


def run(
    argv: Sequence[str],
    *,
    request: str,
    timeout_seconds: float,
    still_ours: Callable[[], bool],
    environment: Mapping[str, str] | None = None,
) -> Completed:
    """Run one command to completion, or stop it and say why.

    `still_ours` is asked on every tick and is where the lease is renewed. It
    returns False the moment this worker stops holding the job, and the run ends
    there.

    No shell, an argv array, and an environment built by name. The request goes
    in on stdin the way every helper in this system takes it, so the command line
    carries no operation-specific values at all - there is nothing in it for a
    payload to influence.
    """

    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    encoded_request = request.encode("utf-8")

    process = subprocess.Popen(  # noqa: S603 - argv array, fixed program, no shell
        list(argv),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
        env=dict(environment) if environment is not None else _environment(),
        #
        # The reason the group exists. Also detaches the command from the
        # worker's terminal signals, so a Ctrl-C in a development shell does not
        # reach a running deploy sideways.
        #
        start_new_session=True,
    )
    group = process.pid
    process_stdin = cast(BinaryIO, process.stdin)
    process_stdout = cast(BinaryIO, process.stdout)
    process_stderr = cast(BinaryIO, process.stderr)

    #
    # Each pipe is continuously drained, but the captures themselves are
    # bounded. Stopping at the limit would fill the pipe and deadlock a helper;
    # communicate(), on the other hand, would keep every byte in memory before
    # the worker could reject it.
    #
    stdout = _PrefixCapture(STDOUT_LIMIT)
    stderr = _EdgeCapture(STDERR_EDGE_BYTES)
    readers_left = 2
    readers_lock = threading.Lock()
    output_done = threading.Event()

    def reader_done() -> None:
        nonlocal readers_left
        with readers_lock:
            readers_left -= 1
            if readers_left == 0:
                output_done.set()

    def drain(pipe: BinaryIO, capture: _PrefixCapture | _EdgeCapture) -> None:
        try:
            descriptor = pipe.fileno()
            while chunk := os.read(descriptor, READ_CHUNK_BYTES):
                capture.add(chunk)
        except OSError:
            # The local descriptor is closed below only if a killed, escaped
            # descendant kept the other end open. The subprocess result is
            # already unknown in that path.
            pass
        finally:
            pipe.close()
            reader_done()

    def write_request() -> None:
        try:
            process_stdin.write(encoded_request)
            process_stdin.flush()
        except BrokenPipeError:
            pass
        finally:
            process_stdin.close()

    threads = (
        threading.Thread(
            target=drain, args=(process_stdout, stdout), name="operation-stdout", daemon=True
        ),
        threading.Thread(
            target=drain, args=(process_stderr, stderr), name="operation-stderr", daemon=True
        ),
        threading.Thread(target=write_request, name="operation-stdin", daemon=True),
    )
    for thread in threads:
        thread.start()

    started = time.monotonic()
    deadline = started + timeout_seconds
    next_tick = started + TICK_SECONDS
    ending: Ending = "finished"
    callback_error: Exception | None = None
    try:
        while True:
            if process.poll() is not None and output_done.is_set():
                break

            now = time.monotonic()
            wake_at = min(next_tick, deadline)
            wait_for = max(0.0, wake_at - now)
            if output_done.is_set():
                with suppress(subprocess.TimeoutExpired):
                    process.wait(timeout=wait_for)
            else:
                output_done.wait(timeout=wait_for)

            now = time.monotonic()
            if process.poll() is not None and output_done.is_set():
                break
            if now >= next_tick and not still_ours():
                logger.error("the lease was lost while the operation was running; stopping it")
                ending = "lease_lost"
                break
            if now >= next_tick:
                next_tick = now + TICK_SECONDS
            if now >= deadline:
                logger.error(
                    "the operation passed its timeout of %ss; stopping it", timeout_seconds
                )
                ending = "timeout"
                break
    except Exception as exc:
        callback_error = exc

    if ending != "finished" or callback_error is not None:
        _stop(process, group)

    #
    # Joined after the kill, so output produced before it is not thrown away. A
    # timed-out deploy's last lines are usually the interesting ones. Closing a
    # still-open local descriptor prevents an escaped descendant from retaining
    # a daemon reader thread forever; named helpers must never create one.
    #
    for thread in threads:
        thread.join(timeout=GRACE_SECONDS)
    if any(thread.is_alive() for thread in threads):
        process_stdout.close()
        process_stderr.close()
        process_stdin.close()
        for thread in threads:
            thread.join(timeout=GRACE_SECONDS)

    raw_stdout = bytes(stdout.value)
    stdout_error: OutputError | None = None
    if stdout.total > STDOUT_LIMIT:
        stdout_error = "too_large"
    try:
        decoded_stdout = raw_stdout.decode("utf-8")
    except UnicodeDecodeError:
        decoded_stdout = raw_stdout.decode("utf-8", "replace")
        if stdout_error is None:
            stdout_error = "invalid_utf8"

    decoded_stderr = stderr.value().decode("utf-8", "replace")

    if callback_error is not None:
        raise callback_error

    return Completed(
        ending=ending,
        exit_code=process.returncode,
        stdout=decoded_stdout,
        stderr=diagnostics.safe_excerpt(decoded_stderr),
        stdout_error=stdout_error,
    )
