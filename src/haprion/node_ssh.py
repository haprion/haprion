"""How the manager talks to a node: one set of ssh options, and answers read within a budget.

Every caller used to build its own options and read the answer its own way
(code review 2026-10-22, 4-5, 5-5, 5-6; security review S2). The keep-alive
that review 2026-10-03 I3 added for the deploy reached the deploy's copy and no
other, one call had no time limit at all, and most read whatever a node sent
into memory as text before looking at it - so a node that answered with
gigabytes, with bytes that are not UTF-8 or with JSON nested deeper than the
parser goes stopped the status, the deploy or the removal of that very node for
the whole cluster.

A node is a machine the manager does not control. What it answers is read here
as bytes, within a byte budget and a deadline, decoded without failing, and
parsed so that any malformed document is one `ValueError`: one node with no
usable answer, never a crash for the others.
"""

from __future__ import annotations

import json
import os
import selectors
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from time import monotonic

from haprion import exit_codes

SSH = "/usr/bin/ssh"

#
# Not defaults worth rediscovering: BatchMode never prompts, IdentitiesOnly
# stops an agent from offering a different key, and StrictHostKeyChecking is
# what makes the connection mean anything at all. A connection that goes
# silent is noticed within a minute rather than never (review 2026-10-03, I3):
# ssh asks every 15 s and gives up after four unanswered.
#
SSH_OPTIONS = (
    "-T",
    "-o",
    "BatchMode=yes",
    "-o",
    "IdentitiesOnly=yes",
    "-o",
    "StrictHostKeyChecking=yes",
    "-o",
    "ConnectionAttempts=1",
    "-o",
    "ServerAliveInterval=15",
    "-o",
    "ServerAliveCountMax=4",
    "-o",
    "LogLevel=ERROR",
)
#
# The handshake. A status read keeps it short, because a poll waits on the
# slowest node; everything that changes a node can afford the longer one.
#
CONNECT_TIMEOUT_SECONDS = 10
STATUS_CONNECT_TIMEOUT_SECONDS = 5

SSH_ENVIRONMENT = {"PATH": "/usr/bin:/bin", "HOME": "/root", "LANG": "C.UTF-8"}

#
# What any node's answer may come to, unless a caller says otherwise. A status
# report is a few kilobytes and a deploy's output a few hundred lines; a
# document a thousand times that is not an answer.
#
MAX_ANSWER_BYTES = 8 * 1024 * 1024
MAX_STDERR_BYTES = 64 * 1024

_CHUNK = 64 * 1024


def ssh_argv(
    key: Path | str,
    user: str,
    host: str,
    *request: str,
    connect_timeout: int = CONNECT_TIMEOUT_SECONDS,
    options: Sequence[str] = (),
) -> list[str]:
    """The command that reaches `user@host` with `key`, and its forced command's request if any.

    `options` are a caller's own `-o` pairs on top of the shared ones, such as
    the join's own known-hosts file.
    """

    return [
        SSH,
        *SSH_OPTIONS,
        "-o",
        f"ConnectTimeout={connect_timeout}",
        *options,
        "-i",
        str(key),
        f"{user}@{host}",
        *request,
    ]


@dataclass(frozen=True, slots=True)
class Streamed:
    """How a streamed call ended. `returncode` is None when it was stopped."""

    returncode: int | None
    stderr: str
    timed_out: bool = False
    too_large: bool = False


def stream(
    argv: Sequence[str],
    sink: Callable[[bytes], object],
    *,
    timeout: float,
    max_bytes: int = MAX_ANSWER_BYTES,
    request: bytes | None = None,
    env: dict[str, str] | None = None,
) -> Streamed:
    """Run `argv`, hand stdout to `sink` as it arrives, and stop it at the budget or the deadline.

    stderr is kept up to `MAX_STDERR_BYTES`. The child is killed and waited for
    on every way out, so nothing outlives the call.
    """

    process = subprocess.Popen(  # noqa: S603 - argv is built by ssh_argv or a caller's fixed command
        list(argv),
        stdin=subprocess.PIPE if request is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=SSH_ENVIRONMENT if env is None else env,
    )
    assert process.stdout is not None and process.stderr is not None  # noqa: S101 - Popen contract
    selected = selectors.DefaultSelector()
    selected.register(process.stdout, selectors.EVENT_READ, "stdout")
    selected.register(process.stderr, selectors.EVENT_READ, "stderr")
    pending = memoryview(request or b"")
    if process.stdin is not None:
        os.set_blocking(process.stdin.fileno(), False)
        if pending:
            selected.register(process.stdin, selectors.EVENT_WRITE, "stdin")
        else:
            process.stdin.close()
    deadline = monotonic() + timeout
    received = 0
    errors = bytearray()
    timed_out = too_large = False
    try:
        while any(key.data != "stdin" for key in selected.get_map().values()):
            remaining = deadline - monotonic()
            if remaining <= 0:
                timed_out = True
                break
            for key, _ in selected.select(min(remaining, 1.0)):
                if key.data == "stdin":
                    try:
                        written = os.write(key.fd, pending)
                    except BrokenPipeError:
                        written = len(pending)
                    pending = pending[written:]
                    if not pending:
                        selected.unregister(key.fileobj)
                        key.fileobj.close()  # type: ignore[union-attr]
                    continue
                chunk = os.read(key.fd, _CHUNK)
                if not chunk:
                    selected.unregister(key.fileobj)
                    continue
                if key.data == "stdout":
                    received += len(chunk)
                    if received > max_bytes:
                        too_large = True
                        break
                    sink(chunk)
                elif len(errors) < MAX_STDERR_BYTES:
                    errors.extend(chunk[: MAX_STDERR_BYTES - len(errors)])
            if too_large:
                break
    finally:
        selected.close()
        if timed_out or too_large:
            process.kill()
        process.wait()
        for pipe in (process.stdin, process.stdout, process.stderr):
            if pipe is not None and not pipe.closed:
                pipe.close()
    stopped = timed_out or too_large
    return Streamed(
        returncode=None if stopped else process.returncode,
        stderr=errors.decode("utf-8", errors="replace"),
        timed_out=timed_out,
        too_large=too_large,
    )


def run_bounded(
    argv: Sequence[str],
    *,
    timeout: float,
    max_bytes: int = MAX_ANSWER_BYTES,
    request: str | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """`subprocess.run` for a node: the same answer, read within a budget.

    Like `subprocess.run(..., timeout=)` it raises `subprocess.TimeoutExpired`
    at the deadline, so every caller's existing handling of a node that took
    too long holds. An answer over `max_bytes` is a failed call with nothing on
    stdout and the reason on stderr. stdout and stderr are decoded with
    replacement: bytes that are not UTF-8 are a bad answer, read as one, not an
    exception.
    """

    collected = bytearray()
    ended = stream(
        argv,
        collected.extend,
        timeout=timeout,
        max_bytes=max_bytes,
        request=None if request is None else request.encode("utf-8"),
        env=env,
    )
    if ended.timed_out:
        raise subprocess.TimeoutExpired(list(argv), timeout, output=bytes(collected))
    if ended.too_large:
        return subprocess.CompletedProcess(
            list(argv),
            exit_codes.FAILED,
            stdout="",
            stderr=f"the node answered with more than {max_bytes} bytes and was stopped",
        )
    return subprocess.CompletedProcess(
        list(argv),
        ended.returncode if ended.returncode is not None else -1,
        stdout=collected.decode("utf-8", errors="replace"),
        stderr=ended.stderr,
    )


def parse_json(text: str | bytes) -> object:
    """A node's JSON document, or `ValueError` for anything that is not one.

    `json.loads` raises `JSONDecodeError` for most bad documents, but
    `UnicodeDecodeError` for bytes that are not UTF-8 and `RecursionError` for
    nesting deeper than the interpreter's stack - the last not a `ValueError`
    at all, so a caller catching the usual one crashed on it.
    """

    try:
        return json.loads(text)
    except RecursionError as error:
        raise ValueError("the document is nested too deeply") from error
