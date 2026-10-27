"""A socket helper's answer, kept where the worker can read it after a restart (B367).

The helpers behind the manager's sockets (`Accept=yes`) run in systemd units of
their own. A stop or restart of the worker - a UI release, needrestart, a
reboot - ends the worker's client and not the helper: the operation goes on as
root and its answer reaches a closed connection. Recovery then had nothing to
read and wrote `unknown` while a node restore was still running.

So the helper keeps a receipt, one file per request under ROOT:

- made, locked, as soon as the request has been read and before anything is
  done, and renamed into place already locked, so no reader sees it unlocked
  before it is finished;
- the answer and the exit code written into it when the helper ends, and the
  lock let go;
- read by recovery under a shared lock it does not wait for. A lock it cannot
  take is a helper still running; `flock` is let go by the kernel when the
  process ends, so a helper that died never reads as running.

The worker's sandbox hides other processes (`ProtectProc=invisible`), and the
lock answers what a process table would have. The directory is root's and
open to the worker's group; it is made by the platform steps, and without it
nothing is kept - an installation with no interface has no worker to read it.
"""

from __future__ import annotations

import contextlib
import errno
import fcntl
import functools
import io
import json
import os
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, TextIO, cast
from uuid import UUID

from haprion import atomic_file

ROOT = Path("/var/lib/haprion/answers")
#
# How long a receipt is kept. A job is settled within minutes of its lease
# running out; two weeks is far past any of them and keeps the directory small.
#
KEEP_SECONDS = 14 * 24 * 3600
#
# The most of an answer kept. The worker reads no more of a helper's output
# than its own hard cap, so a larger answer could not be judged anyway.
#
MAX_ANSWER_BYTES = 4 * 1024 * 1024


type State = Literal["unavailable", "absent", "running", "silent", "answered"]


@dataclass(frozen=True, slots=True)
class Receipt:
    """What the receipt of one request says.

    - `unavailable`: no receipts are kept here, or this one cannot be read.
    - `absent`: receipts are kept and this request has none - its helper never
      began.
    - `running`: its helper holds the lock.
    - `silent`: its helper ended without writing an answer.
    - `answered`: `stdout` is what the helper wrote and `exit_code` how it exited.
    """

    state: State
    stdout: str = ""
    exit_code: int | None = None


def _name(request_id: str) -> str | None:
    """The receipt's file name, or None for anything that is not a request ID."""

    try:
        parsed = UUID(request_id)
    except (ValueError, AttributeError, TypeError):
        return None
    return f"{parsed}.json" if str(parsed) == request_id else None


def root() -> Path | None:
    """Where receipts are kept: ROOT when running as root, else nowhere."""

    return ROOT if os.geteuid() == 0 else None


class Kept(io.TextIOBase):
    """The helper's output: written through to its connection, and kept.

    `begin` takes the receipt once the request ID is known; until then, and
    when nothing can be kept, this is the connection and nothing more.
    """

    def __init__(self, connection: TextIO, directory: Path | None) -> None:
        super().__init__()
        self._connection = connection
        self._directory = directory
        self._text = io.StringIO()
        self._fd: int | None = None
        self._gone = False
        self.warning: str | None = None

    def writable(self) -> bool:
        return True

    def write(self, text: str) -> int:
        self._text.write(text)
        if self._gone:
            return len(text)
        try:
            return self._connection.write(text)
        except (BrokenPipeError, ConnectionResetError):
            self._client_gone()
            return len(text)

    def flush(self) -> None:
        if self._gone:
            return
        try:
            self._connection.flush()
        except (BrokenPipeError, ConnectionResetError):
            self._client_gone()

    def _client_gone(self) -> None:
        """The client stopped waiting; the receipt carries the answer (R2, F16).

        What is still buffered for the connection would fail again when Python
        flushes it on the way out - a traceback and exit 120 for a helper that did
        its work. The descriptor is pointed at /dev/null, as Python's own
        documentation does for a closed pipe, and the helper exits with its code.
        """

        self._gone = True
        with contextlib.suppress(OSError, ValueError, io.UnsupportedOperation):
            devnull = os.open(os.devnull, os.O_WRONLY)
            try:
                os.dup2(devnull, self._connection.fileno())
            finally:
                os.close(devnull)

    def begin(self, request_id: str) -> None:
        if self._directory is None or self._fd is not None or not self._directory.is_dir():
            return
        name = _name(request_id)
        if name is None:
            return
        _prune(self._directory, time.time())
        staging = self._directory / f".{name}.{os.getpid()}"
        try:
            fd = os.open(
                staging, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o640
            )
        except OSError as exc:
            self.warning = f"the answer cannot be kept for recovery: {exc}"
            return
        try:
            # The mode open() asks for is cut by the umask, and the helpers' units run
            # with UMask=0077: the worker could not read a single receipt (R2, F17).
            os.fchmod(fd, 0o640)
            fcntl.flock(fd, fcntl.LOCK_EX)
            os.fchown(fd, -1, os.stat(self._directory).st_gid)
            atomic_file.move(staging, self._directory / name)
        except OSError as exc:
            os.close(fd)
            staging.unlink(missing_ok=True)
            self.warning = f"the answer cannot be kept for recovery: {exc}"
            return
        self._fd = fd

    def end(self, exit_code: int | None) -> None:
        """Write the answer and let go of the lock. `exit_code` None: the helper raised."""

        if self._fd is None:
            return
        fd, self._fd = self._fd, None
        stdout = self._text.getvalue()
        if len(stdout.encode("utf-8", "replace")) > MAX_ANSWER_BYTES:
            stdout = ""
        document = json.dumps({"exit_code": exit_code, "stdout": stdout}).encode("utf-8")
        try:
            os.ftruncate(fd, 0)
            os.pwrite(fd, document, 0)
            os.fsync(fd)
        except OSError as exc:
            self.warning = f"the answer could not be kept for recovery: {exc}"
        finally:
            os.close(fd)


def keeps_answer[**P](main: Callable[P, int]) -> Callable[P, int]:
    """Keep what `main` writes to its `output_stream`, and how it exits.

    The helper calls `begin(output, request.request_id)` once it has read the
    request; everything it writes from the first byte is kept, the refusals
    before that included.
    """

    @functools.wraps(main)
    def kept(*args: P.args, **kwargs: P.kwargs) -> int:
        connection = cast(TextIO | None, kwargs.get("output_stream")) or sys.stdout
        output = Kept(connection, root())
        kwargs["output_stream"] = output
        code: int | None = None
        try:
            code = main(*args, **kwargs)
            return code
        finally:
            output.end(code)
            if output.warning is not None:
                errors = cast(TextIO | None, kwargs.get("error_stream")) or sys.stderr
                errors.write(f"WARNING: {output.warning}\n")

    return kept


def begin(output: Any, request_id: str) -> None:
    """Take the receipt for `request_id`, when `output` keeps one."""

    if isinstance(output, Kept):
        output.begin(request_id)


def read(request_id: str, directory: Path = ROOT) -> Receipt:
    """What the receipt for `request_id` says; never waits."""

    name = _name(request_id)
    if name is None or not directory.is_dir():
        return Receipt("unavailable")
    try:
        fd = os.open(directory / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return Receipt("absent")
    except OSError:
        return Receipt("unavailable")
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno in (errno.EWOULDBLOCK, errno.EAGAIN):
                return Receipt("running")
            return Receipt("unavailable")
        with os.fdopen(os.dup(fd), "rb") as stream:
            content = stream.read(MAX_ANSWER_BYTES * 2)
    finally:
        os.close(fd)
    try:
        document = json.loads(content)
    except ValueError:
        return Receipt("silent")
    stdout = document.get("stdout") if isinstance(document, dict) else None
    exit_code = document.get("exit_code") if isinstance(document, dict) else None
    if not isinstance(stdout, str) or not stdout.strip():
        return Receipt("silent")
    if not isinstance(exit_code, int) or isinstance(exit_code, bool):
        exit_code = None
    return Receipt("answered", stdout=stdout, exit_code=exit_code)


def _prune(directory: Path, now: float) -> None:
    """Remove receipts older than KEEP_SECONDS that no helper holds."""

    try:
        entries = list(os.scandir(directory))
    except OSError:
        return
    for entry in entries:
        staged = entry.name.startswith(".")
        if not staged and _name(entry.name.removesuffix(".json")) is None:
            continue
        try:
            if not entry.is_file(follow_symlinks=False):
                continue
            if now - entry.stat(follow_symlinks=False).st_mtime < KEEP_SECONDS:
                continue
            if staged:
                #
                # A helper that died between making its receipt and renaming
                # it into place; nothing reads these.
                #
                os.unlink(entry.path)
                continue
            fd = os.open(entry.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError:
            continue
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            os.unlink(entry.path)
        except OSError:
            pass
        finally:
            os.close(fd)
