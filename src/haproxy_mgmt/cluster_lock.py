"""One operation per cluster at a time.

Plan §6.3 puts reconcile under a per-cluster lock. The reason is specific rather
than general tidiness: the loop decides what to do next from a status it read a
moment ago, and a second deploy running against the same pair invalidates that
reading without either run being able to tell. Two deploys interleaving could
take both nodes out of traffic at once - each one holding back the owner it saw,
which by then is the node the other has already taken down.

Per cluster, not global: the two clusters share nothing at deploy time, and one
lock for both would make a slow rollout of one block work on the other for no
safety gain.

Why flock and not a lock file
-----------------------------
A file that exists means "locked" leaves a stale file behind whenever a process
is killed, and then the repair is a human deleting a file while guessing whether
anything still holds it. An advisory `flock` is released by the kernel when the
holder exits, however it exits, so there is nothing to clean up and nothing to
guess about. The file itself is only a handle to lock; its contents exist to
answer "who has it", not to decide anything.
"""

from __future__ import annotations

import fcntl
import json
import os
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

DEFAULT_LOCK_ROOT = Path("/run/haprion/locks")

#
# Under /run on purpose: it is cleared on boot, so a lock can never outlive the
# processes that could have held it.
#
DIRECTORY_MODE = 0o755
#
# Only the two deploy helpers open this file, and both run as root: the mode is
# what they create it with, not a permission anyone else needs. The note inside
# it names a pid and an operation, which is not secret but is also not anybody
# else's to read, so the file is root-only rather than world-readable by the
# default umask nobody chose.
#
FILE_MODE = 0o600

EXIT_BUSY = 75


class LockBusy(Exception):
    """Another operation holds this cluster's lock."""

    def __init__(self, message: str, *, exit_code: int = EXIT_BUSY):
        super().__init__(message)
        self.exit_code = exit_code


def _describe_holder(handle: int) -> str:
    """Whatever the current holder wrote about itself, if it is still readable.

    Best effort by design. The lock is correct without this; the note only
    exists so an operator who is told "busy" is not left guessing, and a note
    that cannot be read must never turn a clean refusal into an error.
    """

    try:
        os.lseek(handle, 0, os.SEEK_SET)
        raw = os.read(handle, 4096).decode("utf-8", "replace")
        holder = json.loads(raw)
    except (OSError, ValueError):
        return ""

    if not isinstance(holder, dict):
        return ""

    pid = holder.get("pid")
    started = holder.get("started")
    operation = holder.get("operation")
    parts = [str(operation)] if operation else []
    if pid:
        parts.append(f"pid {pid}")
    if started:
        parts.append(f"started {started}")
    return ", ".join(parts)


@contextmanager
def hold(
    cluster_id: str,
    *,
    operation: str = "deploy",
    root: Path = DEFAULT_LOCK_ROOT,
) -> Iterator[Path]:
    """Hold the cluster's lock for the duration of the block.

    Never waits. A deploy that queues behind another one would run against a
    cluster that changed while it waited, and the operator who started it has
    long since stopped watching - so a busy cluster is reported, not queued.
    """

    root.mkdir(parents=True, exist_ok=True, mode=DIRECTORY_MODE)
    path = root / f"{cluster_id}.lock"

    handle = os.open(path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, FILE_MODE)
    try:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            holder = _describe_holder(handle)
            detail = f" ({holder})" if holder else ""
            raise LockBusy(
                f"another operation is already running for cluster '{cluster_id}'{detail}."
            ) from None

        #
        # Written after the lock is taken, so the note always describes the
        # process that actually holds it.
        #
        os.ftruncate(handle, 0)
        os.lseek(handle, 0, os.SEEK_SET)
        os.write(
            handle,
            json.dumps(
                {
                    "pid": os.getpid(),
                    "operation": operation,
                    "started": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                }
            ).encode(),
        )
        yield path
    finally:
        #
        # Closing releases the lock. Done explicitly rather than left to the
        # garbage collector so the release happens where it can be reasoned
        # about, and so a long-lived caller does not leak descriptors.
        #
        os.close(handle)
