"""The one lock every certificate writer holds: the publisher's, on one path.

Six commands change the registry and the material beside it - issue, import,
delete, retarget, receiver add/remove/migrate - and the publisher reads what
they write. Until 2026-09-20 only the publisher, delete and retarget held the
lock; issue, import and the receiver commands read the registry, changed it
and wrote it back with nothing between them and a renewal running at the same
second. Two writers in one second is a lost update, and a valid file: the
loader has nothing to refuse. So the flock lives here, imported by the
publisher and by the registry alike, and a writer takes it around the read as
well as the write.

`flock` rather than a lock file, for the reason `cluster_lock` gives: the
kernel releases it when the holder dies. It is advisory and per open file
description, which is also why a caller must not take it twice - the second
open would wait for the first, in the same process, forever. Delete and
retarget hold it around their whole run and call nothing here that takes it
again.
"""

from __future__ import annotations

import fcntl
import os
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

DEFAULT_LOCK_PATH = Path("/run/haprion/locks/cert-publish.lock")
LOCK_WAIT_SECONDS = 120


@contextmanager
def hold(path: Path, *, wait: int, refuse: Callable[[str], Exception]) -> Iterator[None]:
    """Hold the lock, waiting a bounded time; `refuse` makes the caller's own error."""

    path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    handle = os.open(path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
    try:
        deadline = datetime.now(UTC) + timedelta(seconds=wait)
        while True:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError:
                if datetime.now(UTC) >= deadline:
                    raise refuse(
                        f"another certificate operation has held {path} for more than "
                        f"{wait} seconds"
                    ) from None
                time.sleep(0.5)
        yield
    finally:
        os.close(handle)
