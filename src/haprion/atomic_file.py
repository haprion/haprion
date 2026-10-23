"""Replacing a file so that a crash leaves the old one or the new one, never half of either.

Written beside its destination, synced, given its mode and owner while nobody
can read it, renamed over the old one, and the directory synced so the rename
itself survives a power cut. Sixteen modules did this by hand until 2026-10-23,
at three levels of care: three never synced the file, several synced the file
and not the directory (review 2026-10-22, 4-7). A test refuses a rename
anywhere else.
"""

from __future__ import annotations

import os
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO


def sync_directory(directory: Path) -> None:
    """Make the directory's entries - a rename into it - survive a crash."""

    handle = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(handle)
    finally:
        os.close(handle)


@contextmanager
def replacing(
    path: Path, *, mode: int, uid: int | None = None, gid: int | None = None
) -> Iterator[BinaryIO]:
    """A stream whose content replaces `path` when the block ends without an error.

    The temporary file is created 0600 and only given `mode`, `uid` and `gid`
    once written, so nobody reads it half way. An error leaves `path` as it was
    and removes the temporary file.

    Mode first, then owner. Changing a file's mode needs ownership of it or
    CAP_FOWNER, and the worker's sandbox grants root CAP_CHOWN alone: once the
    file belongs to a receiver's fetch account, root inside that sandbox may
    no longer chmod it (`write_failed: Operation not permitted`, the first
    receiver file, 2026-09).
    """

    handle, name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    temporary = Path(name)
    try:
        with os.fdopen(handle, "wb") as stream:
            yield stream
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), mode)
            if uid is not None or gid is not None:
                os.fchown(stream.fileno(), -1 if uid is None else uid, -1 if gid is None else gid)
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    sync_directory(path.parent)


def write(
    path: Path, content: bytes, *, mode: int, uid: int | None = None, gid: int | None = None
) -> None:
    """`content` as `path`, in one rename."""

    with replacing(path, mode=mode, uid=uid, gid=gid) as stream:
        stream.write(content)


def write_like(path: Path, content: bytes, *, like: Path | None = None) -> None:
    """`content` as `path`, owned and moded as `like` (by default `path` itself) is now."""

    status = (like or path).stat()
    owned = os.geteuid() == 0
    write(
        path,
        content,
        mode=status.st_mode & 0o7777,
        uid=status.st_uid if owned else None,
        gid=status.st_gid if owned else None,
    )


def move(source: Path, target: Path) -> None:
    """Rename a staged file, link or directory into place, and sync what changed.

    For what was staged some other way - a directory filled file by file, an
    archive streamed from a node, a symlink - the rename is still the one
    step that has to survive a crash.
    """

    os.replace(source, target)
    sync_directory(target.parent)
    if source.parent != target.parent:
        sync_directory(source.parent)
