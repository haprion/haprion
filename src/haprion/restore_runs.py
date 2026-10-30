"""The life of a node restore run's directory, for the restore and for the backup.

A run lives in a directory under ``RUN_ROOT`` from ``prepare`` until it is
discarded or swept. Two modules read that life: `node_restore`, which carries
runs out, and `state_backup`, whose retention must keep the archive a run is
going to restore. They read it here, from one place, so that "a run that can
still use its archive" means the same thing to both. It lived in
`node_restore` until 2026-10-09; the backup could not import it from there
(`node_restore` imports the backup) and so kept its own, looser reading - any
directory naming an archive held it, however long ago the run had ended.
"""

from __future__ import annotations

import fcntl
import json
import os
import shutil
from collections.abc import Callable
from pathlib import Path

from haprion import restore_agent

#
# Where node restore runs live.
#
RUN_ROOT = Path("/var/lib/haprion/restore")
#
# From `prepare` to the start of `run`. Past it the run is gone and the operator
# starts again (B182): a key nobody is about to use is a key
# nobody should be holding. The web page reads the same constant.
#
START_WINDOW = 3600
#
# A run that began writing keeps its outcome after its hour, as long as the
# web keeps its jobs (a week), so a job that lost its answer can still ask
# for it (review 2026-09-25, track 8). Only these files stay: the key,
# known_hosts and the preview's plan go at the hour, as before.
#
RESULT_KEPT = 7 * 24 * 3600
#
# Written to a run's directory before a test restore lets its VM fetch, and
# removed once the lines it let in are out (`restore_fetch`). A run with it is
# not put away until they are.
#
MARKER = "fetch-keys.json"
KEPT_FILES = frozenset({"request.json", "prepared.json", "started.json", "result.json"})


def prepared_at(directory: Path) -> float:
    """When the run was prepared, as epoch seconds.

    Runs prepared before B182 have no `prepared.json`; the request file was
    written in the same breath and never again, so its time stands in.
    """

    try:
        document = json.loads((directory / "prepared.json").read_text(encoding="utf-8"))
        at = document["at"] if isinstance(document, dict) else None
        if isinstance(at, int | float) and not isinstance(at, bool):
            return float(at)
    except (OSError, ValueError, KeyError):
        pass
    try:
        return (directory / "request.json").stat().st_mtime
    except OSError:
        return directory.stat().st_mtime


def expired(directory: Path, now: float) -> bool:
    return now - prepared_at(directory) > START_WINDOW


class Held:
    """An exclusive lock on a run directory for as long as a step works in it.

    `sweep` and `discard` take the same lock without waiting, so a run that is
    being carried out is never removed from under itself.
    """

    def __init__(self, directory: Path, *, wait: bool) -> None:
        self._fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            fcntl.flock(self._fd, fcntl.LOCK_EX if wait else fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(self._fd)
            raise

    def __enter__(self) -> Held:
        return self

    def __exit__(self, *_exc: object) -> None:
        os.close(self._fd)


def working(directory: Path) -> bool:
    """A step holds the run's lock now.

    A lock is per open file, so this sees the step even when the caller is the
    step's own process - the overwrite's backup runs inside the run it serves.
    """

    try:
        with Held(directory, wait=False):
            return False
    except BlockingIOError:
        return True


def retire(directory: Path, now: float) -> bool:
    """Put a run past its hour away; True when its directory is gone.

    A run that began writing keeps its outcome files until RESULT_KEPT, and
    everything else goes - the one-time key first among them. Any other run
    past its hour goes whole.
    """

    began = (directory / "started.json").exists() or (directory / "result.json").exists()
    if not began or now - prepared_at(directory) > RESULT_KEPT:
        shutil.rmtree(directory)
        return True
    for entry in directory.iterdir():
        if entry.name in KEPT_FILES:
            continue
        if entry.is_dir() and not entry.is_symlink():
            shutil.rmtree(entry)
        else:
            entry.unlink()
    return False


class ReleaseFailed(Exception):
    """The temporary fetch keys of a run could not be taken out; its directory stays."""


def sweep(root: Path, now: float, release: Callable[[Path], None] | None = None) -> list[str]:
    """Put away every run past its hour that no step holds; the runs removed whole.

    A run that began writing loses its key and plan at the hour and keeps its
    outcome for `status` until RESULT_KEPT; see `retire`.

    A run with temporary fetch keys still out (`MARKER`) is put away only by a
    caller that can take them out, `release`; any other leaves it for one that can.
    """

    if not root.is_dir():
        return []
    removed = []
    for directory in sorted(root.iterdir()):
        if not directory.is_dir() or not restore_agent.RUN_ID.fullmatch(directory.name):
            continue
        try:
            if not expired(directory, now):
                continue
            with Held(directory, wait=False):
                if (directory / MARKER).exists():
                    if release is None:
                        continue
                    release(directory)
                gone = retire(directory, now)
        except (BlockingIOError, FileNotFoundError, ReleaseFailed):
            continue
        if gone:
            removed.append(directory.name)
    return removed


def waiting_on(root: Path, now: float) -> frozenset[tuple[str, str]]:
    """The (node, archive version) pairs a run can still restore.

    A run may sit prepared for its hour before it is carried out, and an
    overwrite's preview takes a backup of its own. Either backup could prune
    the very archive the run was prepared from - the oldest one kept is a
    reasonable thing to restore (review 2026-09-25, finding 3). So retention
    skips what such a run names.

    Only such a run: one not yet carried out (no `result.json`) and either
    within its hour or being worked on now. A run past its hour can never
    start, and its outcome files stay a week for `status` - holding its
    archive for that week, or for ever while nothing swept, kept one archive
    per node past the count (found 2026-10-09: 15 where 14 were promised).
    A run directory that cannot be read protects nothing: the run itself is
    then refused by its own step, in words.
    """

    held: set[tuple[str, str]] = set()
    try:
        runs = list(root.iterdir())
    except OSError:
        return frozenset()
    for run in runs:
        try:
            if (run / "result.json").exists():
                continue
            if expired(run, now) and not working(run):
                continue
            request = json.loads((run / "request.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(request, dict):
            node, archive = request.get("node"), request.get("archive")
            if isinstance(node, str) and isinstance(archive, str):
                held.add((node, archive))
    return frozenset(held)
