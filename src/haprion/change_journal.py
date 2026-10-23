"""A change to the manager's own files that survives being cut short (B247).

Adding or removing a node or a cluster rewrites up to nine root-owned files
one rename at a time, and a cluster also creates or moves whole directories.
Until 2026-10-06 the way back lived only in the process: a failure it caught
put everything back, but a power cut, a reboot, an out-of-memory kill or a
terminal that lost its session between two renames left the files half
changed - a node in `clusters.yaml` whose keys were never added, or the other
way round - and nothing remembered what the change had been.

So before the first file is touched, the whole change is written down here:
every file's content before and after, every directory the change will move
or create. The record is on disk and synced before anything else happens, and
it is removed only once everything the change wrote has been synced too. In
between, a record on disk means a change that did not finish.

Putting a change back is one path whether the process is still alive or not:
`transaction` calls `recover` itself on any failure it sees, and the node
helper calls `recover` under the same locks before its next request. Recovery
puts a file back only when it still holds what the change wrote; a file that
holds anything else was changed by someone since, and recovery stops before
touching anything and leaves the record for a person to read.

SIGTERM, SIGINT and SIGHUP are held while a change runs, so the ordinary ways
to stop a process wait for it to finish or put back; only what cannot be held
- SIGKILL, power - leaves the record for the next run.
"""

from __future__ import annotations

import base64
import contextlib
import json
import os
import shutil
import signal
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from haprion import atomic_file, exit_codes
from haprion.config import CLUSTER_ID

JOURNAL = Path("/var/lib/haprion/change-journal.json")
SCHEMA_VERSION = 1
HELD_SIGNALS = frozenset({signal.SIGTERM, signal.SIGINT, signal.SIGHUP})


class RecoveryError(Exception):
    """A change that did not finish and cannot be put back without a person."""

    code = "change_interrupted"
    exit_code = exit_codes.BLOCKED


@dataclass(frozen=True, slots=True)
class FileChange:
    path: Path
    before: bytes
    after: bytes
    what: str


@dataclass(frozen=True, slots=True)
class Record:
    """What one change does, in the order it does it.

    `made` are paths the change creates and that did not exist before it (a
    repository, a release directory); `moves` are directories it renames, in
    order; `created` are the empty directories it makes to move them into.
    """

    operation: str
    cluster: str
    files: tuple[FileChange, ...]
    made: tuple[Path, ...] = ()
    moves: tuple[tuple[Path, Path], ...] = ()
    created: tuple[Path, ...] = ()

    @property
    def what(self) -> tuple[str, ...]:
        return tuple(change.what for change in self.files)

    def as_json(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "operation": self.operation,
            "cluster": self.cluster,
            "files": [
                {
                    "path": str(change.path),
                    "before": base64.b64encode(change.before).decode(),
                    "after": base64.b64encode(change.after).decode(),
                    "what": change.what,
                }
                for change in self.files
            ],
            "made": [str(path) for path in self.made],
            "moves": [[str(source), str(destination)] for source, destination in self.moves],
            "created": [str(path) for path in self.created],
        }

    @classmethod
    def from_json(cls, document: object) -> Record:
        try:
            if not isinstance(document, dict) or document["schema_version"] != SCHEMA_VERSION:
                raise ValueError("unknown schema")
            cluster = document["cluster"]
            if not isinstance(cluster, str) or not CLUSTER_ID.fullmatch(cluster):
                raise ValueError("no cluster")
            return cls(
                operation=str(document["operation"]),
                cluster=cluster,
                files=tuple(
                    FileChange(
                        Path(entry["path"]),
                        base64.b64decode(entry["before"], validate=True),
                        base64.b64decode(entry["after"], validate=True),
                        str(entry["what"]),
                    )
                    for entry in document["files"]
                ),
                made=tuple(Path(path) for path in document["made"]),
                moves=tuple((Path(source), Path(target)) for source, target in document["moves"]),
                created=tuple(Path(path) for path in document["created"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise RecoveryError(f"the change record is unreadable ({exc})") from None


@dataclass(frozen=True, slots=True)
class Recovered:
    """A change found unfinished and put back."""

    operation: str
    cluster: str
    files: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {"operation": self.operation, "cluster": self.cluster, "files": list(self.files)}


# ------------------------------------------------------------------ the disk


def write_like(path: Path, content: bytes) -> None:
    """Replace `path` by a rename, keeping its owner and mode."""

    atomic_file.write_like(path, content)


def _write_record(journal: Path, record: Record) -> None:
    journal.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    if journal.exists():
        raise RecoveryError(
            f"{journal} records a change that did not finish; it is put back before the next one"
        )
    atomic_file.write(journal, json.dumps(record.as_json()).encode("utf-8"), mode=0o600)


def _drop_record(journal: Path) -> None:
    journal.unlink()
    atomic_file.sync_directory(journal.parent)


def read(journal: Path = JOURNAL) -> Record | None:
    """The unfinished change on disk, if there is one."""

    try:
        raw = journal.read_bytes()
    except FileNotFoundError:
        return None
    try:
        return Record.from_json(json.loads(raw))
    except ValueError:
        raise RecoveryError(f"{journal} is not a change record") from None


# --------------------------------------------------------------- the way back


def _leftovers(path: Path) -> list[Path]:
    """Temporaries `write_like` made beside `path` and a kill left behind."""

    try:
        return [
            entry
            for entry in path.parent.iterdir()
            if entry.name.startswith(f".{path.name}.") and entry.is_file()
        ]
    except FileNotFoundError:
        return []


def _conflicts(record: Record) -> list[str]:
    found = []
    for change in record.files:
        try:
            current = change.path.read_bytes()
        except FileNotFoundError:
            found.append(f"{change.path} is gone")
            continue
        if current not in (change.before, change.after):
            found.append(f"{change.path} was changed since")
    for source, destination in record.moves:
        if source.exists() and destination.exists():
            found.append(f"both {source} and {destination} exist")
        elif not source.exists() and not destination.exists():
            found.append(f"neither {source} nor {destination} exists")
    return found


def recover(journal: Path = JOURNAL) -> Recovered | None:
    """Put back the unfinished change on disk, if any. Caller holds the locks."""

    record = read(journal)
    if record is None:
        return None
    conflicts = _conflicts(record)
    if conflicts:
        raise RecoveryError(
            f"a {record.operation} of cluster {record.cluster!r} did not finish, and it cannot "
            f"be put back by itself: {'; '.join(conflicts)}. The change is recorded in "
            f"{journal}; put the files right by hand, then remove that file."
        )
    for change in reversed(record.files):
        if change.path.read_bytes() == change.after and change.after != change.before:
            write_like(change.path, change.before)
        for leftover in _leftovers(change.path):
            leftover.unlink()
    for source, destination in reversed(record.moves):
        if destination.exists():
            atomic_file.move(destination, source)
    for directory in reversed(record.created):
        #
        # Made empty by the change; anything in it now is somebody else's.
        #
        with contextlib.suppress(OSError):
            directory.rmdir()
    for path in reversed(record.made):
        shutil.rmtree(path, ignore_errors=True)
    os.sync()
    _drop_record(journal)
    return Recovered(record.operation, record.cluster, record.what)


# ---------------------------------------------------------- the way forward


def apply(files: Sequence[FileChange]) -> None:
    for change in files:
        write_like(change.path, change.after)


@contextmanager
def transaction(record: Record, journal: Path = JOURNAL) -> Iterator[None]:
    """Run the change in the block with its record on disk.

    The block does the work and raises to refuse; whatever it raises, the
    change is put back from the record before the exception goes on.
    """

    previous = signal.pthread_sigmask(signal.SIG_BLOCK, HELD_SIGNALS)
    try:
        _write_record(journal, record)
        try:
            yield
        except BaseException as exc:
            try:
                recover(journal)
            except BaseException as failed:
                raise failed from exc
            raise
        #
        # Everything the change wrote reaches the disk before its record
        # leaves it: a record that outlived a change it describes would be put
        # back by the next run.
        #
        os.sync()
        _drop_record(journal)
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)
