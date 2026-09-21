"""What state backups exist for a cluster's nodes, and nothing about their contents.

The archives hold password hashes and private SSH keys, so this module reads
directory metadata only - name, size, modification time - and never opens one.
Nothing here can leak what is inside a backup because nothing here looks.

`created_at` is the file's modification time, not the timestamp in its name
--------------------------------------------------------------------------
The two disagree, by a second or so: the name is stamped when the backup starts
and the file is closed when it finishes. Two reasons to prefer the file's own
time. It is an instant, where the name is a naive local timestamp that would
have to be interpreted in the manager's timezone - and interpreted wrongly twice
a year, once ambiguously when an hour repeats. And it is what the operator has
been reading: the shell implementation this replaces printed the modification
time in its CREATED column, so a new command that answered differently would be
a change of meaning disguised as a reimplementation.

The name is still what identifies a backup, and is reported as `version`.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from haproxy_mgmt.config import Node

#
# The archive name, and the only thing in the directory this reads. A file that
# does not match is not reported at all: the directory is root-owned and holds
# what the backup engine writes, but "everything that happens to be there" is
# not a listing of backups.
#
ARCHIVE = re.compile(r"^(?P<version>\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2})\.tar\.gz$")
LATEST_LINK = "latest"


class BackupError(Exception):
    """The backup root itself cannot be read, which is not a per-node fact."""


@dataclass(frozen=True, slots=True)
class NodeBackups:
    name: str
    available: bool
    latest_version: str | None
    retained_count: int
    retained_size_bytes: int
    backups: tuple[dict[str, Any], ...]
    error: str | None


def _timestamp(moment: datetime) -> str:
    return moment.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _latest_version(directory: Path) -> str | None:
    """Which archive `latest` points at, read as a name rather than followed.

    Read with readlink instead of resolving it, because a dangling link still
    states which backup was written last - and resolving one would leave the
    directory this is allowed to read.
    """

    link = directory / LATEST_LINK
    try:
        target = link.readlink()
    except (OSError, ValueError):
        return None
    matched = ARCHIVE.match(target.name)
    return matched.group("version") if matched else None


def _archives(directory: Path) -> list[tuple[str, int, datetime]]:
    found: list[tuple[str, int, datetime]] = []
    for entry in directory.iterdir():
        matched = ARCHIVE.match(entry.name)
        if matched is None or not entry.is_file() or entry.is_symlink():
            continue
        stat = entry.stat()
        if stat.st_size < 1:
            #
            # The schema requires a positive size, and a zero-byte archive is
            # not a backup: it is a write that was interrupted. Left out rather
            # than reported as something that could be restored.
            #
            continue
        found.append(
            (matched.group("version"), stat.st_size, datetime.fromtimestamp(stat.st_mtime, UTC))
        )
    #
    # Newest first, by name. The name sorts chronologically by construction, and
    # sorting by it rather than by mtime keeps the order stable if a file is
    # touched.
    #
    found.sort(key=lambda item: item[0], reverse=True)
    return found


def node_backups(root: Path, node: Node, *, limit: int | None) -> NodeBackups:
    """One node's backups, or why they could not be read.

    A node that cannot be read is a fact about that node, never an exception:
    one missing directory must not take the other nodes' answers down with it.
    """

    directory = root / node.name
    try:
        archives = _archives(directory)
    except FileNotFoundError:
        return NodeBackups(node.name, False, None, 0, 0, (), "backup_directory_missing")
    except OSError:
        return NodeBackups(node.name, False, None, 0, 0, (), "backup_metadata_unavailable")

    latest = _latest_version(directory)
    kept = archives if limit is None else archives[:limit]
    return NodeBackups(
        name=node.name,
        available=True,
        latest_version=latest,
        retained_count=len(archives),
        retained_size_bytes=sum(size for _, size, _ in archives),
        backups=tuple(
            {
                "version": version,
                "created_at": _timestamp(created_at),
                "size_bytes": size,
                "latest": version == latest,
            }
            for version, size, created_at in kept
        ),
        error=None,
    )


def backup_list_result(
    root: Path, nodes: Iterable[Node], *, limit: int | None
) -> tuple[dict[str, Any], tuple[NodeBackups, ...]]:
    """The result body, plus the per-node readings the caller has to judge."""

    if not root.is_dir():
        raise BackupError(f"the backup root {root} is not a directory")
    readings = tuple(node_backups(root, node, limit=limit) for node in nodes)
    return {
        "limit": limit,
        "nodes": [
            {
                "name": reading.name,
                "available": reading.available,
                "latest_version": reading.latest_version,
                "retained_count": reading.retained_count,
                "retained_size_bytes": reading.retained_size_bytes,
                "backups": list(reading.backups),
                "error": None
                if reading.error is None
                else {
                    "code": reading.error,
                    "message": "Backup metadata is unavailable",
                    "node": reading.name,
                    "details": None,
                },
            }
            for reading in readings
        ],
    }, readings
