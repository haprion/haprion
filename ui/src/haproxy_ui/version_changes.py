"""One version's diff as the page draws it: files, and each line marked by kind.

The diff is the engine's (`haproxy_mgmt.version_diff`), kept by the poller in
`version_diff`. Nothing here reads a repository or decides what changed; it
only sorts the stored lines into hunk headers, additions, removals and context
so the template can colour them, and adds up the counts for the heading.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal

from haproxy_mgmt.object_manifest import REPOSITORY_PATH as MANIFEST_PATH

type LineKind = Literal["hunk", "add", "del", "ctx"]

#
# The engine's own bookkeeping, not configuration: fingerprints per object that
# let two releases be compared. Every object publish changes it, so it was the
# same block of hashes under every version (2026-10-01). Left out of the
# page and its counts; Git and `haprion-list --diff` still show it.
#
NOT_SHOWN = frozenset({MANIFEST_PATH})


@dataclass(frozen=True, slots=True)
class FileView:
    path: str
    old_path: str | None
    status: str
    added: int
    removed: int
    binary: bool
    left_out: bool
    lines: tuple[tuple[LineKind, str], ...]


@dataclass(frozen=True, slots=True)
class ChangesView:
    files: tuple[FileView, ...]
    added: int
    removed: int
    truncated: bool


def _kind(line: str) -> LineKind:
    if line.startswith("@@"):
        return "hunk"
    if line.startswith("+"):
        return "add"
    if line.startswith("-"):
        return "del"
    return "ctx"


def _count(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def build(diff: Mapping[str, Any] | None) -> ChangesView | None:
    """None when the poller has not fetched this version's diff yet."""

    if diff is None:
        return None
    files: list[FileView] = []
    raw_files = diff.get("files")
    for raw in raw_files if isinstance(raw_files, list) else []:
        if not isinstance(raw, Mapping) or not isinstance(raw.get("path"), str):
            continue
        if raw["path"] in NOT_SHOWN:
            continue
        raw_lines = raw.get("lines")
        lines = tuple(
            (_kind(line), line)
            for line in (raw_lines if isinstance(raw_lines, list) else [])
            if isinstance(line, str)
        )
        added, removed = _count(raw.get("added")), _count(raw.get("removed"))
        binary = raw.get("binary") is True
        old_path = raw.get("old_path")
        files.append(
            FileView(
                path=raw["path"],
                old_path=old_path if isinstance(old_path, str) else None,
                status=str(raw.get("status") or "modified"),
                added=added,
                removed=removed,
                binary=binary,
                left_out=not lines and not binary and bool(added or removed),
                lines=lines,
            )
        )
    return ChangesView(
        files=tuple(files),
        added=sum(item.added for item in files),
        removed=sum(item.removed for item in files),
        truncated=diff.get("truncated") is True,
    )
