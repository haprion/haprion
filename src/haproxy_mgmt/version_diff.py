"""What one version changed: the version against the one before it.

A version is a first-parent commit, and what it changed is its difference from
its first parent - the version before it in the same list. The first version is
compared with an empty tree. That difference never changes once the commit
exists, which is what lets the interface fetch it once and keep it.

One reading for every caller. `haproxy-list --diff` reads the repository as the
person running it; the poller cannot, and asks `haproxy-list-helper` for the
same thing. Both come here, so the terminal and the Versions page cannot show
the same version differently.

Bounded, because a page shows it and a database keeps it: at most
`MAX_DIFF_BYTES` of patch text and `MAX_FILES` files, and a diff that is cut says
so rather than ending as if it were whole. Paths come from `--name-status -z`,
never parsed out of patch text, so a file name cannot be mistaken for a header.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from haproxy_mgmt.git_command import git as _git

MAX_DIFF_BYTES = 256 * 1024
MAX_FILES = 200
#
# git's empty tree. The first version has no parent, and what it changed is
# everything it holds.
#
EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
COMMIT = re.compile(r"^[0-9a-f]{40}$")
#
# Plain unified text: no colour, no external diff driver or text conversion a
# repository's own configuration could name, and renames recognised.
#
DIFF_OPTIONS = ("--no-color", "--no-ext-diff", "--no-textconv", "--find-renames", "-U3")
STATUS = {"A": "added", "M": "modified", "D": "deleted", "R": "renamed", "T": "modified"}


@dataclass(frozen=True, slots=True)
class FileChange:
    path: str
    status: str
    old_path: str | None
    added: int
    removed: int
    binary: bool
    #
    # The hunks as git prints them, from the first `@@` on: header lines,
    # context, `+` and `-`. Empty for a binary file and for a file left out
    # once the bound was reached.
    #
    lines: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "status": self.status,
            "old_path": self.old_path,
            "added": self.added,
            "removed": self.removed,
            "binary": self.binary,
            "lines": list(self.lines),
        }


@dataclass(frozen=True, slots=True)
class VersionDiff:
    commit: str
    parent: str | None
    files: tuple[FileChange, ...]
    truncated: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "commit": self.commit,
            "parent": self.parent,
            "files": [change.as_dict() for change in self.files],
            "truncated": self.truncated,
        }


def _parent(repo: Path, commit: str) -> str | None:
    found = _git(repo, "rev-parse", "--verify", "--quiet", f"{commit}^1", allow_failure=True)
    text = found.decode().strip()
    return text or None


def _changes(repo: Path, base: str, commit: str) -> list[tuple[str, str, str | None]]:
    """(status, path, old path) per file, from NUL-separated name-status."""

    raw = _git(repo, "diff", "--name-status", "-z", "--find-renames", base, commit, "--")
    fields = raw.decode("utf-8", "replace").split("\0")
    found: list[tuple[str, str, str | None]] = []
    index = 0
    while index < len(fields) and fields[index]:
        code = fields[index][:1]
        if code in {"R", "C"}:
            found.append((STATUS.get(code, "modified"), fields[index + 2], fields[index + 1]))
            index += 3
        else:
            found.append((STATUS.get(code, "modified"), fields[index + 1], None))
            index += 2
    return found


def _hunks(text: str) -> tuple[bool, list[str]]:
    lines = text.splitlines()
    if any(line.startswith("Binary files ") for line in lines):
        return True, []
    start = next((i for i, line in enumerate(lines) if line.startswith("@@")), len(lines))
    return False, lines[start:]


def version_diff(repo: Path, commit: str) -> VersionDiff:
    """What `commit` changed against the version before it, within the bounds."""

    if not COMMIT.fullmatch(commit):
        raise ValueError("a version is named by its full commit hash")
    parent = _parent(repo, commit)
    base = parent or EMPTY_TREE
    files: list[FileChange] = []
    budget = MAX_DIFF_BYTES
    truncated = False
    changes = _changes(repo, base, commit)
    if len(changes) > MAX_FILES:
        changes = changes[:MAX_FILES]
        truncated = True
    for status, path, old_path in changes:
        paths = (old_path, path) if old_path else (path,)
        text = _git(repo, "diff", *DIFF_OPTIONS, base, commit, "--", *paths).decode(
            "utf-8", "replace"
        )
        binary, lines = _hunks(text)
        added = sum(1 for line in lines if line.startswith("+"))
        removed = sum(1 for line in lines if line.startswith("-"))
        size = sum(len(line.encode()) + 1 for line in lines)
        if size > budget:
            #
            # The file is still named, with its counts; only its lines are
            # left out. A reader learns what else changed even when one file
            # was too large to show.
            #
            lines = []
            truncated = True
        else:
            budget -= size
        files.append(
            FileChange(
                path=path,
                status=status,
                old_path=old_path,
                added=added,
                removed=removed,
                binary=binary,
                lines=tuple(lines),
            )
        )
    return VersionDiff(commit=commit, parent=parent, files=tuple(files), truncated=truncated)


def render(diff: VersionDiff) -> str:
    """The diff as a terminal reads it: one header per file, then its hunks."""

    out: list[str] = []
    for change in diff.files:
        name = f"{change.old_path} -> {change.path}" if change.old_path else change.path
        out.append(f"=== {name} ({change.status}, +{change.added} -{change.removed})")
        if change.binary:
            out.append("(binary file)")
        elif not change.lines and (change.added or change.removed):
            out.append("(left out: the diff is larger than this command shows)")
        out.extend(change.lines)
        out.append("")
    if diff.truncated:
        out.append(f"(cut: at most {MAX_FILES} files and {MAX_DIFF_BYTES // 1024} KiB are shown)")
    if not diff.files:
        out.append("(this version changed no file)")
    return "\n".join(out) + "\n"
