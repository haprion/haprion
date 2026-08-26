"""Reading a cluster's version history.

The version number is not stored anywhere. It is the depth of a commit in the
first-parent history, counted out every time it is needed - which is why
starting over requires a new history rather than setting a counter, and why two
commands that disagree about how to count would disagree about what "version 7"
means.

So it is counted in exactly one place. Publishing writes the number into
RELEASE, reverting resolves a number the human typed back to a commit, and both
read it from here.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from haproxy_mgmt.git_command import git as _git

#
# The format the revert preview shows. Kept identical to the shell command's,
# which an operator has been reading for months.
#
DATE_FORMAT = "format:%Y-%m-%d %H:%M"


@dataclass(frozen=True, slots=True)
class VersionSummary:
    version: int
    commit: str
    date: str
    comment: str


def count_versions(repo: Path, commit: str = "HEAD") -> int:
    """The version number of `commit`: its depth in the first-parent history."""

    return int(_git(repo, "rev-list", "--first-parent", "--count", commit).decode().strip())


def version_commit(repo: Path, version: int) -> str | None:
    """The commit a version number names, or None when there is no such version.

    Counted from the oldest version forward, so version 1 is the first commit -
    the same direction `count_versions` counts in, and the same direction an
    operator reads a version list in.
    """

    if version < 1:
        return None
    listing = _git(repo, "rev-list", "--first-parent", "--reverse", "HEAD").decode().split()
    if version > len(listing):
        return None
    return listing[version - 1]


def version_summary(repo: Path, version: int, commit: str) -> VersionSummary:
    """What the operator is shown before approving a revert."""

    shown = _git(
        repo,
        "show",
        "-s",
        f"--date={DATE_FORMAT}",
        "--format=%ad%n%s",
        commit,
    ).decode()
    date, _, comment = shown.partition("\n")
    return VersionSummary(
        version=version,
        commit=commit,
        date=date.strip(),
        comment=comment.strip(),
    )


def restore_worktree(repo: Path, commit: str) -> None:
    """Make the draft area show the version that now applies.

    A hard reset, unlike the index-only refresh publishing does: reverting
    changes what the configuration IS, so the files a person opens next must be
    the reverted ones. Safe only because the draft was checked for unsaved work
    twice - once by the caller and once inside the privilege boundary.
    """

    if _git(repo, "rev-parse", "--is-bare-repository").decode().strip() == "true":
        return
    _git(repo, "reset", "--quiet", "--hard", commit)
