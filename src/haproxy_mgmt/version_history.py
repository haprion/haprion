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

#
# How many versions a listing shows. The shell command showed ten, and an
# operator reads the number of rows as "the recent ones", not as "all of them".
#
LIST_LIMIT = 10


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


def current_version(repo: Path) -> VersionSummary:
    """The most recently saved version - the one a publish would build on.

    HEAD is read with `rev-parse` rather than through `resolve_head`, which
    refuses a detached HEAD because publishing has a branch to move. Reporting
    has nothing to move, and a repository in an odd state is exactly when its
    status has to still answer.
    """

    commit = _git(repo, "rev-parse", "HEAD").decode().strip()
    return version_summary(repo, count_versions(repo), commit)


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


def recent_versions(repo: Path, limit: int = LIST_LIMIT) -> tuple[VersionSummary, ...]:
    """The newest versions, newest first, numbered the way the operator counts.

    The numbers are not read from the commits - there is nothing in a commit
    that holds one. The newest commit's number is the depth of the history, and
    each older first-parent commit is one less, which is the same arithmetic
    `version_commit` does in the other direction.

    Fields are separated by NUL rather than by a printable character, so a
    comment cannot forge a field boundary. A subject holds no newline, so one
    line is one version.
    """

    #
    # A branch with no commit on it yet. `rev-list` fails outright there, so
    # the state is recognised before it is counted rather than read out of a
    # git error message.
    #
    if not _git(repo, "rev-parse", "--verify", "--quiet", "HEAD", allow_failure=True).strip():
        return ()

    total = count_versions(repo)
    shown = _git(
        repo,
        "log",
        f"-{limit}",
        "--first-parent",
        f"--date={DATE_FORMAT}",
        "--pretty=tformat:%H%x00%ad%x00%s",
    ).decode()

    summaries: list[VersionSummary] = []
    for offset, line in enumerate(shown.splitlines()):
        commit, _, rest = line.partition("\0")
        date, _, comment = rest.partition("\0")
        summaries.append(
            VersionSummary(
                version=total - offset,
                commit=commit,
                date=date.strip(),
                comment=comment,
            )
        )
    return tuple(summaries)
