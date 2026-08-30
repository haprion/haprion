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
# The same instant in the frozen JSON contract's form. Kept beside the display
# format rather than derived from it: parsing a minute-resolution local string
# back into a timestamp would invent a zone and lose the seconds.
#
ISO_FORMAT = "%aI"

#
# How many versions a listing shows. The shell command showed ten, and an
# operator reads the number of rows as "the recent ones", not as "all of them".
#
LIST_LIMIT = 10

#
# The trailer that ties a recorded version to the request that asked for it.
# A trailer rather than a line in the subject, because the subject is what an
# operator reads in the version list and a UUID there would be noise. Everything
# that reads the list uses `%s`, so the binding is invisible to a person and
# exact to a program.
#
REQUEST_TRAILER = "Request-Id"


@dataclass(frozen=True, slots=True)
class VersionSummary:
    version: int
    commit: str
    date: str
    created_at: str
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
        f"--format=%ad%n{ISO_FORMAT}%n%s",
        commit,
    ).decode()
    date, _, rest = shown.partition("\n")
    created_at, _, comment = rest.partition("\n")
    return VersionSummary(
        version=version,
        commit=commit,
        date=date.strip(),
        created_at=created_at.strip(),
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
        f"--pretty=tformat:%H%x00%ad%x00{ISO_FORMAT}%x00%s",
    ).decode()

    summaries: list[VersionSummary] = []
    for offset, line in enumerate(shown.splitlines()):
        commit, _, rest = line.partition("\0")
        date, _, rest = rest.partition("\0")
        created_at, _, comment = rest.partition("\0")
        summaries.append(
            VersionSummary(
                version=total - offset,
                commit=commit,
                date=date.strip(),
                created_at=created_at.strip(),
                comment=comment,
            )
        )
    return tuple(summaries)


def with_request_trailer(message: str, request_id: str) -> str:
    """The commit message a mutation records, bound to the request that asked.

    This is half of the completion evidence a restart needs. After a crash the
    question is whether an operation took effect, and a version's own content
    cannot answer it: the same configuration can be published twice for two
    different reasons. The trailer says which request produced this commit, so a
    retry can recognise its own earlier work instead of doing it again.
    """

    return f"{message}\n\n{REQUEST_TRAILER}: {request_id}\n"


def request_id_of(repo: Path, commit: str) -> str | None:
    """The request a commit was recorded for, or None if it carries no trailer.

    None is the normal answer for every version published before this existed,
    and for anything committed by hand. It means "this commit cannot confirm a
    request", never "the request did not happen" - the difference matters,
    because only the first is safe to treat as no evidence either way.
    """

    value = (
        _git(
            repo,
            "log",
            "-1",
            f"--format=%(trailers:key={REQUEST_TRAILER},valueonly)",
            commit,
        )
        .decode()
        .strip()
    )
    return value or None
