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

import os
import pwd
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from haproxy_mgmt.git_command import git as _git
from haproxy_mgmt.helper_protocol import HelperProtocolError

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

#
# Who asked for a version, in two trailers because there are two different
# facts (B207, 2026-09-29). `Run-By` is the account sudo says ran the
# helper, which the helper can prove: the interface's worker for anything done
# in the browser, the operator's own account at the terminal. `Requested-By`
# is the person - the signed-in user the interface names in the job, or the
# same account as `Run-By` when nobody names anyone else. The listing shows
# the person; the proven account stays for whoever has to check the claim.
#
# A name is taken from the request only when the account sudo proves is the
# interface's own worker, named in the runtime policy (2026-09-29). Anyone
# else who may run a helper - an operator at the terminal - is recorded as
# themselves whatever the request says, so the column can be trusted.
#
REQUESTED_BY_TRAILER = "Requested-By"
RUN_BY_TRAILER = "Run-By"

#
# The longest listing a caller may ask for. The interface pages through what it
# gets in the browser; `haproxy-list` keeps its ten.
#
MAX_LIST_LIMIT = 250

#
# As long as an account name may be in the interface's database. Anything that
# is not printable is refused rather than cleaned: a newline in a trailer value
# would start a trailer of its own, and a forged `Request-Id` is exactly what
# the restart evidence must never read.
#
MAX_NAME_LENGTH = 64


class UnfitName(ValueError):
    """A name that cannot stand in a commit trailer."""


def trailer_name(value: object) -> str:
    """A person's or account's name, fit to stand in a trailer, or UnfitName."""

    if not isinstance(value, str) or not value.strip():
        raise UnfitName("must be a non-empty string")
    if len(value) > MAX_NAME_LENGTH:
        raise UnfitName(f"must be at most {MAX_NAME_LENGTH} characters")
    if value != value.strip() or any(
        unicodedata.category(character).startswith(("C", "Z")) and character != " "
        for character in value
    ):
        raise UnfitName("may not contain control characters or line breaks")
    return value


def caller_account(environ: Mapping[str, str] | None = None) -> str:
    """The account the helper runs for: the one sudo names, else its own.

    Root running a helper directly - a DR shell, a test - is recorded as root.
    """

    named = (os.environ if environ is None else environ).get("SUDO_USER", "")
    try:
        return trailer_name(named)
    except UnfitName:
        return pwd.getpwuid(os.getuid()).pw_name


@dataclass(frozen=True, slots=True)
class VersionSummary:
    version: int
    commit: str
    date: str
    created_at: str
    comment: str
    #
    # The request that produced this version, when it carries the trailer.
    # None for every version recorded before the binding existed, and for
    # anything committed by hand.
    #
    request_id: str | None = None
    #
    # The person who asked for it, from the `Requested-By` trailer. None for
    # every version recorded before the trailer existed.
    #
    requested_by: str | None = None


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
        #
        # The trailer is last and uses an explicit separator: git's trailer
        # placeholder ends the block with a newline of its own unless one is
        # given, and a newline here would split one version across two lines.
        #
        f"--pretty=tformat:%H%x00%ad%x00{ISO_FORMAT}%x00%s%x00"
        f"%(trailers:key={REQUEST_TRAILER},valueonly,separator=%x2C)%x00"
        f"%(trailers:key={REQUESTED_BY_TRAILER},valueonly,separator=%x2C)",
    ).decode()

    summaries: list[VersionSummary] = []
    for offset, line in enumerate(shown.splitlines()):
        commit, date, created_at, comment, request_id, requested_by = line.split("\0")
        summaries.append(
            VersionSummary(
                version=total - offset,
                commit=commit,
                date=date.strip(),
                created_at=created_at.strip(),
                comment=comment,
                request_id=request_id.strip() or None,
                requested_by=requested_by.strip() or None,
            )
        )
    return tuple(summaries)


def with_request_trailer(
    message: str,
    request_id: str,
    *,
    requested_by: str | None = None,
    run_by: str | None = None,
) -> str:
    """The commit message a mutation records, bound to the request that asked.

    This is half of the completion evidence a restart needs. After a crash the
    question is whether an operation took effect, and a version's own content
    cannot answer it: the same configuration can be published twice for two
    different reasons. The trailer says which request produced this commit, so a
    retry can recognise its own earlier work instead of doing it again.

    The names, when given, have passed `trailer_name`; they are checked again
    here because a line break in one would forge the trailer above.
    """

    trailers = [f"{REQUEST_TRAILER}: {request_id}"]
    if requested_by is not None:
        trailers.append(f"{REQUESTED_BY_TRAILER}: {trailer_name(requested_by)}")
    if run_by is not None:
        trailers.append(f"{RUN_BY_TRAILER}: {trailer_name(run_by)}")
    return f"{message}\n\n" + "\n".join(trailers) + "\n"


def requester(
    parameters: Mapping[str, object],
    environ: Mapping[str, str] | None = None,
    *,
    interface_account: str | None = None,
) -> tuple[str, str]:
    """(requested_by, run_by) for a version this helper records.

    `requested_by` is the parameter of that name when the interface's worker -
    `interface_account`, from the runtime policy - gives one for its signed-in
    user, and the proven account otherwise: when nobody is named, when the
    policy names no worker, and when someone else names somebody. Raises
    UnfitName for a name that cannot stand in a trailer, whoever sent it.
    """

    run_by = caller_account(environ)
    named = parameters.get("requested_by")
    if named is None:
        return run_by, run_by
    person = trailer_name(named)
    return (
        person if interface_account is not None and run_by == interface_account else run_by
    ), run_by


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


def request_names(
    parameters: Mapping[str, object],
    environ: Mapping[str, str] | None = None,
    *,
    interface_account: str | None = None,
) -> tuple[str, str]:
    """`requester` for a helper: a name that cannot stand is the caller's bad input."""

    try:
        return requester(parameters, environ, interface_account=interface_account)
    except UnfitName as exc:
        raise HelperProtocolError(f"parameters.requested_by {exc}", exit_code=65) from exc


def version_message(message: str, request_id: str, names: tuple[str, str]) -> str:
    """A version's commit message: the request and who asked, from `request_names`."""

    requested_by, run_by = names
    return with_request_trailer(message, request_id, requested_by=requested_by, run_by=run_by)
