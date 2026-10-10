"""Start a cluster's version history over, keeping its configuration.

The version number is not stored anywhere. It is counted out of the history
every time it is shown, so there is no counter to set back - the only way to
start at 1 again is to give the cluster a new history whose single commit holds
today's configuration.

This is a one-time cut at a deliberate moment: the end of a build or lab phase,
when the versions behind you have no operational value. It is not a policy and
must not become one. Afterwards the B10 contract applies again, and history is
never rewritten.

Nothing is destroyed in the first move. The previous history is renamed aside
and kept, and the draft area is kept beside it, so the whole operation is undone
by moving two directories back. Deleting either is a separate decision taken
later, by a person, once the new baseline has been published and deployed.

What this does NOT do, deliberately
-----------------------------------
It does not publish, and it does not deploy. Immediately afterwards the cluster's
published release is named after a commit that no longer exists, so publishing
version 1 is the required next step - but it is a separate, visible action rather
than something folded into a command whose name says "reset".
"""

from __future__ import annotations

import os
import shutil
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from haprion import accounts
from haprion.git_command import git

DIRECTORY_MODE = 0o750
FILE_MODE = 0o640
OWNER_GROUP = accounts.CONFIG_GROUP
DEFAULT_BRANCH = "main"

type ChangeOwner = Callable[[Path, int, int], None]


def chown(path: Path, uid: int, gid: int) -> None:
    os.chown(path, uid, gid, follow_symlinks=False)


def _foreground_maintenance() -> dict[str, str]:
    return {
        **os.environ,
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "maintenance.autoDetach",
        "GIT_CONFIG_VALUE_0": "false",
    }


class ResetError(Exception):
    def __init__(self, message: str, *, exit_code: int = 65):
        super().__init__(message)
        self.exit_code = exit_code


@dataclass(frozen=True, slots=True)
class ResetPreview:
    """What the operator is asked to confirm, gathered before anything moves."""

    cluster: str
    draft: Path
    history: Path
    versions: int
    commit: str


@dataclass(frozen=True, slots=True)
class ResetResult:
    commit: str
    versions_discarded: int
    archived_history: Path
    archived_draft: Path


def history_path(draft: Path) -> Path:
    """The bare repository beside a draft area, per the B10 step 6 layout."""

    return draft.with_name(f"{draft.name}.git")


def preview(cluster: str, draft: Path) -> ResetPreview:
    """Read what the reset would discard, without touching anything.

    Refuses on a draft area with unpublished work. Whatever is on disk becomes
    version 1, so unsaved changes would be swept into the new baseline without
    ever having been a version anyone reviewed.
    """

    history = history_path(draft)
    if not history.is_dir():
        raise ResetError(f"cluster '{cluster}' has no configuration history at {history}.")

    dirty = git(draft, "status", "--porcelain").decode().strip()
    if dirty:
        raise ResetError(
            f"cluster '{cluster}' has changes that are not published yet. "
            "Publish or discard them first; otherwise they would silently become "
            "the new baseline."
        )

    return ResetPreview(
        cluster=cluster,
        draft=draft,
        history=history,
        versions=int(git(draft, "rev-list", "--first-parent", "--count", "HEAD").decode()),
        commit=git(draft, "rev-parse", "HEAD").decode().strip(),
    )


def _identity(repo: Path) -> tuple[str, str]:
    name = git(repo, "config", "--get", "user.name", allow_failure=True).decode().strip()
    email = git(repo, "config", "--get", "user.email", allow_failure=True).decode().strip()
    if not name or not email:
        raise ResetError(
            "the repository has no user.name and user.email. The new baseline would be "
            "recorded under an identity nobody chose.",
            exit_code=78,
        )
    return name, email


def _copy_configuration(source: Path, target: Path) -> None:
    """Everything in the draft area except its link to the old history."""

    for entry in sorted(source.rglob("*")):
        relative = entry.relative_to(source)
        if relative.parts[0] == ".git":
            continue
        destination = target / relative
        if entry.is_dir():
            destination.mkdir(parents=True, exist_ok=True)
        else:
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(entry, destination)


def _apply_ownership(path: Path, gid: int, change_owner: ChangeOwner) -> None:
    for entry in (path, *sorted(path.rglob("*"))):
        #
        # The worktree link file and the repository's own files are included:
        # `git init` and `worktree add` create them with root's umask, which is
        # the same trap the B10 step 6 move ran into.
        #
        change_owner(entry, 0, gid)
        if not entry.is_symlink():
            os.chmod(entry, DIRECTORY_MODE if entry.is_dir() else FILE_MODE)


def reset_history(
    plan: ResetPreview,
    *,
    stamp: str,
    message: str,
    group_id: int,
    change_owner: ChangeOwner = chown,
) -> ResetResult:
    """Replace the history with a single version holding today's configuration.

    `stamp` names the archives and must be unique; an existing archive is refused
    rather than overwritten, because it would be the undo path for an earlier
    reset that someone has not finished cleaning up.
    """

    draft = plan.draft
    history = plan.history
    archived_history = history.with_name(f"{history.name}.pre-reset-{stamp}")
    archived_draft = draft.with_name(f"{draft.name}.pre-reset-{stamp}")

    for archive in (archived_history, archived_draft):
        if archive.exists():
            raise ResetError(
                f"{archive} already exists. It is the undo path for an earlier reset; "
                "deal with it before starting another."
            )

    #
    # Read before moving: the identity lives in the repository that is about to
    # be archived, and the new one starts empty.
    #
    name, email = _identity(draft)

    os.rename(history, archived_history)
    os.rename(draft, archived_draft)

    try:
        git(
            Path("/"),
            "init",
            "--quiet",
            "--bare",
            f"--initial-branch={DEFAULT_BRANCH}",
            str(history),
        )
        git(history, "config", "user.name", name)
        git(history, "config", "user.email", email)
        git(history, "worktree", "add", "--quiet", "--orphan", "-b", DEFAULT_BRANCH, str(draft))

        _copy_configuration(archived_draft, draft)

        git(draft, "add", "-A")
        #
        # A commit starts `git maintenance run --auto` detached by default. Run
        # it in the foreground instead, so its lock file is gone and whatever it
        # writes exists before the ownership walk below.
        #
        git(draft, "commit", "--quiet", "-m", message, env=_foreground_maintenance())
    except BaseException:
        #
        # Put it back exactly as it was. A half finished reset is the one state
        # nobody could reason about later.
        #
        shutil.rmtree(draft, ignore_errors=True)
        shutil.rmtree(history, ignore_errors=True)
        os.rename(archived_history, history)
        os.rename(archived_draft, draft)
        raise

    for path in (history, draft):
        _apply_ownership(path, group_id, change_owner)

    return ResetResult(
        commit=git(draft, "rev-parse", "HEAD").decode().strip(),
        versions_discarded=plan.versions,
        archived_history=archived_history,
        archived_draft=archived_draft,
    )
