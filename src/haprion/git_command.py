"""One way to run git, shared by everything that has to.

Extracted rather than copied: two callers with their own idea of how git
failures surface is exactly the drift that makes a privileged path behave
differently depending on which entry point reached it.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from haprion import exit_codes

GIT = "/usr/bin/git"


def _closed(path: Path) -> bool:
    """Root owns it and neither the group nor others can write to it."""

    try:
        status = path.stat()
    except OSError:
        return False
    return status.st_uid == 0 and not status.st_mode & 0o022


def _git_directories(repo: Path) -> list[Path] | None:
    """The git directories a work tree uses, or None if they cannot be told.

    `.git` is a directory, or a file `gitdir: <path>` that points at a linked
    git directory whose `commondir` names the shared one (the layout the
    configuration repositories have).
    """

    dot_git = repo / ".git"
    if dot_git.is_dir():
        return [dot_git]
    try:
        text = dot_git.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return None
    if not text.startswith("gitdir:"):
        return None
    linked = repo / text.removeprefix("gitdir:").strip()
    directories = [dot_git, linked]
    try:
        common = (linked / "commondir").read_text(encoding="utf-8", errors="replace").strip()
    except FileNotFoundError:
        return directories
    except OSError:
        return None
    directories.append(linked / common)
    return directories


def trusted(repo: Path) -> list[str]:
    """Git's trust in a repository root owns, for a caller that is not root.

    The configuration repositories are root's and readable by the
    configuration group, and the commands at the terminal read them as the
    account that runs them (install.md). Git refuses a repository another
    account owns - "dubious ownership" - and root's `safe.directory` entries
    are in root's own configuration, so `haprion-list` and
    `haprion-config-status` said the repository was not usable (26-11-02).

    Trust here is one exact path, given on the command line, and only when
    the work tree directory and every git directory it uses (the `.git` file,
    the linked directory it names and that one's common directory, whose
    configuration git runs) are owned by root and writable by neither group
    nor others: only root can change them, and root can already do anything
    to the caller, so nothing they hold can turn on the reader. Anything
    else is never trusted this way, and root itself gets nothing - its trust
    stays in its own configuration.
    """

    if os.geteuid() == 0:
        return []
    directories = _git_directories(repo)
    if directories is None or not all(_closed(path) for path in [repo, *directories]):
        return []
    return ["-c", f"safe.directory={repo}"]


def _environment(env: dict[str, str] | None) -> dict[str, str]:
    """What git runs with: the caller's `env` if given, else ours without `GIT_*`.

    `GIT_DIR`, `GIT_WORK_TREE`, `GIT_INDEX_FILE` and the like redirect what git
    reads, and a member of the configuration group reads root's repositories
    with their own shell (26-11-02).
    """

    if env is not None:
        return env
    return {name: value for name, value in os.environ.items() if not name.startswith("GIT_")}


# A personal ignore file hides a new draft file from `git status` for the
# operator and not for root, so the two would disagree about what is unsent.
NO_PERSONAL_IGNORE = ["-c", "core.excludesFile=/dev/null"]


class GitError(Exception):
    """A git invocation failed. Carries the exit code the caller reports."""

    def __init__(self, message: str, *, exit_code: int = exit_codes.INTERNAL):
        super().__init__(message)
        self.exit_code = exit_code


def git(
    repo: Path,
    *args: str,
    stdin: bytes | None = None,
    env: dict[str, str] | None = None,
    allow_failure: bool = False,
) -> bytes:
    completed = subprocess.run(  # noqa: S603 - argv is constructed here, never from input
        [GIT, *trusted(repo), *NO_PERSONAL_IGNORE, "-C", str(repo), *args],
        input=stdin,
        capture_output=True,
        check=False,
        env=_environment(env),
    )
    if completed.returncode != 0 and not allow_failure:
        detail = completed.stderr.decode("utf-8", "replace").strip()
        raise GitError(f"git {args[0]} failed: {detail}")
    return completed.stdout


def git_bounded(repo: Path, *args: str, limit: int) -> bytes | None:
    """git's output if it is at most `limit` bytes, None if it is longer.

    Read as it arrives and stopped past the limit, so a reader that keeps a
    bounded amount never holds more than that in memory either (review
    2026-10-03, K6: a 250 000-line file was read whole to be thrown away).
    """

    with subprocess.Popen(  # noqa: S603 - argv is constructed here, never from input
        [GIT, *trusted(repo), *NO_PERSONAL_IGNORE, "-C", str(repo), *args],
        env=_environment(None),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as process:
        assert process.stdout is not None and process.stderr is not None  # noqa: S101
        output: bytes = process.stdout.read(limit + 1)
        if len(output) > limit:
            process.kill()
            process.wait()
            return None
        detail = process.stderr.read()
        if process.wait() != 0:
            raise GitError(f"git {args[0]} failed: {detail.decode('utf-8', 'replace').strip()}")
    return output
