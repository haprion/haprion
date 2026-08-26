"""Is this path a usable configuration repository, and if not, why.

Two questions, deliberately answered by two functions. `is_repo_root` is a
predicate: it answers yes or no and nothing else, because a frozen case matrix
depends on it doing exactly that. `describe_problem` runs only on the "no"
branch and is allowed to be talkative.

The B10 step 6 layout is what makes the second function worth having. A linked
draft area that has lost its history looks, to anything built on `git`, like
"no configuration repository" - while on disk every file the operator wrote is
still there, untouched. Those two states read the same and are repaired in
completely different ways, so the failing branch reads the link file directly
rather than asking git: in exactly this state git refuses to answer anything at
all about the directory, and anything built on `rev-parse` would go blind
precisely when it is needed.

Ported case by case from the shell commands, which keep their own copies until
they are replaced. That the copies agree is guarded by tests rather than by
sharing code across the privilege boundary.
"""

from __future__ import annotations

from pathlib import Path

from haproxy_mgmt.git_command import git as _git


def _resolved(path: Path) -> Path:
    return Path(path).expanduser().resolve(strict=False)


def is_repo_root(repo: Path) -> bool:
    """True when `repo` is the top of a repository, in any of its three layouts.

    Accepted: an ordinary repository's top level, a bare repository, and the top
    of a linked work tree. Rejected: a subdirectory, `<repo>/.git`, and anything
    git cannot answer about.
    """

    root = _resolved(repo)
    git_dir = _git(root, "rev-parse", "--absolute-git-dir", allow_failure=True).decode().strip()
    if not git_dir:
        return False

    bare = _git(root, "rev-parse", "--is-bare-repository", allow_failure=True).decode().strip()
    if bare == "true":
        return _resolved(Path(git_dir)) == root

    #
    # Not compared against `<repo>/.git`: in a linked work tree that is a FILE
    # and the git directory lives under `<bare>/worktrees/<name>`, so the old
    # comparison rejected a perfectly valid draft area. "Is this the top of a
    # work tree" is the question actually being asked.
    #
    top_level = _git(root, "rev-parse", "--show-toplevel", allow_failure=True).decode().strip()
    return bool(top_level) and _resolved(Path(top_level)) == root


def _broken_link(repo: Path) -> Path | None:
    """The history a linked draft area points at, when that history is gone.

    `<draft>/.git` is a file holding one line: `gitdir: <path>`. If the path it
    names no longer exists, the link is broken - the state worth naming.
    """

    link_file = repo / ".git"
    if not link_file.is_file():
        return None
    try:
        content = link_file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    for line in content.splitlines():
        if line.startswith("gitdir:"):
            target = Path(line.removeprefix("gitdir:").strip())
            if not target.is_absolute():
                target = repo / target
            return None if target.is_dir() else target
    return None


def describe_problem(cluster: str, repo: Path) -> str:
    """Why `is_repo_root` said no, in the words the operator needs.

    Stays deliberately plain when none of the known cases fit: a wrong diagnosis
    sends someone down the wrong repair path, which is worse than no diagnosis.
    """

    if not repo.is_dir():
        return f"ERROR: the configuration directory for cluster '{cluster}' is missing: {repo}"

    broken = _broken_link(repo)
    if broken is not None:
        history = str(broken).split("/worktrees/", 1)[0]
        return (
            f"ERROR: the draft area for cluster '{cluster}' is no longer connected to its "
            "saved history.\n\n"
            f"  draft area:            {repo}\n"
            f"  saved history, sought: {history}\n\n"
            "Your files in the draft area are intact; nothing has been lost there.\n"
            "The saved history has been moved, renamed or deleted.\n\n"
            "If you can put it back at the path above, that alone fixes this.\n"
            "If it now lives somewhere else, reconnect the two with:\n\n"
            f'  git -C "<where the history is now>" worktree repair "{repo}"'
        )

    top_level = _git(repo, "rev-parse", "--show-toplevel", allow_failure=True).decode().strip()
    if top_level and _resolved(Path(top_level)) != _resolved(repo):
        return (
            f"ERROR: the path configured for cluster '{cluster}' is not the root of its "
            "configuration repository.\n\n"
            f"  configured: {repo}\n"
            f"  root is:    {top_level}"
        )

    return f"ERROR: '{repo}' is not a usable configuration repository for cluster '{cluster}'."


def unsaved_changes(repo: Path) -> str:
    """What the draft area holds that is not in any version yet.

    Empty means clean. Both publishing paths that rewrite history - reverting
    and resetting - refuse on a non-empty answer, because whatever is here would
    otherwise be swept into a version nobody reviewed, or overwritten by one.
    """

    return _git(repo, "status", "--porcelain").decode().strip()
