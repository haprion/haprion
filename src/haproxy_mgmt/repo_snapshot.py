"""Build a new version from bytes that crossed the privilege boundary.

Publishing creates a commit, and a commit is a write into a repository owned by
root. That write cannot move outside the boundary - so what crosses it is the
configuration bytes, and this module turns them into a version on the far side.

The rules are taken from `haproxy-publish` and are semantic, not incidental:

* only `core/` and `manual/` are replaced. `managed/` is written by the
  application and is carried over from the previous version unchanged, so a
  human publishing does not accidentally ship half-finished generated output
* the previous version is named by the caller and checked on the way in and
  again at the reference swap. If it moved in between - a concurrent publish or
  revert - nothing is written
* a candidate whose tree equals the previous version's tree is not a version.
  Publishing nothing is reported, not recorded

Git is driven through plumbing commands with an index file of our own, so the
repository's real index is never touched and an aborted publish leaves nothing
staged behind.
"""

from __future__ import annotations

import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from haproxy_mgmt.git_command import GitError
from haproxy_mgmt.git_command import git as _git

#
# The layers a human publish owns. Frozen: managed/ is deliberately absent.
#
SNAPSHOT_PREFIXES: tuple[str, ...] = ("core/", "manual/")

#
# Every file in both cluster repositories is a regular non-executable file,
# measured 2026-08-25. An executable bit means nothing to HAProxy, so blobs are
# written with one mode and the question does not arise.
#
BLOB_MODE = "100644"


class PublishError(Exception):
    """Publishing cannot proceed. Carries the exit code the CLI reports."""

    def __init__(self, message: str, *, exit_code: int = 65):
        super().__init__(message)
        self.exit_code = exit_code


class ConcurrentUpdate(PublishError):
    """The repository moved while the candidate was being prepared."""

    def __init__(self, message: str):
        super().__init__(message, exit_code=75)


@dataclass(frozen=True, slots=True)
class Snapshot:
    tree: str
    unchanged: bool


def resolve_head(repo: Path) -> tuple[str, str]:
    """Return (branch reference, commit) for the repository's current position.

    Publishing moves a branch, so a detached HEAD is refused rather than handled:
    there would be nothing to move, and the version would be unreachable.
    """

    #
    # A detached HEAD makes symbolic-ref exit non-zero with no output. That is an
    # answer, not a failure, so it is read rather than raised on.
    #
    branch = _git(repo, "symbolic-ref", "--quiet", "HEAD", allow_failure=True).decode().strip()
    if not branch:
        raise PublishError(
            "the repository is not on a branch. Publishing moves a branch, "
            "so a branch must be checked out."
        )
    return branch, _git(repo, "rev-parse", "HEAD").decode().strip()


def build_candidate_tree(
    repo: Path,
    base_commit: str,
    files: Mapping[str, bytes],
    *,
    prefixes: tuple[str, ...] = SNAPSHOT_PREFIXES,
) -> Snapshot:
    """Write a tree that is `base_commit` with exactly `prefixes` replaced.

    `files` holds every file the caller is publishing, keyed by repository
    relative path. Paths outside the snapshot prefixes are refused rather than
    ignored: silently dropping part of what an operator asked to publish is the
    failure mode this whole path exists to prevent.
    """

    if not prefixes or any(not prefix.endswith("/") for prefix in prefixes):
        raise ValueError("snapshot prefixes must be non-empty repository directory prefixes")

    for path in sorted(files):
        if not path.startswith(prefixes):
            raise PublishError(
                f"'{path}' is outside the layers this path publishes "
                f"({', '.join(prefix.rstrip('/') for prefix in prefixes)})."
            )

    with tempfile.TemporaryDirectory(prefix="haproxy-publish-index-") as work:
        env = {
            "GIT_INDEX_FILE": str(Path(work) / "index"),
            "PATH": "/usr/bin:/bin",
            #
            # git refuses to run against a repository owned by another user
            # unless it is told the path is expected. The helper already
            # established that this is the cluster's configured repository.
            #
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "safe.directory",
            "GIT_CONFIG_VALUE_0": str(repo),
        }
        _git(repo, "read-tree", base_commit, env=env)

        #
        # Drop the snapshot layers wholesale, then add back exactly what was
        # received. Without the removal a file deleted by the operator would
        # survive in the new version, which is the same silent-drift failure in
        # the other direction.
        #
        for prefix in prefixes:
            _git(repo, "rm", "--cached", "-r", "--ignore-unmatch", "-q", "--", prefix, env=env)

        for path in sorted(files):
            blob = _git(repo, "hash-object", "-w", "--stdin", stdin=files[path], env=env)
            _git(
                repo,
                "update-index",
                "--add",
                "--cacheinfo",
                f"{BLOB_MODE},{blob.decode().strip()},{path}",
                env=env,
            )

        tree = _git(repo, "write-tree", env=env).decode().strip()

    base_tree = _git(repo, "rev-parse", f"{base_commit}^{{tree}}").decode().strip()
    return Snapshot(tree=tree, unchanged=tree == base_tree)


def committed_snapshot(repo: Path, commit: str) -> Snapshot:
    """`commit`'s own tree, as the candidate a retry of that commit's request is.

    Nothing is applied on top: the commit already holds what the request asked
    for, and applying it a second time is not always a no-op - a removal asked
    twice is a removal of something that is no longer there.
    """

    return Snapshot(
        tree=_git(repo, "rev-parse", f"{commit}^{{tree}}").decode().strip(), unchanged=True
    )


def read_tree_files(repo: Path, tree: str) -> dict[str, bytes]:
    """Every file in `tree`, keyed by repository relative path.

    This is what the release artifact is derived from - the committed candidate,
    never the work tree, which may differ in managed/.
    """

    listing = _git(repo, "ls-tree", "-r", "-z", "--full-tree", tree).decode()
    blobs: list[tuple[str, str]] = []
    for entry in listing.split("\0"):
        if not entry:
            continue
        metadata, path = entry.split("\t", 1)
        _mode, kind, object_id = metadata.split()
        if kind == "blob":
            blobs.append((path, object_id))
    if not blobs:
        return {}
    #
    # One git for every file rather than one per file (B222, measured
    # 2026-10-01): ten thousand objects took 6.5 s as ten thousand processes.
    # `--batch` answers each requested ID with `<id> blob <size>`, the content
    # and a newline, in the order asked; every header is checked against the ID
    # it answers, so a missing object or a short read is an error rather than a
    # file quietly holding its neighbour's bytes.
    #
    output = _git(
        repo, "cat-file", "--batch", stdin="".join(f"{oid}\n" for _, oid in blobs).encode()
    )
    files: dict[str, bytes] = {}
    position = 0
    for path, object_id in blobs:
        end = output.find(b"\n", position)
        header = output[position:end].split() if end >= 0 else []
        if len(header) != 3 or header[0] != object_id.encode() or header[1] != b"blob":
            raise GitError(f"git cat-file could not read {path}")
        start = end + 1
        size = int(header[2])
        if output[start + size : start + size + 1] != b"\n":
            raise GitError(f"git cat-file returned a short read for {path}")
        files[path] = output[start : start + size]
        position = start + size + 1
    if position != len(output):
        raise GitError("git cat-file returned more than was asked for")
    return files


def _identity(repo: Path) -> dict[str, str]:
    """The name and address versions are recorded under.

    Read from the repository rather than inherited from the environment. A root
    helper must not sign a version with whatever identity happens to be ambient -
    and without this, git falls back to a machine-derived address and records it
    silently.
    """

    identity: dict[str, str] = {}
    for setting, variables in (
        ("user.name", ("GIT_AUTHOR_NAME", "GIT_COMMITTER_NAME")),
        ("user.email", ("GIT_AUTHOR_EMAIL", "GIT_COMMITTER_EMAIL")),
    ):
        value = _git(repo, "config", "--get", setting, allow_failure=True).decode().strip()
        if not value:
            raise PublishError(
                f"the repository has no {setting}. Versions would be recorded under an "
                "identity nobody chose; set it on the repository before publishing.",
                exit_code=78,
            )
        for variable in variables:
            identity[variable] = value
    return identity


def commit_and_swap(
    repo: Path,
    *,
    branch: str,
    tree: str,
    parent: str,
    message: str,
) -> str:
    """Record the version and move the branch, or write nothing at all.

    The swap names the value the branch is expected to still hold. If another
    publish or a revert moved it while this candidate was being validated, the
    swap fails and no version is created - the same compare-and-swap the shell
    path adopted in B10 step 4, at reference level.
    """

    env = {"PATH": "/usr/bin:/bin", **_identity(repo)}
    commit = _git(repo, "commit-tree", tree, "-p", parent, "-m", message, env=env).decode().strip()
    try:
        _git(repo, "update-ref", branch, commit, parent)
    except GitError as exc:
        raise ConcurrentUpdate(
            "the configuration changed while this version was being prepared. "
            "Nothing was published; check the current state and try again."
        ) from exc
    return commit


def refresh_worktree_index(repo: Path, commit: str) -> None:
    """Point the work tree's index at the version that was just recorded.

    The candidate is built in an index of our own, so after the reference swap
    the draft area's real index still describes the previous version - and every
    later check, from `git status` to the reset command's refusal to run on
    unpublished work, would read the draft as dirty when it is not.

    The shell path did the same thing with `git reset --mixed` as its last act.
    Only the index moves; no file in the draft area is written.
    """

    if _git(repo, "rev-parse", "--is-bare-repository").decode().strip() == "true":
        return
    _git(repo, "reset", "--quiet", "--mixed", commit)
