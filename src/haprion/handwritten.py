"""The handwritten layers as the draft area holds them (B529).

`core/` and `manual/` are written by a person, at the terminal, in the cluster's
draft area. Three paths read them, and all three come here so they cannot take
different files:

* `haprion-publish` reads them as the person running it and sends them to its
  helper
* the poller asks `haprion-readings-helper`, which reads them as root, whether
  any of them is not published yet, so the interface can say so
* `changes_publish` reads them as root when the interface publishes them, and
  refuses unless they are still what the page showed (`fingerprint`)

Which files: the ones `git add -A -- core manual` would take - tracked files and
untracked files `.gitignore` does not exclude. A tracked file that is gone is a
deletion.

No link is followed. A symbolic link under either layer is refused rather than
read: as root, following one would publish whatever file it names, and skipping
it, as the terminal command once did, removed a tracked link from the next
version without a word. Each file is opened one directory at a time with
`O_NOFOLLOW`, so a link anywhere on its path is found and not only at its end.
"""

from __future__ import annotations

import errno
import hashlib
import os
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from haprion import exit_codes
from haprion.candidate_validation import MAX_CANDIDATE_BYTES, MAX_CANDIDATE_FILES, MAX_FILE_BYTES
from haprion.git_command import GitError
from haprion.git_command import git as _git
from haprion.regeneration import artifact_diff
from haprion.repo_snapshot import SNAPSHOT_PREFIXES, read_tree_files
from haprion.version_diff import VersionDiff

#
# What the fingerprint is computed over, named so that a later change to its
# form is a different fingerprint and never one that collides with an old one.
#
FINGERPRINT_FORM = b"haprion-handwritten-1\n"
NEW, CHANGED, DELETED = "new", "changed", "deleted"
#
# The layers as git's pathspec names them.
#
LAYERS: tuple[str, ...] = tuple(prefix.rstrip("/") for prefix in SNAPSHOT_PREFIXES)


class HandwrittenError(Exception):
    """The draft area holds something a publish cannot take; nothing was sent."""

    def __init__(self, message: str, *, exit_code: int = exit_codes.REFUSED):
        super().__init__(message)
        self.exit_code = exit_code


class HandwrittenUnreadable(HandwrittenError):
    """The draft area could not be read at all: a reading that failed, not a draft that is wrong (B530, H07)."""

    def __init__(self, message: str):
        super().__init__(message, exit_code=exit_codes.UNAVAILABLE)


@dataclass(frozen=True, slots=True)
class Pending:
    """One file of the draft area that differs from the version: new, changed or deleted."""

    path: str
    kind: str


@dataclass(frozen=True, slots=True)
class Draft:
    """The handwritten layers against one version."""

    head: str
    files: Mapping[str, bytes]
    pending: tuple[Pending, ...]
    fingerprint: str

    def diff(self, published: Mapping[str, bytes]) -> VersionDiff:
        """What publishing these files would change, in the Versions page's shape and bounds."""

        return artifact_diff(published, self.files, self.head)


def _listed(repo: Path) -> list[str]:
    raw = _git(
        repo,
        "ls-files",
        "-z",
        "--cached",
        "--others",
        "--exclude-standard",
        "--",
        *LAYERS,
    ).decode("utf-8", "surrogateescape")
    return sorted({path for path in raw.split("\0") if path})


def _no_link(relative: str) -> HandwrittenError:
    return HandwrittenError(
        f"'{relative}' is a symbolic link, or lies under one. A publish takes files only; "
        "replace the link with the file itself, or remove it."
    )


def _unreadable(relative: str, exc: OSError) -> HandwrittenError:
    if exc.errno == errno.EACCES:
        #
        # The terminal's commands read as the person running them; the
        # configuration group must be able to read every file, as the rest of
        # the repository (B530, H12).
        #
        return HandwrittenError(
            f"'{relative}' cannot be read: {exc.strerror}. The configuration group must be able "
            "to read it: sudo chmod g+r on the file."
        )
    return HandwrittenError(f"'{relative}' cannot be read: {exc.strerror}")


def _read(repo: Path, relative: str) -> bytes | None:
    """One file's bytes, or None when it is gone; refused when anything on its path is a link."""

    parts = relative.split("/")
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        directory = os.open(repo, flags | os.O_DIRECTORY)
    except OSError as exc:
        raise HandwrittenUnreadable(
            f"the draft area {repo} cannot be opened: {exc.strerror}"
        ) from exc
    try:
        for part in parts[:-1]:
            try:
                inner = os.open(part, flags | os.O_DIRECTORY, dir_fd=directory)
            except FileNotFoundError:
                return None
            except OSError as exc:
                if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                    #
                    # A link, or a directory that became a file: git takes the
                    # second as the files under it removed (B530, H06).
                    #
                    try:
                        found = os.lstat(part, dir_fd=directory)
                    except OSError:
                        raise _no_link(relative) from exc
                    if stat.S_ISLNK(found.st_mode):
                        raise _no_link(relative) from exc
                    return None
                raise _unreadable(relative, exc) from exc
            os.close(directory)
            directory = inner
        try:
            handle = os.open(parts[-1], flags | os.O_NONBLOCK, dir_fd=directory)
        except FileNotFoundError:
            return None
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise _no_link(relative) from exc
            raise _unreadable(relative, exc) from exc
    finally:
        os.close(directory)
    with os.fdopen(handle, "rb") as opened:
        if not stat.S_ISREG(os.fstat(opened.fileno()).st_mode):
            raise HandwrittenError(f"'{relative}' is not a file; a publish takes files only.")
        content = opened.read(MAX_FILE_BYTES + 1)
    if len(content) > MAX_FILE_BYTES:
        raise HandwrittenError(
            f"'{relative}' is larger than {MAX_FILE_BYTES // (1024 * 1024)} MiB, "
            "more than one published file may hold."
        )
    return content


def read_layers(repo: Path) -> dict[str, bytes]:
    """`core/` and `manual/` in the draft area, as a publish takes them.

    Text only, as every reader downstream expects: a file that is not UTF-8, or
    holds a NUL, is refused here with its name, as the publish's own limits on
    the number and size of files are.
    """

    try:
        listed = _listed(repo)
    except GitError as exc:
        raise HandwrittenUnreadable(f"the draft area {repo} cannot be listed: {exc}") from exc
    files: dict[str, bytes] = {}
    total = 0
    for relative in listed:
        content = _read(repo, relative)
        if content is None:
            continue
        try:
            content.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise HandwrittenError(
                f"'{relative}' is not UTF-8 text ({exc.reason}). "
                "Configuration is text; remove or fix the file before publishing."
            ) from exc
        if b"\0" in content:
            raise HandwrittenError(
                f"'{relative}' holds a NUL byte. Configuration is text; remove or fix the file."
            )
        total += len(content)
        if len(files) >= MAX_CANDIDATE_FILES or total > MAX_CANDIDATE_BYTES:
            raise HandwrittenError(
                f"core/ and manual/ hold more than a release may: at most {MAX_CANDIDATE_FILES} "
                f"files and {MAX_CANDIDATE_BYTES // (1024 * 1024)} MiB."
            )
        files[relative] = content
    return files


def fingerprint(files: Mapping[str, bytes]) -> str:
    """One value for exactly these files: their paths and their contents."""

    digest = hashlib.sha256(FINGERPRINT_FORM)
    for path in sorted(files):
        digest.update(path.encode("utf-8", "surrogateescape") + b"\0")
        digest.update(hashlib.sha256(files[path]).hexdigest().encode() + b"\n")
    return digest.hexdigest()


def published_layers(repo: Path, commit: str) -> dict[str, bytes]:
    """`core/` and `manual/` as version `commit` holds them."""

    return read_tree_files(repo, commit, SNAPSHOT_PREFIXES)


def pending(published: Mapping[str, bytes], files: Mapping[str, bytes]) -> tuple[Pending, ...]:
    """What differs between the version's layers and the draft's, by path."""

    found: list[Pending] = []
    for path in sorted(set(published) | set(files)):
        if path not in published:
            found.append(Pending(path, NEW))
        elif path not in files:
            found.append(Pending(path, DELETED))
        elif published[path] != files[path]:
            found.append(Pending(path, CHANGED))
    return tuple(found)


def read_draft(repo: Path, head: str) -> tuple[Draft, dict[str, bytes]]:
    """The draft against version `head`, and that version's own layers beside it."""

    files = read_layers(repo)
    published = published_layers(repo, head)
    return (
        Draft(
            head=head,
            files=files,
            pending=pending(published, files),
            fingerprint=fingerprint(files),
        ),
        published,
    )


def settle_index(repo: Path, head: str) -> None:
    """Point the index's `core/` and `manual/` at version `head`; no file is written (B530, H02).

    When the files are the version's and only git's index says otherwise - a
    publish stopped before it moved the index, a file staged by hand - this is
    the whole repair: what git reports then matches what the reader reports.
    """

    if _git(repo, "rev-parse", "--is-bare-repository").decode().strip() == "true":
        return
    if _git(repo, "diff", "--cached", "--name-only", head, "--", *LAYERS).strip():
        _git(repo, "reset", "-q", head, "--", *LAYERS)


def named_paths(paths: Sequence[str], *, at_most: int = 5) -> str:
    """Paths named for a sentence: the first few and how many more (B530, N3)."""

    shown = list(paths[:at_most])
    rest = len(paths) - len(shown)
    return ", ".join(shown) + (f" and {rest} more" if rest > 0 else "")


def listed_paths(found: tuple[Pending, ...], *, at_most: int = 5) -> str:
    """The files, named for a sentence: the first few and how many more."""

    return named_paths([item.path for item in found], at_most=at_most)
