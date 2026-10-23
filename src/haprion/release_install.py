"""Put a validated artifact where the nodes can fetch it.

A release is immutable. It is named by the commit it was built from, written
once, and never edited afterwards - so republishing the same commit reuses what
is already there rather than rewriting it, and the only mutable thing in the
tree is the `current` link, which is replaced atomically.

Ownership is not incidental. The nodes fetch releases over SSH as the identity
`_haprion-pull`, which is deliberately NOT a member of `haprion`: that
identity is reachable from the nodes, and the membership would also have given
it read access to the source repositories and to the cluster definitions. The
published tree is therefore `root:_haprion-pull` 750, mirroring the certificate
path. Releases used to be written `root:root` 755, which made the tree world
readable and undid the tightening on every publish; deployment broke on
2026-08-24 when the last world readability was removed.
"""

from __future__ import annotations

import grp
import os
import shutil
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

from haprion import accounts, atomic_file, exit_codes
from haprion.release_layout import (
    NODE_DIRECTORIES,
    ReleaseMetadata,
    parse_release_file,
    render_release_file,
)

#
# The same constant lives in `haproxy-publish-core` and in
# `private/tools/configs-tighten/configs-tighten`. That the copies do not drift
# apart is guarded by tests, not by hope - see test_release_install.py here and
# test_published_permissions.py in the regression suite.
#
PUBLISH_GROUP = accounts.PULL

DIRECTORY_MODE = 0o750
FILE_MODE = 0o640

#
# Ownership is applied through an injected call so a test can assert exactly
# which paths were given which owner - the property that actually matters here -
# without the test itself having to run as root.
#
type ChangeOwner = Callable[[Path, int, int], None]


def default_change_owner(path: Path, uid: int, gid: int) -> None:
    os.chown(path, uid, gid, follow_symlinks=False)


class InstallError(Exception):
    def __init__(self, message: str, *, exit_code: int = exit_codes.REFUSED):
        super().__init__(message)
        self.exit_code = exit_code


@dataclass(frozen=True, slots=True)
class InstallResult:
    release: Path
    created: bool
    already_current: bool


def _group_id(name: str = PUBLISH_GROUP) -> int:
    """Fail closed when the group is missing.

    Without it the release would be written with a group that does not exist and
    the nodes would lose read access without the publish saying anything.
    """

    try:
        return grp.getgrnam(name).gr_gid
    except KeyError as exc:
        raise InstallError(
            f"the group '{name}' does not exist. The nodes read releases as that "
            "identity, so publishing would silently break deployment.",
            exit_code=exit_codes.CONFIG,
        ) from exc


def _own(path: Path, gid: int, *, mode: int, change_owner: ChangeOwner) -> None:
    change_owner(path, 0, gid)
    os.chmod(path, mode)


#
# What a release IS. The timestamp is not part of it: it records when a release
# was written, and two writes of the same commit are the same release written
# twice - which is exactly the case a repair after a crash has to be able to
# reach. Comparing the whole stamp made that case an error, so an interrupted
# publish could never be completed idempotently from its own commit; it could
# only be refused.
#
IDENTIFYING_FIELDS = ("schema", "cluster", "version", "hash")


def _verify_existing(release: Path, node_path: str, metadata: ReleaseMetadata) -> None:
    """A release that already exists must be the one this commit describes.

    Reached when the same commit is published twice - by an operator repeating
    themselves, or by a recovery finishing a run that was interrupted between
    the commit and the install. A mismatch in what identifies the release means
    the tree holds something other than what its name claims, and overwriting it
    would destroy the evidence. A different timestamp means only that this is
    the second write.
    """

    stamp = release / node_path / "RELEASE"
    try:
        existing = stamp.read_bytes()
    except OSError as exc:
        raise InstallError(
            f"existing release {metadata.commit} has no readable metadata: {exc}"
        ) from exc

    try:
        found = parse_release_file(existing.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise InstallError(f"existing release {metadata.commit} has unreadable metadata.") from exc

    expected = parse_release_file(render_release_file(metadata).decode("utf-8"))
    differing = [field for field in IDENTIFYING_FIELDS if found.get(field) != expected.get(field)]
    if differing:
        raise InstallError(
            f"existing release {metadata.commit} has incorrect metadata: {', '.join(differing)}."
        )


def install_release(
    publish_path: Path,
    *,
    node_path: str,
    artifact: Mapping[str, bytes],
    index: Mapping[str, bytes],
    metadata: ReleaseMetadata,
    group: str = PUBLISH_GROUP,
    change_owner: ChangeOwner = default_change_owner,
) -> InstallResult:
    """Write the release and point `current` at it.

    `artifact` is node relative - `haproxy.cfg`, `conf.d/...`, `maps/...` - and
    is placed under the level the node actually pulls. RELEASE is added here
    rather than being carried in the artifact, because it carries a timestamp
    and would otherwise make two derivations of the same commit differ.

    `index` is release relative, one level above that, and is what the manager
    keeps about a release without handing it to the nodes: the object manifest.
    Required rather than defaulted, so that a call site which forgets it fails
    to type check instead of writing a release whose objects can never be
    compared. A tree that carries no manifest passes an empty mapping, which is
    the same thing every release published before it looks like.
    """

    gid = _group_id(group)
    releases = publish_path / "releases"
    releases.mkdir(parents=True, exist_ok=True)

    #
    # The parents are what a node traverses. Created with root's umask they
    # would be 755 root:root, so they are corrected rather than assumed.
    #
    for directory in (publish_path, releases):
        _own(directory, gid, mode=DIRECTORY_MODE, change_owner=change_owner)

    release = releases / metadata.commit
    created = False

    if release.exists():
        _verify_existing(release, node_path, metadata)
    else:
        #
        # Staged inside `releases` so the final move is a rename on the same
        # filesystem: a node can never observe a half written release.
        #
        stage = Path(tempfile.mkdtemp(dir=releases, prefix=f".{metadata.commit}."))
        try:
            node_root = stage / node_path
            #
            # Created before the files, and unconditionally: a cluster with no
            # map files still ships an empty maps/, exactly as the shell path's
            # `mkdir -p` did.
            #
            for node_directory in NODE_DIRECTORIES:
                (node_root / node_directory).mkdir(parents=True, exist_ok=True)

            files = dict(artifact)
            files["RELEASE"] = render_release_file(metadata)
            for relative in sorted(files):
                target = node_root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                descriptor = os.open(
                    target,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    FILE_MODE,
                )
                with os.fdopen(descriptor, "wb") as output:
                    output.write(files[relative])

            #
            # Beside `node_path`, not inside it. What a node pulls is that
            # directory whole, and the manager's own index is neither
            # configuration the node loads nor something an rsync of the node's
            # view should be able to delete.
            #
            for relative in sorted(index):
                target = stage / relative
                descriptor = os.open(
                    target,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    FILE_MODE,
                )
                with os.fdopen(descriptor, "wb") as output:
                    output.write(index[relative])

            for path in (stage, *sorted(stage.rglob("*"))):
                _own(
                    path,
                    gid,
                    mode=DIRECTORY_MODE if path.is_dir() else FILE_MODE,
                    change_owner=change_owner,
                )

            atomic_file.move(stage, release)
            created = True
        except BaseException:
            shutil.rmtree(stage, ignore_errors=True)
            raise

    current = publish_path / "current"
    if current.is_symlink() and os.path.realpath(current) == str(release.resolve()):
        return InstallResult(release=release, created=created, already_current=True)

    #
    # Atomic swap. The link is relative so the tree can be moved or mirrored
    # without every release pointing back at this machine's absolute paths.
    #
    staged_link = publish_path / "current.new"
    staged_link.unlink(missing_ok=True)
    staged_link.symlink_to(Path("releases") / metadata.commit)
    change_owner(staged_link, 0, gid)
    atomic_file.move(staged_link, current)

    return InstallResult(release=release, created=created, already_current=False)
