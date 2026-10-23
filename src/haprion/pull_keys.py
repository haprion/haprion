"""Every node's fetch keys, bound to its own cluster and its own address (B358).

A node fetches its configuration and its certificates over SSH with two keys
of its own, as the pull accounts `_haprion-pull` and `_haprion-cert-pull`,
each line a forced `rrsync -ro <directory>`. The directory used to be the
whole publish root and the whole certificate root, for every cluster, and no
line said where it could be used from: root on a node of one cluster could
fetch another cluster's private keys, and a leaked key worked from anywhere
(review 2026-10-22, 5-4). Adding a node, creating a cluster and changing a
node's host now write the narrow line; this writes it for the nodes that are
already there, and again when a node's name resolves to another address:

- each node's two lines name its cluster's published tree and its cluster's
  certificate directory, with `from=` its host and the addresses it resolves
  to (`node_enrollment.pull_sources`). A host that does not resolve keeps its
  narrowed root and goes without `from=`, said in the report: a line that
  locked a node out would stop its fetches, which is worse than the lock;
- a line for a node no cluster has is removed - a key nothing manages, which
  would otherwise keep reading every cluster's files;
- a line of any other shape is left as written and said in the report;
- with a certificate registry, the certificates are laid out one directory
  per cluster first - each cluster's from the shared copy, which is removed
  once no line reads the root any more - and each cluster's published tree
  gets the link that keeps a node's old path valid under its narrower root
  (`release_install.ensure_pull_link`).

Each step is the state it leaves, so a second run finds nothing to do, and a
run cut short is finished by the next. The two files change in one recorded
change (`change_journal`), under every cluster's lock and the cluster file's,
as any node change is. The certificate lock is held throughout, so no publish
writes into the layout while it moves.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Callable, Iterator
from contextlib import ExitStack
from dataclasses import dataclass, field
from pathlib import Path

from haprion import atomic_file, cert_registry, change_journal, exit_codes, labels
from haprion.cert_lock import DEFAULT_LOCK_PATH as CERTIFICATE_LOCK
from haprion.certificates import AUTHORITY_DIRECTORY, authority_path, certificate_path
from haprion.change_journal import FileChange as Change
from haprion.change_journal import Record
from haprion.cluster_lock import DEFAULT_LOCK_ROOT, hold
from haprion.config import Cluster, Node, PathPolicy, RuntimeConfig
from haprion.node_enrollment import (
    CERT_PURPOSE,
    CONFIG_PURPOSE,
    RRSYNC,
    EnrollmentError,
    Locations,
    config_root,
    keys_without,
    node_keys,
    pull_line,
    pull_sources,
)
from haprion.release_install import ChangeOwner, default_change_owner, ensure_pull_link

OPERATION = "pull keys"
#
# Taken by every change to the cluster file (`node_helper.CLUSTER_FILE_LOCK`):
# the node lists this reads are what those changes write.
#
CLUSTER_FILE_LOCK = "cluster-file"
CLUSTER_MODE = 0o640
ROOT_UID = 0


class PullKeysError(Exception):
    """A refusal, in the words the terminal shows."""

    def __init__(self, message: str, exit_code: int = exit_codes.REFUSED):
        super().__init__(message)
        self.exit_code = exit_code


@dataclass(slots=True)
class Report:
    """What the run did and what it left, a line each."""

    done: list[str] = field(default_factory=list)
    left: list[str] = field(default_factory=list)


def _nodes_named(runtime: RuntimeConfig, name: str) -> list[tuple[Cluster, Node]]:
    """Every node of that name. Adding a node refuses a second, but the file is hand-editable."""

    return [
        (cluster, node)
        for cluster in runtime.clusters.values()
        for node in cluster.nodes
        if node.name == name
    ]


def _replaced(text: bytes, node: str, purpose: str, line: str) -> bytes:
    """`text` with the node's line for `purpose` replaced where it stands."""

    lines = text.decode().splitlines(keepends=True)
    out = [
        line + "\n" if existing.rstrip("\n").endswith(f" {node} {purpose}") else existing
        for existing in lines
    ]
    return "".join(out).encode()


def plan(
    policy: PathPolicy,
    runtime: RuntimeConfig,
    *,
    read: Callable[[Path], bytes],
    locations: Locations,
    report: Report,
) -> list[Change]:
    """The two files as they should be, and what each change is, in the report."""

    changes: list[Change] = []
    for account, purpose, root_of in (
        (policy.pull_account, CONFIG_PURPOSE, lambda cluster: config_root(policy, cluster)),
        (policy.cert_pull_account, CERT_PURPOSE, policy.certificate_directory),
    ):
        path = locations.authorized_keys(account)
        before = read(path)
        after = before
        for name, key in node_keys(before, purpose).items():
            found = _nodes_named(runtime, name)
            if not found:
                after = keys_without(after, name, purpose)
                report.done.append(f"removed {name}'s {purpose} key: {name} is not a node")
                continue
            if len(found) > 1:
                clusters = " and ".join(cluster.cluster_id for cluster, _ in found)
                report.left.append(
                    f"{name}'s {purpose} key is left as written: {name} is a node of {clusters}"
                )
                continue
            [(cluster, node)] = found
            root = root_of(cluster.cluster_id)
            if root is None:
                continue
            try:
                sources = pull_sources(node.mgmt_host, locations.forward)
            except EnrollmentError:
                sources = ()
                report.left.append(
                    f"{name}'s {purpose} key has no from=: {node.mgmt_host} does not resolve; "
                    "run this again once it does"
                )
            line = pull_line(root, key, name, purpose, sources)
            if line + "\n" not in after.decode().splitlines(keepends=True):
                after = _replaced(after, name, purpose, line)
                report.done.append(f"{name}'s {purpose} key reads {root} alone")
        named = node_keys(after, purpose)
        for other in after.decode().splitlines():
            text = other.strip()
            if (
                text
                and not text.startswith("#")
                and not any(text.endswith(f" {name} {purpose}") for name in named)
            ):
                report.left.append(f"left as written in {path}: a line that names no node")
        if after != before:
            changes.append(Change(path, before, after, f"{account}'s authorized_keys"))
    return changes


# ------------------------------------------------------------ the layout


def _directory_like(parent: Path, directory: Path) -> None:
    """`directory`, made like `parent` if it is not there, as a publish makes it."""

    if not directory.exists():
        metadata = parent.lstat()
        directory.mkdir(mode=0o700)
        os.chmod(directory, stat.S_IMODE(metadata.st_mode) & 0o750)
        os.chown(directory, metadata.st_uid, metadata.st_gid)
    found = directory.lstat()
    if not stat.S_ISDIR(found.st_mode) or stat.S_ISLNK(found.st_mode):
        raise PullKeysError(f"{directory} is not a directory")


def _copied(source: Path, target: Path, gid: int) -> bool:
    """The shared copy into a cluster's directory, unless the cluster has its own already."""

    if target.exists() or not source.is_file():
        return False
    atomic_file.write(target, source.read_bytes(), mode=CLUSTER_MODE, uid=ROOT_UID, gid=gid)
    return True


def lay_out(policy: PathPolicy, runtime: RuntimeConfig, report: Report) -> None:
    """Each cluster's certificates in its own directory, from the shared copies (B358)."""

    root = policy.certificate_root
    if root is None or policy.certificate_registry is None:
        return
    if AUTHORITY_DIRECTORY in runtime.clusters and (root / AUTHORITY_DIRECTORY).is_dir():
        raise PullKeysError(
            f"a cluster is named {AUTHORITY_DIRECTORY!r}, which is also the directory the shared "
            "authorities are in; rename the cluster before the certificates are laid out"
        )
    gid = root.lstat().st_gid
    for cluster in runtime.clusters.values():
        directory = policy.certificate_directory(cluster.cluster_id)
        assert directory is not None  # noqa: S101 - the root is set
        _directory_like(root, directory)
        copies = [
            (certificate_path(root, identifier), certificate_path(directory, identifier))
            for identifier in cluster.certificate_ids
        ]
        if cluster.authority_ids:
            _directory_like(root, directory / AUTHORITY_DIRECTORY)
            copies += [
                (authority_path(root, identifier), authority_path(directory, identifier))
                for identifier in cluster.authority_ids
            ]
        made = [target.name for source, target in copies if _copied(source, target, gid)]
        if made:
            report.done.append(
                f"{cluster.cluster_id}: {labels.counted(len(made), 'certificate file')} "
                f"in {directory}"
            )


def _shared(root: Path) -> Iterator[Path]:
    """The copies the clusters shared: the root's own `*.pem` and its authorities'."""

    for directory in (root, root / AUTHORITY_DIRECTORY):
        if directory.is_dir() and not directory.is_symlink():
            for path in sorted(directory.glob("*.pem")):
                if path.is_file() and not path.is_symlink():
                    yield path


def clear_shared(
    policy: PathPolicy, read: Callable[[Path], bytes], locations: Locations, report: Report
) -> None:
    """The shared copies removed, once no line reads the whole root."""

    root = policy.certificate_root
    if root is None or policy.certificate_registry is None:
        return
    wide = f'command="{RRSYNC} -ro {root}"'
    if any(
        wide in line
        for line in read(locations.authorized_keys(policy.cert_pull_account)).decode().splitlines()
    ):
        report.left.append(f"the shared copies in {root} stay: a line still reads all of it")
        return
    removed = 0
    for path in list(_shared(root)):
        path.unlink()
        removed += 1
    authorities = root / AUTHORITY_DIRECTORY
    if authorities.is_dir() and not authorities.is_symlink() and not any(authorities.iterdir()):
        authorities.rmdir()
    if removed:
        report.done.append(
            f"removed the {labels.counted(removed, 'shared certificate file')} from {root}"
        )


def link_trees(
    policy: PathPolicy,
    runtime: RuntimeConfig,
    report: Report,
    change_owner: ChangeOwner = default_change_owner,
) -> None:
    """Each published tree's link to itself, so the nodes' paths hold under the narrow root.

    A cluster not yet published has no tree; its first publish makes the link.
    """

    for cluster in runtime.clusters:
        tree = config_root(policy, cluster)
        if tree.is_dir() and ensure_pull_link(tree, tree.lstat().st_gid, change_owner=change_owner):
            report.done.append(f"{cluster}: {tree / cluster} -> .")


# ------------------------------------------------------------- the whole


def _read(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except FileNotFoundError:
        raise PullKeysError(f"{path} does not exist; it is created by the installer") from None


def run(
    policy: PathPolicy,
    runtime: RuntimeConfig,
    *,
    locations: Locations | None = None,
    lock_root: Path = DEFAULT_LOCK_ROOT,
    certificate_lock: Path = CERTIFICATE_LOCK,
    change_owner: ChangeOwner = default_change_owner,
) -> Report:
    """Every step, under the locks every node and certificate change takes."""

    locations = locations or Locations()
    report = Report()
    if not runtime.clusters:
        return report
    with ExitStack() as locks:
        for cluster in sorted(runtime.clusters):
            locks.enter_context(hold(cluster, operation=OPERATION, root=lock_root))
        locks.enter_context(hold(CLUSTER_FILE_LOCK, operation=OPERATION, root=lock_root))
        if policy.certificate_registry is not None:
            locks.enter_context(cert_registry.locked(certificate_lock))
        if change_journal.read(locations.journal) is not None:
            recovered = change_journal.recover(locations.journal)
            if recovered is not None:
                report.done.append(
                    f"a {recovered.operation} of cluster '{recovered.cluster}' did not finish "
                    f"and was put back: {', '.join(recovered.files)}"
                )
        lay_out(policy, runtime, report)
        link_trees(policy, runtime, report, change_owner)
        changes = plan(policy, runtime, read=_read, locations=locations, report=report)
        if changes:
            record = Record(OPERATION, sorted(runtime.clusters)[0], tuple(changes))
            with change_journal.transaction(record, locations.journal):
                change_journal.apply(changes)
        clear_shared(policy, _read, locations, report)
    return report
