"""Fetch and retain one cluster's node state archives.

The node-side forced command writes a tar.gz stream and accepts no arguments.
This side decides which configured nodes to ask, writes only below the
root-owned backup root, validates the complete DR manifest and then atomically
gives the archive its permanent name.  A partial file is never a backup and is
never visible to the listing command.
"""

from __future__ import annotations

import fcntl
import os
import stat
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from time import monotonic, sleep
from typing import BinaryIO, Literal, Protocol
from uuid import uuid4

from haprion import atomic_file, exit_codes, node_ssh, restore_runs
from haprion.backup_archive import MAX_ARCHIVE_BYTES, ArchiveError, ArchiveFacts, validate
from haprion.backup_retention import DEFAULT_RETENTION
from haprion.config import Cluster, DeployIdentity, Node

FETCH_TIMEOUT_SECONDS = 300.0
#
# One run's whole budget, the lock's wait included (logic review 2026-10-22,
# L4). The worker's client gives the helper 720 s (`backup_job_ask`) and the
# worker its job 900 s; a run that took 300 s a node, one after the other,
# under a lock it waited for without end went past both while every node was
# within its own limit, and the job read `unknown` while the helper carried on.
# Within this the run answers itself: the nodes it reached, and the ones it
# had no time left for. 120 s is left for the last archive's validation and
# the answer.
#
RUN_BUDGET_SECONDS = 600.0
LOCK_WAIT_SECONDS = 120.0
#
# Less than this left, a node is not started: an export that cannot finish is
# a hung connection, not a backup.
#
MIN_FETCH_SECONDS = 10.0
# Fourteen daily archives per node cover two weeks unless the Backups page set
# another count (`backup_retention`).  Retention is deliberately per node: a
# two-node cluster on the default therefore holds 28 archives in total.
RETENTION = DEFAULT_RETENTION
LOCK_PATH = Path("/run/lock/haprion-state-backup.lock")


class BackupRunError(RuntimeError):
    """The installation cannot start a trustworthy backup run."""


class BackupBusy(BackupRunError):
    """Another backup run held the lock for longer than this one could wait."""


@dataclass(frozen=True, slots=True)
class FetchResult:
    exit_code: int
    stderr: str = ""


class Fetch(Protocol):
    def __call__(
        self, node: Node, identity: DeployIdentity, destination: BinaryIO, *, timeout: float
    ) -> FetchResult: ...


@dataclass(frozen=True, slots=True)
class NodeResult:
    name: str
    outcome: str
    version: str | None
    size_bytes: int | None
    error: str | None

    def as_dict(self) -> dict[str, str | int | None]:
        return {
            "name": self.name,
            "outcome": self.outcome,
            "version": self.version,
            "size_bytes": self.size_bytes,
            "error": self.error,
        }


@dataclass(frozen=True, slots=True)
class BackupResult:
    cluster: str
    version: str
    nodes: tuple[NodeResult, ...]

    @property
    def outcome(self) -> Literal["done", "partial", "failed"]:
        succeeded = sum(node.outcome == "done" for node in self.nodes)
        if succeeded == len(self.nodes):
            return "done"
        return "partial" if succeeded else "failed"

    def as_dict(self) -> dict[str, object]:
        return {
            "version": self.version,
            "nodes": [node.as_dict() for node in self.nodes],
        }


def _key_is_private(path: Path) -> bool:
    try:
        details = path.lstat()
    except OSError:
        return False
    return (
        stat.S_ISREG(details.st_mode)
        and not path.is_symlink()
        and details.st_uid == 0
        and stat.S_IMODE(details.st_mode) & 0o077 == 0
    )


def _root_is_private(path: Path) -> bool:
    try:
        details = path.lstat()
    except OSError:
        return False
    return (
        stat.S_ISDIR(details.st_mode)
        and not path.is_symlink()
        and details.st_uid == 0
        and stat.S_IMODE(details.st_mode) & 0o077 == 0
    )


def _directory_is_private(path: Path) -> bool:
    try:
        details = path.lstat()
    except OSError:
        return False
    return (
        stat.S_ISDIR(details.st_mode)
        and not path.is_symlink()
        and details.st_uid == 0
        and stat.S_IMODE(details.st_mode) == 0o700
    )


def fetch_over_ssh(
    node: Node,
    identity: DeployIdentity,
    destination: BinaryIO,
    *,
    timeout: float = FETCH_TIMEOUT_SECONDS,
    max_bytes: int = MAX_ARCHIVE_BYTES,
) -> FetchResult:
    """Stream one forced-command response with a hard byte and time ceiling."""

    ended = node_ssh.stream(
        node_ssh.ssh_argv(identity.key, identity.user, node.mgmt_host),
        destination.write,
        timeout=timeout,
        max_bytes=max_bytes,
    )
    if ended.timed_out:
        return FetchResult(exit_codes.TIMED_OUT, "the node state export timed out")
    if ended.too_large:
        return FetchResult(
            exit_codes.REFUSED, "the node state export exceeded the archive size limit"
        )
    assert ended.returncode is not None  # noqa: S101 - a call not stopped has its exit code
    return FetchResult(ended.returncode, ended.stderr)


def _commit_latest(directory: Path, archive: Path) -> None:
    temporary = directory / f".latest-{uuid4().hex}"
    temporary.symlink_to(archive.name)
    atomic_file.move(temporary, directory / "latest")


def _retain(directory: Path, keep: int, held: frozenset[str] = frozenset()) -> None:
    archives = sorted(
        (
            path
            for path in directory.iterdir()
            if path.is_file()
            and not path.is_symlink()
            and path.name.endswith(".tar.gz")
            and not path.name.startswith(".")
        ),
        key=lambda path: path.name,
        reverse=True,
    )
    for old in archives[keep:]:
        if old.name.removesuffix(".tar.gz") not in held:
            old.unlink()


def _one_node(
    node: Node,
    identity: DeployIdentity,
    root: Path,
    version: str,
    *,
    fetch: Fetch,
    validator: Callable[[Path], ArchiveFacts],
    retention: int,
    held: frozenset[str] = frozenset(),
    timeout: float = FETCH_TIMEOUT_SECONDS,
) -> NodeResult:
    directory = root / node.name
    directory.mkdir(mode=0o700, exist_ok=True)
    if not _directory_is_private(directory):
        return NodeResult(node.name, "failed", None, None, "backup_directory_insecure")

    final = directory / f"{version}.tar.gz"
    if final.exists():
        return NodeResult(node.name, "failed", None, None, "backup_version_exists")
    incoming = directory / f".incoming-{uuid4().hex}"
    try:
        descriptor = os.open(incoming, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as destination:
            fetched = fetch(node, identity, destination, timeout=timeout)
            destination.flush()
            os.fsync(destination.fileno())
        if fetched.exit_code != 0:
            return NodeResult(node.name, "failed", None, None, "node_export_failed")
        facts = validator(incoming)
        if facts.hostname != node.name:
            return NodeResult(node.name, "failed", None, None, "backup_node_mismatch")
        atomic_file.move(incoming, final)
        _commit_latest(directory, final)
        _retain(directory, retention, held)
        return NodeResult(node.name, "done", version, facts.size_bytes, None)
    except (OSError, ArchiveError):
        return NodeResult(node.name, "failed", None, None, "backup_archive_invalid")
    finally:
        with suppress(FileNotFoundError):
            incoming.unlink()


def run(
    cluster_id: str,
    cluster: Cluster,
    identity: DeployIdentity | None,
    root: Path | None,
    retention: int = RETENTION,
    *,
    fetch: Fetch = fetch_over_ssh,
    validator: Callable[[Path], ArchiveFacts] = validate,
    now: datetime | None = None,
    lock_path: Path = LOCK_PATH,
    restore_root: Path = restore_runs.RUN_ROOT,
    budget: float = RUN_BUDGET_SECONDS,
    clock: Callable[[], float] = monotonic,
    wait: Callable[[float], None] = sleep,
) -> BackupResult:
    """Take a state archive from every configured node under one global lock, within `budget`."""

    if identity is None:
        raise BackupRunError("backup_identity is not configured in the runtime policy")
    if root is None:
        raise BackupRunError("backup_root is not configured in the runtime policy")
    if not _key_is_private(identity.key):
        raise BackupRunError("the backup identity key is missing or is not root-only")
    if not _root_is_private(root):
        raise BackupRunError("the backup root is missing or is not root-owned mode 0700")
    if retention < 1:
        raise BackupRunError("backup retention must be positive")

    #
    # The archive is named on the manager's clock, like the timer that takes it
    # and every archive the fleet-wide script left behind. Names sort the
    # listing and drive retention, so one stamped in another zone would file
    # itself two hours into the past and be pruned before its elders.
    #
    taken = now or datetime.now(UTC)
    version = taken.astimezone().strftime("%Y-%m-%d_%H-%M-%S")
    deadline = clock() + budget
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+b") as lock:
        _lock_within(lock.fileno(), min(deadline, clock() + LOCK_WAIT_SECONDS), clock, wait)
        #
        # Runs past their hour first, as a restore step would: nothing else
        # puts them away when no restore runs for weeks (found 2026-10-09,
        # two runs from 2026-09-25 still on disk). Then the archives a run can
        # still restore. A sweep that fails costs tidiness, not the backup:
        # `waiting_on` reads the hour itself.
        #
        with suppress(OSError):
            restore_runs.sweep(restore_root, taken.timestamp())
        held = restore_runs.waiting_on(restore_root, taken.timestamp())
        nodes: list[NodeResult] = []
        for node in cluster.nodes:
            remaining = deadline - clock()
            if remaining < MIN_FETCH_SECONDS:
                nodes.append(NodeResult(node.name, "failed", None, None, "backup_budget_exhausted"))
                continue
            nodes.append(
                _one_node(
                    node,
                    identity,
                    root,
                    version,
                    fetch=fetch,
                    validator=validator,
                    retention=retention,
                    held=frozenset(version for name, version in held if name == node.name),
                    timeout=min(FETCH_TIMEOUT_SECONDS, remaining),
                )
            )
    return BackupResult(cluster=cluster_id, version=version, nodes=tuple(nodes))


def _lock_within(
    descriptor: int, until: float, clock: Callable[[], float], wait: Callable[[float], None]
) -> None:
    """The global lock, or BackupBusy once `until` has passed without it."""

    while True:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            if clock() >= until:
                raise BackupBusy(
                    "another node backup or restore holds the backup lock; try again when it has "
                    "finished"
                ) from None
            wait(0.5)
        else:
            return
