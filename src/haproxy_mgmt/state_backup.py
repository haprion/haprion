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
import selectors
import stat
import subprocess
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from time import monotonic
from typing import BinaryIO, Literal
from uuid import uuid4

from haproxy_mgmt.backup_archive import MAX_ARCHIVE_BYTES, ArchiveError, ArchiveFacts, validate
from haproxy_mgmt.config import Cluster, DeployIdentity, Node

SSH = "/usr/bin/ssh"
SSH_OPTIONS = (
    "-T",
    "-o",
    "BatchMode=yes",
    "-o",
    "IdentitiesOnly=yes",
    "-o",
    "StrictHostKeyChecking=yes",
    "-o",
    "ConnectTimeout=10",
    "-o",
    "ConnectionAttempts=1",
    "-o",
    "LogLevel=ERROR",
)
SSH_ENVIRONMENT = {"PATH": "/usr/bin:/bin", "HOME": "/root", "LANG": "C.UTF-8"}

MAX_STDERR_BYTES = 64 * 1024
FETCH_TIMEOUT_SECONDS = 300.0
# Fourteen daily archives per node cover two weeks.  Retention is deliberately
# per node: a two-node cluster therefore holds 28 archives in total.
RETENTION = 14
LOCK_PATH = Path("/run/lock/haproxy-state-backup.lock")


class BackupRunError(RuntimeError):
    """The installation cannot start a trustworthy backup run."""


@dataclass(frozen=True, slots=True)
class FetchResult:
    exit_code: int
    stderr: str = ""


type Fetch = Callable[[Node, DeployIdentity, BinaryIO], FetchResult]


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

    process = subprocess.Popen(  # noqa: S603 - fixed command; validated config supplies target
        [
            SSH,
            *SSH_OPTIONS,
            "-i",
            str(identity.key),
            f"{identity.user}@{node.mgmt_host}",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=SSH_ENVIRONMENT,
    )
    if process.stdout is None or process.stderr is None:  # pragma: no cover - Popen contract
        process.kill()
        raise BackupRunError("ssh did not provide its output pipes")

    selected = selectors.DefaultSelector()
    selected.register(process.stdout, selectors.EVENT_READ, "stdout")
    selected.register(process.stderr, selectors.EVENT_READ, "stderr")
    deadline = monotonic() + timeout
    written = 0
    errors = bytearray()
    too_large = timed_out = False
    try:
        while selected.get_map():
            remaining = deadline - monotonic()
            if remaining <= 0:
                timed_out = True
                process.kill()
                break
            events = selected.select(min(remaining, 1.0))
            for key, _ in events:
                chunk = os.read(key.fd, 64 * 1024)
                if not chunk:
                    selected.unregister(key.fileobj)
                    continue
                if key.data == "stdout":
                    written += len(chunk)
                    if written > max_bytes:
                        too_large = True
                        process.kill()
                        break
                    destination.write(chunk)
                elif len(errors) < MAX_STDERR_BYTES:
                    errors.extend(chunk[: MAX_STDERR_BYTES - len(errors)])
            if too_large:
                break
    finally:
        selected.close()
        process.wait()
        process.stdout.close()
        process.stderr.close()

    if timed_out:
        return FetchResult(124, "the node state export timed out")
    if too_large:
        return FetchResult(65, "the node state export exceeded the archive size limit")
    return FetchResult(process.returncode, errors.decode("utf-8", errors="replace"))


def _commit_latest(directory: Path, archive: Path) -> None:
    temporary = directory / f".latest-{uuid4().hex}"
    temporary.symlink_to(archive.name)
    temporary.replace(directory / "latest")


def _retain(directory: Path, keep: int) -> None:
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
            fetched = fetch(node, identity, destination)
            destination.flush()
            os.fsync(destination.fileno())
        if fetched.exit_code != 0:
            return NodeResult(node.name, "failed", None, None, "node_export_failed")
        facts = validator(incoming)
        if facts.hostname != node.name:
            return NodeResult(node.name, "failed", None, None, "backup_node_mismatch")
        incoming.replace(final)
        _commit_latest(directory, final)
        _retain(directory, retention)
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
    *,
    fetch: Fetch = fetch_over_ssh,
    validator: Callable[[Path], ArchiveFacts] = validate,
    now: datetime | None = None,
    retention: int = RETENTION,
    lock_path: Path = LOCK_PATH,
) -> BackupResult:
    """Take a state archive from both configured nodes under one global lock."""

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

    version = (now or datetime.now(UTC)).astimezone(UTC).strftime("%Y-%m-%d_%H-%M-%S")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+b") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        nodes = tuple(
            _one_node(
                node,
                identity,
                root,
                version,
                fetch=fetch,
                validator=validator,
                retention=retention,
            )
            for node in cluster.nodes
        )
    return BackupResult(cluster=cluster_id, version=version, nodes=nodes)
