"""How many state archives each node of a cluster keeps.

The count is not a systemd fact and it is not a policy fact either: the policy
is root-installed by hand and this is something an administrator changes from
the Backups page with the schedule. So it lives in one small root-owned file
per cluster, next to the runtime policy, read by whoever prunes - the timer's
service, the socket helper behind *Back up now*, and the break-glass
``sudo haproxy-state-backup``. One reader for all three, because a manual run
that pruned to the code's default would delete what the schedule promised to
keep.

Absent file means the default. A file that is present but unreadable is an
error, not the default: pruning is destructive, and "I could not tell how many
to keep, so I kept fourteen" is exactly the guess a backup tool must not make.
"""

from __future__ import annotations

import json
import os
import stat
from contextlib import suppress
from pathlib import Path
from uuid import uuid4

from haproxy_mgmt.config import CLUSTER_ID

RETENTION_ROOT = Path("/etc/haproxy-manager/backup-retention")
#
# Fourteen daily archives per node cover two weeks. It is the default a cluster
# has before anyone sets one, and the value the fleet-wide script always used.
#
DEFAULT_RETENTION = 14
RETENTION_MIN = 1
RETENTION_MAX = 365
MAX_FILE_BYTES = 4096


class RetentionError(ValueError):
    """The retention file is present and cannot be trusted."""


def bounded(value: object) -> int:
    """The count as the contract allows it, or an error naming the bound."""

    if type(value) is not int or not RETENTION_MIN <= value <= RETENTION_MAX:
        raise RetentionError(
            f"retention must be a whole number of archives from {RETENTION_MIN} to {RETENTION_MAX}"
        )
    return value


def path(cluster_id: str, *, root: Path = RETENTION_ROOT) -> Path:
    if not CLUSTER_ID.fullmatch(cluster_id):
        raise RetentionError("cluster is not a valid cluster ID")
    return root / f"{cluster_id}.json"


def read(cluster_id: str, *, root: Path = RETENTION_ROOT) -> int:
    """The cluster's retention, or the default when none has been set."""

    file = path(cluster_id, root=root)
    try:
        details = file.lstat()
    except FileNotFoundError:
        return DEFAULT_RETENTION
    except OSError as exc:
        raise RetentionError(f"the backup retention file could not be read: {exc}") from exc
    if not stat.S_ISREG(details.st_mode) or details.st_size > MAX_FILE_BYTES:
        raise RetentionError("the backup retention file is not a small regular file")
    try:
        document = json.loads(file.read_bytes().decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RetentionError("the backup retention file is not valid JSON") from exc
    if not isinstance(document, dict):
        raise RetentionError("the backup retention file is not a JSON object")
    return bounded(document.get("retention"))


def _private_directory(directory: Path) -> bool:
    try:
        details = directory.lstat()
    except OSError:
        return False
    return (
        stat.S_ISDIR(details.st_mode)
        and details.st_uid == 0
        and stat.S_IMODE(details.st_mode) & 0o022 == 0
    )


def write(cluster_id: str, retention: int, *, root: Path = RETENTION_ROOT) -> bytes | None:
    """Record the count atomically; returns the previous content for a rollback."""

    file = path(cluster_id, root=root)
    root.mkdir(mode=0o755, exist_ok=True)
    if not _private_directory(root):
        raise RetentionError("the backup retention directory is not root-owned and private")
    os.chmod(root, 0o755)  # noqa: S103 - root-owned; the helper's umask would leave it 0700
    if file.is_symlink():
        raise RetentionError("the backup retention file is a symlink")
    previous = file.read_bytes() if file.exists() else None
    content = json.dumps({"retention": bounded(retention)}, separators=(",", ":")).encode() + b"\n"
    restore(file, content)
    return previous


def restore(file: Path, content: bytes | None) -> None:
    """Put exactly this content in place, or remove the file for None."""

    if content is None:
        file.unlink(missing_ok=True)
        return
    temporary = file.parent / f".{file.name}.{uuid4().hex}"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(file)
        directory = os.open(file.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        with suppress(FileNotFoundError):
            temporary.unlink()
