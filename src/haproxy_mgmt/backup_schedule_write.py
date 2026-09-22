"""Write one cluster's bounded backup schedule and verify systemd readback."""

from __future__ import annotations

import os
import stat
import subprocess
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from haproxy_mgmt import backup_retention
from haproxy_mgmt.backup_schedule import Schedule, ScheduleError, parse_schedule, schedule_result
from haproxy_mgmt.config import CLUSTER_ID

SYSTEMCTL = "/usr/bin/systemctl"
UNIT_ROOT = Path("/etc/systemd/system")


class ScheduleWriteError(RuntimeError):
    """The requested schedule was invalid or could not be committed."""


@dataclass(frozen=True, slots=True)
class Result:
    cluster: str
    requested: Schedule
    enabled: bool
    schedule: dict[str, object]

    @property
    def time(self) -> str:
        return self.requested.time

    def as_dict(self) -> dict[str, object]:
        return {
            "cluster": self.cluster,
            **self.requested.as_dict(),
            "enabled": self.enabled,
            "schedule": self.schedule,
        }


type Run = Callable[[tuple[str, ...]], int]
type Read = Callable[[str], dict[str, object] | None]


def timer_unit(cluster_id: str) -> str:
    if not CLUSTER_ID.fullmatch(cluster_id):
        raise ScheduleWriteError("cluster is not a valid cluster ID")
    return f"haproxy-state-backup@{cluster_id}.timer"


def schedule(parameters: Mapping[str, object]) -> Schedule:
    """The bounded request, refused as a write error so callers see one kind."""

    try:
        return parse_schedule(parameters)
    except ScheduleError as exc:
        raise ScheduleWriteError(str(exc)) from exc


def _run(command: tuple[str, ...]) -> int:
    completed = subprocess.run(command, check=False)  # noqa: S603 - fixed systemctl argv
    return completed.returncode


def _read(unit: str) -> dict[str, object] | None:
    return schedule_result(unit)


def _private_directory(path: Path) -> bool:
    try:
        details = path.lstat()
    except OSError:
        return False
    return (
        stat.S_ISDIR(details.st_mode)
        and not path.is_symlink()
        and details.st_uid == 0
        and stat.S_IMODE(details.st_mode) & 0o022 == 0
    )


def _write(path: Path, content: bytes) -> None:
    temporary = path.parent / f".{path.name}.{uuid4().hex}"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        with suppress(FileNotFoundError):
            temporary.unlink()


def _command(run: Run, *arguments: str) -> None:
    if run((SYSTEMCTL, *arguments)) != 0:
        raise ScheduleWriteError(f"systemctl {arguments[0]} failed")


def apply(
    cluster_id: str,
    requested: Schedule,
    enabled: bool,
    *,
    unit_root: Path = UNIT_ROOT,
    retention_root: Path = backup_retention.RETENTION_ROOT,
    run: Run = _run,
    read: Read = _read,
) -> Result:
    """Commit a schedule on the manager's clock, rolling every file and the enablement back on any error."""

    expression = requested.calendar()
    unit = timer_unit(cluster_id)
    #
    # The retention count is written first and rolled back last: it has no
    # readback of its own, so it is only ever left in place when systemd has
    # confirmed the schedule it was asked for alongside.
    #
    try:
        previous_retention = backup_retention.write(
            cluster_id, requested.retention, root=retention_root
        )
    except (OSError, backup_retention.RetentionError) as exc:
        raise ScheduleWriteError(str(exc)) from exc
    try:
        return _apply_timer(cluster_id, requested, enabled, expression, unit, unit_root, run, read)
    except ScheduleWriteError as exc:
        try:
            backup_retention.restore(
                backup_retention.path(cluster_id, root=retention_root), previous_retention
            )
        except (OSError, backup_retention.RetentionError) as rollback:
            raise ScheduleWriteError(f"{exc}; retention rollback failed: {rollback}") from exc
        raise


def _apply_timer(
    cluster_id: str,
    requested: Schedule,
    enabled: bool,
    expression: str,
    unit: str,
    unit_root: Path,
    run: Run,
    read: Read,
) -> Result:
    dropin = unit_root / f"{unit}.d"
    dropin.mkdir(mode=0o755, exist_ok=True)
    if not _private_directory(dropin):
        raise ScheduleWriteError("the timer drop-in directory is not root-owned and private")
    #
    # Explicitly, and after the ownership check: the helper runs under
    # `UMask=0077` and `mkdir`'s mode is filtered through it. systemd reads a
    # 0700 drop-in directory fine and says so in the journal on every load,
    # which is noise an operator will go looking for the cause of.
    #
    os.chmod(dropin, 0o755)  # noqa: S103 - root-owned unit drop-in, like its siblings
    path = dropin / "schedule.conf"
    if path.is_symlink():
        raise ScheduleWriteError("the timer schedule is a symlink")
    previous = path.read_bytes() if path.exists() else None
    before = read(unit) or {}
    content = f"[Timer]\nOnCalendar=\nOnCalendar={expression}\n".encode()

    try:
        _write(path, content)
        _command(run, "daemon-reload")
        if enabled:
            _command(run, "enable", "--now", unit)
            _command(run, "restart", unit)
        else:
            _command(run, "disable", "--now", unit)
        observed = read(unit) or {}
        if observed.get("known") is not True:
            raise ScheduleWriteError("systemd did not load the cluster timer")
        if observed.get("enabled") is not enabled or observed.get("active") is not enabled:
            raise ScheduleWriteError("systemd did not enter the requested timer state")
        if observed.get("calendar") != expression:
            raise ScheduleWriteError("systemd did not read back the requested calendar")
        return Result(cluster_id, requested, enabled, observed)
    except (OSError, ScheduleWriteError) as exc:
        try:
            if previous is None:
                path.unlink(missing_ok=True)
            else:
                _write(path, previous)
            _command(run, "daemon-reload")
            if before.get("enabled") is True:
                _command(run, "enable", "--now", unit)
                _command(run, "restart", unit)
            else:
                _command(run, "disable", "--now", unit)
        except (OSError, ScheduleWriteError) as rollback:
            raise ScheduleWriteError(f"{exc}; rollback failed: {rollback}") from exc
        raise ScheduleWriteError(str(exc)) from exc
