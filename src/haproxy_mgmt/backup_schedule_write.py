"""Write one cluster's bounded daily backup schedule and verify systemd readback."""

from __future__ import annotations

import os
import re
import stat
import subprocess
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from haproxy_mgmt.backup_schedule import schedule_result
from haproxy_mgmt.config import CLUSTER_ID

SYSTEMCTL = "/usr/bin/systemctl"
UNIT_ROOT = Path("/etc/systemd/system")
TIME = re.compile(r"^(?P<hour>[01][0-9]|2[0-3]):(?P<minute>[0-5][0-9])$")


class ScheduleWriteError(RuntimeError):
    """The requested schedule was invalid or could not be committed."""


@dataclass(frozen=True, slots=True)
class Result:
    cluster: str
    time: str
    enabled: bool
    schedule: dict[str, object]

    def as_dict(self) -> dict[str, object]:
        return {
            "cluster": self.cluster,
            "time": self.time,
            "enabled": self.enabled,
            "schedule": self.schedule,
        }


type Run = Callable[[tuple[str, ...]], int]
type Read = Callable[[str], dict[str, object] | None]


def timer_unit(cluster_id: str) -> str:
    if not CLUSTER_ID.fullmatch(cluster_id):
        raise ScheduleWriteError("cluster is not a valid cluster ID")
    return f"haproxy-state-backup@{cluster_id}.timer"


def calendar(value: str) -> str:
    matched = TIME.fullmatch(value)
    if matched is None:
        raise ScheduleWriteError("time must be HH:MM on the manager's clock")
    #
    # No zone suffix on purpose: systemd then reads the expression in the
    # manager's own zone, which is the clock every other timer on the machine
    # and the journal keep. A schedule in UTC would be the one time on the host
    # an operator had to convert before comparing it with anything else.
    #
    return f"*-*-* {matched.group('hour')}:{matched.group('minute')}:00"


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
    value: str,
    enabled: bool,
    *,
    unit_root: Path = UNIT_ROOT,
    run: Run = _run,
    read: Read = _read,
) -> Result:
    """Commit a daily local time, rolling the file and enablement back on any error."""

    expression = calendar(value)
    unit = timer_unit(cluster_id)
    dropin = unit_root / f"{unit}.d"
    dropin.mkdir(mode=0o755, exist_ok=True)
    if not _private_directory(dropin):
        raise ScheduleWriteError("the timer drop-in directory is not root-owned and private")
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
        return Result(cluster_id, value, enabled, observed)
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
