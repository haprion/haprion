from __future__ import annotations

import os
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path
from unittest import mock

from haproxy_mgmt import backup_retention, backup_schedule_write
from haproxy_mgmt.backup_schedule import Schedule


def recording(commands: list[tuple[str, ...]]) -> Callable[[tuple[str, ...]], int]:
    """A `run` that keeps each command and reports success."""

    def run(command: tuple[str, ...]) -> int:
        commands.append(command)
        return 0

    return run


class BackupScheduleWriteTests(unittest.TestCase):
    def test_a_daily_schedule_is_written_enabled_and_read_back(self) -> None:
        previous_umask = os.umask(0o077)  # as the socket helper runs
        self.addCleanup(os.umask, previous_umask)
        commands: list[tuple[str, ...]] = []
        states: list[dict[str, object]] = [
            {"known": True, "enabled": False, "active": False, "calendar": None},
            {
                "known": True,
                "enabled": True,
                "active": True,
                "calendar": "*-*-* 04:30:00",
            },
        ]
        readings = iter(states)
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            with (
                mock.patch.object(backup_schedule_write, "_private_directory", return_value=True),
                mock.patch.object(backup_retention, "_private_directory", return_value=True),
            ):
                result = backup_schedule_write.apply(
                    "alpha",
                    Schedule("04:30", retention=30),
                    True,
                    unit_root=root,
                    retention_root=root / "retention",
                    run=recording(commands),
                    read=lambda unit: next(readings),
                )
            dropin = root / "haproxy-state-backup@alpha.timer.d"
            content = (dropin / "schedule.conf").read_text()
            kept = backup_retention.read("alpha", root=root / "retention")
            # World-readable whatever umask the helper runs under: systemd's
            # loader complains about anything else on every query.
            self.assertEqual(oct(os.stat(dropin).st_mode & 0o777), "0o755")
            self.assertEqual(oct(os.stat(dropin / "schedule.conf").st_mode & 0o777), "0o644")

        self.assertEqual(result.time, "04:30")
        self.assertEqual(result.as_dict()["retention"], 30)
        self.assertEqual(kept, 30)
        self.assertIn("OnCalendar=*-*-* 04:30:00", content)
        self.assertEqual(
            [command[1] for command in commands], ["daemon-reload", "enable", "restart"]
        )

    def test_a_failed_readback_restores_the_previous_schedule_and_state(self) -> None:
        commands: list[tuple[str, ...]] = []
        before = {
            "known": True,
            "enabled": True,
            "active": True,
            "calendar": "*-*-* 05:00:00",
        }
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            dropin = root / "haproxy-state-backup@alpha.timer.d"
            dropin.mkdir()
            path = dropin / "schedule.conf"
            old = b"[Timer]\nOnCalendar=\nOnCalendar=*-*-* 05:00:00\n"
            path.write_bytes(old)
            retention_root = root / "retention"
            retention_root.mkdir()
            (retention_root / "alpha.json").write_bytes(b'{"retention":21}\n')
            with (
                mock.patch.object(backup_schedule_write, "_private_directory", return_value=True),
                mock.patch.object(backup_retention, "_private_directory", return_value=True),
                self.assertRaisesRegex(
                    backup_schedule_write.ScheduleWriteError, "requested timer state"
                ),
            ):
                backup_schedule_write.apply(
                    "alpha",
                    Schedule("06:15", retention=60),
                    False,
                    unit_root=root,
                    retention_root=retention_root,
                    run=recording(commands),
                    read=lambda unit: before,
                )

            self.assertEqual(path.read_bytes(), old)
            self.assertEqual(backup_retention.read("alpha", root=retention_root), 21)
        self.assertEqual([command[1] for command in commands].count("daemon-reload"), 2)
        self.assertEqual(commands[-2][1], "enable")
        self.assertEqual(commands[-1][1], "restart")

    def test_weekly_and_monthly_shapes_reach_the_drop_in(self) -> None:
        for requested, expected in (
            (
                Schedule("22:00", "weekly", ("Mon", "Wed", "Fri")),
                "OnCalendar=Mon,Wed,Fri *-*-* 22:00:00",
            ),
            (Schedule("01:15", "monthly", (), 28), "OnCalendar=*-*-28 01:15:00"),
        ):
            with self.subTest(expected=expected):
                content = self._apply(requested, expected.removeprefix("OnCalendar="))
                self.assertIn(expected, content)

    def _apply(self, requested: Schedule, observed: str) -> str:
        states: list[dict[str, object]] = [
            {"known": True, "enabled": False, "active": False, "calendar": None},
            {"known": True, "enabled": True, "active": True, "calendar": observed},
        ]
        readings = iter(states)
        with (
            tempfile.TemporaryDirectory() as raw,
            mock.patch.object(backup_schedule_write, "_private_directory", return_value=True),
            mock.patch.object(backup_retention, "_private_directory", return_value=True),
        ):
            root = Path(raw)
            backup_schedule_write.apply(
                "alpha",
                requested,
                True,
                unit_root=root,
                retention_root=root / "retention",
                run=lambda command: 0,
                read=lambda unit: next(readings),
            )
            return (root / "haproxy-state-backup@alpha.timer.d/schedule.conf").read_text()

    def test_only_a_bounded_schedule_and_cluster_id_are_accepted(self) -> None:
        for parameters in (
            {"time": "5:00"},
            {"time": "24:00"},
            {"time": "05:60"},
            {"time": "daily"},
            {"time": "05:00; reboot"},
            {"time": "05:00", "frequency": "hourly"},
            {"time": "05:00", "frequency": "weekly"},
            {"time": "05:00", "frequency": "weekly", "weekdays": ["Mon..Fri"]},
            {"time": "05:00", "frequency": "monthly", "day_of_month": 31},
            {"time": "05:00", "frequency": "monthly", "day_of_month": "7"},
            {"time": "05:00", "retention": 0},
            {"time": "05:00", "retention": 366},
            {"time": "05:00", "retention": True},
        ):
            with (
                self.subTest(parameters=parameters),
                self.assertRaises(backup_schedule_write.ScheduleWriteError),
            ):
                backup_schedule_write.schedule(parameters)
        with self.assertRaises(backup_schedule_write.ScheduleWriteError):
            backup_schedule_write.timer_unit("../alpha")

    def test_the_fields_the_frequency_does_not_use_are_dropped(self) -> None:
        daily = backup_schedule_write.schedule(
            {"time": "05:00", "frequency": "daily", "weekdays": ["Mon"], "day_of_month": 3}
        )
        self.assertEqual((daily.weekdays, daily.day_of_month), ((), None))
        weekly = backup_schedule_write.schedule(
            {"time": "05:00", "frequency": "weekly", "weekdays": ["Fri", "Mon", "Fri"]}
        )
        self.assertEqual(weekly.weekdays, ("Mon", "Fri"))
        self.assertEqual(weekly.calendar(), "Mon,Fri *-*-* 05:00:00")


if __name__ == "__main__":
    unittest.main()
