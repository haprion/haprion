from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from haproxy_mgmt import backup_schedule_write


class BackupScheduleWriteTests(unittest.TestCase):
    def test_a_daily_utc_schedule_is_written_enabled_and_read_back(self) -> None:
        commands: list[tuple[str, ...]] = []
        readings = iter(
            (
                {"known": True, "enabled": False, "active": False, "calendar": None},
                {
                    "known": True,
                    "enabled": True,
                    "active": True,
                    "calendar": "*-*-* 04:30:00",
                },
            )
        )
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            with mock.patch.object(backup_schedule_write, "_private_directory", return_value=True):
                result = backup_schedule_write.apply(
                    "alpha",
                    "04:30",
                    True,
                    unit_root=root,
                    run=lambda command: commands.append(command) or 0,
                    read=lambda unit: next(readings),
                )
            content = (root / "haproxy-state-backup@alpha.timer.d/schedule.conf").read_text()

        self.assertEqual(result.time, "04:30")
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
            with (
                mock.patch.object(backup_schedule_write, "_private_directory", return_value=True),
                self.assertRaisesRegex(
                    backup_schedule_write.ScheduleWriteError, "requested timer state"
                ),
            ):
                backup_schedule_write.apply(
                    "alpha",
                    "06:15",
                    False,
                    unit_root=root,
                    run=lambda command: commands.append(command) or 0,
                    read=lambda unit: before,
                )

            self.assertEqual(path.read_bytes(), old)
        self.assertEqual([command[1] for command in commands].count("daemon-reload"), 2)
        self.assertEqual(commands[-2][1], "enable")
        self.assertEqual(commands[-1][1], "restart")

    def test_only_a_clock_time_and_cluster_id_are_accepted(self) -> None:
        for value in ("5:00", "24:00", "05:60", "daily", "05:00; reboot"):
            with (
                self.subTest(value=value),
                self.assertRaises(backup_schedule_write.ScheduleWriteError),
            ):
                backup_schedule_write.calendar(value)
        with self.assertRaises(backup_schedule_write.ScheduleWriteError):
            backup_schedule_write.timer_unit("../alpha")


if __name__ == "__main__":
    unittest.main()
