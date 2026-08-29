"""Reading the backup timer from systemd, without ever changing it.

The listing beside this cannot tell a directory that is still being filled from
one a broken timer stopped adding to, so the timer is read as well. These tests
use systemd's real `systemctl show` output shapes, including the ones that only
appear when something is wrong.
"""

from __future__ import annotations

import unittest

from haproxy_mgmt.backup_schedule import (
    SYSTEMCTL,
    ScheduleError,
    _run,
    schedule_result,
)

TIMER = "haproxy-state-backup.timer"

#
# Copied from a real `systemctl show --timestamp=unix` on a manager, with the
# unit renamed. A hand-written approximation would test the parser against
# itself.
#
LOADED = {
    "LoadState": "loaded",
    "UnitFileState": "enabled",
    "ActiveState": "active",
    "TimersCalendar": "{ OnCalendar=*-*-* 05:00:00 ; next_elapse=Sun 2026-08-30 05:00:00 CEST }",
    "NextElapseUSecRealtime": "@1788058800",
    "LastTriggerUSec": "@1787972440",
    "Unit": "haproxy-state-backup.service",
}


def reader(timer: dict[str, str], service: dict[str, str] | None = None):
    asked: list[tuple[str, tuple[str, ...]]] = []

    def show(unit: str, properties: tuple[str, ...]) -> dict[str, str]:
        asked.append((unit, properties))
        return timer if unit.endswith(".timer") else (service or {})

    return show, asked


class ScheduleTests(unittest.TestCase):
    def test_an_installation_without_a_timer_answers_null_rather_than_failing(self) -> None:
        #
        # Not every deployment backs up on a schedule. A command that failed
        # because a key it does not need is absent would be worse than one that
        # says nothing about it.
        #
        show, asked = reader({})

        self.assertIsNone(schedule_result(None, show=show))
        self.assertEqual(asked, [])

    def test_a_running_timer_reports_its_calendar_and_both_ends_of_its_run(self) -> None:
        show, _ = reader(LOADED, {"Result": "success"})
        schedule = schedule_result(TIMER, show=show)
        assert schedule is not None

        self.assertTrue(schedule["known"])
        self.assertTrue(schedule["enabled"])
        self.assertTrue(schedule["active"])
        self.assertEqual(schedule["calendar"], "*-*-* 05:00:00")
        self.assertEqual(schedule["last_run"], "2026-08-29T03:00:40Z")
        self.assertEqual(schedule["next_run"], "2026-08-30T03:00:00Z")
        self.assertEqual(schedule["last_result"], "success")

    def test_the_run_that_failed_is_read_from_the_service_not_the_timer(self) -> None:
        #
        # A timer that fires every night into a service that fails every night
        # is the state this exists to make visible, and the timer alone looks
        # perfectly healthy in it.
        #
        show, _ = reader(LOADED, {"Result": "exit-code"})
        schedule = schedule_result(TIMER, show=show)
        assert schedule is not None

        self.assertTrue(schedule["active"])
        self.assertEqual(schedule["last_result"], "exit-code")

    def test_a_timer_systemd_does_not_know_is_an_answer_not_an_error(self) -> None:
        show, _ = reader({"LoadState": "not-found"})
        schedule = schedule_result(TIMER, show=show)
        assert schedule is not None

        self.assertFalse(schedule["known"])
        self.assertFalse(schedule["enabled"])
        self.assertIsNone(schedule["calendar"])
        self.assertIsNone(schedule["last_run"])

    def test_a_disabled_timer_is_reported_as_disabled_rather_than_absent(self) -> None:
        show, _ = reader({**LOADED, "UnitFileState": "disabled", "ActiveState": "inactive"})
        schedule = schedule_result(TIMER, show=show)
        assert schedule is not None

        self.assertTrue(schedule["known"])
        self.assertFalse(schedule["enabled"])
        self.assertFalse(schedule["active"])
        self.assertEqual(schedule["calendar"], "*-*-* 05:00:00")

    def test_a_timer_that_has_never_fired_reports_no_last_run(self) -> None:
        # systemd reports an event that has not happened as epoch zero.
        show, _ = reader({**LOADED, "LastTriggerUSec": "@0"})
        schedule = schedule_result(TIMER, show=show)
        assert schedule is not None

        self.assertIsNone(schedule["last_run"])
        self.assertEqual(schedule["next_run"], "2026-08-30T03:00:00Z")

    def test_a_name_that_is_not_a_unit_name_never_reaches_an_argv(self) -> None:
        for unit in (
            "haproxy-state-backup.service",
            "../../etc/passwd.timer",
            "backup.timer; rm -rf /",
            "backup timer.timer",
            "",
        ):
            with self.subTest(unit=unit):
                show, asked = reader(LOADED)
                with self.assertRaises(ScheduleError):
                    schedule_result(unit, show=show)
                self.assertEqual(asked, [])


class CommandShapeTests(unittest.TestCase):
    def test_systemd_is_asked_for_properties_and_nothing_else(self) -> None:
        #
        # `show` reports and changes nothing. This is the whole reason the read
        # is allowed to live in a root helper, so the shape of the command is
        # pinned rather than left to a later edit.
        #
        captured: dict[str, object] = {}

        def fake_run(command, **kwargs):  # type: ignore[no-untyped-def]
            captured["command"] = command
            captured["kwargs"] = kwargs
            return type("Completed", (), {"stdout": "LoadState=loaded\n", "returncode": 0})

        import haproxy_mgmt.backup_schedule as module

        original = module.subprocess.run
        module.subprocess.run = fake_run  # type: ignore[assignment]
        try:
            values = _run(TIMER, ("LoadState",))
        finally:
            module.subprocess.run = original  # type: ignore[assignment]

        self.assertEqual(values, {"LoadState": "loaded"})
        self.assertEqual(
            captured["command"],
            [SYSTEMCTL, "show", TIMER, "--timestamp=unix", "--property=LoadState"],
        )
        self.assertIn("timeout", captured["kwargs"])

    def test_a_systemctl_that_cannot_be_run_is_an_empty_reading(self) -> None:
        def fake_run(command, **kwargs):  # type: ignore[no-untyped-def]
            raise OSError("no such binary")

        import haproxy_mgmt.backup_schedule as module

        original = module.subprocess.run
        module.subprocess.run = fake_run  # type: ignore[assignment]
        try:
            values = _run(TIMER, ("LoadState",))
        finally:
            module.subprocess.run = original  # type: ignore[assignment]

        self.assertEqual(values, {})
        # An empty reading is "systemd does not know this unit", which is the
        # honest answer when the query itself could not be made.
        self.assertFalse(schedule_result(TIMER, show=lambda *_: {})["known"])  # type: ignore[index]


if __name__ == "__main__":
    unittest.main()
