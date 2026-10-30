"""``haprion-backup-schedule``: one cluster's backup schedule from the terminal (Fas 23).

The service's write and readback are held in its own tests; this holds when
the command asks it at all - only where the timer or the retention differ -
and what it answers, against `schemas/v1/haprion-backup-schedule`.
"""

from __future__ import annotations

import io
import json
import unittest
from typing import Any

from haprion import exit_codes
from haprion.cli import backup_schedule_set
from tests.contract_schema import assert_contract

TIMER = {
    "unit": "haprion-state-backup@alpha.timer",
    "known": True,
    "enabled": True,
    "active": True,
    "calendar": "Mon,Thu *-*-* 03:30:00",
    "next_run": None,
    "last_run": None,
    "last_result": None,
    "scheduled": True,
}


class TheScheduleCommand(unittest.TestCase):
    def run_command(
        self, *argv: str, timer: dict[str, Any] | None = None, retention: int = 14
    ) -> tuple[int, str, list[dict[str, Any]]]:
        asked: list[dict[str, Any]] = []

        def ask(request: dict[str, Any]) -> str:
            asked.append(request)
            parameters = request["parameters"]
            return json.dumps(
                {
                    "schema_version": 1,
                    "ok": True,
                    "outcome": "done",
                    "operation": "backup_schedule",
                    "cluster": request["cluster"],
                    "request_id": request["request_id"],
                    "result": {
                        "cluster": request["cluster"],
                        **{key: value for key, value in parameters.items() if key != "enabled"},
                        "enabled": parameters["enabled"],
                        "schedule": TIMER,
                    },
                    "warnings": [],
                    "error": None,
                }
            )

        out = io.StringIO()
        code = backup_schedule_set.main(
            ["-c", "alpha", *argv],
            ask=ask,
            read=lambda _cluster: (TIMER if timer is None else timer, retention),
            stream_out=out,
            stream_err=io.StringIO(),
            require_root=False,
        )
        return code, out.getvalue(), asked

    def test_a_service_that_went_silent_is_an_unknown_outcome_not_unavailable(self) -> None:
        """Review 26-10-24, 06-11: the timer may have been written; a document said it failed."""

        from haprion import helper_socket

        def silent(_request: dict[str, Any]) -> str:
            raise helper_socket.HelperSilent("the backup service took the request and went quiet.")

        for asked in (silent, lambda _request: ""):
            with self.subTest(asked=asked):
                out, err = io.StringIO(), io.StringIO()
                code = backup_schedule_set.main(
                    ["-c", "alpha", "--time", "04:00", "--weekly", "Mon", "--json"],
                    ask=asked,
                    read=lambda _cluster: (TIMER, 14),
                    stream_out=out,
                    stream_err=err,
                    require_root=False,
                )
                self.assertEqual(code, exit_codes.FAILED)
                answer = assert_contract("haprion-backup-schedule", out.getvalue())
                self.assertEqual(answer["error"]["code"], "helper_silent")
                self.assertIn("[helper_silent]", err.getvalue())
                self.assertIn("outcome is unknown", err.getvalue())
                self.assertIn("haprion-backup-schedule -c alpha", err.getvalue())

        def gone(_request: dict[str, Any]) -> str:
            raise helper_socket.HelperUnavailable("the backup service is not running.")

        out = io.StringIO()
        code = backup_schedule_set.main(
            ["-c", "alpha", "--time", "04:00", "--weekly", "Mon", "--json"],
            ask=gone,
            read=lambda _cluster: (TIMER, 14),
            stream_out=out,
            stream_err=io.StringIO(),
            require_root=False,
        )
        self.assertEqual(code, exit_codes.UNAVAILABLE)
        self.assertEqual(
            assert_contract("haprion-backup-schedule", out.getvalue())["outcome"], "failed"
        )

    def test_as_asked_is_no_change_and_asks_nothing(self) -> None:
        code, out, asked = self.run_command(
            "--time", "03:30", "--weekly", "Thu,Mon", "--retention", "14", "--json"
        )

        self.assertEqual((code, asked), (0, []))
        answer = assert_contract("haprion-backup-schedule", out)
        self.assertFalse(answer["result"]["changed"])

    def test_another_time_or_retention_asks_the_service(self) -> None:
        for argv, retention in (
            (("--time", "04:00", "--weekly", "Mon,Thu"), 14),
            (("--time", "03:30", "--weekly", "Mon,Thu", "--retention", "7"), 14),
            (("--time", "03:30", "--weekly", "Mon,Thu", "--disable"), 14),
        ):
            with self.subTest(argv):
                code, out, asked = self.run_command(*argv, "--json", retention=retention)

                self.assertEqual((code, len(asked)), (0, 1))
                self.assertTrue(
                    assert_contract("haprion-backup-schedule", out)["result"]["changed"]
                )

    def test_a_left_out_retention_keeps_the_number_in_force(self) -> None:
        """Review 26-10-24, 15-01: it became 14, and the next run removed the older archives."""

        code, out, asked = self.run_command(
            "--time", "03:30", "--weekly", "Mon,Thu", "--json", retention=60
        )

        self.assertEqual((code, asked), (0, []))
        answer = assert_contract("haprion-backup-schedule", out)
        self.assertEqual((answer["result"]["changed"], answer["result"]["retention"]), (False, 60))

    def test_disable_alone_keeps_the_schedule_and_the_retention(self) -> None:
        code, out, asked = self.run_command("--disable", "--json", retention=30)

        self.assertEqual(code, 0, out)
        (request,) = asked
        self.assertEqual(request["parameters"]["enabled"], False)
        self.assertEqual(request["parameters"]["frequency"], "weekly")
        self.assertEqual(request["parameters"]["weekdays"], ["Mon", "Thu"])
        self.assertEqual(request["parameters"]["retention"], 30)

    def test_without_time_or_disable_nothing_is_asked(self) -> None:
        code, _, asked = self.run_command("--weekly", "Mon")

        self.assertEqual((code, asked), (64, []))

    def test_check_asks_nothing(self) -> None:
        code, out, asked = self.run_command("--time", "05:00", "--check")

        self.assertEqual((code, asked), (0, []))
        self.assertIn("would set", out)

    def test_a_bad_schedule_is_refused_before_anything_is_read(self) -> None:
        code, out, asked = self.run_command("--time", "03:30", "--monthly", "31", "--json")

        self.assertEqual((code, asked), (64, []))
        self.assertIn(
            "day_of_month", assert_contract("haprion-backup-schedule", out)["error"]["message"]
        )


if __name__ == "__main__":
    unittest.main()
