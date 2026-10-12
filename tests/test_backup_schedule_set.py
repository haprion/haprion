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
