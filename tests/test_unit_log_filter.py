"""The one sudo line the worker and the poller drop from their journal (review 26-10-13).

A unit that runs sudo (NoNewPrivileges=no) behind ProtectProc=invisible makes
sudo-rs warn on every call that it cannot read its parent's start time. The
units drop that exact line with LogFilterPatterns and nothing else, so the
filter cannot quietly grow into one that hides what sudo refuses.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

EXAMPLES = Path(__file__).resolve().parents[1] / "install" / "platform" / "examples"
FILTER = "LogFilterPatterns=~^Could not get parent process starting time$"
WARNING = "Could not get parent process starting time"


def directives(text: str, name: str) -> list[str]:
    return [line for line in text.splitlines() if line.startswith(f"{name}=")]


class TheSudoWarningIsDroppedAndNothingElse(unittest.TestCase):
    def units(self) -> dict[str, str]:
        return {path.name: path.read_text() for path in sorted(EXAMPLES.glob("*.service.example"))}

    def test_every_unit_that_runs_sudo_behind_hidden_processes_drops_the_line(self) -> None:
        callers = [
            name
            for name, text in self.units().items()
            if "NoNewPrivileges=no" in directives(text, "NoNewPrivileges")
            and "ProtectProc=invisible" in directives(text, "ProtectProc")
        ]
        self.assertEqual(
            callers, ["haprion-poller.service.example", "haprion-worker.service.example"]
        )
        for name in callers:
            with self.subTest(unit=name):
                self.assertEqual(directives(self.units()[name], "LogFilterPatterns"), [FILTER])

    def test_no_other_unit_filters_its_journal(self) -> None:
        for name, text in self.units().items():
            if name in ("haprion-poller.service.example", "haprion-worker.service.example"):
                continue
            with self.subTest(unit=name):
                self.assertEqual(directives(text, "LogFilterPatterns"), [])

    def test_the_pattern_matches_the_warning_and_not_its_neighbours(self) -> None:
        pattern = re.compile(FILTER.split("=~", 1)[1])
        self.assertTrue(pattern.search(WARNING))
        for other in (
            "Could not get terminal foreground process starting time",
            "Could not get parent process starting time: and something else",
            "authentication failure; Could not get parent process starting time",
            "_haprion-poller : command not allowed",
        ):
            with self.subTest(message=other):
                self.assertIsNone(pattern.search(other))


if __name__ == "__main__":
    unittest.main()
