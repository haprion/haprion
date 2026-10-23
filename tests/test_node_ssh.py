"""A node's answer, read within a budget (code review 2026-10-22, 4-5, 5-5, 5-6; security review S2).

The child here is a local Python process in place of ssh: what is held is how
the manager reads, not how a node answers. A node is a machine the manager does
not control, so each case is an answer a hostile or broken one could give.
"""

from __future__ import annotations

import re
import subprocess
import sys
import unittest
from pathlib import Path
from time import monotonic

from haprion import exit_codes, node_ssh


def child(code: str) -> list[str]:
    return [sys.executable, "-I", "-c", code]


class AnAnswerIsReadWithinItsBudget(unittest.TestCase):
    def test_an_answer_is_read_as_text(self) -> None:
        completed = node_ssh.run_bounded(
            child("import sys; sys.stdout.write('{\"ok\": true}')"), timeout=10
        )
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(node_ssh.parse_json(completed.stdout), {"ok": True})

    def test_the_request_reaches_the_node_on_stdin(self) -> None:
        completed = node_ssh.run_bounded(
            child("import sys; sys.stdout.write(sys.stdin.read().upper())"),
            timeout=10,
            request="probe",
        )
        self.assertEqual(completed.stdout, "PROBE")

    def test_an_answer_over_the_budget_is_stopped_there(self) -> None:
        started = monotonic()
        completed = node_ssh.run_bounded(
            child("import sys\nwhile True: sys.stdout.write('x' * 65536)"),
            timeout=30,
            max_bytes=1024 * 1024,
        )
        self.assertLess(monotonic() - started, 10)
        self.assertEqual(completed.returncode, exit_codes.FAILED)
        self.assertEqual(completed.stdout, "")
        self.assertIn("more than 1048576 bytes", completed.stderr)

    def test_a_node_that_never_finishes_runs_out_of_time(self) -> None:
        started = monotonic()
        with self.assertRaises(subprocess.TimeoutExpired):
            node_ssh.run_bounded(child("import time; time.sleep(60)"), timeout=1)
        self.assertLess(monotonic() - started, 10)

    def test_bytes_that_are_not_utf8_are_a_bad_answer_not_an_exception(self) -> None:
        completed = node_ssh.run_bounded(
            child('import sys; sys.stdout.buffer.write(b\'{"x": "\\xff"}\')'), timeout=10
        )
        self.assertIn("\ufffd", completed.stdout)

    def test_the_exit_code_and_stderr_are_kept(self) -> None:
        completed = node_ssh.run_bounded(
            child("import sys; sys.stderr.write('refused'); sys.exit(65)"), timeout=10
        )
        self.assertEqual((completed.returncode, completed.stderr), (65, "refused"))


class AnyMalformedDocumentIsOneValueError(unittest.TestCase):
    def test_nesting_deeper_than_the_parser_goes(self) -> None:
        with self.assertRaises(ValueError):
            node_ssh.parse_json("[" * 200_000)

    def test_bytes_that_are_not_utf8(self) -> None:
        with self.assertRaises(ValueError):
            node_ssh.parse_json(b'{"x": "\xff"}')

    def test_not_json(self) -> None:
        with self.assertRaises(ValueError):
            node_ssh.parse_json("not json")


class TheOptionsAreOneSet(unittest.TestCase):
    def test_every_call_keeps_the_connection_alive_and_checks_the_host(self) -> None:
        argv = node_ssh.ssh_argv("/root/.ssh/key", "svc-app", "node-a", "status")
        self.assertEqual(argv[0], node_ssh.SSH)
        joined = " ".join(argv)
        for option in (
            "StrictHostKeyChecking=yes",
            "ServerAliveInterval=15",
            "ServerAliveCountMax=4",
            "ConnectTimeout=10",
        ):
            self.assertIn(option, joined)
        self.assertEqual(argv[-2:], ["svc-app@node-a", "status"])


class NoOtherCallBuildsItsOwn(unittest.TestCase):
    """The keep-alive of review 2026-10-03 I3 reached one copy of five; a sixth would repeat it."""

    OWN_SSH = re.compile(r'"/usr/bin/ssh"|BatchMode=yes|ServerAliveInterval')

    def test_only_node_ssh_names_ssh_or_its_options(self) -> None:
        base = Path(__file__).resolve().parents[1]
        found = [
            f"{path.relative_to(base)}:{number}"
            for root in (base / "src" / "haprion", base / "ui" / "src" / "haprion_ui")
            for path in sorted(root.rglob("*.py"))
            if path.name != "node_ssh.py"
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
            if self.OWN_SSH.search(line)
        ]
        self.assertEqual(found, [], "build the call with haprion.node_ssh.ssh_argv")


if __name__ == "__main__":
    unittest.main()
