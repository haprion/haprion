"""Quick and exact reporting use the same partition catalogue, with an explicit count opt-in."""

from __future__ import annotations

import subprocess
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "install/platform/bin/haprion-retention"
FUNCTIONS = (
    "eval \"$(sed -n '/^log()/p;/^partition_report_query() {/,/^}/p;"
    '/^traffic_report() {/,/^}/p\' "$0")"; '
    "TRAFFIC_KEEP_DAYS=7; exact_count=$1; "
)


class RetentionReport(unittest.TestCase):
    def test_exact_count_is_opt_in_and_both_reports_label_their_numbers(self) -> None:
        for exact in ("0", "1"):
            result = subprocess.run(  # noqa: S603 - fixed Bash, repository functions
                [
                    "/bin/bash",
                    "-c",
                    FUNCTIONS  # noqa: S608 - fixed SQL inside a Bash test stub
                    + 'psql_as() { echo "$2" >&2; '
                    + "if [[ \"$2\" == 'select count(*) from traffic_log' ]]; "
                    + "then echo 13; else echo '12|1|8192 bytes'; fi; }; traffic_report traffic_log",
                    str(SCRIPT),
                    exact,
                ],
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertIn("8192 bytes, retention 7 day(s)", result.stdout)
            if exact == "1":
                self.assertIn("13 row(s) (exact)", result.stdout)
                self.assertIn("select count(*) from traffic_log", result.stderr)
            else:
                self.assertIn("12 row(s) (estimated)", result.stdout)
                self.assertIn("1 partition(s) without statistics", result.stdout)
                self.assertNotIn("select count(*) from traffic_log", result.stderr)

    def test_a_failed_catalogue_read_does_not_print_a_successful_report(self) -> None:
        result = subprocess.run(  # noqa: S603 - fixed Bash, repository functions
            [
                "/bin/bash",
                "-e",
                "-c",
                FUNCTIONS + "psql_as() { return 9; }; traffic_report traffic_log",
                str(SCRIPT),
                "0",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 9)
        self.assertEqual(result.stdout, "")
