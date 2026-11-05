"""`haprion-retention horizon` makes the partitions ahead and removes nothing (review 2026-10-22, 3-2).

Run by bash with its root check and configuration directory pointed at a scratch
tree, and `psql` replaced by a stub that records every statement. Step 11 and
every update run this; a statement that deleted anything there would delete on
the way past, which the installer promises it does not.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "install" / "platform" / "bin" / "haprion-retention"

#
# Every table exists; every count is nought.
#
PSQL_STUB = """#!/bin/sh
for argument; do printf '%s\\n---\\n' "$argument" >> "$RECORD"; done
case "$*" in
    *to_regclass*) echo t ;;
    *) for argument; do [ "$argument" = -c ] && echo 0; done ;;
esac
exit 0
"""


class TheHorizonRemovesNothing(unittest.TestCase):
    def test_partitions_are_made_ahead_and_nothing_is_dropped_or_deleted(self) -> None:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        (root / "ui-admin.conf").write_text("DB_NAME=haprion\nDB_ROLE=haprion\n")
        psql = root / "psql"
        psql.write_text(PSQL_STUB)
        psql.chmod(0o755)
        script = root / "haprion-retention"
        text = SCRIPT.read_text()
        for old, new in (
            ("CONFIG_DIRECTORY=/etc/haprion", f"CONFIG_DIRECTORY={root}"),
            ('[[ $EUID -eq 0 ]] || die "run this with sudo"', ":"),
        ):
            self.assertIn(old, text)
            text = text.replace(old, new)
        script.write_text(text)
        record = root / "record"

        done = subprocess.run(
            ["/bin/bash", str(script), "horizon"],
            capture_output=True,
            text=True,
            env={"PATH": f"{root}:/usr/bin:/bin", "RECORD": str(record)},
            check=False,
            timeout=60,
        )

        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        statements = record.read_text().lower()
        self.assertIn("metric_partition(", statements)
        self.assertIn("traffic_log_partition(", statements)
        self.assertIn("waf_match_partition(", statements)
        for word in ("drop ", "delete ", "truncate "):
            self.assertNotIn(word, statements)


#
# The traffic and WAF partitions hold 10^15 bytes, far over a quarter of any
# volume this runs on, in four finished days of 4 x 10^14: three go, oldest
# first, and the fourth leaves them under.
#
BUDGET_PSQL_STUB = """#!/bin/sh
for argument; do printf '%s\\n---\\n' "$argument" >> "$RECORD"; done
case "$*" in
    *"group by 1"*) printf '20260901|400000000000000\\n20260902|400000000000000\\n20260903|400000000000000\\n20260904|400000000000000\\n' ;;
    *pg_total_relation_size*) echo 1000000000000000 ;;
    *) for argument; do [ "$argument" = -c ] && echo 0; done ;;
esac
exit 0
"""
SUDO_STUB = """#!/bin/sh
echo "$DATA_DIRECTORY"
"""


class TheBudgetDropsTheOldestFinishedDays(unittest.TestCase):
    """B356: the retention is days, and a flood fills the volume within them."""

    def run_budget(self, *arguments: str) -> tuple[subprocess.CompletedProcess[str], str]:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        (root / "ui-admin.conf").write_text("DB_NAME=haprion\nDB_ROLE=haprion\n")
        for name, stub in (("psql", BUDGET_PSQL_STUB), ("sudo", SUDO_STUB)):
            (root / name).write_text(stub)
            (root / name).chmod(0o755)
        script = root / "haprion-retention"
        text = SCRIPT.read_text()
        for old, new in (
            ("CONFIG_DIRECTORY=/etc/haprion", f"CONFIG_DIRECTORY={root}"),
            # Never the machine's own: this may run as root on a manager.
            (
                "STAGING_DIRECTORY=/var/lib/haprion-ui/logs/staging",
                f"STAGING_DIRECTORY={root}/none",
            ),
            ('[[ $EUID -eq 0 ]] || die "run this with sudo"', ":"),
        ):
            self.assertIn(old, text)
            text = text.replace(old, new)
        script.write_text(text)
        record = root / "record"
        done = subprocess.run(
            ["/bin/bash", str(script), "budget", *arguments],
            capture_output=True,
            text=True,
            env={
                "PATH": f"{root}:/usr/bin:/bin",
                "RECORD": str(record),
                "DATA_DIRECTORY": str(root),
            },
            check=False,
            timeout=60,
        )
        return done, record.read_text()

    def test_over_its_share_the_oldest_days_go_with_both_tables(self) -> None:
        done, statements = self.run_budget()

        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        dropped = re.findall(r'drop table if exists "([a-z_]+_[0-9]{8})"', statements)
        self.assertEqual(
            dropped,
            [
                f"{table}_{day}"
                for day in ("20260901", "20260902", "20260903")
                for table in ("traffic_log", "waf_match")
            ],
        )
        self.assertEqual(done.stderr.count("before their time"), 3)
        self.assertIn("< current_date", statements)

    def test_a_dry_run_drops_nothing(self) -> None:
        done, statements = self.run_budget("--dry-run")

        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertNotIn("drop ", statements.lower())
        self.assertEqual(done.stdout.count("would go before its time"), 3)


#
# No finished day is left to drop, and today's partitions alone are over their
# share, or they are not.
#
TODAY_ONLY_PSQL_STUB = """#!/bin/sh
for argument; do printf '%s\\n---\\n' "$argument" >> "$RECORD"; done
case "$*" in
    *"group by 1"*) ;;
    *pg_total_relation_size*) echo "$HELD" ;;
    *) for argument; do [ "$argument" = -c ] && echo 0; done ;;
esac
exit 0
"""
STAT_STUB = """#!/bin/sh
echo "1000000 1 900000"
"""


class TodaysPartitionsAloneOverTheBudget(unittest.TestCase):
    """Review 2026-11-05, T05: the budget drops finished days only, so one day's flood
    stays over the volume's share until midnight. It says so to the collector, which
    stops importing into the day; PostgreSQL does not meet the volume's end first."""

    def run_budget(
        self, held: int, *arguments: str, marker: str | None = None
    ) -> tuple[subprocess.CompletedProcess[str], Path]:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        (root / "ui-admin.conf").write_text("DB_NAME=haprion\nDB_ROLE=haprion\n")
        for name, stub in (
            ("psql", TODAY_ONLY_PSQL_STUB),
            ("sudo", SUDO_STUB),
            ("stat", STAT_STUB),
        ):
            (root / name).write_text(stub)
            (root / name).chmod(0o755)
        staging = root / "staging"
        staging.mkdir()
        mark = staging / ".database-budget"
        if marker is not None:
            mark.write_text(marker)
        script = root / "haprion-retention"
        text = SCRIPT.read_text()
        for old, new in (
            ("CONFIG_DIRECTORY=/etc/haprion", f"CONFIG_DIRECTORY={root}"),
            ("STAGING_DIRECTORY=/var/lib/haprion-ui/logs/staging", f"STAGING_DIRECTORY={staging}"),
            ('[[ $EUID -eq 0 ]] || die "run this with sudo"', ":"),
        ):
            self.assertIn(old, text)
            text = text.replace(old, new)
        script.write_text(text)
        done = subprocess.run(
            ["/bin/bash", str(script), "budget", *arguments],
            capture_output=True,
            text=True,
            env={
                "PATH": f"{root}:/usr/bin:/bin",
                "RECORD": str(root / "record"),
                "DATA_DIRECTORY": str(root),
                "HELD": str(held),
            },
            check=False,
            timeout=60,
        )
        return done, mark

    def test_a_day_alone_over_the_share_leaves_a_mark_for_the_collector(self) -> None:
        done, mark = self.run_budget(400_000)  # of 1 000 000, at most 25 %

        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertTrue(mark.exists())
        self.assertIn("today", done.stderr)

    def test_under_the_share_the_mark_is_taken_away(self) -> None:
        done, mark = self.run_budget(100_000, marker="over\n")

        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertFalse(mark.exists())

    def test_a_dry_run_changes_no_mark(self) -> None:
        done, mark = self.run_budget(400_000, "--dry-run")
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertFalse(mark.exists())
        done, mark = self.run_budget(100_000, "--dry-run", marker="over\n")
        self.assertTrue(mark.exists())

    def test_without_a_collector_there_is_nothing_to_tell(self) -> None:
        """No staging directory: the budget still runs and fails on nothing."""

        done, _ = self.run_budget(400_000)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)


if __name__ == "__main__":
    unittest.main()
