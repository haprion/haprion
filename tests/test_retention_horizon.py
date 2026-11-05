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


MV_STUB = """#!/bin/sh
echo "$@" >> "$RECORD.mv"
exec /bin/mv "$@"
"""


# What a collector that owns the staging directory can do between `mktemp` and the write:
# take the file away and put a link in its place. It cannot do it anywhere else.
SWAPPING_MKTEMP_STUB = """#!/bin/sh
made="$(/usr/bin/mktemp "$@")" || exit 1
case "$made" in
    "$STAGING"/*) rm -f "$made"; ln -s "$PRECIOUS" "$made" ;;
esac
echo "$made"
"""


class TodaysPartitionsAloneOverTheBudget(unittest.TestCase):
    """Review 2026-11-05, T05: the budget drops finished days only, so one day's flood
    stays over the volume's share until midnight. It says so to the collector, which
    stops importing into the day; PostgreSQL does not meet the volume's end first."""

    def run_budget(
        self,
        held: int,
        *arguments: str,
        marker: str | None = None,
        link: bool = False,
        swap: bool = False,
    ) -> tuple[subprocess.CompletedProcess[str], Path]:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        (root / "ui-admin.conf").write_text("DB_NAME=haprion\nDB_ROLE=haprion\n")
        for name, stub in (
            ("psql", TODAY_ONLY_PSQL_STUB),
            ("sudo", SUDO_STUB),
            ("stat", STAT_STUB),
            ("mv", MV_STUB),
        ):
            (root / name).write_text(stub)
            (root / name).chmod(0o755)
        staging = root / "staging"
        staging.mkdir()
        mark = staging / ".database-budget"
        if marker is not None:
            mark.write_text(marker)
        if link:
            (root / "elsewhere").write_text("untouched\n")
            mark.symlink_to(root / "elsewhere")
        if swap:
            (root / "mktemp").write_text(SWAPPING_MKTEMP_STUB)
            (root / "mktemp").chmod(0o755)
            (root / "precious").write_text("precious\n")
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
                "STAGING": str(staging),
                "PRECIOUS": str(root / "precious"),
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

    def test_the_mark_is_made_aside_and_moved_over_the_old_one(self) -> None:
        """Review 2026-11-05, U04: root writes into a directory the collector owns, so
        nothing is written through a name the collector could have made a link."""

        done, mark = self.run_budget(400_000, marker="old\n")

        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual(mark.read_text(), "over\n")
        self.assertFalse(mark.is_symlink())
        self.assertEqual(sorted(path.name for path in mark.parent.iterdir()), [mark.name])
        moves = (mark.parent.parent / "record.mv").read_text().splitlines()
        self.assertEqual(len(moves), 1, moves)
        self.assertTrue(moves[0].startswith("-fT -- "), moves)
        self.assertTrue(moves[0].endswith(f" {mark}"), moves)

    def test_a_link_put_in_the_temporary_files_place_is_not_written_through(self) -> None:
        """Review 2026-11-05, Y02: the temporary file is made where the collector cannot
        reach it, so a link it swaps in between the two calls is never opened."""

        done, mark = self.run_budget(400_000, swap=True)

        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual((mark.parent.parent / "precious").read_text(), "precious\n")
        self.assertEqual(mark.read_text(), "over\n")
        self.assertFalse(mark.is_symlink())
        self.assertEqual(sorted(path.name for path in mark.parent.iterdir()), [mark.name])

    def test_a_link_in_the_marks_place_is_replaced_not_followed(self) -> None:
        done, mark = self.run_budget(400_000, link=True)

        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertFalse(mark.is_symlink())
        self.assertEqual(mark.read_text(), "over\n")
        self.assertEqual((mark.parent.parent / "elsewhere").read_text(), "untouched\n")

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


class TodaysBlockRangeIndexIsSummarized(unittest.TestCase):
    """B472, R01: autosummarize queues 256 requests and drops the rest under a burst, so
    every run summarizes the new ranges of today's index itself."""

    def run_retention(self, *arguments: str) -> str:
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
            ["/bin/bash", str(script), "prune", *arguments],
            capture_output=True,
            text=True,
            env={"PATH": f"{root}:/usr/bin:/bin", "RECORD": str(record)},
            check=False,
            timeout=60,
        )
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        return record.read_text().lower()

    def test_a_run_summarizes_the_new_ranges_of_the_index_of_today(self) -> None:
        statements = self.run_retention()

        self.assertIn("brin_summarize_new_values(", statements)
        self.assertIn("traffic_log_", statements.split("brin_summarize_new_values(")[1])
        self.assertIn("_inserted", statements.split("brin_summarize_new_values(")[1])

    def test_a_dry_run_summarizes_nothing(self) -> None:
        self.assertNotIn("brin_summarize_new_values", self.run_retention("--dry-run"))
