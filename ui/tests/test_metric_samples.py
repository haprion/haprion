"""What the metric tables promise, read out of the migration and the command.

Neither of these can be proved by running them here - the migration needs a
database and the retention command needs root - so what is checked is the text
that will be run. That is worth doing for exactly two things: the grants, which
decide what a compromised process can do, and the distinctions the phase rests
on. B93 says the poller cannot create a partition; B94 says a standby's pool
verdict is not a measurement. Both are promises made in SQL and in a shell
script, and both are the kind of promise that is quietly broken by an edit that
looks harmless.
"""

from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "ui" / "migrations" / "versions" / "0018_metric_samples.py"
RETENTION = ROOT / "install" / "platform" / "bin" / "haproxy-ui-retention"


class TheMetricTables(unittest.TestCase):
    def setUp(self) -> None:
        self.sql = MIGRATION.read_text()

    def test_both_tables_are_partitioned_by_the_day_the_sample_was_taken(self) -> None:
        self.assertEqual(self.sql.count("partition by range (observed_at)"), 2)

    def test_the_poller_may_write_a_sample_and_never_its_timestamp(self) -> None:
        """`observed_at` comes from the statement, so it cannot be backdated."""

        for grant in (
            "grant insert (cluster, node, frontend",
            "grant insert (cluster, node, backend",
        ):
            with self.subTest(grant=grant):
                columns = self.sql.split(grant, 1)[1].split(")", 1)[0]
                self.assertNotIn("observed_at", columns)

    def test_the_web_role_may_read_and_never_write(self) -> None:
        self.assertIn("to app_poller, app_web", self.sql)
        self.assertNotIn("to app_web, app_poller", self.sql)
        for statement in self.sql.split(";"):
            if "app_web" in statement:
                self.assertIn("grant select", statement)

    def test_nobody_is_granted_delete_or_update(self) -> None:
        """Removing a sample is the retention command's work, as its owner."""

        self.assertNotIn("grant delete", self.sql)
        self.assertNotIn("grant update", self.sql)

    def test_every_counter_is_nullable(self) -> None:
        """Null is "not applicable"; zero is a measurement. See the node script.

        A counter declared `not null default 0` would turn a column HAProxy
        does not fill into a listener that received nothing, which is the one
        confusion these tables exist to avoid.
        """

        for line in self.sql.splitlines():
            if line.strip().endswith("bigint,"):
                self.assertNotIn("not null", line)
                self.assertNotIn("default", line)

    def test_there_is_no_default_partition(self) -> None:
        """A day with no partition must fail, not land somewhere misleading."""

        for line in self.sql.splitlines():
            if "partition of" in line:
                self.assertIn("for values from", line)
                self.assertNotIn(" default", line)

    def test_the_partition_function_refuses_a_table_it_does_not_know(self) -> None:
        self.assertIn(
            "if table_name not in ('metric_listener', 'metric_pool_member') then", self.sql
        )
        self.assertIn("raise exception 'not a metric table: %', table_name;", self.sql)


class WhatTheRetentionCommandKeeps(unittest.TestCase):
    def setUp(self) -> None:
        self.script = RETENTION.read_text()

    def test_the_partitions_are_this_command_s_work_and_not_the_poller_s(self) -> None:
        """B93: no application role holds `create` on the schema."""

        self.assertIn("METRIC_TABLES=(metric_listener metric_pool_member)", self.script)
        self.assertIn("metric_partition(", self.script)

    def test_the_horizon_is_long_enough_that_a_missed_run_is_harmless(self) -> None:
        """Weekly timer, so days of headroom would be a single point of failure."""

        ahead = int(self.script.split("METRIC_AHEAD_DAYS=", 1)[1].split("\n", 1)[0])
        keep = int(self.script.split("METRIC_KEEP_DAYS=", 1)[1].split("\n", 1)[0])
        self.assertGreaterEqual(ahead, 28)
        self.assertGreater(ahead, keep)

    def test_report_changes_nothing(self) -> None:
        """The command somebody runs to find out whether `prune` is safe."""

        body = self.script.split("metrics_report() {", 1)[1].split("\nmetrics() {", 1)[0]
        for writing in ("metric_partition(", "drop table", "delete from"):
            with self.subTest(writing=writing):
                self.assertNotIn(writing, body)

    def test_a_dry_run_neither_creates_nor_drops(self) -> None:
        body = self.script.split("\nmetrics() {", 1)[1].split("\nmain()", 1)[0]
        for guard in ('if [[ "$dry_run" -eq 1 ]]; then',):
            self.assertEqual(body.count(guard), 2)

    def test_an_expired_partition_is_dropped_rather_than_emptied(self) -> None:
        """A delete would rewrite a week of rows as dead tuples."""

        self.assertIn("drop table if exists", self.script)
        self.assertNotIn("delete from metric_", self.script)

    def test_the_horizon_is_extended_before_the_jobs_are_pruned(self) -> None:
        """A failure should not leave the horizon short and the jobs gone."""

        prune = self.script.split("        prune)\n", 1)[1]
        self.assertLess(prune.index("metrics\n"), prune.index("where_removable"))


if __name__ == "__main__":
    unittest.main()
