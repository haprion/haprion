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

import ast
import re
import unittest
from pathlib import Path

from haproxy_ui.metrics import METRIC_COUNTERS

ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "ui" / "migrations" / "versions" / "0018_metric_samples.py"
SAMPLE_INSTANT = ROOT / "ui" / "migrations" / "versions" / "0019_sample_instant.py"
RETENTION = ROOT / "install" / "platform" / "bin" / "haproxy-ui-retention"
NODE_SCRIPT = ROOT / "install" / "node" / "haproxy-node-status"
ROLLUP = ROOT / "ui" / "migrations" / "versions" / "0020_metric_pool_hour.py"


def _tuple_named(source: str, name: str) -> tuple[str, ...]:
    """The value of one module-level tuple, read without importing the file.

    Neither of the other two can be imported: the node script is installed
    rather than packaged, and a migration must not import application code.
    """

    for node in ast.parse(source).body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == name for target in node.targets
        ):
            return tuple(ast.literal_eval(node.value))
    raise AssertionError(f"{name} is no longer a module-level tuple")


class TheThreeCounterLists(unittest.TestCase):
    """One list of column names, in three places that cannot share it.

    The node reads them, the reader keeps them and the migration stores them.
    A name added to one and not the others is a counter measured and dropped,
    or a column that never gets a value - neither of which fails anywhere else.
    """

    def test_the_node_reads_exactly_what_the_reader_keeps(self) -> None:
        self.assertEqual(_tuple_named(NODE_SCRIPT.read_text(), "COUNTER_COLUMNS"), METRIC_COUNTERS)

    def test_the_migration_stores_exactly_what_the_reader_keeps(self) -> None:
        self.assertEqual(_tuple_named(MIGRATION.read_text(), "COUNTERS"), METRIC_COUNTERS)

    def test_the_rollup_stores_exactly_what_the_reader_keeps(self) -> None:
        self.assertEqual(_tuple_named(ROLLUP.read_text(), "COUNTERS"), METRIC_COUNTERS)

    def test_the_retention_command_rolls_up_exactly_those(self) -> None:
        """The fourth copy, and a shell script cannot import the other three."""

        listed = RETENTION.read_text().split('METRIC_COUNTERS="', 1)[1].split('"', 1)[0]
        self.assertEqual(tuple(name.strip() for name in listed.split(",")), METRIC_COUNTERS)


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

    def test_one_poll_is_one_instant(self) -> None:
        """`executemany` sends a statement per row, so the statement clock ticks.

        Measured on the first release that wrote samples: two rows of one poll
        landed 55 microseconds apart. Nothing was wrong with the data - but the
        rows of one poll are one reading, and an aggregation that groups them
        by time should not need a tolerance to put them back together.
        """

        later = SAMPLE_INSTANT.read_text()
        self.assertEqual(later.count("set default transaction_timestamp()"), 1)
        for table in ("metric_listener", "metric_pool_member"):
            self.assertIn(table, later)

    def test_the_caches_keep_the_statement_clock(self) -> None:
        """There the question is when the row was written, not what it read."""

        self.assertNotIn("cluster_status", SAMPLE_INSTANT.read_text())

    def test_the_partition_function_refuses_a_table_it_does_not_know(self) -> None:
        self.assertIn(
            "if table_name not in ('metric_listener', 'metric_pool_member') then", self.sql
        )
        self.assertIn("raise exception 'not a metric table: %', table_name;", self.sql)


class WhatTheRollupPromises(unittest.TestCase):
    """A rollup row is a bucketed reading, not an hour's delta.

    Same shape as what the raw query returns, so one difference-and-restart
    implementation serves both and the only thing a longer window changes is
    which table answers.
    """

    def setUp(self) -> None:
        self.sql = ROLLUP.read_text()
        self.script = RETENTION.read_text()

    def test_the_row_carries_a_cumulative_reading_and_the_hour_s_floor(self) -> None:
        self.assertIn("floor_uptime_sec  bigint", self.sql)
        self.assertIn("uptime_sec        bigint", self.sql)

    def test_the_hour_is_an_hour(self) -> None:
        self.assertIn("check (bucket_at = date_trunc('hour', bucket_at))", self.sql)

    def test_no_application_role_may_write_it(self) -> None:
        """Derived data, written by the one privileged hand. See B93."""

        self.assertNotIn("grant insert", self.sql)
        self.assertNotIn("grant update", self.sql)
        self.assertNotIn("grant delete", self.sql)

    def test_an_hour_that_exists_is_never_recomputed(self) -> None:
        """It would be rebuilt from rows that may since have been dropped."""

        self.assertIn("on conflict do nothing", self.script)

    def test_the_rollup_runs_before_the_pruning(self) -> None:
        """It reads rows the pruning removes; reversed, it would make a gap."""

        prune = self.script.split("        prune)\n", 1)[1]
        self.assertLess(prune.index("rollup"), prune.index("where_removable"))

    def test_it_calls_only_helpers_it_defines(self) -> None:
        """The command is standalone; it does not source the installer's lib.

        `step` is defined in `install/lib.sh`, which every numbered platform
        step sources and this command does not - so calling it aborted the run
        under `set -e`, after the partitions and before the pruning. Caught by
        a dry run rather than by a gate, which is why there is now a gate.
        """

        defined = {"log", "die", "usage", "psql_as", "counts", "main"}
        called = set(re.findall(r"^\s{4}([a-z_][a-z_0-9]*)\b", self.script, re.MULTILINE))
        undefined = called - defined - set(re.findall(r"^([a-z_]+)\(\)", self.script, re.MULTILINE))
        self.assertEqual(undefined & {"step", "fail", "need_root", "require_vars"}, set())

    def test_a_successful_run_is_quiet(self) -> None:
        """Keeping the horizon idempotent costs one NOTICE per existing partition.

        About seventy-five a week. An output that is mostly noise is one that
        stops being read, and the run that finally has something to say says it
        in the middle of it.
        """

        self.assertIn("client_min_messages=warning", self.script)

    def test_the_lag_leaves_room_for_missed_runs(self) -> None:
        """An hour becomes eligible days before its samples are dropped."""

        lag = int(self.script.split("METRIC_ROLLUP_LAG_DAYS=", 1)[1].split("\n", 1)[0])
        keep = int(self.script.split("METRIC_KEEP_DAYS=", 1)[1].split("\n", 1)[0])
        self.assertGreaterEqual(lag, 1)
        self.assertGreater(keep - lag, 3)


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

        #
        # Bounded by the function's own closing brace rather than by whatever
        # is defined after it: the next function moved once already, and the
        # test then read its body as this one's.
        #
        body = self.script.split("metrics_report() {", 1)[1].split("\n}\n", 1)[0]
        for writing in ("metric_partition(", "drop table", "delete from"):
            with self.subTest(writing=writing):
                self.assertNotIn(writing, body)

    def test_a_dry_run_neither_creates_nor_drops(self) -> None:
        body = self.script.split("\nmetrics() {", 1)[1].split("\n}\n", 1)[0]
        for guard in ('if [[ "$dry_run" -eq 1 ]]; then',):
            self.assertEqual(body.count(guard), 2)

    def test_an_unmigrated_environment_still_gets_its_jobs_pruned(self) -> None:
        """One script, several environments, and they sit at different migrations.

        Without the guard, `prune` against a database without the metric tables
        fails on the missing function and returns before removing a single job
        row - so the environment that is furthest behind is also the one whose
        retention silently stops.
        """

        self.assertIn("to_regclass('public.metric_listener') is not null", self.script)
        for function in ("metrics_report() {", "metrics() {"):
            body = self.script.split(function, 1)[1].split("\n}", 1)[0]
            with self.subTest(function=function):
                self.assertLess(body.index("metrics_present"), body.index("for table"))

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
