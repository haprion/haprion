"""What the metric tables promise, read out of the migration and the command.

Neither of these can be proved by running them here - the migration needs a
database and the retention command needs root - so what is checked is the text
that will be run. That is worth doing for exactly two things: the grants, which
decide what a compromised process can do, and the distinctions the phase rests
on. B93 says the poller cannot create a partition; B94 says a standby's backend
verdict is not a measurement. Both are promises made in SQL and in a shell
script, and both are the kind of promise that is quietly broken by an edit that
looks harmless.
"""

from __future__ import annotations

import ast
import re
import unittest
from collections.abc import Iterator, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path

from haproxy_ui import db
from haproxy_ui.metrics import CARD_COUNTERS, METRIC_COUNTERS, SUMMARY_COUNTERS

ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "ui" / "migrations" / "versions" / "0018_metric_samples.py"
SAMPLE_INSTANT = ROOT / "ui" / "migrations" / "versions" / "0019_sample_instant.py"
RETENTION = ROOT / "install" / "platform" / "bin" / "haproxy-ui-retention"
NODE_SCRIPT = ROOT / "install" / "node" / "haproxy-node-status"
ROLLUP = ROOT / "ui" / "migrations" / "versions" / "0020_metric_pool_hour.py"
ROLLUP_STATE = ROOT / "ui" / "migrations" / "versions" / "0021_metric_rollup_state.py"
RENAME = ROOT / "ui" / "migrations" / "versions" / "0023_metric_table_names.py"


class BackendTotalConnection:
    class Cursor:
        def __init__(self, owner: BackendTotalConnection) -> None:
            self.owner = owner

        def __enter__(self) -> BackendTotalConnection.Cursor:
            return self

        def __exit__(self, *_: object) -> None:
            return None

        def execute(self, statement: object, arguments: dict[str, object] | None = None) -> None:
            self.owner.statement = str(statement)
            self.owner.statements.append(self.owner.statement)
            self.owner.arguments = arguments or {}

        def fetchone(self) -> tuple[object, ...] | None:
            return self.owner.row

        def fetchall(self) -> list[tuple[object, ...]]:
            """For the readers that return a set of rows rather than one.

            The listing queries and the bucketed reads take this path; the
            aggregates take `fetchone`. One fake serves both so a test does not
            have to know which, which is also how a reader that changed shape
            would be caught here rather than in a page.
            """

            return list(self.owner.rows)

    def __init__(
        self,
        row: tuple[object, ...],
        *,
        rows: Sequence[tuple[object, ...]] = (),
    ) -> None:
        self.row = row
        self.rows = rows
        self.statement = ""
        self.statements: list[str] = []
        self.arguments: dict[str, object] = {}

    def cursor(self) -> BackendTotalConnection.Cursor:
        return self.Cursor(self)


class ThePoolFiguresQuery(unittest.TestCase):
    """The figure reads the finest stored series, never the graph's buckets."""

    def test_a_long_range_is_summed_from_the_hourly_sums_with_its_edges_read_raw(self) -> None:
        at = datetime(2026, 9, 6, 12, tzinfo=UTC)
        pairs: list[object] = []
        for index, _counter in enumerate(CARD_COUNTERS, start=1):
            pairs.extend((index * 100, 60.0))
        connection = BackendTotalConnection(
            (3, at - timedelta(minutes=1), at, False, False, 60.0, 60.0, *pairs)
        )

        measured = db.read_backend_totals(
            connection,  # type: ignore[arg-type]
            cluster="alpha",
            backend="mgd-site-web",
            since=at - timedelta(days=30),
            until=at,
        )

        self.assertEqual(len(connection.statements), 1)
        self.assertIn("metric_backend_hour_delta", connection.statement)
        self.assertIn("metric_backend_member", connection.statement)
        self.assertNotIn('metric_backend_hour"', connection.statement)
        self.assertNotIn("metric_rollup_state", connection.statement)
        self.assertNotIn("date_bin", connection.statement)
        self.assertNotIn("width", connection.arguments)
        self.assertEqual(connection.arguments["after"], at - timedelta(days=30))
        self.assertEqual(
            [total.value for total in measured.totals], [100, 200, 300, 400, 500, 600, 700]
        )

    def test_a_range_marked_weeks_ago_is_read_from_the_hourly_sums_that_hold_it(self) -> None:
        """Nothing about the range depends on today any more.

        Seen 2026-10-01: 15-18 Sep marked on the 30-day window read 0 under a
        visible peak, because a boundary counted from the marks' end put the
        whole range on the raw side, where its rows had been pruned. The hourly
        sums keep the whole window, so there is no boundary to misplace.
        """

        pairs = [value for _counter in CARD_COUNTERS for value in (0, 0.0)]
        connection = BackendTotalConnection((0, None, None, False, False, 0.0, 0.0, *pairs))
        since = datetime(2026, 9, 15, 20, tzinfo=UTC)
        until = datetime(2026, 9, 18, 20, tzinfo=UTC)

        db.read_backend_totals(
            connection,  # type: ignore[arg-type]
            cluster="alpha",
            backend="mgd-site-web",
            since=since,
            until=until,
        )

        self.assertIn("metric_backend_hour_delta", connection.statement)
        self.assertEqual(
            (connection.arguments["after"], connection.arguments["until"]), (since, until)
        )

    def test_a_day_or_less_reads_the_raw_samples_only(self) -> None:
        at = datetime(2026, 9, 6, 12, tzinfo=UTC)
        pairs = [value for _counter in CARD_COUNTERS for value in (0, 0.0)]
        for read in (db.read_backend_totals, db.read_frontend_totals):
            with self.subTest(read.__name__):
                connection = BackendTotalConnection((0, None, None, False, False, 0.0, 0.0, *pairs))
                scope = (
                    {"backend": "mgd-site-web"}
                    if read is db.read_backend_totals
                    else {"frontend": "fe"}
                )
                read(
                    connection,  # type: ignore[arg-type]
                    cluster="alpha",
                    since=at - timedelta(days=1),
                    until=at,
                    **scope,
                )

                self.assertEqual(len(connection.statements), 1)
                self.assertNotIn("_hour_delta", connection.statement)

    def test_a_drawing_reads_the_hourly_sums_only_when_its_buckets_are_whole_hours(self) -> None:
        at = datetime(2026, 9, 6, 12, tzinfo=UTC)
        cases = (
            (timedelta(days=30), timedelta(hours=6), True),
            (timedelta(days=7), timedelta(hours=1), True),
            (timedelta(days=7), timedelta(minutes=90), False),
            (timedelta(days=2), timedelta(minutes=10), False),
            (timedelta(days=1), timedelta(hours=1), False),
        )
        for span, width, hourly in cases:
            for read in (db.read_backend_series, db.read_frontend_series):
                with self.subTest(read.__name__, span=span, width=width):
                    connection = BackendTotalConnection(())
                    scope = (
                        {"backend": "mgd-site-web"}
                        if read is db.read_backend_series
                        else {"frontend": "fe"}
                    )
                    read(
                        connection,  # type: ignore[arg-type]
                        cluster="alpha",
                        since=at - span,
                        until=at,
                        width=width,
                        **scope,
                    )

                    self.assertEqual(len(connection.statements), 1)
                    self.assertEqual("_hour_delta" in connection.statement, hourly)

    def test_the_same_sql_measurement_carries_figures_and_the_restart(self) -> None:
        at = datetime(2026, 9, 6, 12, tzinfo=UTC)
        pairs: list[object] = []
        for index, _counter in enumerate(CARD_COUNTERS, start=1):
            pairs.extend((index, 40.0 if index == 1 else 20.0))
        connection = BackendTotalConnection(
            (4, at - timedelta(seconds=60), at, True, False, 50.0, 60.0, *pairs)
        )

        measured = db.read_backend_totals(
            connection,  # type: ignore[arg-type]
            cluster="alpha",
            backend="mgd-site-web",
            since=at - timedelta(hours=1),
            until=at,
        )

        self.assertEqual([total.value for total in measured.totals][:2], [1, 2])
        self.assertTrue(all(total.known for total in measured.totals))
        self.assertTrue(measured.restarted)


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
        does not fill into a frontend that received nothing, which is the one
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
        """Asked of 0023, which replaced the function when the tables were renamed."""

        current = RENAME.read_text()
        self.assertIn(
            "if table_name not in ('metric_frontend', 'metric_backend_member') then", current
        )
        self.assertIn("raise exception 'not a metric table: %', table_name;", current)


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

    def test_completion_is_stored_even_for_an_hour_with_no_row(self) -> None:
        state = ROLLUP_STATE.read_text()
        self.assertIn("create table metric_rollup_state", state)
        self.assertIn("complete_before timestamptz not null", state)
        self.assertIn("grant select (rollup_name, complete_before)", state)
        self.assertNotIn("to app_poller", state)

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
        self.assertLess(prune.index("rollup\n"), prune.index("metric_partitions_prune\n"))

    def test_rows_and_completion_advance_in_one_statement(self) -> None:
        rollup = self.script.split("\nrollup() {", 1)[1].split("\n}\n", 1)[0]
        statement = rollup.split("<<SQL", 1)[1].split("\nSQL", 1)[0]
        self.assertIn("insert into ${METRIC_ROLLUP_TABLE}", statement)
        self.assertIn("insert into metric_rollup_state", statement)

    def test_backend_raw_data_is_gated_by_completion_and_a_safety_day(self) -> None:
        predicate = self.script.split("metric_partitions_expired() {", 1)[1].split("\n}", 1)[0]
        self.assertIn(
            'if [[ "$table" == "metric_backend_member" ]] && rollup_state_present', predicate
        )
        self.assertIn("complete_before - make_interval", predicate)
        self.assertIn("METRIC_ROLLUP_SAFETY_DAYS", predicate)

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

    def test_the_global_command_still_serves_an_environment_on_revision_0020(self) -> None:
        """One installed script serves databases migrated at different times."""

        rollup = self.script.split("\nrollup() {", 1)[1].split("\n}\n", 1)[0]
        self.assertIn("elif rollup_state_present; then", rollup)
        self.assertIn("completion boundary unavailable", rollup)

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

        self.assertIn("METRIC_TABLES=(metric_frontend metric_backend_member)", self.script)
        self.assertIn("metric_partition(", self.script)

    def test_the_horizon_is_long_enough_that_a_missed_run_is_harmless(self) -> None:
        """A horizon of days would make the timer a single point of failure.

        There is no default partition, so a day without one is an insert that
        fails rather than a row that lands somewhere misleading.
        """

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
        prepare = self.script.split("\nmetric_partitions_prepare() {", 1)[1].split("\n}\n", 1)[0]
        prune = self.script.split("\nmetric_partitions_prune() {", 1)[1].split("\n}\n", 1)[0]
        rollup = self.script.split("\nrollup() {", 1)[1].split("\n}\n", 1)[0]
        self.assertIn('if [[ "$dry_run" -eq 1 ]]; then', prepare)
        self.assertIn('if [[ "$dry_run" -eq 1 ]]; then', prune)
        self.assertLess(
            rollup.index('if [[ "$dry_run" -eq 1 ]]; then'),
            rollup.index("metric_month_partition("),
        )

    def test_an_unmigrated_environment_still_gets_its_jobs_pruned(self) -> None:
        """One script, several environments, and they sit at different migrations.

        Without the guard, `prune` against a database without the metric tables
        fails on the missing function and returns before removing a single job
        row - so the environment that is furthest behind is also the one whose
        retention silently stops.
        """

        self.assertIn("to_regclass('public.metric_frontend') is not null", self.script)
        for function in ("metrics_report() {", "metric_partitions_prepare() {"):
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
        self.assertLess(prune.index("metric_partitions_prepare\n"), prune.index("where_removable"))


if __name__ == "__main__":
    unittest.main()


class TheListenerQueriesReadWhatTheyClaimTo(unittest.TestCase):
    """The newest reader in the phase, and the one nothing executed.

    Its backend counterpart has had this since the raw chain was built; this half
    was mocked wherever it appeared, so a difference between the two reached
    production as a number on a page. The 2026-09-07 review found exactly that:
    the frontend query collapsed its buckets across nodes where the backend query
    does not, and an address moving inside one bucket then reported a node's
    lifetime counter as that bucket's traffic.
    """

    AT = datetime(2026, 9, 7, 12, tzinfo=UTC)

    def figures(self) -> BackendTotalConnection:
        pairs: list[object] = []
        for index, _counter in enumerate(CARD_COUNTERS, start=1):
            pairs.extend((index * 10, 60.0))
        return BackendTotalConnection((2, self.AT, self.AT, False, False, 60.0, 60.0, *pairs))

    def test_the_figures_read_one_raw_table_and_no_rollup(self) -> None:
        """Frontends have none, so there is no boundary to meet wrongly."""

        connection = self.figures()

        db.read_frontend_totals(
            connection,  # type: ignore[arg-type]
            cluster="alpha",
            frontend="mgd-vip-int-https",
            since=self.AT - timedelta(days=1),
            until=self.AT,
        )

        self.assertIn("metric_frontend", connection.statement)
        self.assertNotIn("metric_backend_hour", connection.statement)
        self.assertNotIn("raw_from", connection.arguments)

    def test_the_figures_are_the_holding_node_s(self) -> None:
        connection = self.figures()

        db.read_frontend_totals(
            connection,  # type: ignore[arg-type]
            cluster="alpha",
            frontend="mgd-vip-int-https",
            since=self.AT - timedelta(days=1),
            until=self.AT,
        )

        self.assertIn("owns_vip", connection.statement)

    def test_every_bucket_is_per_node_exactly_as_the_backend_query_is(self) -> None:
        """The 2026-09-07 finding: collapsing across nodes invents a restart.

        An address that moves away and back inside one bucket leaves the other
        machine's low uptime as the floor while the kept row is the original
        node - a restart with no change of author, which the reader answers
        with that node's cumulative counter.
        """

        connection = BackendTotalConnection(())

        db.read_frontend_series(
            connection,  # type: ignore[arg-type]
            cluster="alpha",
            frontend="mgd-vip-int-https",
            since=self.AT - timedelta(days=1),
            until=self.AT,
            width=timedelta(minutes=10),
        )

        statement = connection.statement
        self.assertIn("group by node,", statement)
        self.assertIn("owns_vip", statement)
        self.assertIn("Identifier('delta_req_tot')", statement)
        # The grid in UTC, never the server's zone (2026-10-04).
        self.assertIn("timestamptz '2000-01-01 00:00:00+00'", statement)
        self.assertNotIn("timestamptz '2000-01-01')", statement)

    def test_the_listing_asks_which_addresses_were_seen_not_which_were_held(self) -> None:
        """`owns_vip` is nullable, and null is "this node could not say".

        Filtering the list by it removed the whole address from the page while
        its rows sat in the table - and went quiet during the total outage this
        page exists to diagnose.
        """

        connection = BackendTotalConnection(())

        db.read_cluster_frontends(
            connection,  # type: ignore[arg-type]
            cluster="alpha",
            since=self.AT - timedelta(days=1),
            until=self.AT,
        )

        listing = connection.statement
        self.assertIn("bool_or(owns_vip)", listing)
        self.assertNotIn("and owns_vip and", listing)

    def test_both_aggregates_return_the_same_columns_in_the_same_order(self) -> None:
        """`_measurement` unpacks both by position, so a drift is silent.

        One reader has a rollup half and the other cannot. Compare rendered
        SQL, because a Composed object's debug representation is not the
        statement PostgreSQL executes.
        """

        backend = db._backend_totals().as_string()
        frontend = db._frontend_totals().as_string()
        tail = "select count(*)::bigint, min(started_at), max(ended_at), "

        self.assertIn(tail, backend)
        self.assertIn(tail, frontend)
        self.assertEqual(
            backend.split(tail, 1)[1].split(" from intervals", 1)[0],
            frontend.split(tail, 1)[1].split(" from intervals", 1)[0],
        )


class TheStoredDifferencesCoverEverySummedCounter(unittest.TestCase):
    """Migration 0048 stores a difference per counter; a figure may only sum those."""

    def test_the_cards_and_the_dashboard_sum_only_stored_counters(self) -> None:
        summed = {name for name, _label in (*CARD_COUNTERS, *SUMMARY_COUNTERS)}

        self.assertLessEqual(summed, set(db.STORED_DELTAS))

    def test_the_reader_and_the_migration_name_the_same_counters(self) -> None:
        import importlib.util
        from pathlib import Path

        path = Path(__file__).resolve().parents[1] / "migrations/versions/0048_metric_deltas.py"
        specification = importlib.util.spec_from_file_location("metric_deltas", path)
        if specification is None or specification.loader is None:
            self.fail("migration 0048 could not be loaded")
        migration = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(migration)

        self.assertEqual(tuple(migration.COUNTERS), db.STORED_DELTAS)


class TheDashboardCountsVisitorsNotScrapes(unittest.TestCase):
    def test_every_frontend_but_the_exporter_s_is_summed(self) -> None:
        from haproxy_mgmt.generate import METRICS_FRONTEND
        from psycopg import sql

        statement = db._frontend_totals(SUMMARY_COUNTERS, every_frontend=True)

        self.assertIn(sql.Literal(METRICS_FRONTEND), list(_parts(statement)))
        self.assertNotIn(
            sql.Literal(METRICS_FRONTEND), list(_parts(db._frontend_totals(CARD_COUNTERS)))
        )


def _parts(composed: object) -> Iterator[object]:
    """Every leaf of a composed statement, so a literal can be found without a connection."""

    from psycopg import sql

    if isinstance(composed, sql.Composed):
        for part in composed:
            yield from _parts(part)
    else:
        yield composed
