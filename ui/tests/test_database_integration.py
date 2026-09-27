"""Checks that need PostgreSQL rather than an imitation of its cursor."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import psycopg
from haproxy_mgmt.traffic_collector import (
    RETENTION_DAYS,
    CollectorConfig,
    NodeTarget,
    _database_days,
    _ingest_part,
    _mirror_window,
)

from haproxy_ui import auth, db, traffic_logs

DSN = os.environ.get("HAPROXY_UI_TEST_DATABASE_DSN", "")


@unittest.skipUnless(DSN, "run through ui/tools/test-database")
class ARealDatabase(unittest.TestCase):
    def connect(self, role_variable: str = "HAPROXY_UI_TEST_MIGRATION_ROLE") -> psycopg.Connection:
        role = os.environ[role_variable]
        return psycopg.connect(f"{DSN} user={role}")

    def test_the_release_guard_names_a_running_restore_and_nothing_else(self) -> None:
        """`update-platform-release` asks this before it restarts the worker.

        The query is read out of the script, so what is proved here is what
        runs. A running restore with a live lease is named; a finished one, a
        running deploy, and a restore whose lease has run out are not.
        """

        script = Path(__file__).resolve().parents[2] / "install/platform/update-platform-release"
        text = script.read_text()
        start = text.index('-c "', text.index("no node restore or backup is running")) + 4
        query = text[start : text.index('")"', start)]
        #
        # One cluster each: a cluster has one active job at a time.
        #
        rows = (
            ("alpha", "node_restore", "running", "10 minutes"),
            ("beta", "node_restore", "done", None),
            ("gamma", "deploy", "running", "10 minutes"),
            ("delta", "backup_run", "running", "-1 minute"),
        )
        with self.connect() as connection, connection.cursor() as cursor:
            ids = []
            for cluster, operation, state, lease in rows:
                cursor.execute(
                    "insert into job (operation, cluster, payload, idempotency_key, state, "
                    "claim_token, worker_id, lease_until, started_at, finished_at) "
                    "values (%(operation)s, %(cluster)s, '{}', %(key)s, %(state)s, %(token)s, "
                    "'w', now() + %(lease)s::interval, now(), "
                    "case when %(state)s = 'running' then null else now() end) returning id",
                    {
                        "cluster": cluster,
                        "operation": operation,
                        "key": uuid4(),
                        "state": state,
                        "token": uuid4() if lease else None,
                        "lease": lease,
                    },
                )
                ids.append(cursor.fetchone()[0])
            cursor.execute(query)
            self.assertEqual(cursor.fetchone(), (f"node_restore (job {ids[0]})",))
            connection.rollback()

    def test_retention_keeps_what_a_profile_s_state_is_read_from(self) -> None:
        """A profile in effect for months must not read "Not applied" after a week.

        The clause is printed by the retention command's own functions, so what
        is proved here is what prunes. Everything is a month old and the floor
        of recent rows is set to nothing, so only the profile rule keeps a row.
        """

        script = Path(__file__).resolve().parents[2] / "install/platform/bin/haproxy-ui-retention"
        clause = subprocess.run(  # noqa: S603 - fixed interpreter, the repository's script
            [
                "/bin/bash",
                "-c",
                'KEEP_DAYS=7; KEEP_MINIMUM=0; eval "$(sed -n'
                " '/^profile_evidence() {/,/^}/p;/^where_removable() {/,/^}/p'"
                ' "$0")"; where_removable',
                str(script),
            ],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        jobs = (
            ("old-apply", "dns_profile_apply", {"profile": "kept", "revision": 1}),
            ("newest-apply", "dns_profile_apply", {"profile": "kept", "revision": 2}),
            ("refused-removal", "dns_profile_apply", {"profile": "kept", "revision": 2,
                                                      "remove": True}),
            ("removed-profile", "dns_profile_apply", {"profile": "gone", "revision": 1}),
            ("deploy", "deploy", {}),
        )  # fmt: skip
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "insert into dns_provider_profile (id, name, provider_id, schema_version, "
                "key_id, revision, ciphertext, created_by, updated_by) values "
                "('kept', 'kept', 'cloudflare', 1, '0123456789abcdef', 2, %(blob)s, 'a', 'a')",
                {"blob": b"x" * 48},
            )
            named = {}
            for name, operation, payload in jobs:
                cursor.execute(
                    "insert into job (operation, cluster, payload, idempotency_key, state, "
                    "started_at, finished_at) values (%(operation)s, %(cluster)s, %(payload)s, "
                    "%(key)s, 'done', now() - interval '30 days', now() - interval '30 days') "
                    "returning id",
                    {
                        "operation": operation,
                        "cluster": "alpha" if operation == "deploy" else None,
                        "payload": json.dumps(payload),
                        "key": uuid4(),
                    },
                )
                named[cursor.fetchone()[0]] = name
            cursor.execute(f"select id from job where {clause}")  # noqa: S608 - the script's own
            removable = {named[row[0]] for row in cursor.fetchall() if row[0] in named}
            self.assertEqual(removable, {"old-apply", "removed-profile", "deploy"})
            connection.rollback()

    def test_every_migration_reaches_the_declared_head(self) -> None:
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute("select version_num from alembic_version")
            self.assertEqual(cursor.fetchone(), ("0039",))

    def test_runtime_accounts_inherit_exactly_one_contract_role(self) -> None:
        expected = {
            "HAPROXY_UI_TEST_WEB_ROLE": "app_web",
            "HAPROXY_UI_TEST_WORKER_ROLE": "app_worker",
            "HAPROXY_UI_TEST_POLLER_ROLE": "app_poller",
            "HAPROXY_UI_TEST_COLLECTOR_ROLE": "app_collector",
        }
        with self.connect() as connection, connection.cursor() as cursor:
            for variable, contract in expected.items():
                cursor.execute(
                    "select parent.rolname from pg_auth_members membership "
                    "join pg_roles member on member.oid = membership.member "
                    "join pg_roles parent on parent.oid = membership.roleid "
                    "where member.rolname = %s order by parent.rolname",
                    (os.environ[variable],),
                )
                self.assertEqual(cursor.fetchall(), [(contract,)])

    def test_web_can_read_status_but_cannot_write_it(self) -> None:
        with self.connect("HAPROXY_UI_TEST_WEB_ROLE") as connection, connection.cursor() as cursor:
            cursor.execute("select cluster from cluster_status limit 0")
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                cursor.execute(
                    "insert into cluster_status (cluster, outcome) values ('alpha', 'done')"
                )

    def test_worker_can_read_jobs_but_not_accounts(self) -> None:
        with (
            self.connect("HAPROXY_UI_TEST_WORKER_ROLE") as connection,
            connection.cursor() as cursor,
        ):
            cursor.execute("select id from job limit 0")
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                cursor.execute("select id from app_user limit 0")

    def test_poller_can_write_metrics_but_cannot_read_jobs(self) -> None:
        now = datetime.now(UTC)
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute("select metric_partition('metric_frontend', %s::date)", (now.date(),))
        with (
            self.connect("HAPROXY_UI_TEST_POLLER_ROLE") as connection,
            connection.cursor() as cursor,
        ):
            cursor.execute(
                "insert into metric_frontend "
                "(cluster, node, frontend, owns_vip, uptime_sec, req_tot) "
                "values ('alpha', 'node-a', 'mgd-main-http', true, 60, 1)"
            )
        with (
            self.connect("HAPROXY_UI_TEST_POLLER_ROLE") as connection,
            connection.cursor() as cursor,
            self.assertRaises(psycopg.errors.InsufficientPrivilege),
        ):
            cursor.execute("select id from job limit 0")

    def test_traffic_log_roles_are_one_way_and_partitions_are_indexed(self) -> None:
        now = datetime.now(UTC).replace(microsecond=0)
        values = (
            b"x" * 32,
            "alpha",
            "node-a",
            now,
            1,
            "192.0.2.10",
            "GET",
            "service.example.com",
            "/health",
            "mgd-main-http",
            "mgd-app-primary",
            "s1",
            200,
            0,
            0,
            1,
            2,
            3,
            42,
        )
        statement = """insert into traffic_log
            (event_id, cluster, node, occurred_at, request_number, client, method, host,
             path, frontend, backend, server, status, request_time, queue_time, connect_time,
             response_time, total_time, bytes)
            values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            on conflict do nothing"""
        with self.connect("HAPROXY_UI_TEST_COLLECTOR_ROLE") as connection:
            connection.execute(statement, values)
            connection.execute(statement, values)
        with self.connect("HAPROXY_UI_TEST_WEB_ROLE") as connection, connection.cursor() as cursor:
            cursor.execute(
                "select host, path, status from traffic_log "
                "where cluster = 'alpha' and host = 'service.example.com'"
            )
            self.assertEqual(cursor.fetchall(), [("service.example.com", "/health", 200)])
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                cursor.execute(statement, values)
        with (
            self.connect("HAPROXY_UI_TEST_COLLECTOR_ROLE") as connection,
            connection.cursor() as cursor,
            self.assertRaises(psycopg.errors.InsufficientPrivilege),
        ):
            cursor.execute("select host from traffic_log limit 0")
        suffix = f"{now:%Y%m%d}"
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "select indexname from pg_indexes where tablename = %s order by indexname",
                (f"traffic_log_{suffix}",),
            )
            indexes = {row[0] for row in cursor.fetchall()}
        # The primary key orders by occurred_at already; a second index on it
        # cost a fifth of the index bytes for nothing (migration 0031).
        self.assertNotIn(f"traffic_log_{suffix}_occurred_at", indexes)
        self.assertIn(f"traffic_log_{suffix}_pkey", indexes)
        self.assertIn(f"traffic_log_{suffix}_search", indexes)

    def test_collector_copy_is_checkpointed_and_safe_to_repeat(self) -> None:
        now = datetime.now(UTC).replace(microsecond=0)
        record = {
            "schema": 1,
            "at": int(now.timestamp()),
            "request": 77,
            "client": "192.0.2.20",
            "method": "GET",
            "host": "copy.example.com",
            "path": "/ready",
            "frontend": "mgd-main-http",
            "backend": "mgd-app-primary",
            "server": "s1",
            "status": 204,
            "request_time": 0,
            "queue_time": 0,
            "connect_time": 1,
            "response_time": 2,
            "total_time": 3,
            "bytes": 0,
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            part = root / f"alpha--node-a--{now:%Y-%m-%d}.jsonl"
            part.write_text(json.dumps(record, separators=(",", ":")) + "\n")
            target = NodeTarget("alpha", "node-a", "node-a.example.com")
            config = CollectorConfig(
                "svc-logread",
                root / "key",
                root / "known_hosts",
                root,
                root,
                (target,),
            )
            with self.connect("HAPROXY_UI_TEST_COLLECTOR_ROLE") as connection:
                _ingest_part(config, connection, target, part)
                checkpoint = root / f".{part.name}.database-offset"
                checkpoint.unlink()
                _ingest_part(config, connection, target, part)
            self.assertEqual(int(checkpoint.read_text()), part.stat().st_size)
        with self.connect("HAPROXY_UI_TEST_WEB_ROLE") as connection, connection.cursor() as cursor:
            cursor.execute("select count(*) from traffic_log where host = 'copy.example.com'")
            self.assertEqual(cursor.fetchone(), (1,))

    def test_an_unusable_record_is_stepped_over_rather_than_wedging_the_stream(self) -> None:
        """One bad line must not stop the good ones, this run or any later one.

        Measured on the real mirror before this was written: three lines out of
        roughly a hundred thousand could not be read - the traffic route's own
        probe record, which carries no timestamp, and two lines an rsyslog
        restart had cut in half. Each of them stopped the import of every node,
        every minute, because the checkpoint never passes the record that
        raised.
        """

        now = datetime.now(UTC).replace(microsecond=0)

        def record(host: str, at: int | None = None) -> str:
            return json.dumps(
                {
                    "schema": 1,
                    "at": int(now.timestamp()) if at is None else at,
                    "request": 91,
                    "client": "192.0.2.21",
                    "method": "GET",
                    "host": host,
                    "path": "/after",
                    "frontend": "mgd-main-http",
                    "backend": "mgd-app-primary",
                    "server": "s1",
                    "status": 200,
                    "request_time": 0,
                    "queue_time": 0,
                    "connect_time": 1,
                    "response_time": 2,
                    "total_time": 3,
                    "bytes": 0,
                },
                separators=(",", ":"),
            )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            part = root / f"alpha--node-a--{now:%Y-%m-%d}.jsonl"
            #
            # Two more shapes the guard has to own, both found in the review of
            # 2026-09-17: a stamp datetime cannot hold (OSError, ValueError) and
            # a NUL a text column cannot hold (psycopg.DataError for the whole
            # batch). Neither is a CollectorError on its own, and either would
            # stop the import for good.
            #
            part.write_text(
                '{"schema":1,"probe":true}\n'
                + "{not json at all\n"
                + record("stamp.example.com", at=2**62)
                + "\n"
                + record("stamp.example.com", at=10**12)
                + "\n"
                + record("nul\u0000.example.com")
                + "\n"
                + record("skipped.example.com")
                + "\n"
            )
            target = NodeTarget("alpha", "node-a", "node-a.example.com")
            config = CollectorConfig(
                "svc-logread",
                root / "key",
                root / "known_hosts",
                root,
                root,
                (target,),
            )
            with self.connect("HAPROXY_UI_TEST_COLLECTOR_ROLE") as connection:
                skipped = _ingest_part(config, connection, target, part)
            self.assertEqual(skipped, 5)
            checkpoint = root / f".{part.name}.database-offset"
            self.assertEqual(int(checkpoint.read_text()), part.stat().st_size)
        with self.connect("HAPROXY_UI_TEST_WEB_ROLE") as connection, connection.cursor() as cursor:
            cursor.execute("select count(*) from traffic_log where host = 'skipped.example.com'")
            self.assertEqual(cursor.fetchone(), (1,))

    def test_a_record_still_being_written_is_left_for_the_next_run(self) -> None:
        """The open day grows under the reader; half a line is not damage."""

        now = datetime.now(UTC).replace(microsecond=0)
        body = {
            "schema": 1,
            "at": int(now.timestamp()),
            "request": 92,
            "client": "192.0.2.22",
            "method": "GET",
            "host": "partial.example.com",
            "path": "/tail",
            "frontend": "mgd-main-http",
            "backend": "mgd-app-primary",
            "server": "s1",
            "status": 200,
            "request_time": 0,
            "queue_time": 0,
            "connect_time": 1,
            "response_time": 2,
            "total_time": 3,
            "bytes": 0,
        }
        line = json.dumps(body, separators=(",", ":"))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            part = root / f"alpha--node-a--{now:%Y-%m-%d}.jsonl"
            part.write_text(line[:40])
            target = NodeTarget("alpha", "node-a", "node-a.example.com")
            config = CollectorConfig(
                "svc-logread",
                root / "key",
                root / "known_hosts",
                root,
                root,
                (target,),
            )
            checkpoint = root / f".{part.name}.database-offset"
            with self.connect("HAPROXY_UI_TEST_COLLECTOR_ROLE") as connection:
                self.assertEqual(_ingest_part(config, connection, target, part), 0)
                self.assertFalse(checkpoint.exists())
                part.write_text(line + "\n")
                self.assertEqual(_ingest_part(config, connection, target, part), 0)
            self.assertEqual(int(checkpoint.read_text()), part.stat().st_size)
        with self.connect("HAPROXY_UI_TEST_WEB_ROLE") as connection, connection.cursor() as cursor:
            cursor.execute("select count(*) from traffic_log where host = 'partial.example.com'")
            self.assertEqual(cursor.fetchone(), (1,))

    def test_the_database_names_the_days_it_can_still_store(self) -> None:
        """The mirror keeps files for longer than the database keeps rows.

        That difference is deliberate - after a restore the mirror is the only
        thing left to replay from - so the collector asks which days exist
        rather than assuming its own window matches the platform's retention.
        """

        with self.connect("HAPROXY_UI_TEST_COLLECTOR_ROLE") as connection:
            days = _database_days(connection)
        self.assertIn(f"{datetime.now(UTC):%Y%m%d}", days)
        self.assertNotIn("19990101", days)

    def test_a_day_outside_the_window_is_refused_by_postgresql_not_stored(self) -> None:
        """The reason the filter above exists, stated as a measurement.

        A row whose day has no partition does not fail quietly on its own row:
        PostgreSQL refuses it, the transaction is lost, and with it every other
        node's batch in the same run.
        """

        old = datetime(1999, 1, 1, 12, tzinfo=UTC)
        record = {
            "schema": 1,
            "at": int(old.timestamp()),
            "request": 93,
            "client": "192.0.2.23",
            "method": "GET",
            "host": "expired.example.com",
            "path": "/gone",
            "frontend": "mgd-main-http",
            "backend": "mgd-app-primary",
            "server": "s1",
            "status": 200,
            "request_time": 0,
            "queue_time": 0,
            "connect_time": 1,
            "response_time": 2,
            "total_time": 3,
            "bytes": 0,
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            part = root / f"alpha--node-a--{old:%Y-%m-%d}.jsonl"
            part.write_text(json.dumps(record, separators=(",", ":")) + "\n")
            target = NodeTarget("alpha", "node-a", "node-a.example.com")
            config = CollectorConfig(
                "svc-logread",
                root / "key",
                root / "known_hosts",
                root,
                root,
                (target,),
            )
            with (
                self.connect("HAPROXY_UI_TEST_COLLECTOR_ROLE") as connection,
                self.assertRaises(psycopg.Error),
            ):
                _ingest_part(config, connection, target, part)

    def test_the_mirror_window_follows_the_database_with_one_margin_day(self) -> None:
        """One window, derived - not a second number kept in step by hand.

        The database's own retention decides how far back anything can be read,
        so the manager keeps that many days plus one to replay from after a
        restore. Days beyond it can be neither read nor imported.
        """

        now = datetime.now(UTC)
        with self.connect("HAPROXY_UI_TEST_COLLECTOR_ROLE") as connection:
            days = _database_days(connection)
        past = sum(1 for day in days if day <= f"{now:%Y%m%d}")
        config = CollectorConfig(
            "svc-logread",
            Path("/nonexistent/key"),
            Path("/nonexistent/known_hosts"),
            Path("/nonexistent/mirror"),
            Path("/nonexistent/staging"),
            (NodeTarget("alpha", "node-a", "node-a.example.com"),),
            os.environ["HAPROXY_UI_TEST_DATABASE_NAME"],
            os.environ["HAPROXY_UI_TEST_DATABASE_SOCKET"],
        )
        self.assertEqual(_mirror_window(config, now=now), past + 1)

    def test_an_unreachable_database_widens_the_window_rather_than_stopping_the_mirror(
        self,
    ) -> None:
        """Fetching is the part that cannot be caught up later.

        A node drops its own day files on its own schedule, so a run that cannot
        reach the database still has to mirror. It falls back to the wider
        window - the safe direction - and the import phase reports the failure.
        """

        config = CollectorConfig(
            "svc-logread",
            Path("/nonexistent/key"),
            Path("/nonexistent/known_hosts"),
            Path("/nonexistent/mirror"),
            Path("/nonexistent/staging"),
            (NodeTarget("alpha", "node-a", "node-a.example.com"),),
            "haproxy_ui_absent",
            "/nonexistent/socket",
        )
        self.assertEqual(_mirror_window(config, now=datetime.now(UTC)), RETENTION_DAYS)

    def test_database_search_uses_boolean_terms_status_and_newest_first(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temporary,
            self.connect("HAPROXY_UI_TEST_WEB_ROLE") as connection,
        ):
            reading = traffic_logs.read_database(
                connection,
                Path(temporary),
                ("alpha",),
                status="2xx",
                substring="copy AND ready NOT missing",
            )

        self.assertEqual([entry.host for entry in reading.entries], ["copy.example.com"])
        self.assertEqual(reading.entries[0].path, "/ready")

    def test_frontend_buckets_never_mix_two_nodes_uptime(self) -> None:
        #
        # Pinned to the start of a ten-minute bucket rather than placed relative
        # to now. `date_bin` bins against a fixed origin, so rows laid out at
        # `now - 20 min` and `+2 min` straddled a bucket boundary whenever that
        # minute ended in 8 or 9 - the test then failed about one run in five
        # while describing nothing but the clock.
        #
        now = datetime.now(UTC)
        start = now.replace(minute=now.minute // 10 * 10, second=0, microsecond=0) - timedelta(
            minutes=20
        )
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute("select metric_partition('metric_frontend', %s::date)", (start.date(),))
            cursor.executemany(
                "insert into metric_frontend "
                "(cluster, node, frontend, observed_at, owns_vip, uptime_sec, req_tot) "
                "values (%s, %s, %s, %s, true, %s, %s)",
                [
                    ("alpha", "node-a", "mgd-main-http", start, 5000, 5_000_000),
                    ("alpha", "node-b", "mgd-main-http", start + timedelta(minutes=1), 10, 100),
                    (
                        "alpha",
                        "node-a",
                        "mgd-main-http",
                        start + timedelta(minutes=2),
                        5120,
                        5_000_400,
                    ),
                ],
            )
        with self.connect("HAPROXY_UI_TEST_WEB_ROLE") as connection:
            samples = db.read_frontend_samples(
                connection,
                cluster="alpha",
                frontend="mgd-main-http",
                since=start,
                until=start + timedelta(minutes=9),
                width=timedelta(minutes=10),
            )
        by_node = {sample.node: sample for sample in samples}
        self.assertEqual(set(by_node), {"node-a", "node-b"})
        self.assertEqual(by_node["node-a"].floor_uptime_sec, 5000)
        self.assertEqual(by_node["node-b"].floor_uptime_sec, 10)


@unittest.skipUnless(DSN, "run through ui/tools/test-database")
class TheMetricTablesUnderTheirNewNames(unittest.TestCase):
    """Migration 0023 renamed the metric tables and left the old names as views.

    The views are what let the UI release before the rename accept this
    revision: it reads and writes `metric_listener` during the minutes between
    migration and activation, and again if the rename is rolled back. So the
    old names must carry exactly the old grants, and a row written through one
    name must be the row read through the other.
    """

    MIGRATION = (
        Path(__file__).resolve().parents[1]
        / "migrations"
        / "versions"
        / "0023_metric_table_names.py"
    )

    def connect(self, role_variable: str = "HAPROXY_UI_TEST_MIGRATION_ROLE") -> psycopg.Connection:
        return psycopg.connect(f"{DSN} user={os.environ[role_variable]}")

    def test_the_old_names_are_views_over_the_new_tables(self) -> None:
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "select relname, relkind from pg_class where relname in "
                "('metric_frontend', 'metric_backend_member', 'metric_backend_hour', "
                " 'metric_listener', 'metric_pool_member', 'metric_pool_hour') order by 1"
            )
            self.assertEqual(
                cursor.fetchall(),
                [
                    ("metric_backend_hour", "p"),
                    ("metric_backend_member", "p"),
                    ("metric_frontend", "p"),
                    ("metric_listener", "v"),
                    ("metric_pool_hour", "v"),
                    ("metric_pool_member", "v"),
                ],
            )

    def test_the_poller_writes_the_old_name_and_the_web_reads_the_new(self) -> None:
        day = datetime.now(UTC).date()
        with self.connect() as connection, connection.cursor() as cursor:
            #
            # Asked for under the old name, as the retention command installed
            # beside the previous release still does; made under the new one.
            #
            cursor.execute("select metric_partition('metric_listener', %s::date)", (day,))
            self.assertEqual(cursor.fetchone(), (f"metric_frontend_{day:%Y%m%d}",))
        with (
            self.connect("HAPROXY_UI_TEST_POLLER_ROLE") as connection,
            connection.cursor() as cursor,
        ):
            cursor.execute(
                "insert into metric_listener "
                "(cluster, node, frontend, owns_vip, uptime_sec, req_tot) "
                "values ('bridge', 'node-a', 'mgd-old-name', true, 60, 7)"
            )
        with self.connect("HAPROXY_UI_TEST_WEB_ROLE") as connection, connection.cursor() as cursor:
            cursor.execute(
                "select req_tot, observed_at is not null from metric_frontend "
                "where cluster = 'bridge' and frontend = 'mgd-old-name'"
            )
            self.assertEqual(cursor.fetchall(), [(7, True)])

    def test_the_rollup_boundary_moved_with_the_table(self) -> None:
        with self.connect("HAPROXY_UI_TEST_WEB_ROLE") as connection, connection.cursor() as cursor:
            cursor.execute("select rollup_name from metric_rollup_state order by 1")
            self.assertEqual(cursor.fetchall(), [("backend_hour",)])

    def test_partitions_and_their_indexes_are_renamed_with_the_parent(self) -> None:
        """The rename loop, exercised against a partition it has to carry along.

        The harness migrates an empty database, so no partition existed when
        0023 ran. This makes one, runs the migration's own downgrade and upgrade
        through the same statements alembic would, and checks the partition, its
        primary key, the read index and the check constraint changed prefix each
        way - because the retention command finds partitions by prefix, and one
        left behind would never be dropped.
        """

        day = datetime.now(UTC).date() + timedelta(days=200)
        suffix = f"{day:%Y%m%d}"
        migration = self.load_migration()

        def names(cursor: psycopg.Cursor, prefix: str) -> set[str]:
            cursor.execute(
                "select relname from pg_class where relname like %s "
                "union select conname from pg_constraint where conname like %s",
                (prefix + "%", prefix + "%"),
            )
            return {row[0] for row in cursor.fetchall()}

        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute("select metric_partition('metric_frontend', %s::date)", (day,))
            migration.op = _Executes(cursor)
            migration.downgrade()
            old = names(cursor, "metric_listener")
            self.assertIn(f"metric_listener_{suffix}", old)
            self.assertIn(f"metric_listener_{suffix}_pkey", old)
            self.assertIn("metric_listener_read", old)
            self.assertIn("metric_listener_cluster_shape", old)
            self.assertFalse(names(cursor, "metric_frontend"))
            migration.upgrade()
            new = names(cursor, "metric_frontend")
            self.assertIn(f"metric_frontend_{suffix}", new)
            self.assertIn(f"metric_frontend_{suffix}_pkey", new)
            self.assertIn("metric_frontend_read", new)
            self.assertIn("metric_frontend_cluster_shape", new)
            self.assertEqual(names(cursor, "metric_listener"), {"metric_listener"})

    def load_migration(self) -> Any:
        spec = importlib.util.spec_from_file_location("migration_0023", self.MIGRATION)
        if spec is None or spec.loader is None:
            self.fail(f"cannot load {self.MIGRATION}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module


class _Executes:
    """What the migration needs of alembic's `op`: `execute`, on our cursor."""

    def __init__(self, cursor: psycopg.Cursor) -> None:
        self.cursor = cursor

    def execute(self, sql: str) -> None:
        self.cursor.execute(sql)


@unittest.skipUnless(DSN, "run through ui/tools/test-database")
class TheQueueCarriesCertificateJobs(unittest.TestCase):
    """Migration 0024: a job whose scope is a certificate rather than a cluster.

    The constraints are the point. A cluster operation without a cluster and a
    certificate operation with one are both refused by the database, so a
    process that has been talked into queueing a job whose cluster column means
    nothing fails before a worker ever claims the row.
    """

    def connect(self, role_variable: str = "HAPROXY_UI_TEST_MIGRATION_ROLE") -> psycopg.Connection:
        role = os.environ[role_variable]
        return psycopg.connect(f"{DSN} user={role}")

    def setUp(self) -> None:
        self.connection = self.connect()
        self.addCleanup(self.connection.close)
        with self.connection.cursor() as cursor:
            cursor.execute("delete from job")
        self.connection.commit()

    def queue(self, operation: str, cluster: str | None, **payload: Any) -> db.Job:
        return db.queue_job(
            self.connection,
            operation=operation,
            cluster=cluster,
            payload=payload,
            idempotency_key=uuid4(),
        )

    def finish(self, job: db.Job) -> None:
        with self.connection.cursor() as cursor:
            cursor.execute(
                "update job set state = 'done', outcome = 'done', finished_at = now() "
                " where id = %(id)s",
                {"id": job.id},
            )
        self.connection.commit()

    def test_a_certificate_job_is_queued_with_no_cluster(self) -> None:
        job = self.queue("cert_publish", None, certificates=["example.com"])

        self.assertIsNone(job.cluster)
        self.assertEqual(job.operation, "cert_publish")

    def test_a_certificate_job_carrying_a_cluster_is_refused(self) -> None:
        with self.assertRaises(psycopg.errors.CheckViolation):
            self.queue("cert_publish", "alpha")

    def test_a_profile_s_apply_jobs_are_found_behind_any_number_of_newer_jobs(self) -> None:
        """2026-09-18: the form read the newest twenty of every kind and lost the apply job."""

        # One certificate job at a time: each is finished before the next is
        # queued, the way the worker leaves them.
        applied = self.queue("dns_profile_apply", None, profile="cf-main", revision=1)
        self.finish(applied)
        for index in range(25):
            self.finish(self.queue("cert_publish", None, certificates=[f"cert-{index}.example"]))

        recent = db.recent_jobs(self.connection)
        self.assertNotIn(applied.id, [job.id for job in recent])
        found = db.operation_jobs(self.connection, "dns_profile_apply")
        self.assertEqual([job.id for job in found], [applied.id])
        self.assertEqual(db.operation_jobs(self.connection, "ndes_profile_apply"), [])

    def test_a_receiver_job_is_queued_with_no_cluster(self) -> None:
        """Migration 0032: `cert_receiver` is on the list, and clusterless."""

        job = self.queue("cert_receiver", None, receiver="lb-02.example.net", action="remove")

        self.assertIsNone(job.cluster)
        with self.assertRaises(psycopg.errors.CheckViolation):
            self.queue("cert_receiver", "alpha", receiver="lb-02.example.net", action="remove")

    def test_an_import_job_is_queued_with_no_cluster(self) -> None:
        """Migration 0033: `cert_import` is on the list, and clusterless."""

        job = self.queue("cert_import", None, id="shop.example", key_id="0" * 16, ciphertext="AA==")

        self.assertIsNone(job.cluster)
        with self.assertRaises(psycopg.errors.CheckViolation):
            self.queue(
                "cert_import", "alpha", id="shop.example", key_id="0" * 16, ciphertext="AA=="
            )

    def test_a_signing_request_job_is_queued_with_no_cluster(self) -> None:
        """Migration 0034: `cert_request` is on the list, and clusterless."""

        job = self.queue("cert_request", None, id="shop.example", domains=["shop.example"])

        self.assertIsNone(job.cluster)
        with self.assertRaises(psycopg.errors.CheckViolation):
            self.queue("cert_request", "alpha", id="shop.example", domains=["shop.example"])

    def test_a_cluster_job_without_a_cluster_is_refused(self) -> None:
        with self.assertRaises(psycopg.errors.CheckViolation):
            self.queue("deploy", None)

    def test_only_one_certificate_job_may_be_in_flight_at_a_time(self) -> None:
        """The queue agreeing with the publisher, which takes one lock for all of them."""

        self.queue("cert_publish", None, certificates=["example.com"])

        with self.assertRaises(db.CertificateBusy):
            self.queue("cert_issue", None, domain="new.example")

    def test_a_certificate_job_does_not_make_a_cluster_busy(self) -> None:
        """It holds no cluster's slot, so a deploy may still be queued beside it."""

        self.queue("cert_publish", None, certificates=["example.com"])

        job = self.queue("deploy", "alpha")

        self.assertEqual(job.cluster, "alpha")

    def test_a_retry_of_a_certificate_job_is_the_job_it_already_queued(self) -> None:
        """`null = null` is null, so the retry lookup has to compare the absence too."""

        key = uuid4()
        payload = {"certificates": ["example.com"]}
        first = db.queue_job(
            self.connection,
            operation="cert_publish",
            cluster=None,
            payload=payload,
            idempotency_key=key,
        )

        second = db.queue_job(
            self.connection,
            operation="cert_publish",
            cluster=None,
            payload=payload,
            idempotency_key=key,
        )

        self.assertEqual(second.id, first.id)


@unittest.skipUnless(DSN, "run through ui/tools/test-database")
class TheProfileTableHoldsABoxNobodyHereCanOpen(unittest.TestCase):
    """Migration 0025: sealed DNS provider profiles and the job that applies them.

    The grants are the point. The web writes boxes and reads metadata; the
    worker reads a box to hand it to root; the poller sees nothing. Whether
    the box can be opened is not a question this database can answer, which
    is the whole design.
    """

    def connect(self, role_variable: str) -> psycopg.Connection:
        role = os.environ[role_variable]
        return psycopg.connect(f"{DSN} user={role}")

    def setUp(self) -> None:
        with self.connect("HAPROXY_UI_TEST_MIGRATION_ROLE") as connection:
            with connection.cursor() as cursor:
                cursor.execute("delete from job")
                cursor.execute("delete from dns_provider_profile")
            connection.commit()

    def test_the_web_creates_replaces_and_lists_without_seeing_the_box(self) -> None:
        with self.connect("HAPROXY_UI_TEST_WEB_ROLE") as connection:
            created = db.create_dns_profile(
                connection,
                profile_id="cf-main",
                name="Cloudflare main",
                provider_id="cloudflare",
                key_id="0123456789abcdef",
                ciphertext=b"x" * 48,
                actor="operator",
            )
            self.assertEqual(created.revision, 1)
            with self.assertRaises(db.ProfileExists):
                db.create_dns_profile(
                    connection,
                    profile_id="cf-main",
                    name="again",
                    provider_id="cloudflare",
                    key_id="0123456789abcdef",
                    ciphertext=b"y" * 48,
                    actor="operator",
                )
            replaced = db.replace_dns_profile(
                connection,
                profile_id="cf-main",
                revision=2,
                key_id="fedcba9876543210",
                ciphertext=b"z" * 48,
                actor="admin",
                name=None,
            )
            self.assertEqual(
                (replaced.revision, replaced.key_id, replaced.name),
                (2, "fedcba9876543210", "Cloudflare main"),
            )
            self.assertEqual(replaced.updated_by, "admin")
            with self.assertRaises(db.ProfileMissing):
                db.replace_dns_profile(
                    connection,
                    profile_id="cf-main",
                    revision=2,
                    key_id="fedcba9876543210",
                    ciphertext=b"w" * 48,
                    actor="admin",
                )
            self.assertEqual([row.id for row in db.dns_profiles(connection)], ["cf-main"])
            self.assertIsNone(db.dns_profile(connection, "missing"))
            with (
                connection.cursor() as cursor,
                self.assertRaises(psycopg.errors.InsufficientPrivilege),
            ):
                cursor.execute("select ciphertext from dns_provider_profile")
            connection.rollback()
            with (
                connection.cursor() as cursor,
                self.assertRaises(psycopg.errors.InsufficientPrivilege),
            ):
                cursor.execute("update dns_provider_profile set provider_id = 'hetzner'")
            connection.rollback()
            with (
                connection.cursor() as cursor,
                self.assertRaises(psycopg.errors.InsufficientPrivilege),
            ):
                cursor.execute("delete from dns_provider_profile")
            connection.rollback()

    def test_the_worker_reads_the_box_and_the_poller_reads_nothing(self) -> None:
        with self.connect("HAPROXY_UI_TEST_WEB_ROLE") as connection:
            db.create_dns_profile(
                connection,
                profile_id="cf-main",
                name="Cloudflare main",
                provider_id="cloudflare",
                key_id="0123456789abcdef",
                ciphertext=b"x" * 48,
                actor="operator",
            )
            connection.commit()
        with self.connect("HAPROXY_UI_TEST_WORKER_ROLE") as connection:
            sealed = db.sealed_profile(connection, "cf-main")
            self.assertIsNotNone(sealed)
            self.assertEqual(bytes(sealed.ciphertext if sealed else b""), b"x" * 48)
            with (
                connection.cursor() as cursor,
                self.assertRaises(psycopg.errors.InsufficientPrivilege),
            ):
                cursor.execute("select created_by from dns_provider_profile")
            connection.rollback()
            self.assertTrue(db.delete_dns_profile(connection, "cf-main", 1))
            self.assertFalse(db.delete_dns_profile(connection, "cf-main", 1))
            connection.commit()
        with (
            self.connect("HAPROXY_UI_TEST_POLLER_ROLE") as connection,
            connection.cursor() as cursor,
            self.assertRaises(psycopg.errors.InsufficientPrivilege),
        ):
            cursor.execute("select id from dns_provider_profile")

    def test_the_apply_job_is_a_certificate_job(self) -> None:
        with self.connect("HAPROXY_UI_TEST_WEB_ROLE") as connection:
            job = db.queue_job(
                connection,
                operation="dns_profile_apply",
                cluster=None,
                payload={"profile": "cf-main", "revision": 1},
                idempotency_key=uuid4(),
            )
            self.assertIsNone(job.cluster)
            with self.assertRaises(db.CertificateBusy):
                db.queue_job(
                    connection,
                    operation="cert_issue",
                    cluster=None,
                    payload={"domain": "example.com"},
                    idempotency_key=uuid4(),
                )
            connection.rollback()
            with self.assertRaises(psycopg.errors.CheckViolation):
                db.queue_job(
                    connection,
                    operation="dns_profile_apply",
                    cluster="alpha",
                    payload={},
                    idempotency_key=uuid4(),
                )

    def test_the_migration_downgrades_and_upgrades_cleanly_on_an_empty_queue(self) -> None:
        """The whitelist narrows and widens with the table, both ways, in one transaction."""

        migration_path = (
            Path(__file__).resolve().parents[1]
            / "migrations"
            / "versions"
            / "0025_dns_provider_profiles.py"
        )
        spec = importlib.util.spec_from_file_location("migration_0025", migration_path)
        if spec is None or spec.loader is None:
            self.fail(f"cannot load {migration_path}")
        migration = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(migration)

        with self.connect("HAPROXY_UI_TEST_MIGRATION_ROLE") as connection:
            with connection.cursor() as cursor:
                migration.op = _Executes(cursor)
                migration.downgrade()
                cursor.execute("select to_regclass('dns_provider_profile')")
                self.assertEqual(cursor.fetchone(), (None,))
                cursor.execute(
                    "select pg_get_constraintdef(oid) from pg_constraint "
                    "where conname = 'job_operation_allowed'"
                )
                self.assertNotIn("dns_profile_apply", cursor.fetchone()[0])
                migration.upgrade()
                cursor.execute("select to_regclass('dns_provider_profile')")
                self.assertEqual(cursor.fetchone(), ("dns_provider_profile",))
            connection.rollback()


@unittest.skipUnless(DSN, "run through ui/tools/test-database")
class CertificateDeletion(unittest.TestCase):
    """Migration 0026: the queue may carry `cert_delete`, in the certificate slot."""

    def connect(self, role_variable: str) -> psycopg.Connection:
        role = os.environ[role_variable]
        return psycopg.connect(f"{DSN} user={role}")

    def setUp(self) -> None:
        with self.connect("HAPROXY_UI_TEST_MIGRATION_ROLE") as connection:
            with connection.cursor() as cursor:
                cursor.execute("delete from job")
            connection.commit()

    def test_the_delete_job_is_a_clusterless_certificate_job(self) -> None:
        with self.connect("HAPROXY_UI_TEST_WEB_ROLE") as connection:
            job = db.queue_job(
                connection,
                operation="cert_delete",
                cluster=None,
                payload={"certificates": ["old.example.com"]},
                idempotency_key=uuid4(),
            )
            self.assertIsNone(job.cluster)
            with self.assertRaises(db.CertificateBusy):
                db.queue_job(
                    connection,
                    operation="cert_publish",
                    cluster=None,
                    payload={},
                    idempotency_key=uuid4(),
                )
            connection.rollback()

    def test_cert_scep_is_a_clusterless_certificate_job(self) -> None:
        # Migration 0029: the enrollment job in the same slot as the others.
        with self.connect("HAPROXY_UI_TEST_WEB_ROLE") as connection:
            job = db.queue_job(
                connection,
                operation="cert_scep",
                cluster=None,
                payload={"id": "web.example.com", "resume": True},
                idempotency_key=uuid4(),
            )
            self.assertIsNone(job.cluster)
            connection.rollback()
            with (
                connection.cursor() as cursor,
                self.assertRaises(psycopg.errors.CheckViolation),
            ):
                cursor.execute(
                    "insert into job (operation, cluster, payload, idempotency_key) "
                    "values ('cert_scep', 'alpha', '{}', %(key)s)",
                    {"key": uuid4()},
                )
            connection.rollback()
            with self.assertRaises(psycopg.errors.CheckViolation):
                db.queue_job(
                    connection,
                    operation="cert_delete",
                    cluster="alpha",
                    payload={},
                    idempotency_key=uuid4(),
                )

    def test_the_worker_cannot_read_drafts_so_the_draft_check_is_the_web_s(self) -> None:
        """What took the worker down on 2026-09-13: the run-time draft check.

        The grant is the design, not the bug. The worker publishes from the
        payload and never from the table, so the last look at the drafts is
        the moment the web queues the job; `db.live_drafts` is a web-only
        read and must fail here.
        """

        with (
            self.connect("HAPROXY_UI_TEST_WORKER_ROLE") as connection,
            self.assertRaises(psycopg.errors.InsufficientPrivilege),
        ):
            db.live_drafts(connection)
        with self.connect("HAPROXY_UI_TEST_WEB_ROLE") as connection:
            self.assertEqual(db.live_drafts(connection), [])

    def test_the_migration_downgrades_and_upgrades_cleanly_on_an_empty_queue(self) -> None:
        migration_path = (
            Path(__file__).resolve().parents[1] / "migrations" / "versions" / "0026_cert_delete.py"
        )
        spec = importlib.util.spec_from_file_location("migration_0026", migration_path)
        if spec is None or spec.loader is None:
            self.fail(f"cannot load {migration_path}")
        migration = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(migration)

        with self.connect("HAPROXY_UI_TEST_MIGRATION_ROLE") as connection:
            with connection.cursor() as cursor:
                migration.op = _Executes(cursor)
                migration.downgrade()
                cursor.execute(
                    "select pg_get_constraintdef(oid) from pg_constraint "
                    "where conname = 'job_operation_allowed'"
                )
                self.assertNotIn("cert_delete", cursor.fetchone()[0])
                migration.upgrade()
                cursor.execute(
                    "select pg_get_constraintdef(oid) from pg_constraint "
                    "where conname = 'job_operation_allowed'"
                )
                self.assertIn("cert_delete", cursor.fetchone()[0])
            connection.rollback()


@unittest.skipUnless(DSN, "run through ui/tools/test-database")
class NdesDatabase(unittest.TestCase):
    def connect(self, role_variable: str = "HAPROXY_UI_TEST_MIGRATION_ROLE") -> psycopg.Connection:
        return psycopg.connect(f"{DSN} user={os.environ[role_variable]}")

    def setUp(self) -> None:
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute("delete from job")
            cursor.execute("delete from ndes_provider_profile")
            connection.commit()

    def create(self) -> None:
        with self.connect("HAPROXY_UI_TEST_WEB_ROLE") as connection:
            db.create_ndes_profile(
                connection,
                profile_id="internal-ca",
                name="internal-ca",
                provider_id="ndes",
                key_id="0123456789abcdef",
                ciphertext=b"x" * 48,
                actor="admin",
                endpoint="https://ca.example.com/certsrv/mscep/mscep.dll",
            )
            connection.commit()

    def test_web_can_write_list_and_replace_but_cannot_read_ciphertext(self) -> None:
        self.create()
        with self.connect("HAPROXY_UI_TEST_WEB_ROLE") as connection:
            listed = db.ndes_profiles(connection)[0]
            self.assertEqual(listed.id, "internal-ca")
            self.assertEqual(listed.endpoint, "https://ca.example.com/certsrv/mscep/mscep.dll")
            self.assertIsNotNone(db.ndes_profile(connection, "internal-ca"))
            replaced = db.replace_ndes_profile(
                connection,
                profile_id="internal-ca",
                revision=2,
                key_id="0123456789abcdef",
                ciphertext=b"y" * 48,
                actor="admin",
                endpoint="https://ca2.example.com/certsrv/mscep/mscep.dll",
            )
            self.assertEqual(replaced.revision, 2)
            self.assertEqual(replaced.endpoint, "https://ca2.example.com/certsrv/mscep/mscep.dll")
            connection.commit()
            with self.assertRaises(db.ProfileMissing):
                db.replace_ndes_profile(
                    connection,
                    profile_id="internal-ca",
                    revision=2,
                    key_id="0123456789abcdef",
                    ciphertext=b"z" * 48,
                    actor="admin",
                    endpoint="https://ca.example.com/certsrv/mscep/mscep.dll",
                )
            with (
                connection.cursor() as cursor,
                self.assertRaises(psycopg.errors.CheckViolation),
            ):
                cursor.execute("update ndes_provider_profile set endpoint = 'http://plain'")
            connection.rollback()
            for sql in (
                "select ciphertext from ndes_provider_profile",
                "delete from ndes_provider_profile",
                "update ndes_provider_profile set provider_id = 'cloudflare'",
            ):
                with (
                    connection.cursor() as cursor,
                    self.assertRaises(psycopg.errors.InsufficientPrivilege),
                ):
                    cursor.execute(sql)
                connection.rollback()

    def test_worker_reads_only_sealed_binding_and_poller_has_no_access(self) -> None:
        self.create()
        with self.connect("HAPROXY_UI_TEST_WORKER_ROLE") as connection:
            row = db.sealed_ndes_profile(connection, "internal-ca")
            self.assertIsNotNone(row)
            self.assertEqual(row.ciphertext if row else None, b"x" * 48)
            # The removal job's last step: exactly the fenced row, nothing else.
            self.assertFalse(db.delete_ndes_profile(connection, "internal-ca", 7))
            self.assertTrue(db.delete_ndes_profile(connection, "internal-ca", 1))
            connection.rollback()
            with (
                connection.cursor() as cursor,
                self.assertRaises(psycopg.errors.InsufficientPrivilege),
            ):
                cursor.execute("select created_by from ndes_provider_profile")
            connection.rollback()
        with self.connect("HAPROXY_UI_TEST_POLLER_ROLE") as connection:
            with (
                connection.cursor() as cursor,
                self.assertRaises(psycopg.errors.InsufficientPrivilege),
            ):
                cursor.execute("select id from ndes_provider_profile")
            connection.rollback()

    def test_ndes_apply_uses_the_shared_certificate_slot(self) -> None:
        with self.connect("HAPROXY_UI_TEST_WEB_ROLE") as connection:
            job = db.queue_job(
                connection,
                operation="ndes_profile_apply",
                cluster=None,
                payload={"profile": "internal-ca", "revision": 1},
                idempotency_key=uuid4(),
            )
            self.assertIsNone(job.cluster)
            with self.assertRaises(db.CertificateBusy):
                db.queue_job(
                    connection,
                    operation="cert_publish",
                    cluster=None,
                    payload={},
                    idempotency_key=uuid4(),
                )
            connection.rollback()


@unittest.skipUnless(DSN, "run through ui/tools/test-database")
class AccountsFromTheWeb(unittest.TestCase):
    """Migration 0039: the web writes accounts inside grants and a guard (B187)."""

    HASH = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA"

    def connect(self, role_variable: str = "HAPROXY_UI_TEST_MIGRATION_ROLE") -> psycopg.Connection:
        return psycopg.connect(f"{DSN} user={os.environ[role_variable]}")

    def setUp(self) -> None:
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute("delete from app_user")
            cursor.execute("delete from login_attempt")
            cursor.execute("delete from login_unlock")
            for name, role in (("alice", "admin"), ("bob", "admin"), ("carol", "reader")):
                cursor.execute(
                    "insert into app_user (username, password_hash, role) values (%s, %s, %s)",
                    (name, self.HASH, role),
                )
            connection.commit()

    def tearDown(self) -> None:
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute("delete from app_user")
            cursor.execute("delete from login_attempt")
            cursor.execute("delete from login_unlock")
            connection.commit()

    def web(self, statement: str, parameters: tuple[Any, ...] = ()) -> None:
        with self.connect("HAPROXY_UI_TEST_WEB_ROLE") as connection:
            connection.execute(statement, parameters)
            connection.commit()

    def test_the_web_creates_and_changes_an_account_but_never_its_dates_or_its_row(self) -> None:
        self.web(
            "insert into app_user (username, password_hash, role) values ('dave', %s, 'reader')",
            (self.HASH,),
        )
        self.web("update app_user set role = 'admin' where username = 'dave'")
        for statement in (
            "insert into app_user (username, password_hash, role, created_at) "
            "values ('eve', '" + self.HASH + "', 'reader', now() - interval '1 year')",
            "update app_user set updated_at = now() - interval '1 year' where username = 'dave'",
            "update app_user set username = 'mallory' where username = 'dave'",
            "delete from app_user where username = 'carol'",
        ):
            with (
                self.subTest(statement=statement),
                self.assertRaises(psycopg.errors.InsufficientPrivilege),
            ):
                self.web(statement)

    def test_an_update_moves_updated_at_whoever_writes_it(self) -> None:
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "update app_user set updated_at = now() - interval '1 year' where username = 'carol'"
            )
            connection.commit()
        self.web("update app_user set disabled = true where username = 'carol'")
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "select updated_at > now() - interval '1 minute' from app_user "
                "where username = 'carol'"
            )
            self.assertEqual(cursor.fetchone(), (True,))

    def test_the_web_changes_its_own_password_and_ends_only_the_other_sessions(self) -> None:
        """U3's one statement pair, under the web's grants and nothing more."""

        kept, other = auth.token_hash("kept"), auth.token_hash("other")
        with self.connect("HAPROXY_UI_TEST_WEB_ROLE") as connection:
            user_id = connection.execute(
                "select id from app_user where username = 'carol'"
            ).fetchone()[0]  # type: ignore[index]
            for token in (kept, other):
                db.create_session(
                    connection,
                    token_hash=token,
                    user_id=user_id,
                    expires_at=datetime.now(UTC) + timedelta(hours=1),
                )
            connection.commit()
            ended = db.change_password(
                connection, user_id=user_id, password_hash=self.HASH + "x", keep=kept
            )
            connection.commit()
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "select token_hash, revoked_at is not null from app_session "
                "where user_id = %s order by revoked_at nulls first",
                (user_id,),
            )
            sessions = cursor.fetchall()
            cursor.execute(
                "select password_hash, updated_at > now() - interval '1 minute' "
                "from app_user where id = %s",
                (user_id,),
            )
            account = cursor.fetchone()
            cursor.execute("delete from app_session where user_id = %s", (user_id,))
            connection.commit()

        self.assertEqual(ended, 1)
        self.assertEqual(sessions, [(kept, False), (other, True)])
        self.assertEqual(account, (self.HASH + "x", True))

    def web_connection(self) -> Any:
        return self.connect("HAPROXY_UI_TEST_WEB_ROLE")

    def test_settings_lists_accounts_and_reads_a_lock_from_any_one_address(self) -> None:
        with self.web_connection() as connection:
            for address in ("192.0.2.1", "192.0.2.1", "192.0.2.2"):
                db.record_login_attempt(
                    connection, username="carol", client_ip=address, succeeded=False
                )
            db.record_login_attempt(
                connection, username="bob", client_ip="192.0.2.1", succeeded=True
            )
            connection.commit()
            rows = db.account_rows(connection, window_minutes=15, max_failures=2)
            self.assertEqual([r.username for r in rows], ["alice", "bob", "carol"])
            by_name = {r.username: r for r in rows}
            self.assertTrue(by_name["carol"].locked)
            self.assertFalse(by_name["bob"].locked)
            self.assertIsNotNone(by_name["bob"].last_sign_in)
            self.assertIsNone(by_name["alice"].last_sign_in)

            db.unlock_account(connection, username="Carol", actor="alice")
            connection.commit()
            carol = db.account_row(connection, "carol", window_minutes=15, max_failures=2)
            self.assertIsNotNone(carol)
            self.assertFalse(getattr(carol, "locked", True))

    def test_the_web_s_account_verbs_under_its_own_grants(self) -> None:
        with self.web_connection() as connection:
            self.assertTrue(
                db.create_account(
                    connection, username="dave", password_hash=self.HASH, role="reader"
                )
            )
            self.assertFalse(
                db.create_account(
                    connection, username="DAVE", password_hash=self.HASH, role="admin"
                )
            )
            dave = db.account_row(connection, "dave", window_minutes=15, max_failures=10)
            assert dave is not None  # noqa: S101 - the row was just created
            db.set_role(connection, user_id=dave.id, role="admin")
            self.assertEqual(db.set_disabled(connection, user_id=dave.id, disabled=True), 0)
            db.set_disabled(connection, user_id=dave.id, disabled=False)
            self.assertEqual(
                db.reset_password(connection, user_id=dave.id, password_hash=self.HASH + "y"), 0
            )
            connection.commit()
            dave = db.account_row(connection, "dave", window_minutes=15, max_failures=10)
            self.assertEqual(
                (getattr(dave, "role", None), getattr(dave, "disabled", None)), ("admin", False)
            )

    def test_the_last_admin_refusal_reaches_the_web_as_last_admin(self) -> None:
        with self.web_connection() as connection:
            rows = {
                r.username: r
                for r in db.account_rows(connection, window_minutes=15, max_failures=10)
            }
            db.set_disabled(connection, user_id=rows["bob"].id, disabled=True)
            with self.assertRaises(db.LastAdmin):
                db.set_role(connection, user_id=rows["alice"].id, role="reader")
            # The savepoint leaves the transaction usable for what comes after.
            db.record_audit_event(connection, actor="alice", action="probe", detail={})
            connection.commit()

    def test_the_last_active_admin_is_neither_disabled_nor_demoted(self) -> None:
        self.web("update app_user set disabled = true where username = 'bob'")
        for statement in (
            "update app_user set disabled = true where username = 'alice'",
            "update app_user set role = 'reader' where username = 'alice'",
        ):
            with (
                self.subTest(statement=statement),
                self.assertRaises(psycopg.errors.CheckViolation),
            ):
                self.web(statement)
        # The migration role is held to the same rule: the CLI's disable.
        with self.connect() as connection, self.assertRaises(psycopg.errors.CheckViolation):
            connection.execute("update app_user set disabled = true where username = 'alice'")
        # A reader, and enabling bob, pass.
        self.web("update app_user set disabled = true where username = 'carol'")
        self.web("update app_user set disabled = false where username = 'bob'")
        self.web("update app_user set role = 'reader' where username = 'alice'")

    def test_two_admins_disabling_each_other_at_once_cannot_both_pass(self) -> None:
        import threading

        first = self.connect("HAPROXY_UI_TEST_WEB_ROLE")
        second = self.connect("HAPROXY_UI_TEST_WEB_ROLE")
        outcome: list[BaseException | None] = []
        try:
            first.execute("update app_user set disabled = true where username = 'alice'")

            def other() -> None:
                try:
                    second.execute("update app_user set disabled = true where username = 'bob'")
                    second.commit()
                    outcome.append(None)
                except psycopg.Error as exc:
                    second.rollback()
                    outcome.append(exc)

            thread = threading.Thread(target=other)
            thread.start()
            thread.join(0.5)
            self.assertTrue(thread.is_alive(), "the second change must wait for the first")
            first.commit()
            thread.join(5)
            self.assertEqual(len(outcome), 1)
            self.assertIsInstance(outcome[0], psycopg.errors.CheckViolation)
        finally:
            first.close()
            second.close()

    def test_an_unlock_is_a_row_the_throttle_counts_from(self) -> None:
        with self.connect("HAPROXY_UI_TEST_WEB_ROLE") as connection:
            for _ in range(3):
                db.record_login_attempt(
                    connection, username="Carol", client_ip="192.0.2.7", succeeded=False
                )
            connection.commit()
            self.assertEqual(
                db.failures_since_last_success(
                    connection, username="carol", client_ip="192.0.2.7", window_minutes=15
                ),
                3,
            )
            connection.execute(
                "insert into login_unlock (username_normalised, actor) values ('carol', 'alice')"
            )
            connection.commit()
            self.assertEqual(
                db.failures_since_last_success(
                    connection, username="carol", client_ip="192.0.2.7", window_minutes=15
                ),
                0,
            )
        for statement in (
            "delete from login_attempt",
            "delete from login_unlock",
            "update login_unlock set actor = 'x'",
            "insert into login_unlock (username_normalised, actor, at) "
            "values ('carol', 'alice', now() + interval '1 day')",
        ):
            with (
                self.subTest(statement=statement),
                self.assertRaises(psycopg.errors.InsufficientPrivilege),
            ):
                self.web(statement)

    def test_the_migration_downgrades_and_upgrades_cleanly(self) -> None:
        migration_path = (
            Path(__file__).resolve().parents[1]
            / "migrations"
            / "versions"
            / "0039_accounts_from_the_web.py"
        )
        spec = importlib.util.spec_from_file_location("migration_0039", migration_path)
        if spec is None or spec.loader is None:
            self.fail(f"cannot load {migration_path}")
        migration = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(migration)

        with self.connect() as connection:
            with connection.cursor() as cursor:
                migration.op = _Executes(cursor)
                migration.downgrade()
                cursor.execute("select to_regclass('login_unlock')")
                self.assertEqual(cursor.fetchone(), (None,))
                migration.upgrade()
                cursor.execute("select to_regclass('login_unlock')")
                self.assertEqual(cursor.fetchone(), ("login_unlock",))
            connection.rollback()
