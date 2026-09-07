"""Checks that need PostgreSQL rather than an imitation of its cursor."""

from __future__ import annotations

import os
import unittest
from datetime import UTC, datetime, timedelta

import psycopg

from haproxy_ui import db

DSN = os.environ.get("HAPROXY_UI_TEST_DATABASE_DSN", "")


@unittest.skipUnless(DSN, "run through ui/tools/test-database")
class ARealDatabase(unittest.TestCase):
    def connect(self, role_variable: str = "HAPROXY_UI_TEST_MIGRATION_ROLE") -> psycopg.Connection:
        role = os.environ[role_variable]
        return psycopg.connect(f"{DSN} user={role}")

    def test_every_migration_reaches_the_declared_head(self) -> None:
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute("select version_num from alembic_version")
            self.assertEqual(cursor.fetchone(), ("0022",))

    def test_runtime_accounts_inherit_exactly_one_contract_role(self) -> None:
        expected = {
            "HAPROXY_UI_TEST_WEB_ROLE": "app_web",
            "HAPROXY_UI_TEST_WORKER_ROLE": "app_worker",
            "HAPROXY_UI_TEST_POLLER_ROLE": "app_poller",
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
            cursor.execute("select metric_partition('metric_listener', %s::date)", (now.date(),))
        with (
            self.connect("HAPROXY_UI_TEST_POLLER_ROLE") as connection,
            connection.cursor() as cursor,
        ):
            cursor.execute(
                "insert into metric_listener "
                "(cluster, node, frontend, owns_vip, uptime_sec, req_tot) "
                "values ('alpha', 'node-a', 'mgd-main-http', true, 60, 1)"
            )
        with (
            self.connect("HAPROXY_UI_TEST_POLLER_ROLE") as connection,
            connection.cursor() as cursor,
            self.assertRaises(psycopg.errors.InsufficientPrivilege),
        ):
            cursor.execute("select id from job limit 0")

    def test_listener_buckets_never_mix_two_nodes_uptime(self) -> None:
        start = datetime.now(UTC).replace(second=0, microsecond=0) - timedelta(minutes=20)
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute("select metric_partition('metric_listener', %s::date)", (start.date(),))
            cursor.executemany(
                "insert into metric_listener "
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
            samples = db.read_listener_samples(
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
