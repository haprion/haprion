"""Checks that need PostgreSQL rather than an imitation of its cursor."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import re
import subprocess
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest import mock
from uuid import uuid4

import psycopg
from haproxy_mgmt.traffic_collector import (
    RETENTION_DAYS,
    CollectorConfig,
    NodeTarget,
    _database_days,
    _ingest_part,
    _mirror_window,
    forget_database_positions,
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

    def test_retention_removes_oidc_sign_ins_older_than_a_day(self) -> None:
        """The clause is printed by the retention command itself, as above."""

        script = Path(__file__).resolve().parents[2] / "install/platform/bin/haproxy-ui-retention"
        clause = subprocess.run(  # noqa: S603 - fixed interpreter, the repository's script
            [
                "/bin/bash",
                "-c",
                'eval "$(sed -n'
                " '/^OIDC_LOGIN_KEEP_HOURS=/p;/^where_oidc_login_expired() {/,/^}/p'"
                ' "$0")"; where_oidc_login_expired',
                str(script),
            ],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        ages = {"fresh": "1 minute", "used-today": "23 hours", "yesterday": "25 hours"}
        with self.connect() as connection, connection.cursor() as cursor:
            for name, age in ages.items():
                cursor.execute(
                    "insert into oidc_login (state, nonce, verifier, mode, pre_session_hash, "
                    "created_at, used_at) values (%(state)s, %(filler)s, %(filler)s, 'sign_in', "
                    "%(hash)s, now() - %(age)s::interval, "
                    "case when %(name)s = 'used-today' then now() end)",
                    {
                        "state": name.ljust(32, "-"),
                        "filler": "v" * 43,
                        "hash": b"h" * 32,
                        "age": age,
                        "name": name,
                    },
                )
            cursor.execute(f"select state from oidc_login where {clause}")  # noqa: S608 - the script's own
            removable = {row[0].rstrip("-") for row in cursor.fetchall()}
            self.assertEqual(removable, {"yesterday"})
            connection.rollback()

    def retention_clause(self, function: str, keep: str) -> str:
        script = Path(__file__).resolve().parents[2] / "install/platform/bin/haproxy-ui-retention"
        return subprocess.run(  # noqa: S603 - fixed interpreter, the repository's script
            [
                "/bin/bash",
                "-c",
                f'eval "$(sed -n \'/^{keep}=/p;/^{function}() {{/,/^}}/p\' "$0")"; {function}',
                str(script),
            ],
            capture_output=True,
            text=True,
            check=True,
        ).stdout

    def test_retention_removes_sessions_a_month_after_they_ended(self) -> None:
        """Review 2026-09-28 F07; the clause is the retention command's own."""

        from haproxy_ui import auth

        clause = self.retention_clause("where_session_ended", "SESSION_KEEP_DAYS")
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "insert into app_user (username, password_hash, role) "
                "values ('retention-probe', %s, 'reader') returning id",
                (auth.hash_password("a long enough password"),),
            )
            user = cursor.fetchone()[0]
            sessions = {
                b"live": ("now() - interval '1 day'", "now() + interval '1 day'", "null"),
                b"expired-recently": (
                    "now() - interval '9 days'",
                    "now() - interval '2 days'",
                    "null",
                ),
                b"expired-long-ago": (
                    "now() - interval '60 days'",
                    "now() - interval '40 days'",
                    "null",
                ),
                b"revoked-long-ago": (
                    "now() - interval '60 days'",
                    "now() + interval '1 day'",
                    "now() - interval '40 days'",
                ),
            }
            for name, (created, expires, revoked) in sessions.items():
                cursor.execute(
                    "insert into app_session (token_hash, user_id, created_at, last_seen_at, "  # noqa: S608 - fixed literals
                    f"expires_at, revoked_at) values (%s, %s, {created}, {created}, {expires}, {revoked})",
                    (name.ljust(32, b"-"), user),
                )
            cursor.execute(f"select token_hash from app_session where {clause}")  # noqa: S608 - the script's own
            removable = {bytes(row[0]).rstrip(b"-") for row in cursor.fetchall()}
            self.assertEqual(removable, {b"expired-long-ago", b"revoked-long-ago"})
            connection.rollback()

    def test_retention_keeps_each_name_s_last_sign_in(self) -> None:
        """Old attempts go, except the newest success that "Last sign-in" reads."""

        clause = self.retention_clause("where_login_attempt_old", "LOGIN_ATTEMPT_KEEP_DAYS")
        attempts = (
            ("recent-failure", "fresh", "1 day", False),
            ("old-failure", "fresh", "100 days", False),
            ("old-success", "fresh", "120 days", True),
            ("newer-old-success", "rare", "100 days", True),
            ("older-old-success", "rare", "200 days", True),
            ("recent-success", "fresh", "2 days", True),
        )
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute("delete from login_attempt")
            ids = {}
            for label, name, age, succeeded in attempts:
                cursor.execute(
                    "insert into login_attempt (at, username_normalised, client_ip, succeeded) "
                    "values (now() - %s::interval, %s, '192.0.2.10', %s) returning id",
                    (age, name, succeeded),
                )
                ids[cursor.fetchone()[0]] = label
            cursor.execute(f"select id from login_attempt where {clause}")  # noqa: S608 - the script's own
            removable = {ids[row[0]] for row in cursor.fetchall()}
            self.assertEqual(removable, {"old-failure", "old-success", "older-old-success"})
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
            self.assertEqual(cursor.fetchone(), ("0045",))

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

    def test_the_poller_records_cluster_settings_and_web_only_reads_them(self) -> None:
        # Fas 15: the cache the Settings card reads, written only by the poller.
        result = {
            "cluster": "alpha",
            "head": "a" * 40,
            "stored": False,
            "log_targets": [],
            "metrics": None,
        }
        with self.connect("HAPROXY_UI_TEST_POLLER_ROLE") as connection:
            db.record_cluster_settings(connection, cluster="alpha", outcome="done", result=result)
            db.record_cluster_settings(connection, cluster="alpha", outcome="done", result=result)
            connection.commit()
        with self.connect("HAPROXY_UI_TEST_WEB_ROLE") as connection:
            (row,) = db.cluster_settings(connection)
            self.assertEqual((row.cluster, row.result), ("alpha", result))
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                db.record_cluster_settings(
                    connection, cluster="beta", outcome="done", result=result
                )
        with self.connect() as connection:
            connection.execute("delete from cluster_settings")
            connection.commit()

    def test_the_poller_replaces_the_cluster_list_and_web_only_reads_it(self) -> None:
        # Fas 16 (B206/B211): one row, replaced by update, so no delete grant.
        with self.connect("HAPROXY_UI_TEST_WEB_ROLE") as connection:
            self.assertIsNone(db.cluster_list(connection))
        with self.connect("HAPROXY_UI_TEST_POLLER_ROLE") as connection:
            db.record_cluster_list(connection, ["alpha", "beta"])
            db.record_cluster_list(connection, ["beta", "gamma"])
            connection.commit()
        with self.connect("HAPROXY_UI_TEST_WEB_ROLE") as connection:
            self.assertEqual(db.cluster_list(connection), ("beta", "gamma"))
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                db.record_cluster_list(connection, ["alpha"])
        with self.connect() as connection:
            connection.execute("delete from cluster_list")
            connection.commit()

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

    def test_a_database_restored_on_its_own_gets_back_what_staging_still_holds(self) -> None:
        """Review 2026-09-30, R3, its acceptance case.

        A is imported, the dump is taken, B is imported, and only the database
        goes back to the dump - B's row is gone while staging and its position
        still say B was imported. Replaying brings B back and A stays one row.
        The restore is played by removing B's row as the owner, which is what
        the database looks like afterwards; staging is the collector's own.
        """

        now = datetime.now(UTC).replace(microsecond=0)

        def line(host: str, request: int) -> str:
            return json.dumps(
                {
                    "schema": 1,
                    "at": int(now.timestamp()),
                    "request": request,
                    "client": "192.0.2.21",
                    "method": "GET",
                    "host": host,
                    "path": "/",
                    "frontend": "mgd-main-http",
                    "backend": "mgd-app-primary",
                    "server": "s1",
                    "status": 200,
                    "request_time": 0,
                    "queue_time": 0,
                    "connect_time": 1,
                    "response_time": 2,
                    "total_time": 3,
                    "bytes": 10,
                },
                separators=(",", ":"),
            )

        def count(host: str) -> int:
            with (
                self.connect("HAPROXY_UI_TEST_WEB_ROLE") as connection,
                connection.cursor() as cursor,
            ):
                cursor.execute("select count(*) from traffic_log where host = %s", (host,))
                row = cursor.fetchone()
                return -1 if row is None else int(row[0])

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            part = root / f"alpha--node-r3--{now:%Y-%m-%d}.jsonl"
            target = NodeTarget("alpha", "node-r3", "node-r3.example.com")
            config = CollectorConfig(
                "svc-logread", root / "key", root / "known_hosts", root, root, (target,)
            )
            part.write_text(line("a.restore.example.com", 1) + "\n")
            with self.connect("HAPROXY_UI_TEST_COLLECTOR_ROLE") as connection:
                _ingest_part(config, connection, target, part)
            with part.open("a") as stream:
                stream.write(line("b.restore.example.com", 2) + "\n")
            with self.connect("HAPROXY_UI_TEST_COLLECTOR_ROLE") as connection:
                _ingest_part(config, connection, target, part)
            with self.connect() as connection, connection.cursor() as cursor:
                cursor.execute("delete from traffic_log where host = 'b.restore.example.com'")
            self.assertEqual(count("b.restore.example.com"), 0)

            with self.connect("HAPROXY_UI_TEST_COLLECTOR_ROLE") as connection:
                _ingest_part(config, connection, target, part)
            self.assertEqual(count("b.restore.example.com"), 0, "without the replay B stays lost")

            self.assertEqual(forget_database_positions(config), 1)
            with self.connect("HAPROXY_UI_TEST_COLLECTOR_ROLE") as connection:
                _ingest_part(config, connection, target, part)

        self.assertEqual(count("b.restore.example.com"), 1)
        self.assertEqual(count("a.restore.example.com"), 1)

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

    def test_the_dashboard_sums_every_frontend_the_way_each_card_counts_one(self) -> None:
        """B220, 2026-10-01: one query for the dashboard, the card's own arithmetic.

        Two frontends in `alpha` - one restarting part way - a frontend in
        `beta` that is not asked for, and a node that does not hold the VIP.
        The sum must be the two cards' figures added, so the dashboard and the
        metrics page cannot disagree about what a counter did.
        """

        start = datetime.now(UTC).replace(second=0, microsecond=0) - timedelta(minutes=30)
        rows = [
            # (cluster, node, frontend, minute, owns_vip, uptime, req_tot, bin, bout)
            ("alpha", "node-a", "mgd-one-http", 0, True, 1000, 100, 10_000, 90_000),
            ("alpha", "node-a", "mgd-one-http", 1, True, 1060, 160, 16_000, 150_000),
            ("alpha", "node-a", "mgd-one-http", 2, True, 1120, 200, 20_000, 190_000),
            ("alpha", "node-a", "mgd-two-http", 0, True, 1000, 5_000, 1_000, 2_000),
            ("alpha", "node-a", "mgd-two-http", 1, True, 30, 40, 100, 300),
            ("alpha", "node-a", "mgd-two-http", 2, True, 90, 70, 400, 900),
            ("alpha", "node-b", "mgd-one-http", 1, False, 500, 9_999, 9_999, 9_999),
            ("alpha", "node-b", "mgd-one-http", 2, False, 560, 19_999, 19_999, 19_999),
            ("beta", "node-c", "mgd-one-http", 0, True, 1000, 0, 0, 0),
            ("beta", "node-c", "mgd-one-http", 2, True, 1120, 777, 777, 777),
        ]
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute("select metric_partition('metric_frontend', %s::date)", (start.date(),))
            cursor.execute(
                "select metric_partition('metric_frontend', %s::date)",
                ((start + timedelta(minutes=2)).date(),),
            )
            cursor.executemany(
                "insert into metric_frontend "
                "(cluster, node, frontend, observed_at, owns_vip, uptime_sec, req_tot, bin, bout) "
                "values (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                [
                    (c, n, f, start + timedelta(minutes=m), o, u, r, i, out)
                    for c, n, f, m, o, u, r, i, out in rows
                ],
            )
        until = start + timedelta(minutes=3)
        with self.connect("HAPROXY_UI_TEST_WEB_ROLE") as connection:
            summed = db.read_traffic_summary(
                connection, clusters=["alpha"], since=start, until=until
            )
            cards = [
                db.read_frontend_totals(
                    connection, cluster="alpha", frontend=name, since=start, until=until
                )
                for name in ("mgd-one-http", "mgd-two-http")
            ]
        by_label = {total.label: total for total in summed.totals}
        #
        # mgd-one: 60 + 40 requests. mgd-two restarted at minute 1, so that
        # interval carries what the new process counted (40), then 30 more.
        #
        self.assertEqual(by_label["Requests"].value, 100 + 40 + 30)
        self.assertEqual(
            by_label["Requests"].value,
            sum(next(t.value for t in card.totals if t.label == "Requests") for card in cards),
        )
        self.assertEqual(by_label["Bytes in"].value, 10_000 + 100 + 300)
        self.assertEqual(by_label["Bytes out"].value, 100_000 + 300 + 600)
        self.assertTrue(summed.restarted)
        self.assertFalse(by_label["Requests"].whole, "the restart's minute was not seen whole")

    def test_response_times_leave_out_requests_no_server_answered(self) -> None:
        now = datetime.now(UTC).replace(microsecond=0)
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute("select traffic_log_partition(%s::date)", (now.date(),))
            cursor.executemany(
                "insert into traffic_log (event_id, cluster, node, occurred_at, request_number, "
                "client, method, host, path, frontend, backend, server, status, request_time, "
                "queue_time, connect_time, response_time, total_time, bytes) values "
                "(%s, %s, 'node-a', %s, %s, '192.0.2.30', 'GET', 'rt.example.com', '/', "
                "'mgd-main-http', 'mgd-app', 's1', 200, 0, 0, 1, %s, 5, 10)",
                [
                    (os.urandom(32), "rt-only", now, number, response)
                    for number, response in enumerate((*range(1, 101), -1, -1, -1))
                ]
                + [(os.urandom(32), "rt-other", now, 500, 99_999)],
            )
        with self.connect("HAPROXY_UI_TEST_WEB_ROLE") as connection:
            answered, median, p95 = db.read_response_times(
                connection,
                clusters=["rt-only"],
                since=now - timedelta(minutes=1),
                until=now + timedelta(minutes=1),
            )
        self.assertEqual((answered, median, p95), (100, 50, 95))


@unittest.skipUnless(DSN, "run through ui/tools/test-database")
class TheInstallCheckMatchesTheMigrations(unittest.TestCase):
    """`03-verify`'s tables and grants, held against a database at head.

    The step is a second description of the privilege surface on purpose, and
    it is written by hand from what a migration grants. Twice (2026-09-04 and
    2026-09-27, `0039`) it was not, and the gap showed as a failed production
    install after every gate had passed. Read out of the script, so what is
    proved here is the list the install compares with; the list itself is still
    written by hand, never from this test's diff.
    """

    SCRIPT = Path(__file__).resolve().parents[2] / "install/platform/03-verify"

    def expected(self) -> tuple[list[str], list[str]]:
        text = self.SCRIPT.read_text()
        tables = re.search(r"^expected_tables=\$'([^']*)'$", text, re.MULTILINE)
        grants = re.search(
            r"^expected_grants=\$\(cat <<'EOF'\n(.*?)\nEOF$", text, re.MULTILINE | re.DOTALL
        )
        if tables is None or grants is None:
            self.fail("03-verify no longer states its lists in the shape this reads")
        return tables.group(1).split("\\n"), grants.group(1).split("\n")

    def test_the_tables_and_grants_are_the_ones_the_install_step_expects(self) -> None:
        tables, grants = self.expected()
        role = os.environ["HAPROXY_UI_TEST_MIGRATION_ROLE"]
        with psycopg.connect(f"{DSN} user={role}") as connection, connection.cursor() as cursor:
            cursor.execute(
                "select c.relname from pg_class c"
                "  join pg_namespace n on n.oid = c.relnamespace"
                " where n.nspname = 'public' and c.relkind in ('r', 'p')"
                "   and not c.relispartition order by 1"
            )
            actual_tables = [name for (name,) in cursor.fetchall()]
            cursor.execute(
                "select grantee, table_name, privilege_type,"
                "       string_agg(column_name, ', ' order by column_name)"
                "  from information_schema.column_privileges"
                " where table_schema = 'public' and grantee like 'app\\_%'"
                " group by grantee, table_name, privilege_type"
                " order by grantee, table_name, privilege_type"
            )
            actual_grants = ["\t".join(row) for row in cursor.fetchall()]

        self.assertEqual(actual_tables, tables)
        self.assertEqual(actual_grants, grants)

    def test_what_the_step_says_the_web_cannot_do_it_cannot_and_what_it_can_it_can(self) -> None:
        text = self.SCRIPT.read_text()
        probes = re.findall(
            r'^(refuse|allow) "\$WEB_USER"\s+"([^"]+)" \\\n\s+"((?:[^"\\]|\\.)*)"',
            text,
            re.MULTILINE,
        )
        self.assertGreater(len(probes), 5)
        #
        # `allow` reads its expected answer as $4 under `set -u`: a call with
        # three arguments stops the install step at that line (2026-09-27).
        #
        calls = re.findall(
            r'^allow "[^"]+"\s+"[^"]+" \\\n\s+"(?:[^"\\]|\\.)*"( \\\n\s+"[^"]*")?',
            text,
            re.MULTILINE,
        )
        self.assertTrue(calls)
        self.assertNotIn("", calls, "an allow call without its expected answer")
        role = os.environ["HAPROXY_UI_TEST_WEB_ROLE"]
        for kind, description, statement in probes:
            statement = statement.replace('\\"', '"')
            with self.subTest(description=description):
                with psycopg.connect(f"{DSN} user={role}") as connection:
                    try:
                        connection.execute(statement)
                        refused = False
                    except psycopg.Error:
                        refused = True
                    connection.rollback()
                self.assertEqual(refused, kind == "refuse")


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


def _migration(filename: str, cursor: psycopg.Cursor) -> Any:
    """One migration module, loaded by file, with `op` bound to this cursor."""

    path = Path(__file__).resolve().parents[1] / "migrations" / "versions" / filename
    spec = importlib.util.spec_from_file_location(f"migration_{filename[:4]}", path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.op = _Executes(cursor)
    return module


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

    def test_a_profile_s_evidence_is_found_behind_any_number_of_other_profiles_jobs(
        self,
    ) -> None:
        """Review 2026-09-26: 500 newer applies for another profile hid this one's."""

        applied = self.queue("dns_profile_apply", None, profile="cf-main", revision=1)
        self.finish(applied)
        refused = self.queue("dns_profile_apply", None, profile="cf-main", revision=1, remove=True)
        self.finish(refused)
        for index in range(501):
            self.finish(self.queue("dns_profile_apply", None, profile="cf-other", revision=index))

        found = db.profile_jobs(self.connection, "dns_profile_apply")
        mine = [job.id for job in found if job.payload.get("profile") == "cf-main"]
        self.assertEqual(mine, [refused.id, applied.id])
        others = [job for job in found if job.payload.get("profile") == "cf-other"]
        self.assertEqual(len(others), 1)
        self.assertNotIn(
            applied.id, [j.id for j in db.operation_jobs(self.connection, "dns_profile_apply")]
        )

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
            # Not `delete`: since 0041 the last active admin cannot be deleted,
            # and truncate is the owner's reset, which fires no row trigger.
            cursor.execute("truncate app_user cascade")
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
            # Not `delete`: since 0041 the last active admin cannot be deleted,
            # and truncate is the owner's reset, which fires no row trigger.
            cursor.execute("truncate app_user cascade")
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
                # 0041 builds on 0039's guard, so it steps back first and
                # forward last, as a real downgrade to 0038 would.
                later = _migration("0041_oidc_accounts.py", cursor)
                later.downgrade()
                migration.op = _Executes(cursor)
                migration.downgrade()
                cursor.execute("select to_regclass('login_unlock')")
                self.assertEqual(cursor.fetchone(), (None,))
                migration.upgrade()
                cursor.execute("select to_regclass('login_unlock')")
                self.assertEqual(cursor.fetchone(), ("login_unlock",))
                later.upgrade()
            connection.rollback()


@unittest.skipUnless(DSN, "run through ui/tools/test-database")
class FeatureSwitchesFromTheWeb(unittest.TestCase):
    """Migrations 0040 and 0042: switches the web flips and nothing more (B193, B204)."""

    def connect(self, role_variable: str = "HAPROXY_UI_TEST_MIGRATION_ROLE") -> psycopg.Connection:
        return psycopg.connect(f"{DSN} user={os.environ[role_variable]}")

    def tearDown(self) -> None:
        with self.connect() as connection:
            connection.execute(
                "update feature_switch set enabled = (name = 'cluster_colours'), "
                "remembered = '{}', updated_by = null"
            )
            connection.commit()

    def test_every_switch_exists_and_starts_where_its_migration_put_it(self) -> None:
        with self.connect("HAPROXY_UI_TEST_WEB_ROLE") as connection:
            switches = db.feature_switches(connection)

        self.assertEqual(
            {name: switch.enabled for name, switch in switches.items()},
            {"cert_receivers": False, "node_backups": False, "cluster_colours": True},
        )

    def test_the_colours_switch_downgrades_and_upgrades_cleanly(self) -> None:
        with self.connect() as connection:
            with connection.cursor() as cursor:
                migration = _migration("0042_cluster_colours_switch.py", cursor)
                migration.downgrade()
                cursor.execute("select name from feature_switch order by name")
                self.assertEqual(cursor.fetchall(), [("cert_receivers",), ("node_backups",)])
                with self.assertRaises(psycopg.errors.CheckViolation):
                    cursor.execute("insert into feature_switch (name) values ('cluster_colours')")
            connection.rollback()
            with connection.cursor() as cursor:
                migration = _migration("0042_cluster_colours_switch.py", cursor)
                migration.downgrade()
                migration.upgrade()
                cursor.execute("select enabled from feature_switch where name = 'cluster_colours'")
                self.assertEqual(cursor.fetchone(), (True,))
            connection.rollback()

    def test_the_web_flips_a_switch_once_and_remembers_what_it_is_given(self) -> None:
        with self.connect() as connection:
            connection.execute("update feature_switch set enabled = true")
            connection.commit()
        with self.connect("HAPROXY_UI_TEST_WEB_ROLE") as connection:
            first = db.set_feature_switch(
                connection,
                name="node_backups",
                enabled=False,
                remembered={"schedules": {"alpha": {"time": "04:00"}}},
                actor="operator",
            )
            again = db.set_feature_switch(
                connection, name="node_backups", enabled=False, remembered={}, actor="operator"
            )
            connection.commit()
            switch = db.feature_switches(connection)["node_backups"]

        self.assertEqual((first, again), (True, False))
        self.assertFalse(switch.enabled)
        self.assertEqual(switch.remembered, {"schedules": {"alpha": {"time": "04:00"}}})
        self.assertEqual(switch.updated_by, "operator")
        self.assertLess(datetime.now(UTC) - switch.updated_at, timedelta(minutes=1))

    def test_the_web_cannot_add_remove_rename_or_date_a_switch(self) -> None:
        for statement in (
            "insert into feature_switch (name) values ('cert_receivers')",
            "delete from feature_switch",
            "update feature_switch set name = 'node_backups' where name = 'cert_receivers'",
            "update feature_switch set updated_at = now() - interval '1 year'",
        ):
            with (
                self.subTest(statement=statement),
                self.assertRaises(psycopg.errors.InsufficientPrivilege),
                self.connect("HAPROXY_UI_TEST_WEB_ROLE") as connection,
            ):
                connection.execute(statement)

    def test_the_worker_and_the_poller_do_not_read_the_switches(self) -> None:
        for role in ("HAPROXY_UI_TEST_WORKER_ROLE", "HAPROXY_UI_TEST_POLLER_ROLE"):
            with (
                self.subTest(role=role),
                self.assertRaises(psycopg.errors.InsufficientPrivilege),
                self.connect(role) as connection,
            ):
                connection.execute("select enabled from feature_switch")


@unittest.skipUnless(DSN, "run through ui/tools/test-database")
class OidcAccounts(unittest.TestCase):
    """Migration 0041: two kinds of account, break-glass, deletion and the provider row (B195-B199)."""

    HASH = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA"
    SECRET = b"sealed"

    def connect(self, role_variable: str = "HAPROXY_UI_TEST_MIGRATION_ROLE") -> psycopg.Connection:
        return psycopg.connect(f"{DSN} user={os.environ[role_variable]}")

    def setUp(self) -> None:
        self.reset()
        with self.connect() as connection, connection.cursor() as cursor:
            for name, role, break_glass in (
                ("alice", "admin", True),
                ("bob", "admin", False),
                ("carol", "reader", False),
            ):
                cursor.execute(
                    "insert into app_user (username, password_hash, role, break_glass) "
                    "values (%s, %s, %s, %s)",
                    (name, self.HASH, role, break_glass),
                )
            connection.commit()

    def tearDown(self) -> None:
        self.reset()

    def reset(self) -> None:
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute("update oidc_provider set enabled = false")
            cursor.execute(
                "update oidc_provider set issuer = null, client_id = null, "
                "client_secret_sealed = null, key_id = null, admin_group = null, "
                "reader_group = null, verified_revision = null"
            )
            cursor.execute("truncate app_user cascade")
            cursor.execute("truncate oidc_login")
            connection.commit()

    def web(self, statement: str, parameters: tuple[Any, ...] = ()) -> None:
        with self.connect("HAPROXY_UI_TEST_WEB_ROLE") as connection:
            connection.execute(statement, parameters)
            connection.commit()

    def one(self, statement: str, parameters: tuple[Any, ...] = ()) -> Any:
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute(statement, parameters)
            row = cursor.fetchone()
            return None if row is None else row[0]

    def configure_and_verify(self) -> None:
        """A complete provider, verified at its current revision, still off."""

        self.web(
            "update oidc_provider set issuer = 'https://auth.example/application/o/app/', "
            "client_id = 'client', client_secret_sealed = %s, key_id = 'k1', "
            "admin_group = 'haproxy-admins', updated_by = 'alice'",
            (self.SECRET,),
        )
        self.web("update oidc_provider set verified_revision = revision")

    def test_the_web_deletes_an_account_and_its_sessions_go_with_it(self) -> None:
        carol = self.one("select id from app_user where username = 'carol'")
        with self.connect() as connection:
            connection.execute(
                "insert into app_session (token_hash, user_id, expires_at) "
                "values (%s, %s, now() + interval '1 hour')",
                (auth.token_hash("carol"), carol),
            )
            connection.commit()

        self.web("delete from app_user where username = 'carol'")

        self.assertIsNone(self.one("select id from app_user where username = 'carol'"))
        self.assertEqual(
            self.one("select count(*) from app_session where user_id = %s", (carol,)), 0
        )

    def test_the_last_active_admin_cannot_be_deleted(self) -> None:
        self.web("delete from app_user where username = 'bob'")
        with self.assertRaises(psycopg.errors.CheckViolation):
            self.web("delete from app_user where username = 'alice'")
        self.assertEqual(self.one("select count(*) from app_user where role = 'admin'"), 1)

    def test_a_disabled_admin_can_be_deleted_while_another_is_active(self) -> None:
        self.web("update app_user set disabled = true where username = 'bob'")
        self.web("delete from app_user where username = 'bob'")
        self.assertIsNone(self.one("select id from app_user where username = 'bob'"))

    def test_an_account_s_hash_follows_its_kind(self) -> None:
        for statement, parameters in (
            (
                "insert into app_user (username, role, source) values ('dave', 'reader', 'local')",
                (),
            ),
            (
                "insert into app_user (username, password_hash, role, source) "
                "values ('dave', %s, 'reader', 'oidc')",
                (self.HASH,),
            ),
            (
                "insert into app_user (username, role, source, break_glass) "
                "values ('dave', 'admin', 'oidc', true)",
                (),
            ),
            (
                "insert into app_user (username, role, source, oidc_issuer) "
                "values ('dave', 'reader', 'oidc', 'https://auth.example/')",
                (),
            ),
            (
                "insert into app_user (username, password_hash, role, oidc_issuer, oidc_subject) "
                "values ('dave', %s, 'reader', 'https://auth.example/', 'sub')",
                (self.HASH,),
            ),
        ):
            with (
                self.subTest(statement=statement),
                self.assertRaises(psycopg.errors.CheckViolation),
            ):
                self.web(statement, parameters)

    def test_an_oidc_account_is_one_per_provider_identity(self) -> None:
        insert = (
            "insert into app_user (username, role, source, oidc_issuer, oidc_subject) "
            "values (%s, 'reader', 'oidc', 'https://auth.example/', 'sub-1')"
        )
        self.web(insert, ("dave",))
        with self.assertRaises(psycopg.errors.UniqueViolation):
            self.web(insert, ("erin",))
        # Prepared by an admin, before its first sign-in: neither half yet.
        self.web("insert into app_user (username, role, source) values ('frank', 'reader', 'oidc')")

    def test_the_web_cannot_turn_a_local_account_into_a_provider_one(self) -> None:
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.web("update app_user set source = 'oidc' where username = 'carol'")

    def test_a_setting_raises_the_revision_and_a_verify_does_not(self) -> None:
        before = self.one("select revision from oidc_provider")
        self.configure_and_verify()
        after = self.one("select revision from oidc_provider")
        self.assertEqual(after, before + 1)
        self.assertEqual(self.one("select verified_revision from oidc_provider"), after)

        self.web("update oidc_provider set enabled = true")
        self.assertEqual(self.one("select revision from oidc_provider"), after)

    def test_the_provider_is_on_only_when_complete_and_verified(self) -> None:
        with self.assertRaises(psycopg.errors.CheckViolation):
            self.web("update oidc_provider set enabled = true")
        # Complete, and never verified: the case a check passing on null let through.
        self.web(
            "update oidc_provider set issuer = 'https://auth.example/', client_id = 'client', "
            "client_secret_sealed = %s, key_id = 'k1', admin_group = 'haproxy-admins'",
            (self.SECRET,),
        )
        with self.assertRaises(psycopg.errors.CheckViolation):
            self.web("update oidc_provider set enabled = true")

        self.configure_and_verify()
        # Not together with a change: the new text is a revision nobody verified.
        with self.assertRaises(psycopg.errors.CheckViolation):
            self.web(
                "update oidc_provider set enabled = true, button_text = 'Sign in with authentik'"
            )
        self.assertFalse(self.one("select enabled from oidc_provider"))

    def test_turning_on_needs_an_active_break_glass_admin(self) -> None:
        self.configure_and_verify()
        self.web("update app_user set break_glass = false where username = 'alice'")
        with self.assertRaises(psycopg.errors.CheckViolation):
            self.web("update oidc_provider set enabled = true")

        self.web("update app_user set break_glass = true where username = 'bob'")
        self.web("update oidc_provider set enabled = true")
        self.assertTrue(self.one("select enabled from oidc_provider"))

    def test_while_on_the_last_break_glass_admin_stays(self) -> None:
        self.configure_and_verify()
        self.web("update oidc_provider set enabled = true")
        for statement in (
            "update app_user set break_glass = false where username = 'alice'",
            "update app_user set disabled = true where username = 'alice'",
            "update app_user set role = 'reader' where username = 'alice'",
            "delete from app_user where username = 'alice'",
        ):
            with (
                self.subTest(statement=statement),
                self.assertRaises(psycopg.errors.CheckViolation),
            ):
                self.web(statement)
        # Bob is no break-glass account, so he may go.
        self.web("delete from app_user where username = 'bob'")

    def test_a_sign_in_in_progress_is_used_once_and_never_rewritten(self) -> None:
        state = "s" * 43
        self.web(
            "insert into oidc_login (state, nonce, verifier, mode, pre_session_hash) "
            "values (%s, %s, %s, 'sign_in', %s)",
            (state, "n" * 43, "v" * 43, auth.token_hash("pre")),
        )
        with self.connect("HAPROXY_UI_TEST_WEB_ROLE") as connection:
            used = connection.execute(
                "update oidc_login set used_at = now() "
                "where state = %s and used_at is null returning state",
                (state,),
            ).fetchall()
            again = connection.execute(
                "update oidc_login set used_at = now() "
                "where state = %s and used_at is null returning state",
                (state,),
            ).fetchall()
            connection.commit()
        self.assertEqual((len(used), len(again)), (1, 0))
        for statement in (
            "update oidc_login set nonce = 'x'",
            "delete from oidc_login",
        ):
            with (
                self.subTest(statement=statement),
                self.assertRaises(psycopg.errors.InsufficientPrivilege),
            ):
                self.web(statement)

    def test_the_downgrade_refuses_while_a_provider_account_exists(self) -> None:
        self.web("insert into app_user (username, role, source) values ('dave', 'reader', 'oidc')")
        with self.connect() as connection:
            with connection.cursor() as cursor, self.assertRaises(psycopg.errors.RaiseException):
                _migration("0041_oidc_accounts.py", cursor).downgrade()
            connection.rollback()

    def test_the_migration_downgrades_and_upgrades_cleanly(self) -> None:
        with self.connect() as connection:
            with connection.cursor() as cursor:
                migration = _migration("0041_oidc_accounts.py", cursor)
                migration.downgrade()
                cursor.execute("select to_regclass('oidc_provider'), to_regclass('oidc_login')")
                self.assertEqual(cursor.fetchone(), (None, None))
                cursor.execute(
                    "select count(*) from information_schema.columns "
                    "where table_name = 'app_user' and column_name = 'source'"
                )
                self.assertEqual(cursor.fetchone(), (0,))
                migration.upgrade()
                cursor.execute("select count(*) from oidc_provider")
                self.assertEqual(cursor.fetchone(), (1,))
            connection.rollback()


@unittest.skipUnless(DSN, "run through ui/tools/test-database")
class TheAccountToolAgainstARealDatabase(unittest.TestCase):
    """`haproxy-ui-user`'s verbs from 0041 (B196, B197), through `main`, on the real schema."""

    HASH = OidcAccounts.HASH

    def connect(self, role_variable: str = "HAPROXY_UI_TEST_MIGRATION_ROLE") -> psycopg.Connection:
        return psycopg.connect(f"{DSN} user={os.environ[role_variable]}")

    def setUp(self) -> None:
        from haproxy_ui import admin

        self.admin = admin
        with self.connect() as connection:
            connection.execute("truncate app_user cascade")
            connection.commit()
        for patch in (
            mock.patch("os.geteuid", return_value=0),
            mock.patch.object(
                admin,
                "load_environment",
                return_value=admin.Environment(name="test", database="test", role="test"),
            ),
            mock.patch.object(admin, "connect", side_effect=lambda _e: self.connect()),
            mock.patch.dict(os.environ, {"SUDO_USER": "operator"}),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def tearDown(self) -> None:
        with self.connect() as connection:
            connection.execute("truncate app_user cascade")
            connection.commit()

    def run_tool(self, *argv: str) -> tuple[int, str]:
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            code = self.admin.main(list(argv))
        return code, out.getvalue()

    def account(self, name: str) -> tuple[Any, ...] | None:
        with self.connect() as connection:
            return connection.execute(
                "select role, source, break_glass, password_hash from app_user where username = %s",
                (name,),
            ).fetchone()

    def add(self, name: str, role: str = "admin", **fields: Any) -> None:
        columns = {"username": name, "password_hash": self.HASH, "role": role, **fields}
        with self.connect() as connection:
            connection.execute(
                f"insert into app_user ({', '.join(columns)}) "  # noqa: S608 - our own names
                f"values ({', '.join(['%s'] * len(columns))})",
                tuple(columns.values()),
            )
            connection.commit()

    def test_init_admin_makes_a_break_glass_admin_once_with_the_typed_password(self) -> None:
        with mock.patch.object(self.admin, "read_new_password", return_value="long enough pw"):
            code, output = self.run_tool("init-admin")

        self.assertEqual(code, 0)
        role, source, break_glass, password_hash = self.account("admin") or ()
        self.assertEqual((role, source, break_glass), ("admin", "local", True))
        self.assertTrue(auth.verify_password(password_hash, "long enough pw"))
        self.assertNotIn("long enough pw", output)

        with mock.patch.object(self.admin, "read_new_password") as asked:
            again, output = self.run_tool("init-admin")
        self.assertEqual(again, 0)
        self.assertIn("accounts exist", output)
        asked.assert_not_called()
        with self.connect() as connection:
            self.assertEqual(connection.execute("select count(*) from app_user").fetchone(), (1,))

    def test_init_admin_does_nothing_where_any_account_exists(self) -> None:
        self.add("operator", role="reader")
        with mock.patch.object(self.admin, "read_new_password") as asked:
            code, output = self.run_tool("init-admin")
        self.assertEqual(code, 0)
        self.assertIsNone(self.account("admin"))
        asked.assert_not_called()

    def test_init_admin_without_a_terminal_makes_no_account(self) -> None:
        with mock.patch("sys.stdin.isatty", return_value=False):
            code, output = self.run_tool("init-admin")
        self.assertNotEqual(code, 0)
        self.assertIn("terminal", output)
        self.assertIsNone(self.account("admin"))

    def test_add_makes_break_glass_accounts_unless_told_not_to(self) -> None:
        with mock.patch.object(self.admin, "read_new_password", return_value="long enough pw"):
            self.run_tool("add", "alice", "--role", "admin")
            self.run_tool("add", "bob", "--role", "reader", "--no-break-glass")
        self.assertTrue((self.account("alice") or ())[2])
        self.assertFalse((self.account("bob") or ())[2])

    def test_add_refuses_a_name_a_version_could_not_record(self) -> None:
        # Review 2026-09-29 F1: refused before a password is asked for.
        with mock.patch.object(self.admin, "read_new_password") as asked:
            code, output = self.run_tool("add", "ada\u00a0admin", "--role", "admin")
        self.assertNotEqual(code, 0)
        self.assertIn("invisible characters", output)
        asked.assert_not_called()
        self.assertIsNone(self.account("ada\u00a0admin"))

    def test_delete_says_what_without_yes_and_does_it_with(self) -> None:
        self.add("alice")
        self.add("bob", role="reader")

        code, output = self.run_tool("delete", "bob")
        self.assertEqual(code, 64)
        self.assertIn("repeat with --yes", output)
        self.assertIsNotNone(self.account("bob"))

        self.assertEqual(self.run_tool("delete", "bob", "--yes")[0], 0)
        self.assertIsNone(self.account("bob"))

    def test_delete_refuses_the_last_active_admin(self) -> None:
        self.add("alice")
        code, output = self.run_tool("delete", "alice", "--yes")
        self.assertEqual(code, 74)
        self.assertIn("last active admin", output)
        self.assertIsNotNone(self.account("alice"))

    def test_break_glass_marks_and_unmarks_a_local_account_only(self) -> None:
        self.add("alice")
        self.add("bob", role="reader", source="oidc", password_hash=None)

        self.assertEqual(self.run_tool("break-glass", "alice")[0], 0)
        self.assertTrue((self.account("alice") or ())[2])
        self.assertEqual(self.run_tool("break-glass", "alice", "--off")[0], 0)
        self.assertFalse((self.account("alice") or ())[2])

        code, output = self.run_tool("break-glass", "bob")
        self.assertEqual(code, 64)
        self.assertIn("only local accounts", output)

    def test_reset_refuses_a_provider_account_before_asking_for_a_password(self) -> None:
        self.add("bob", role="reader", source="oidc", password_hash=None)
        with mock.patch.object(self.admin, "read_new_password") as asked:
            code, output = self.run_tool("reset", "bob")
        self.assertEqual(code, 64)
        self.assertIn("has no password", output)
        asked.assert_not_called()

    def test_list_names_each_account_s_kind(self) -> None:
        self.add("alice", break_glass=True)
        self.add("bob", role="reader", source="oidc", password_hash=None)
        self.add("carol", role="reader")
        output = self.run_tool("list")[1]
        self.assertRegex(output, r"alice\s+admin\s+break-glass")
        self.assertRegex(output, r"bob\s+reader\s+sso")
        self.assertRegex(output, r"carol\s+reader\s+local")


@unittest.skipUnless(DSN, "run through ui/tools/test-database")
class TheProviderRowFromTheWeb(unittest.TestCase):
    """O4's database functions, under the web role's grants (B197)."""

    def connect(self, role_variable: str = "HAPROXY_UI_TEST_MIGRATION_ROLE") -> psycopg.Connection:
        return psycopg.connect(f"{DSN} user={os.environ[role_variable]}")

    SETTINGS: dict[str, Any] = {
        "issuer": "https://id.example.com/",
        "client_id": "c",
        "client_secret_sealed": b"sealed",
        "key_id": "0123456789abcdef",
        "admin_group": "haproxy-admins",
    }

    def setUp(self) -> None:
        OidcAccounts.reset(self)  # type: ignore[arg-type]
        with self.connect() as connection:
            connection.execute(
                "insert into app_user (username, password_hash, role, break_glass) "
                "values ('alice', %s, 'admin', true)",
                (OidcAccounts.HASH,),
            )
            connection.commit()

    def tearDown(self) -> None:
        OidcAccounts.reset(self)  # type: ignore[arg-type]

    def web(self) -> psycopg.Connection:
        return self.connect("HAPROXY_UI_TEST_WEB_ROLE")

    def row(self, connection: psycopg.Connection) -> db.OidcProvider:
        provider = db.oidc_provider(connection)
        if provider is None:
            self.fail("no provider row")
        return provider

    def test_the_row_reads_back_with_its_secret_as_bytes(self) -> None:
        with self.web() as connection:
            db.save_oidc_provider(connection, settings=self.SETTINGS, actor="alice")
            connection.commit()
            provider = self.row(connection)
        self.assertEqual(provider.client_secret_sealed, b"sealed")
        self.assertEqual(provider.updated_by, "alice")
        self.assertFalse(provider.verified)

    def test_verify_is_recorded_only_at_the_revision_it_passed(self) -> None:
        with self.web() as connection:
            db.save_oidc_provider(connection, settings=self.SETTINGS, actor="alice")
            provider = self.row(connection)
            self.assertFalse(db.record_oidc_verified(connection, revision=provider.revision - 1))
            self.assertTrue(db.record_oidc_verified(connection, revision=provider.revision))
            connection.commit()
            verified = self.row(connection)
        self.assertTrue(verified.verified)

    def test_on_needs_verified_settings_and_says_so(self) -> None:
        with self.web() as connection:
            db.save_oidc_provider(connection, settings=self.SETTINGS, actor="alice")
            with self.assertRaisesRegex(db.ProviderRefused, "Verify the settings first"):
                db.set_oidc_enabled(connection, enabled=True, actor="alice")
            provider = self.row(connection)
            db.record_oidc_verified(connection, revision=provider.revision)
            db.set_oidc_enabled(connection, enabled=True, actor="alice")
            connection.commit()
            self.assertTrue(self.row(connection).enabled)

    def test_on_needs_a_break_glass_admin_and_says_so(self) -> None:
        with self.connect() as connection:
            connection.execute("update app_user set break_glass = false")
            connection.commit()
        with self.web() as connection:
            db.save_oidc_provider(connection, settings=self.SETTINGS, actor="alice")
            provider = self.row(connection)
            db.record_oidc_verified(connection, revision=provider.revision)
            with self.assertRaisesRegex(db.ProviderRefused, "break-glass"):
                db.set_oidc_enabled(connection, enabled=True, actor="alice")

    def test_while_on_a_change_saves_only_as_verified(self) -> None:
        with self.web() as connection:
            db.save_oidc_provider(connection, settings=self.SETTINGS, actor="alice")
            provider = self.row(connection)
            db.record_oidc_verified(connection, revision=provider.revision)
            db.set_oidc_enabled(connection, enabled=True, actor="alice")
            connection.commit()

            with self.assertRaises(db.ProviderRefused):
                db.save_oidc_provider(connection, settings={"button_text": "Other"}, actor="alice")
            db.save_oidc_provider(
                connection, settings={"button_text": "Other"}, actor="alice", verified=True
            )
            connection.commit()
            after = self.row(connection)
        self.assertEqual((after.enabled, after.button_text, after.verified), (True, "Other", True))
        self.assertEqual(after.revision, provider.revision + 1)


# Three dotted words, the shape of an id_token and nothing more.
DOTTED_FIXTURE = "header.payload.signature"


@unittest.skipUnless(DSN, "run through ui/tools/test-database")
class SigningInThroughTheProviderInTheDatabase(unittest.TestCase):
    """O5's database functions, under the web role's grants (B195-B199)."""

    def connect(self, role_variable: str = "HAPROXY_UI_TEST_MIGRATION_ROLE") -> psycopg.Connection:
        return psycopg.connect(f"{DSN} user={os.environ[role_variable]}")

    def setUp(self) -> None:
        OidcAccounts.reset(self)  # type: ignore[arg-type]
        with self.connect() as connection:
            connection.execute(
                "insert into app_user (username, password_hash, role, break_glass) "
                "values ('admin', %s, 'admin', true)",
                (OidcAccounts.HASH,),
            )
            connection.commit()

    def tearDown(self) -> None:
        OidcAccounts.reset(self)  # type: ignore[arg-type]

    def web(self) -> psycopg.Connection:
        return self.connect("HAPROXY_UI_TEST_WEB_ROLE")

    def test_an_account_is_created_found_by_identity_and_never_twice(self) -> None:
        with self.web() as connection:
            self.assertTrue(
                db.create_oidc_account(
                    connection,
                    username="alice",
                    role="admin",
                    issuer="https://id.example/",
                    subject="s1",
                )
            )
            self.assertFalse(
                db.create_oidc_account(
                    connection,
                    username="alice2",
                    role="admin",
                    issuer="https://id.example/",
                    subject="s1",
                )
            )
            self.assertFalse(
                db.create_oidc_account(
                    connection,
                    username="ADMIN",
                    role="reader",
                    issuer="https://id.example/",
                    subject="s2",
                )
            )
            connection.commit()
            found = db.account_by_oidc(connection, issuer="https://id.example/", subject="s1")
        if found is None:
            self.fail("no account for the identity")
        self.assertEqual(
            (found.username, found.source, found.password_hash), ("alice", "oidc", None)
        )

    def test_a_prepared_account_is_bound_once(self) -> None:
        with self.web() as connection:
            db.create_oidc_account(
                connection, username="bob", role="reader", issuer=None, subject=None
            )
            bob = db.account_by_username(connection, "bob")
            if bob is None:
                self.fail("no prepared account")
            self.assertTrue(
                db.bind_oidc_account(
                    connection, user_id=bob.id, issuer="https://id.example/", subject="s9"
                )
            )
            self.assertFalse(
                db.bind_oidc_account(
                    connection, user_id=bob.id, issuer="https://id.example/", subject="s10"
                )
            )
            admin = db.account_by_username(connection, "admin")
            if admin is None:
                self.fail("no admin")
            self.assertFalse(
                db.bind_oidc_account(
                    connection, user_id=admin.id, issuer="https://id.example/", subject="s11"
                )
            )
            connection.commit()

    def test_a_sign_in_in_progress_is_used_once_and_expires(self) -> None:
        pre = auth.token_hash("pre")
        with self.web() as connection:
            for state in ("a" * 43, "b" * 43):
                db.start_oidc_login(
                    connection,
                    state=state,
                    nonce="n" * 43,
                    verifier="v" * 43,
                    mode="sign_in",
                    pre_session_hash=pre,
                )
            connection.commit()
            used = db.use_oidc_login(connection, state="a" * 43)
            again = db.use_oidc_login(connection, state="a" * 43)
            connection.commit()
        if used is None:
            self.fail("the sign-in was not found")
        self.assertEqual((used.nonce, used.mode, used.pre_session_hash), ("n" * 43, "sign_in", pre))
        self.assertIsNone(again)
        with self.connect() as connection:
            connection.execute("update oidc_login set created_at = now() - interval '11 minutes'")
            connection.commit()
        with self.web() as connection:
            self.assertIsNone(db.use_oidc_login(connection, state="b" * 43))

    def test_a_session_keeps_the_id_token_and_says_its_account_s_kind(self) -> None:
        with self.web() as connection:
            db.create_oidc_account(
                connection,
                username="alice",
                role="admin",
                issuer="https://id.example/",
                subject="s1",
            )
            account = db.account_by_oidc(connection, issuer="https://id.example/", subject="s1")
            if account is None:
                self.fail("no account")
            digest = auth.token_hash("session")
            db.create_session(
                connection,
                token_hash=digest,
                user_id=account.id,
                expires_at=datetime.now(UTC) + timedelta(hours=1),
                **{"id_token": DOTTED_FIXTURE},
            )
            connection.commit()
            session = db.session_by_hash(connection, digest)
            self.assertEqual(db.session_id_token(connection, digest), DOTTED_FIXTURE)
        if session is None:
            self.fail("no session")
        self.assertEqual(session.source, "oidc")
