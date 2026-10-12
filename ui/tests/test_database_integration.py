"""Checks that need PostgreSQL rather than an imitation of its cursor."""

from __future__ import annotations

import ast
import contextlib
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest import mock
from uuid import uuid4

import psycopg
import psycopg.sql
from haprion.traffic_collector import (
    RETENTION_DAYS,
    CollectorConfig,
    NodeTarget,
    _database_days,
    _database_reason,
    _ingest_part,
    _ingest_waf_pages,
    _mirror_window,
    _parse_waf_response,
    forget_database_positions,
)
from psycopg.types.json import Jsonb

from haprion_ui import auth, db, metrics, search_index, timing, traffic_logs

DSN = os.environ.get("HAPRION_UI_TEST_DATABASE_DSN", "")


@unittest.skipUnless(DSN, "run through ui/tools/test-database")
class ARealDatabase(unittest.TestCase):
    def connect(self, role_variable: str = "HAPRION_UI_TEST_MIGRATION_ROLE") -> psycopg.Connection:
        role = os.environ[role_variable]
        return psycopg.connect(f"{DSN} user={role}")

    def test_the_timing_cursor_counts_each_statement_in_a_request(self) -> None:
        with psycopg.connect(
            f"{DSN} user={os.environ['HAPRION_UI_TEST_MIGRATION_ROLE']}",
            cursor_factory=timing.TimedCursor,
        ) as connection:
            # Outside a request: an ordinary cursor.
            self.assertEqual(connection.execute("select 1").fetchone(), (1,))
            measured = timing.Timing()
            token = timing._CURRENT.set(measured)
            try:
                connection.execute("select pg_sleep(0.01)")
                with connection.cursor() as cursor:
                    cursor.execute("select %s::int", (2,))
                    self.assertEqual(cursor.fetchone(), (2,))
            finally:
                timing._CURRENT.reset(token)
        self.assertEqual(measured.queries, 2)
        self.assertGreaterEqual(measured.database, 0.01)

    def drain(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        """`haprion-drain` itself, against this database, as the migration role."""

        directory = Path(tempfile.mkdtemp(prefix="drain-"))
        self.addCleanup(shutil.rmtree, directory)
        (directory / "ui-admin.conf").write_text(
            f"DB_NAME={os.environ['HAPRION_UI_TEST_DATABASE_NAME']}\n"
            f"DB_ROLE={os.environ['HAPRION_UI_TEST_MIGRATION_ROLE']}\n"
        )
        script = Path(__file__).resolve().parents[2] / "install/platform/bin/haprion-drain"
        return subprocess.run(  # noqa: S603 - fixed interpreter, the repository's script
            ["/bin/bash", str(script), *arguments],
            capture_output=True,
            text=True,
            check=False,
            env={
                **os.environ,
                "HAPRION_UI_DRAIN_CONFIG": str(directory),
                "PGHOST": os.environ["HAPRION_UI_TEST_DATABASE_SOCKET"],
            },
        )

    def running(self, operation: str, lease: str) -> int:
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "insert into job (operation, cluster, payload, idempotency_key, state, "
                "claim_token, worker_id, lease_until, started_at) values (%s, 'alpha', '{}', "
                "%s, 'running', %s, 'w', now() + %s::interval, now()) returning id",
                (operation, uuid4(), uuid4(), lease),
            )
            job = _first(cursor)
            connection.commit()
        self.addCleanup(self.forget_job, job)
        return int(job)

    def forget_job(self, job: int) -> None:
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute("delete from job where id = %s", (job,))
            cursor.execute("update job_claim_gate set paused_until = null, paused_by = null")
            connection.commit()

    def paused_until(self) -> object:
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute("select paused_until from job_claim_gate")
            return _first(cursor)

    def test_a_release_waits_for_a_running_job_and_refuses_after_its_wait(self) -> None:
        """CR-12: a running restore holds the restart; the pause is lifted on refusal."""

        job = self.running("node_restore", "10 minutes")

        answer = self.drain("pause", "--wait", "3")

        self.assertEqual(answer.returncode, 75, answer.stderr)
        self.assertIn(f"node_restore (job {job})", answer.stderr)
        self.assertIsNone(self.paused_until())

    def test_a_job_whose_lease_ran_out_is_not_waited_for(self) -> None:
        self.running("backup_run", "-1 minute")

        answer = self.drain("pause", "--wait", "3")

        self.assertEqual(answer.returncode, 0, answer.stderr)
        self.assertIsNotNone(self.paused_until())
        self.assertEqual(self.drain("resume").returncode, 0)
        self.assertIsNone(self.paused_until())

    def test_a_paused_gate_stops_the_worker_s_claim_and_resume_lets_it_go(self) -> None:
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "insert into job (operation, cluster, payload, idempotency_key) "
                "values ('deploy', 'alpha', '{}', %s) returning id",
                (uuid4(),),
            )
            pending = int(_first(cursor))
            connection.commit()
        self.addCleanup(self.forget_job, pending)
        self.assertEqual(self.drain("pause", "--wait", "3").returncode, 0)

        with self.connect("HAPRION_UI_TEST_WORKER_ROLE") as connection:
            self.assertIsNone(db.claim_job(connection, worker_id="w", lease_seconds=60))
            connection.rollback()
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                connection.execute("update job_claim_gate set paused_until = null")
            connection.rollback()

        self.assertEqual(self.drain("resume").returncode, 0)
        with self.connect("HAPRION_UI_TEST_WORKER_ROLE") as connection:
            claimed = db.claim_job(connection, worker_id="w", lease_seconds=60)
            connection.rollback()
        self.assertIsNotNone(claimed)
        self.assertEqual(claimed.id if claimed else None, pending)

    def test_a_claim_in_flight_is_either_finished_before_the_pause_or_waited_for(self) -> None:
        """The race a second SELECT would have left open: the claim that has not committed.

        The pause takes a SHARE lock on the job table, so it waits for the
        claim's transaction; the claim's job is then running, and is waited for.
        """

        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "insert into job (operation, cluster, payload, idempotency_key) "
                "values ('backup_run', 'alpha', '{}', %s) returning id",
                (uuid4(),),
            )
            pending = int(_first(cursor))
            connection.commit()
        self.addCleanup(self.forget_job, pending)

        script = Path(__file__).resolve().parents[2] / "install/platform/bin/haprion-drain"
        with self.connect("HAPRION_UI_TEST_WORKER_ROLE") as worker:
            claimed = db.claim_job(worker, worker_id="w", lease_seconds=60)
            self.assertIsNotNone(claimed)
            directory = Path(tempfile.mkdtemp(prefix="drain-"))
            self.addCleanup(shutil.rmtree, directory)
            (directory / "ui-admin.conf").write_text(
                f"DB_NAME={os.environ['HAPRION_UI_TEST_DATABASE_NAME']}\n"
                f"DB_ROLE={os.environ['HAPRION_UI_TEST_MIGRATION_ROLE']}\n"
            )
            pausing = subprocess.Popen(  # noqa: S603 - fixed interpreter, the repository's script
                ["/bin/bash", str(script), "pause", "--wait", "3"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env={
                    **os.environ,
                    "HAPRION_UI_DRAIN_CONFIG": str(directory),
                    "PGHOST": os.environ["HAPRION_UI_TEST_DATABASE_SOCKET"],
                },
            )
            with self.assertRaises(subprocess.TimeoutExpired):
                pausing.wait(timeout=1.5)
            worker.commit()
        _, stderr = pausing.communicate(timeout=30)

        self.assertEqual(pausing.returncode, 75, stderr)
        self.assertIn(f"backup_run (job {pending})", stderr)

    def test_a_pause_left_behind_by_a_killed_release_runs_out(self) -> None:
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "insert into job (operation, cluster, payload, idempotency_key) "
                "values ('deploy', 'alpha', '{}', %s) returning id",
                (uuid4(),),
            )
            pending = int(_first(cursor))
            cursor.execute("update job_claim_gate set paused_until = now() - interval '1 second'")
            connection.commit()
        self.addCleanup(self.forget_job, pending)

        with self.connect("HAPRION_UI_TEST_WORKER_ROLE") as connection:
            claimed = db.claim_job(connection, worker_id="w", lease_seconds=60)
            connection.rollback()

        self.assertIsNotNone(claimed)

    def test_retention_removes_oidc_sign_ins_older_than_a_day(self) -> None:
        """The clause is printed by the retention command itself, as above."""

        script = Path(__file__).resolve().parents[2] / "install/platform/bin/haprion-retention"
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

    def test_retention_removes_diffs_for_versions_no_longer_listed(self) -> None:
        """The poller only adds diffs; the retention command is what removes them."""

        clause = self.retention_clause("where_version_diff_unlisted", "VERSION_DIFF_NONE")
        listed, gone, other = "a" * 40, "b" * 40, "c" * 40
        with self.connect() as connection, connection.cursor() as cursor:
            for cluster, outcome, versions in (
                ("vd-done", "done", [{"hash": listed}]),
                ("vd-unread", "failed", []),
            ):
                cursor.execute(
                    "insert into cluster_history (cluster, outcome, result) values (%s, %s, %s)",
                    (cluster, outcome, Jsonb({"versions": versions})),
                )
            for cluster, commit in (
                ("vd-done", listed),
                ("vd-done", gone),
                ("vd-unread", other),
                ("vd-removed", other),
            ):
                cursor.execute(
                    "insert into version_diff (cluster, commit, diff) values (%s, %s, '{}')",
                    (cluster, commit),
                )
            cursor.execute(f"select cluster, commit from version_diff where {clause}")  # noqa: S608 - the script's own
            removable = set(cursor.fetchall())
            connection.rollback()
        self.assertEqual(removable, {("vd-done", gone), ("vd-removed", other)})

    def test_the_poller_asks_for_the_newest_versions_it_has_no_diff_for(self) -> None:
        hashes = [f"{n:x}" * 40 for n in range(1, 5)]
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "insert into cluster_history (cluster, outcome, result) values (%s, 'done', %s)",
                ("vd-ask", Jsonb({"versions": [{"hash": h} for h in hashes], "diffs": {}})),
            )
        with self.connect("HAPRION_UI_TEST_POLLER_ROLE") as connection:
            self.assertEqual(
                db.record_version_diffs(
                    connection,
                    cluster="vd-ask",
                    result={"diffs": {hashes[0]: {"files": []}, "not-a-hash": {}}},
                ),
                1,
            )
            connection.commit()
            self.assertEqual(
                db.versions_without_diff(connection, cluster="vd-ask", limit=2), tuple(hashes[1:3])
            )
            self.assertEqual(
                db.record_version_diffs(
                    connection, cluster="vd-ask", result={"diffs": {hashes[0]: {"files": [1]}}}
                ),
                0,
                "kept once; never replaced",
            )
            connection.commit()
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
            self.assertEqual(
                db.read_version_diff(connection, cluster="vd-ask", commit=hashes[0]), {"files": []}
            )
            self.assertIsNone(db.read_version_diff(connection, cluster="vd-ask", commit=hashes[1]))

    def retention_clause(self, function: str, keep: str) -> str:
        script = Path(__file__).resolve().parents[2] / "install/platform/bin/haprion-retention"
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

        from haprion_ui import auth

        clause = self.retention_clause("where_session_ended", "SESSION_KEEP_DAYS")
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "insert into app_user (username, password_hash, role) "
                "values ('retention-probe', %s, 'reader') returning id",
                (auth.hash_password("a long enough password"),),
            )
            user = _first(cursor)
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
                ids[_first(cursor)] = label
            cursor.execute(f"select id from login_attempt where {clause}")  # noqa: S608 - the script's own
            removable = {ids[row[0]] for row in cursor.fetchall()}
            self.assertEqual(removable, {"old-failure", "old-success", "older-old-success"})
            connection.rollback()

    def test_retention_removes_audit_records_after_two_years(self) -> None:
        """26-10-11: the record is kept two years, and nothing younger goes."""

        clause = self.retention_clause("where_audit_old", "AUDIT_KEEP_DAYS")
        with self.connect() as connection, connection.cursor() as cursor:
            ids = {}
            for label, age in (("old", "731 days"), ("kept", "729 days"), ("new", "1 day")):
                cursor.execute(
                    "insert into audit_event (at, actor, action, detail) "
                    "values (now() - %s::interval, 'admin', 'login', '{}') returning id",
                    (age,),
                )
                ids[_first(cursor)] = label
            cursor.execute(f"select id from audit_event where {clause}")  # noqa: S608 - the script's own
            removable = {ids[row[0]] for row in cursor.fetchall() if row[0] in ids}
            self.assertEqual(removable, {"old"})
            connection.rollback()

    def test_retention_keeps_what_a_profile_s_state_is_read_from(self) -> None:
        """A profile in effect for months must not read "Not applied" after a week.

        The clause is printed by the retention command's own functions, so what
        is proved here is what prunes. Everything is a month old and the floor
        of recent rows is set to nothing, so only the profile rule keeps a row.
        """

        script = Path(__file__).resolve().parents[2] / "install/platform/bin/haprion-retention"
        clause = subprocess.run(  # noqa: S603 - fixed interpreter, the repository's script
            [
                "/bin/bash",
                "-c",
                'KEEP_DAYS=7; KEEP_MINIMUM=0; eval "$(sed -n'
                " '/^profile_evidence() {/,/^}/p;/^draft_evidence() {/,/^}/p;"
                "/^where_removable() {/,/^}/p'"
                ' "$0")"; where_removable',
                str(script),
            ],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        jobs: tuple[tuple[str, str, dict[str, object]], ...] = (
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
                named[_first(cursor)] = name
            cursor.execute(f"select id from job where {clause}")  # noqa: S608 - the script's own
            removable = {named[row[0]] for row in cursor.fetchall() if row[0] in named}
            self.assertEqual(removable, {"old-apply", "removed-profile", "deploy"})
            connection.rollback()

    def test_retention_keeps_the_publish_a_draft_is_cleared_by(self) -> None:
        """A done publish is the evidence a draft is published; it outlives the week (CR-04).

        Kept while its draft exists, and pruned like any job once it does not.
        The clause is the retention command's own, as above.
        """

        script = Path(__file__).resolve().parents[2] / "install/platform/bin/haprion-retention"
        clause = subprocess.run(  # noqa: S603 - fixed interpreter, the repository's script
            [
                "/bin/bash",
                "-c",
                'KEEP_DAYS=7; KEEP_MINIMUM=0; eval "$(sed -n'
                " '/^profile_evidence() {/,/^}/p;/^draft_evidence() {/,/^}/p;"
                "/^where_removable() {/,/^}/p'"
                ' "$0")"; where_removable',
                str(script),
            ],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "insert into proxy_draft (cluster, object_id, yaml, base_hash, updated_by) "
                "values ('alpha', 'shop', 'schema: 1', %s, 'admin') returning id",
                ("a" * 40,),
            )
            kept = str(_first(cursor))
            named = {}
            for name, draft in (("kept", kept), ("gone", str(uuid4()))):
                cursor.execute(
                    "insert into job (operation, cluster, payload, idempotency_key, state, "
                    "started_at, finished_at) values ('objects_publish', 'alpha', %(payload)s, "
                    "%(key)s, 'done', now() - interval '30 days', now() - interval '30 days') "
                    "returning id",
                    {
                        "payload": json.dumps({"draft": {"id": draft, "revision": 1}}),
                        "key": uuid4(),
                    },
                )
                named[_first(cursor)] = name
            cursor.execute(f"select id from job where {clause}")  # noqa: S608 - the script's own
            removable = {named[row[0]] for row in cursor.fetchall() if row[0] in named}
            self.assertEqual(removable, {"gone"})
            connection.rollback()

    def test_the_web_saves_and_discards_a_cluster_s_network_and_settings(self) -> None:
        """B257: one saved document per cluster and kind, held to its revision."""

        common: dict[str, Any] = {
            "cluster": "alpha",
            "kind": "network",
            "base_hash": "a" * 40,
            "updated_by": "admin",
        }
        try:
            with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
                first = db.save_cluster_change(
                    connection, **common, document="vips: {}\n", expected_revision=None
                )
                with self.assertRaises(db.DraftConflict):
                    db.save_cluster_change(
                        connection, **common, document="vips: {}\n", expected_revision=None
                    )
                again = db.save_cluster_change(
                    connection, **common, document="vips: {x: 1}\n", expected_revision=1
                )
                db.save_cluster_change(
                    connection,
                    **{**common, "kind": "settings"},
                    document="metrics: null\n",
                    expected_revision=None,
                )
                connection.commit()
                self.assertEqual((again.revision, again.id), (2, first.id))
                self.assertEqual(
                    sorted(db.cluster_changes(connection, "alpha")), ["network", "settings"]
                )
                with self.assertRaises(db.DraftConflict):
                    db.discard_cluster_change(
                        connection, cluster="alpha", kind="network", expected_revision=1
                    )
                db.discard_cluster_change(
                    connection, cluster="alpha", kind="network", expected_revision=2
                )
                connection.commit()
                self.assertEqual(list(db.cluster_changes(connection, "alpha")), ["settings"])
                with self.assertRaises(psycopg.errors.CheckViolation):
                    db.save_cluster_change(
                        connection,
                        **{**common, "kind": "objects"},
                        document="x\n",
                        expected_revision=None,
                    )
                connection.rollback()
        finally:
            with self.connect() as connection:
                connection.execute("delete from cluster_change")
                connection.commit()

    def test_retention_keeps_the_publish_a_saved_network_is_cleared_by(self) -> None:
        """The draft rule (CR-04), for a saved network description or settings (B257)."""

        script = Path(__file__).resolve().parents[2] / "install/platform/bin/haprion-retention"
        clause = subprocess.run(  # noqa: S603 - fixed interpreter, the repository's script
            [
                "/bin/bash",
                "-c",
                'KEEP_DAYS=7; KEEP_MINIMUM=0; eval "$(sed -n'
                " '/^profile_evidence() {/,/^}/p;/^draft_evidence() {/,/^}/p;"
                "/^where_removable() {/,/^}/p'"
                ' "$0")"; where_removable',
                str(script),
            ],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "insert into cluster_change (cluster, kind, document, base_hash, updated_by) "
                "values ('alpha', 'network', 'vips: {}', %s, 'admin') returning id",
                ("a" * 40,),
            )
            kept = str(_first(cursor))
            named = {}
            for name, change in (("kept", kept), ("gone", str(uuid4()))):
                cursor.execute(
                    "insert into job (operation, cluster, payload, idempotency_key, state, "
                    "started_at, finished_at) values ('network_publish', 'alpha', %(payload)s, "
                    "%(key)s, 'done', now() - interval '30 days', now() - interval '30 days') "
                    "returning id",
                    {
                        "payload": json.dumps({"change": {"id": change, "revision": 1}}),
                        "key": uuid4(),
                    },
                )
                named[_first(cursor)] = name
            cursor.execute(f"select id from job where {clause}")  # noqa: S608 - the script's own
            removable = {named[row[0]] for row in cursor.fetchall() if row[0] in named}
            self.assertEqual(removable, {"gone"})
            found = db.change_publishes(connection, cluster="alpha", change_ids={kept})
            self.assertEqual([job.payload["change"]["id"] for job in found], [kept])
            connection.rollback()

    def test_a_package_s_publish_is_the_evidence_for_each_row_it_carried(self) -> None:
        """B257: `drafts` and `changes` lists, read and kept as one object's `draft` is."""

        script = Path(__file__).resolve().parents[2] / "install/platform/bin/haprion-retention"
        clause = subprocess.run(  # noqa: S603 - fixed interpreter, the repository's script
            [
                "/bin/bash",
                "-c",
                'KEEP_DAYS=7; KEEP_MINIMUM=0; eval "$(sed -n'
                " '/^profile_evidence() {/,/^}/p;/^draft_evidence() {/,/^}/p;"
                "/^where_removable() {/,/^}/p'"
                ' "$0")"; where_removable',
                str(script),
            ],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "insert into proxy_draft (cluster, object_id, yaml, base_hash, updated_by, stage) "
                "values ('alpha', 'shop', 'schema: 1', %s, 'admin', 'saved') returning id",
                ("a" * 40,),
            )
            draft = str(_first(cursor))
            cursor.execute(
                "insert into cluster_change (cluster, kind, document, base_hash, updated_by) "
                "values ('alpha', 'settings', 'metrics: null', %s, 'admin') returning id",
                ("a" * 40,),
            )
            change = str(_first(cursor))
            named = {}
            for name, payload in (
                ("objects", {"drafts": [{"id": draft, "revision": 1}]}),
                ("settings", {"changes": [{"id": change, "revision": 1}]}),
                ("gone", {"drafts": [{"id": str(uuid4()), "revision": 1}]}),
            ):
                cursor.execute(
                    "insert into job (operation, cluster, payload, idempotency_key, state, "
                    "started_at, finished_at) values ('changes_publish', 'alpha', %(payload)s, "
                    "%(key)s, 'done', now() - interval '30 days', now() - interval '30 days') "
                    "returning id",
                    {"payload": json.dumps(payload), "key": uuid4()},
                )
                named[_first(cursor)] = name
            cursor.execute(f"select id from job where {clause}")  # noqa: S608 - the script's own
            removable = {named[row[0]] for row in cursor.fetchall() if row[0] in named}
            self.assertEqual(removable, {"gone"})
            found = db.draft_publishes(connection, cluster="alpha", draft_ids={draft})
            self.assertEqual([named[job.id] for job in found], ["objects"])
            #
            # Publish & deploy whose deploy failed: the job is `failed`, and
            # the publish under `publish` still recorded the version.
            #
            cursor.execute(
                "insert into job (operation, cluster, payload, idempotency_key, state, result, "
                "started_at, finished_at) values ('changes_publish', 'alpha', %(payload)s, "
                "%(key)s, 'failed', %(result)s, now(), now()) returning id",
                {
                    "payload": json.dumps({"drafts": [{"id": draft, "revision": 1}]}),
                    "key": uuid4(),
                    "result": json.dumps({"outcome": "failed", "publish": {"outcome": "done"}}),
                },
            )
            named[_first(cursor)] = "deploy failed"
            found = db.draft_publishes(connection, cluster="alpha", draft_ids={draft})
            self.assertEqual(sorted(named[job.id] for job in found), ["deploy failed", "objects"])
            found = db.change_publishes(connection, cluster="alpha", change_ids={change})
            self.assertEqual([named[job.id] for job in found], ["settings"])
            connection.rollback()

    def test_the_web_reads_a_draft_s_publishes_by_its_id(self) -> None:
        """`draft_publishes` as the web runs it: done publishes of these drafts only (CR-04)."""

        with self.connect() as connection, connection.cursor() as cursor:
            mine, other = str(uuid4()), str(uuid4())
            for draft, state in ((mine, "done"), (mine, "failed"), (other, "done")):
                cursor.execute(
                    "insert into job (operation, cluster, payload, idempotency_key, state, "
                    "started_at, finished_at) values ('objects_publish', 'alpha', %(payload)s, "
                    "%(key)s, %(state)s, now(), now())",
                    {
                        "payload": json.dumps({"draft": {"id": draft, "revision": 1}}),
                        "key": uuid4(),
                        "state": state,
                    },
                )
            connection.commit()
        try:
            with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
                found = db.draft_publishes(connection, cluster="alpha", draft_ids={mine})
            self.assertEqual([job.payload["draft"]["id"] for job in found], [mine])
        finally:
            with self.connect() as connection, connection.cursor() as cursor:
                cursor.execute(
                    "delete from job where payload->'draft'->>'id' = any(%s)", ([mine, other],)
                )
                connection.commit()

    def test_every_column_the_interface_writes_is_granted_to_one_of_its_roles(self) -> None:
        """A write no role may make is a refusal waiting for its first use.

        `rename_draft` set `object_id`, and no migration granted that column:
        every test of the rename imitated the cursor, so the first real rename
        of an unpublished draft was refused by the database (found
        2026-10-08). Read here from the statements themselves, so the next
        such column fails this test and not a person's save.
        """

        source = (Path(__file__).resolve().parents[1] / "src/haprion_ui/db.py").read_text()
        statements = [
            node.value
            for node in ast.walk(ast.parse(source))
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        ]
        written: set[tuple[str, str, str]] = set()
        for statement in statements:
            text = " ".join(statement.split())
            for table, assignments in re.findall(
                r"\bupdate (\w+) set (.+?) (?:where|returning|$)", text
            ):
                for column in re.findall(r"(?:^|,)\s*(\w+)\s*=", assignments):
                    written.add(("UPDATE", table, column))
            for table, columns in re.findall(r"\binsert into (\w+) ?\(([^)]*)\)", text):
                for column in columns.split(","):
                    written.add(("INSERT", table, column.strip()))
        self.assertIn(("UPDATE", "proxy_draft", "object_id"), written)
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "select privilege_type, table_name, column_name "
                "  from information_schema.column_privileges "
                " where grantee in ('app_web', 'app_worker', 'app_poller', 'app_collector')"
            )
            granted = set(cursor.fetchall())
        self.assertEqual(sorted(written - granted), [])

    def test_the_web_can_rename_a_draft_it_wrote(self) -> None:
        """The rename moves the key, so the web needs `update` on `object_id` too.

        Every editor test imitated the cursor, and the grant left the column
        out: a rename of an unpublished draft was refused by the database.
        """

        try:
            with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
                draft = db.save_draft(
                    connection,
                    cluster="alpha",
                    object_id="console",
                    yaml="name: console\n",
                    base_version=None,
                    base_hash="a" * 40,
                    updated_by="admin",
                    expected_revision=None,
                )
                moved = db.rename_draft(
                    connection,
                    cluster="alpha",
                    object_id="console",
                    new_object_id="terminal",
                    yaml="name: terminal\n",
                    base_version=None,
                    base_hash="a" * 40,
                    updated_by="admin",
                    expected_revision=draft.revision,
                )
                connection.commit()
            self.assertEqual((moved.object_id, moved.id), ("terminal", draft.id))
        finally:
            with self.connect() as connection:
                connection.execute("delete from proxy_draft where cluster = 'alpha'")
                connection.commit()

    def test_saving_finishes_the_draft_in_one_transaction(self) -> None:
        """B257: the saved change is written and the draft dropped, or neither."""

        common: dict[str, Any] = {
            "cluster": "alpha",
            "object_id": "shop",
            "base_version": None,
            "base_hash": "a" * 40,
            "updated_by": "admin",
        }
        try:
            with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
                saved = db.save_change(
                    connection,
                    **common,
                    yaml="name: shop\n",
                    saved_revision=None,
                    draft_revision=None,
                )
                draft = db.save_draft(
                    connection, **common, yaml="name: shop # wip\n", expected_revision=None
                )
                #
                # Both at once: a draft over saved changes.
                #
                self.assertEqual(
                    [(row.stage, row.revision) for row in db.cluster_drafts(connection, "alpha")],
                    [("draft", 1), ("saved", 1)],
                )
                with self.assertRaises(db.DraftConflict):
                    db.save_change(
                        connection,
                        **common,
                        yaml="name: shop # done\n",
                        saved_revision=saved.revision + 5,
                        draft_revision=draft.revision,
                    )
                self.assertIsNotNone(db.read_draft(connection, "alpha", "shop", db.DRAFT))
                finished = db.save_change(
                    connection,
                    **common,
                    yaml="name: shop # done\n",
                    replaces="market",
                    saved_revision=saved.revision,
                    draft_revision=draft.revision,
                )
                connection.commit()
                rows = db.cluster_drafts(connection, "alpha")
            self.assertEqual([(row.stage, row.id) for row in rows], [("saved", saved.id)])
            self.assertEqual((finished.revision, finished.replaces), (2, "market"))
        finally:
            with self.connect() as connection:
                connection.execute("delete from proxy_draft where cluster = 'alpha'")
                connection.commit()

    def test_an_object_cannot_replace_itself(self) -> None:
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
            with self.assertRaises(psycopg.errors.CheckViolation):
                db.save_draft(
                    connection,
                    cluster="alpha",
                    object_id="shop",
                    yaml="name: shop\n",
                    base_version=None,
                    base_hash="a" * 40,
                    updated_by="admin",
                    replaces="shop",
                    expected_revision=None,
                )
            connection.rollback()

    def test_every_migration_reaches_the_declared_head(self) -> None:
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute("select version_num from alembic_version")
            declared = json.loads(
                (
                    Path(__file__).resolve().parents[1] / "src/haprion_ui/compatibility.json"
                ).read_text()
            )["requires"]["database_head"]
            self.assertEqual(cursor.fetchone(), (declared,))

    def test_runtime_accounts_inherit_exactly_one_contract_role(self) -> None:
        expected = {
            "HAPRION_UI_TEST_WEB_ROLE": "app_web",
            "HAPRION_UI_TEST_WORKER_ROLE": "app_worker",
            "HAPRION_UI_TEST_POLLER_ROLE": "app_poller",
            "HAPRION_UI_TEST_COLLECTOR_ROLE": "app_collector",
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
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection, connection.cursor() as cursor:
            cursor.execute("select cluster from cluster_status limit 0")
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                cursor.execute(
                    "insert into cluster_status (cluster, outcome) values ('alpha', 'done')"
                )

    def test_the_poller_works_out_cpu_from_the_row_it_replaces(self) -> None:
        # B239: CPU use is a rate; the previous reading is the row being replaced,
        # read as the poller, whose grants have to allow it.
        def answer(total: int, idle: int) -> dict[str, Any]:
            return {
                "nodes": [
                    {
                        "name": "node-a",
                        "status_ok": True,
                        "status": {
                            "resources": {
                                "cpu": {"total": total, "idle": idle},
                                "memory": None,
                                "load": None,
                                "cpus": 1,
                            }
                        },
                    }
                ]
            }

        with self.connect("HAPRION_UI_TEST_POLLER_ROLE") as connection:
            db.record_cluster_status(
                connection, cluster="cpu-share", outcome="done", result=answer(1000, 900)
            )
            connection.commit()
            db.record_cluster_status(
                connection, cluster="cpu-share", outcome="done", result=answer(3000, 2400)
            )
            connection.commit()
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
            (row,) = [row for row in db.cluster_statuses(connection) if row.cluster == "cpu-share"]
            self.assertEqual(row.result["nodes"][0]["cpu_percent"], 25)

    def test_the_poller_records_cluster_settings_and_web_only_reads_them(self) -> None:
        # Fas 15: the cache the Settings card reads, written only by the poller.
        result = {
            "cluster": "alpha",
            "head": "a" * 40,
            "stored": False,
            "log_targets": [],
            "metrics": None,
        }
        with self.connect("HAPRION_UI_TEST_POLLER_ROLE") as connection:
            db.record_cluster_settings(connection, cluster="alpha", outcome="done", result=result)
            db.record_cluster_settings(connection, cluster="alpha", outcome="done", result=result)
            connection.commit()
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
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
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
            self.assertIsNone(db.cluster_list(connection))
        with self.connect("HAPRION_UI_TEST_POLLER_ROLE") as connection:
            db.record_cluster_list(connection, ["alpha", "beta"])
            db.record_cluster_list(connection, ["beta", "gamma"])
            connection.commit()
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
            self.assertEqual(db.cluster_list(connection), ("beta", "gamma"))
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                db.record_cluster_list(connection, ["alpha"])
        with self.connect() as connection:
            connection.execute("delete from cluster_list")
            connection.commit()

    def test_a_cluster_catches_up_once_a_pass_begun_after_its_job_is_settled(self) -> None:
        # 0068: the moment the dashboard's spinner may go.
        def finished_job(ago: str) -> None:
            with self.connect() as connection:
                connection.execute(
                    "insert into job (operation, cluster, payload, idempotency_key, state, "
                    "started_at, finished_at) values ('deploy', 'passa', '{}', %s, 'done', "
                    "now() - %s::interval, now() - %s::interval)",
                    (uuid4(), ago, ago),
                )
                connection.commit()

        def catching(within: timedelta = timedelta(minutes=1)) -> list[str]:
            with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
                return db.clusters_catching_up(connection, ["passa", "passb"], within=within)

        def mark(*marks: Any) -> None:
            with self.connect("HAPRION_UI_TEST_POLLER_ROLE") as connection:
                for one in marks:
                    one(connection, "passa")
                    connection.commit()

        def forget() -> None:
            with self.connect() as connection:
                connection.execute("delete from job where cluster = 'passa'")
                connection.execute("delete from cluster_pass")
                connection.commit()

        self.addCleanup(forget)
        finished_job("10 minutes")
        self.assertEqual(catching(), [], "a job older than the window is caught up")
        self.assertEqual(catching(timedelta(hours=1)), ["passa"], "never read since")

        finished_job("0 seconds")
        self.assertEqual(catching(), ["passa"])
        mark(db.begin_cluster_pass)
        self.assertEqual(catching(), ["passa"], "begun is not read through")
        mark(db.settle_cluster_pass)
        self.assertEqual(catching(), [])
        mark(db.begin_cluster_pass)
        self.assertEqual(catching(), [], "the next pass running takes nothing back")

        #
        # The pass that was running when the job ended: settled, yet every
        # reading in it may be from before the change.
        #
        finished_job("0 seconds")
        mark(db.settle_cluster_pass)
        self.assertEqual(catching(), ["passa"])
        mark(db.begin_cluster_pass, db.settle_cluster_pass)
        self.assertEqual(catching(), [])

        with (
            self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection,
            self.assertRaises(psycopg.errors.InsufficientPrivilege),
        ):
            db.begin_cluster_pass(connection, "passa")

    def test_the_web_reads_the_record_backwards_and_by_filter(self) -> None:
        """B275: Audit's page, the job's queuer, a drain's setter, and the names that exist."""

        from haprion_ui import auth

        request = uuid4()
        marker = f"audit-probe-{uuid4().hex[:8]}"
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
            for actor, action, cluster, request_id, detail in (
                (marker, "login", None, None, {"client_ip": "192.0.2.10"}),
                (marker, "queue_job", "alpha", request, {"operation": "deploy", "job": 1}),
                (
                    marker,
                    "queue_job",
                    "alpha",
                    None,
                    {
                        "operation": "server_state",
                        "object": marker,
                        "state": "drain",
                        "servers": ["192.0.2.10:8080"],
                    },
                ),
                ("worker", "job_finished", "alpha", request, {"job": 1}),
            ):
                db.record_audit_event(
                    connection,
                    actor=actor,
                    action=action,
                    cluster=cluster,
                    request_id=request_id,
                    detail=detail,
                )
            connection.commit()
            mine = db.audit_events(connection, actor=marker)
            in_alpha = db.audit_events(connection, actor=marker, cluster="alpha")
            searched = db.audit_events(connection, search="192.0.2.10:8080")
            page = db.audit_events(connection, actor=marker, limit=1)
            older = db.audit_events(connection, actor=marker, offset=1)
            by_kind = db.audit_events(connection, actor=marker, order="what", descending=False)
            counted = db.audit_count(connection, actor=marker)
            future = db.audit_count(
                connection, actor=marker, since=datetime.now(UTC) + timedelta(days=1)
            )
            queued = db.requested_by(connection, [request, uuid4()])
            drains = db.server_state_events(connection, cluster="alpha", object_name=marker)
        self.assertEqual([event.action for event in mine], ["queue_job", "queue_job", "login"])
        self.assertEqual(len(in_alpha), 2)
        self.assertTrue(any(event.actor == marker for event in searched))
        self.assertEqual([event.action for event in older], ["queue_job", "login"])
        self.assertEqual(len(page), 1)
        self.assertEqual(counted, 3)
        self.assertEqual([event.action for event in by_kind], ["login", "queue_job", "queue_job"])
        self.assertEqual(future, 0)
        self.assertEqual(queued, {request: marker})
        self.assertEqual([event.detail["state"] for event in drains], ["drain"])

        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "insert into app_user (username, password_hash, role) values (%s, %s, 'reader')",
                (marker.upper(), auth.hash_password("a long enough password")),
            )
            connection.commit()
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
            self.assertIn(marker, db.account_names(connection))

    def test_the_web_keeps_the_status_endpoint_s_list(self) -> None:
        """B274: replaced whole, read back as networks."""

        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
            db.set_status_access(
                connection, networks=("192.0.2.10/32", "198.51.100.0/24"), actor="admin"
            )
            connection.commit()
            first = [entry.network for entry in db.status_access(connection)]
            db.set_status_access(connection, networks=("203.0.113.0/24",), actor="admin")
            connection.commit()
            second = [entry.network for entry in db.status_access(connection)]
            #
            # An address that stays keeps who added it (26-10-12); only the
            # new one is the second saver's.
            #
            db.set_status_access(
                connection, networks=("203.0.113.0/24", "192.0.2.20/32"), actor="operator"
            )
            connection.commit()
            kept = {entry.network: entry.added_by for entry in db.status_access(connection)}
            db.set_status_access(connection, networks=(), actor="admin")
            connection.commit()
            emptied = db.status_access(connection)
        self.assertEqual(first, ["192.0.2.10/32", "198.51.100.0/24"])
        self.assertEqual(second, ["203.0.113.0/24"])
        self.assertEqual(kept, {"203.0.113.0/24": "admin", "192.0.2.20/32": "operator"})
        self.assertEqual(emptied, [])

    def test_worker_can_read_jobs_but_not_accounts(self) -> None:
        with (
            self.connect("HAPRION_UI_TEST_WORKER_ROLE") as connection,
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
            self.connect("HAPRION_UI_TEST_POLLER_ROLE") as connection,
            connection.cursor() as cursor,
        ):
            cursor.execute(
                "insert into metric_frontend "
                "(cluster, node, frontend, owns_vip, uptime_sec, req_tot) "
                "values ('alpha', 'node-a', 'mgd-main-http', true, 60, 1)"
            )
        with (
            self.connect("HAPRION_UI_TEST_POLLER_ROLE") as connection,
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
        with self.connect("HAPRION_UI_TEST_COLLECTOR_ROLE") as connection:
            connection.execute(statement, values)
            connection.execute(statement, values)
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection, connection.cursor() as cursor:
            cursor.execute(
                "select host, path, status from traffic_log "
                "where cluster = 'alpha' and host = 'service.example.com'"
            )
            self.assertEqual(cursor.fetchall(), [("service.example.com", "/health", 200)])
            # A collector that knows nothing of `rule` still writes "no rule" (0050).
            cursor.execute("select rule from traffic_log where host = 'service.example.com'")
            self.assertEqual(cursor.fetchall(), [("",)])
            # ... and "nothing found" for the engine's fields (0051).
            cursor.execute(
                "select waf_rules, waf_score from traffic_log where host = 'service.example.com'"
            )
            self.assertEqual(cursor.fetchall(), [("", 0)])
            # ... and no engine transaction (0052).
            cursor.execute("select waf_id from traffic_log where host = 'service.example.com'")
            self.assertEqual(cursor.fetchall(), [("",)])
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                cursor.execute(statement, values)
        with (
            self.connect("HAPRION_UI_TEST_COLLECTOR_ROLE") as connection,
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
        self.assertIn(f"traffic_log_{suffix}_rule", indexes)

    def test_traffic_rule_is_bounded_and_downgrades_and_upgrades_cleanly(self) -> None:
        now = datetime.now(UTC).replace(microsecond=0)
        suffix = f"{now:%Y%m%d}"
        with self.connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute("select traffic_log_partition(%s::date)", (now.date(),))
                with self.assertRaises(psycopg.errors.CheckViolation):
                    cursor.execute(
                        "insert into traffic_log (event_id, cluster, node, occurred_at, "
                        "request_number, client, method, host, path, frontend, backend, server, "
                        "status, request_time, queue_time, connect_time, response_time, "
                        "total_time, bytes, rule) values (%s, 'alpha', 'node-a', %s, 1, "
                        "'192.0.2.10', 'GET', 'h.example.com', '/', 'f', 'b', 's', 200, "
                        "0, 0, 0, 0, 0, 0, %s)",
                        (b"r" * 32, now, "x" * 161),
                    )
            connection.rollback()
        with self.connect("HAPRION_UI_TEST_COLLECTOR_ROLE") as connection:
            connection.execute(
                "insert into traffic_log (event_id, cluster, node, occurred_at, "
                "request_number, client, method, host, path, frontend, backend, server, "
                "status, request_time, queue_time, connect_time, response_time, "
                "total_time, bytes, rule) values (%s, 'alpha', 'node-a', %s, 1, "
                "'192.0.2.10', 'GET', 'rule.example.com', '/admin', 'f', 'b', 's', 403, "
                "0, 0, 0, 0, 0, 0, 'block-admin:deny') on conflict do nothing",
                (b"q" * 32, now),
            )
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection, connection.cursor() as cursor:
            cursor.execute("select rule from traffic_log where host = 'rule.example.com'")
            self.assertEqual(cursor.fetchall(), [("block-admin:deny",)])
        #
        # The WAF page's question and the traffic page's filter (Fas 21).
        #
        with (
            tempfile.TemporaryDirectory() as temporary,
            self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection,
        ):
            hits = traffic_logs.read_database(connection, Path(temporary), ("alpha",), waf="hits")
            none = traffic_logs.read_database(connection, Path(temporary), ("alpha",), waf="none")
            # The Requests tab's figure counts the rows the tab lists.
            since = now - timedelta(days=7)
            counted = db.waf_request_count(connection, clusters=("alpha",), since=since)
            elsewhere = db.waf_request_count(connection, clusters=("beta",), since=since)
        self.assertEqual(counted, sum(1 for entry in hits.entries if entry.at >= since))
        self.assertGreaterEqual(counted, 1)
        self.assertEqual(elsewhere, 0)
        self.assertIn(
            ("rule.example.com", "block-admin:deny"), [(e.host, e.rule) for e in hits.entries]
        )
        #
        # One object's requests (26-10-10): its backend, or its name before any.
        #
        with (
            tempfile.TemporaryDirectory() as temporary,
            self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection,
        ):
            by_name = traffic_logs.read_database(
                connection, Path(temporary), ("alpha",), owned=((), ("Rule.Example.com",))
            )
            by_backend = traffic_logs.read_database(
                connection, Path(temporary), ("alpha",), owned=(("b",), ())
            )
            nothing = traffic_logs.read_database(
                connection, Path(temporary), ("alpha",), owned=((), ())
            )
        self.assertEqual({entry.host for entry in by_name.entries}, {"rule.example.com"})
        #
        # A subdomain object's (B278): one label under it, less the exact
        # names another object claims there.
        #
        with self.connect("HAPRION_UI_TEST_COLLECTOR_ROLE") as connection:
            for index, host in enumerate(
                ("shop.apps.example.com:80", "grafana.apps.example.com", "a.b.apps.example.com")
            ):
                connection.execute(
                    "insert into traffic_log (event_id, cluster, node, occurred_at, "
                    "request_number, client, method, host, path, frontend, backend, server, "
                    "status, request_time, queue_time, connect_time, response_time, "
                    "total_time, bytes, rule) values (%s, 'alpha', 'node-a', %s, %s, "
                    "'192.0.2.10', 'GET', %s, '/', 'f', 'f', '', 403, "
                    "0, 0, 0, 0, 0, 0, '') on conflict do nothing",
                    (bytes([index]) * 32, now, 100 + index, host),
                )
        with (
            tempfile.TemporaryDirectory() as temporary,
            self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection,
        ):
            subdomain = traffic_logs.read_database(
                connection,
                Path(temporary),
                ("alpha",),
                owned=((), ("*.apps.example.com", "!grafana.apps.example.com")),
            )
        self.assertEqual({entry.host for entry in subdomain.entries}, {"shop.apps.example.com:80"})
        self.assertTrue(by_backend.entries)
        self.assertTrue(all(entry.backend == "b" for entry in by_backend.entries))
        self.assertEqual(nothing.entries, ())
        self.assertTrue(all(entry.rule for entry in hits.entries))
        self.assertTrue(all(not entry.rule for entry in none.entries))
        with self.connect() as connection:
            with connection.cursor() as cursor:
                migration = _migration("0050_traffic_rule.py", cursor)
                migration.downgrade()
                cursor.execute(
                    "select count(*) from information_schema.columns "
                    "where table_name = 'traffic_log' and column_name = 'rule'"
                )
                self.assertEqual(cursor.fetchone(), (0,))
                migration.upgrade()
                cursor.execute(
                    "select count(*) from pg_indexes where indexname = %s",
                    (f"traffic_log_{suffix}_rule",),
                )
                self.assertEqual(cursor.fetchone(), (1,))
            connection.rollback()

    def test_waf_findings_are_bounded_and_downgrade_and_upgrade_cleanly(self) -> None:
        now = datetime.now(UTC).replace(microsecond=0)
        insert = (
            "insert into traffic_log (event_id, cluster, node, occurred_at, "
            "request_number, client, method, host, path, frontend, backend, server, "
            "status, request_time, queue_time, connect_time, response_time, "
            "total_time, bytes, rule, waf_rules, waf_score) values (%s, 'alpha', 'node-a', %s, 1, "
            "'192.0.2.10', 'GET', %s, '/', 'f', 'b', 's', 403, "
            "0, 0, 0, 0, 0, 0, 'crs:deny', %s, %s) on conflict do nothing"
        )
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute("select traffic_log_partition(%s::date)", (now.date(),))
            connection.commit()
        for rules, score in (
            ("930120,", 5),  # a trailing comma
            ("93012", 5),  # not six digits
            ("930120;932160", 5),  # another separator
            (",".join(["930120"] * 147), 5),  # beyond the bound
            ("930120", -1),
            ("930120", 100001),
        ):
            with (
                self.subTest(rules=rules[:20], score=score),
                self.connect() as connection,
                self.assertRaises(psycopg.errors.CheckViolation),
            ):
                connection.execute(insert, (b"w" * 32, now, "waf.example.com", rules, score))
        with self.connect("HAPRION_UI_TEST_COLLECTOR_ROLE") as connection:
            connection.execute(insert, (b"v" * 32, now, "waf.example.com", "930120,932160", 43))
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection, connection.cursor() as cursor:
            cursor.execute(
                "select waf_rules, waf_score from traffic_log where host = 'waf.example.com'"
            )
            self.assertEqual(cursor.fetchall(), [("930120,932160", 43)])
        with self.connect() as connection:
            with connection.cursor() as cursor:
                migration = _migration("0051_waf_engine.py", cursor)
                migration.downgrade()
                cursor.execute(
                    "select count(*) from information_schema.columns "
                    "where table_name = 'traffic_log' and column_name in ('waf_rules', 'waf_score')"
                )
                self.assertEqual(cursor.fetchone(), (0,))
                migration.upgrade()
                cursor.execute(
                    "select waf_rules, waf_score from traffic_log where host = 'waf.example.com'"
                )
                self.assertEqual(cursor.fetchall(), [("", 0)])
            connection.rollback()

    def test_0053_widens_the_id_shapes_a_database_kept_from_the_first_0052(self) -> None:
        # Production was migrated with 0052 before it was edited, kept the narrow
        # shapes and refused every engine ID with the object's name (26-10-03).
        now = datetime.now(UTC).replace(microsecond=0)
        dotted = "web-app.0b5e3c1a-7d42-4f0e-9c1b-2a6d8e4f7a90"
        insert = (
            "insert into waf_match (event_id, cluster, node, occurred_at, request_id, object, "
            "rule_id, field, matched, path, client) values "
            "(%s, 'alpha', 'node-a', %s, %s, 'web-app', 942100, '', 'x', '/', '192.0.2.10')"
        )
        with self.connect() as connection:
            connection.execute("select waf_match_partition(%s::date)", (now.date(),))
            connection.commit()
            with connection.cursor() as cursor:
                cursor.execute(
                    "alter table waf_match drop constraint waf_match_request_id_shape, "
                    "add constraint waf_match_request_id_shape "
                    "check (request_id ~ '^[A-Za-z0-9_-]{1,64}$')"
                )
                cursor.execute(
                    "alter table traffic_log drop constraint traffic_log_waf_id_shape, "
                    "add constraint traffic_log_waf_id_shape "
                    "check (waf_id ~ '^([A-Za-z0-9_-]{1,64})?$')"
                )
                cursor.execute("savepoint narrow")
                with self.assertRaises(psycopg.errors.CheckViolation):
                    cursor.execute(insert, (b"n" * 32, now, dotted))
                cursor.execute("rollback to savepoint narrow")

                _migration("0053_waf_id_shape.py", cursor).upgrade()

                cursor.execute(insert, (b"n" * 32, now, dotted))
                cursor.execute(
                    "select pg_get_constraintdef(oid) from pg_constraint "
                    "where conname = 'traffic_log_waf_id_shape' "
                    "and conrelid = 'traffic_log'::regclass"
                )
                self.assertIn("_.-]{1,96}", _first(cursor))
            connection.rollback()

    def test_waf_matches_are_bounded_joined_and_downgrade_and_upgrade_cleanly(self) -> None:
        now = datetime.now(UTC).replace(microsecond=0)
        insert = (
            "insert into waf_match (event_id, cluster, node, occurred_at, request_id, object, "
            "rule_id, field, matched, path, client) values "
            "(%s, 'alpha', 'node-a', %s, %s, %s, %s, %s, %s, %s, %s) on conflict do nothing"
        )
        good = (
            "shop.0b5e3c1a-7d42-4f0e-9c1b-2a6d8e4f7a90",
            "shop",
            942100,
            "ARGS:q",
            "1' OR 1=1--",
            "/search",
            "192.0.2.10",
        )
        with self.connect() as connection:
            connection.execute("select waf_match_partition(%s::date)", (now.date(),))
            connection.execute("select traffic_log_partition(%s::date)", (now.date(),))
            connection.commit()
        for index, value in (
            (0, "has space"),  # request_id
            (0, "A" * 97),
            (1, "Shop"),  # object
            (2, 0),  # rule_id
            (2, 1_000_000),
            (3, "ARGS:q\nsecond"),  # field: no control characters
            (3, "A" * 257),
            (4, "x" * 1025),  # matched
            (5, "/" * 2049),  # path
            (6, "1" * 65),  # client
        ):
            row = list(good)
            row[index] = value
            with (
                self.subTest(column=index, value=str(value)[:20]),
                self.connect() as connection,
                self.assertRaises(psycopg.errors.CheckViolation),
            ):
                connection.execute(insert, (b"w" * 32, now, *row))
        with self.connect("HAPRION_UI_TEST_COLLECTOR_ROLE") as connection:
            connection.execute(insert, (b"m" * 32, now, *good))
            connection.execute(insert, (b"m" * 32, now, *good))  # a re-read changes nothing
            connection.execute(
                "insert into traffic_log (event_id, cluster, node, occurred_at, "
                "request_number, client, method, host, path, frontend, backend, server, "
                "status, request_time, queue_time, connect_time, response_time, "
                "total_time, bytes, rule, waf_id) values (%s, 'alpha', 'node-a', %s, 1, "
                "'192.0.2.10', 'GET', 'match.example.com', '/search', 'f', 'b', 's', 200, "
                "0, 0, 0, 0, 0, 0, 'crs:log', %s) on conflict do nothing",
                (b"t" * 32, now, good[0]),
            )
        with (
            self.connect() as connection,
            self.assertRaises(psycopg.errors.CheckViolation),
        ):
            connection.execute(
                "update traffic_log set waf_id = 'has space' where host = 'match.example.com'"
            )
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection, connection.cursor() as cursor:
            cursor.execute(
                "select t.path, m.object, m.rule_id, m.field, m.matched from traffic_log t "
                "join waf_match m on m.cluster = t.cluster and m.request_id = t.waf_id "
                "where t.host = 'match.example.com'"
            )
            self.assertEqual(cursor.fetchall(), [("/search", "shop", 942100, "ARGS:q", good[4])])
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                cursor.execute(insert, (b"n" * 32, now, *good))
        with self.connect() as connection, connection.cursor() as cursor:
            old = now.date() - timedelta(days=30)
            cursor.execute("select waf_match_partition(%s::date)", (old,))
            cursor.execute(self.retention_partitions_expired("waf_match"))
            expired = [row[0] for row in cursor.fetchall()]
            self.assertIn(f"waf_match_{old:%Y%m%d}", expired)
            self.assertNotIn(f"waf_match_{now:%Y%m%d}", expired)
            connection.rollback()
        with self.connect() as connection:
            with connection.cursor() as cursor:
                migration = _migration("0052_waf_match.py", cursor)
                migration.downgrade()
                cursor.execute("select to_regclass('public.waf_match')")
                self.assertEqual(cursor.fetchone(), (None,))
                cursor.execute(
                    "select count(*) from information_schema.columns "
                    "where table_name = 'traffic_log' and column_name = 'waf_id'"
                )
                self.assertEqual(cursor.fetchone(), (0,))
                migration.upgrade()
                cursor.execute("select waf_id from traffic_log where host = 'match.example.com'")
                self.assertEqual(cursor.fetchall(), [("",)])
            connection.rollback()

    # The WAF page's question as it was asked of the matches themselves until
    # 0054: what the counts kept in advance must answer exactly.
    WAF_FINDINGS_FROM_MATCHES = (
        "select cluster, object, rule_id, field, "
        "       count(distinct request_id)::int, "
        "       count(distinct nullif(client, ''))::int, "
        "       max(occurred_at), "
        "       (array_agg(matched order by occurred_at desc))[1], "
        "       (array_agg(distinct path order by path))[1:20], "
        "       count(distinct path)::int "
        "  from waf_match "
        " where cluster = any(%s) and occurred_at >= %s "
        " group by cluster, object, rule_id, field "
        " order by cluster, object, max(occurred_at) desc"
    )

    def waf_findings_both_ways(self, since: datetime) -> tuple[list[tuple[Any, ...]], ...]:
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
            kept = [
                (
                    f.cluster,
                    f.object,
                    f.rule_id,
                    f.field,
                    f.requests,
                    f.clients,
                    f.last_seen,
                    f.matched,
                    f.paths,
                    f.path_count,
                )
                for f in db.waf_findings(connection, clusters=["rollup"], since=since)
            ]
        with self.connect() as connection:
            counted = connection.execute(
                self.WAF_FINDINGS_FROM_MATCHES, (["rollup"], since)
            ).fetchall()
        return kept, [tuple(row) for row in counted]

    def test_waf_findings_kept_in_advance_answer_as_the_matches_do(self) -> None:
        """0054: counted as the collector imports, with its repeats, and refilled on upgrade."""

        now = datetime.now(UTC).replace(minute=30, second=0, microsecond=0)
        rows = []
        for number, (hours_ago, request, rule, field, path, client, matched) in enumerate(
            (
                (3, "a", 942100, "ARGS:q", "/search", "192.0.2.10", "old"),
                (3, "b", 942100, "ARGS:q", "/search", "192.0.2.11", "older"),
                (1, "c", 942100, "ARGS:q", "/other", "192.0.2.10", "newest"),
                (1, "c", 920350, "", "/other", "192.0.2.10", "192.0.2.1"),
                (0, "d", 920350, "", "/health", "", "192.0.2.1"),
                (0, "e", 942100, "ARGS:id", "/search", "198.51.100.7", "1 OR 1"),
            )
        ):
            at = now - timedelta(hours=hours_ago, seconds=number)
            rows.append(
                (
                    bytes([number]) * 32,
                    "rollup",
                    "node-a",
                    at,
                    f"shop.{request}",
                    "shop",
                    rule,
                    field,
                    matched,
                    path,
                    client,
                )
            )
        copy = (
            "copy waf_match (event_id, cluster, node, occurred_at, request_id, object, "
            "rule_id, field, matched, path, client) from stdin"
        )
        with self.connect() as connection:
            for day in {row[3].date() for row in rows}:
                connection.execute("select waf_match_partition(%s::date)", (day,))
            connection.commit()
        with self.connect("HAPRION_UI_TEST_COLLECTOR_ROLE") as connection:
            # Two imports, and the second read again from an earlier checkpoint.
            for batch in (rows[:4], rows[2:]):
                with connection.cursor() as cursor, cursor.copy(copy) as writer:
                    for row in batch:
                        writer.write_row(row)
                connection.commit()

        since = now - timedelta(days=7)
        kept, counted = self.waf_findings_both_ways(since)
        self.assertEqual(len(counted), 3)
        self.assertEqual(kept, counted)
        by_rule = {(row[2], row[3]): row for row in kept}
        self.assertEqual(by_rule[(942100, "ARGS:q")][4:6], (3, 2))
        self.assertEqual(by_rule[(942100, "ARGS:q")][7], "newest")
        self.assertEqual(by_rule[(920350, "")][5], 1)  # an empty client is no client

        with self.connect() as connection:
            with connection.cursor() as cursor:
                #
                # 0069 changed the client rollup after it, so it goes first
                # and comes back last, leaving the schema at head.
                #
                later = _migration("0069_waf_counter_client_path.py", cursor)
                later.downgrade()
                migration = _migration("0054_waf_finding_rollup.py", cursor)
                migration.downgrade()
                cursor.execute("select to_regclass('public.waf_finding_path')")
                self.assertEqual(cursor.fetchone(), (None,))
                migration.upgrade()
                later.upgrade()
            connection.commit()
        self.assertEqual(self.waf_findings_both_ways(since), (counted, counted))

        script = Path(__file__).resolve().parents[2] / "install/platform/bin/haprion-retention"
        expired = subprocess.run(  # noqa: S603 - fixed interpreter, the repository's script
            [
                "/bin/bash",
                "-c",
                'eval "$(sed -n \'/^TRAFFIC_KEEP_DAYS=/p;/^where_waf_finding_expired() {/,/^}/p\' "$0")"; '
                "where_waf_finding_expired",
                str(script),
            ],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "insert into waf_finding_path values "
                "('rollup', 'shop', 942100, 'ARGS:q', %s, '/gone', 1, %s, 'x')",
                (now - timedelta(days=30), now - timedelta(days=30)),
            )
            cursor.execute(
                f"select path from waf_finding_path where cluster = 'rollup' and {expired}"  # noqa: S608 - the script's own clause
            )
            self.assertEqual(cursor.fetchall(), [("/gone",)])
            connection.rollback()

    def test_retention_analyzes_every_partitioned_table_and_no_other(self) -> None:
        """Review 2026-10-03, D1: autovacuum never analyzes a partitioned parent."""

        script = Path(__file__).resolve().parents[2] / "install/platform/bin/haprion-retention"
        listed = subprocess.run(  # noqa: S603 - fixed interpreter, the repository's script
            [
                "/bin/bash",
                "-c",
                'eval "$(sed -n \'/^PARTITIONED_TABLES=/p\' "$0")"; printf "%s\\n" "${PARTITIONED_TABLES[@]}"',
                str(script),
            ],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.split()
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "select relname from pg_class where relkind = 'p' "
                "and relnamespace = 'public'::regnamespace order by relname"
            )
            self.assertEqual(sorted(listed), [row[0] for row in cursor.fetchall()])
            for table in listed:
                cursor.execute(f"analyze {table}")  # the names are the schema's own, checked above
            connection.rollback()

    def test_quick_log_report_sums_leaf_statistics_and_sizes_once(self) -> None:
        script = Path(__file__).resolve().parents[2] / "install/platform/bin/haprion-retention"
        for table in ("traffic_log", "waf_match"):
            query = subprocess.run(  # noqa: S603 - fixed interpreter, repository script
                [
                    "/bin/bash",
                    "-c",
                    'eval "$(sed -n \'/^partition_report_query() {/,/^}/p\' "$0")"; '
                    'partition_report_query "$1"',
                    str(script),
                    table,
                ],
                capture_output=True,
                text=True,
                check=True,
            ).stdout
            with self.connect() as connection, connection.cursor() as cursor:
                cursor.execute(psycopg.sql.SQL("analyze {}").format(psycopg.sql.Identifier(table)))
                cursor.execute(query)
                actual = cursor.fetchone()
                cursor.execute(
                    "select coalesce(sum(greatest(child.reltuples, 0)), 0)::bigint, "
                    "count(*) filter (where child.reltuples < 0), "
                    "pg_size_pretty(coalesce(sum(pg_total_relation_size(child.oid)), 0)::bigint) "
                    "from pg_inherits join pg_class child on child.oid = inhrelid "
                    "where inhparent = %s::regclass",
                    (table,),
                )
                self.assertEqual(actual, cursor.fetchone())
                self.assertNotIn("count(*) from", query.lower())
                connection.rollback()

    def test_editor_cache_readers_select_the_cluster_before_decoding_documents(self) -> None:
        pairs = (
            (db.record_cluster_objects, db.cluster_objects),
            (db.record_cluster_network, db.cluster_networks),
            (db.record_cluster_history, db.cluster_histories),
            (db.record_cluster_certificates, db.cluster_certificates),
        )
        with self.connect() as connection:
            for writer, reader in pairs:
                for cluster in ("read-alpha", "read-beta"):
                    writer(connection, cluster=cluster, outcome="done", result={"marker": cluster})
                selected = reader(connection, cluster="read-alpha")
                self.assertEqual([row.cluster for row in selected], ["read-alpha"])
                self.assertEqual(selected[0].result, {"marker": "read-alpha"})
                self.assertEqual(reader(connection, cluster="read-absent"), [])
                self.assertTrue(
                    {"read-alpha", "read-beta"}.issubset(
                        {row.cluster for row in reader(connection)}
                    )
                )
            connection.rollback()

    def retention_partitions_expired(self, table: str) -> str:
        """The retention command's own query for a day-partitioned table's expired days."""
        script = Path(__file__).resolve().parents[2] / "install/platform/bin/haprion-retention"
        return subprocess.run(  # noqa: S603 - fixed interpreter, the repository's script
            [
                "/bin/bash",
                "-c",
                'eval "$(sed -n \'/^TRAFFIC_KEEP_DAYS=/p;/^partitions_expired() {/,/^}/p\' "$0")"; '
                'partitions_expired "$1"',
                str(script),
                table,
            ],
            capture_output=True,
            text=True,
            check=True,
        ).stdout

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
            with self.connect("HAPRION_UI_TEST_COLLECTOR_ROLE") as connection:
                _ingest_part(config, connection, target, part)
                checkpoint = root / f".{part.name}.database-offset"
                checkpoint.unlink()
                _ingest_part(config, connection, target, part)
            self.assertEqual(int(checkpoint.read_text()), part.stat().st_size)
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection, connection.cursor() as cursor:
            cursor.execute("select count(*) from traffic_log where host = 'copy.example.com'")
            self.assertEqual(cursor.fetchone(), (1,))

    def test_the_waf_engine_s_matches_are_stored_once_and_the_cursor_follows(self) -> None:
        """Fas 21 steg 4a: what the collector role may write into waf_match is
        what the parser builds, a repeat of the same journal lines stores
        nothing twice, and the page's role reads it back."""

        at = int(datetime.now(UTC).timestamp()) * 1_000_000 + 250_000
        request_id = f"shop.{uuid4()}"
        match = {
            "client": "192.0.2.30",
            "rule_id": 942100,
            "data": "Matched Data: s&1c found within ARGS:id: 1' OR 1=1--\u0007",
            "uri": "/search?id=1",
            "unique_id": request_id,
        }
        records = [
            {"at": at, "cursor": "s=ab;i=1;b=cd", "message": json.dumps({"match": match})},
            {
                "at": at + 1,
                "cursor": "s=ab;i=2;b=cd",
                "message": json.dumps({"match": match | {"rule_id": 949110}}),
            },
        ]
        raw = (
            json.dumps({"cursor": "s=ab;i=2;b=cd", "eof": True, "reset": False, "sent": 2})
            + "\n"
            + "".join(json.dumps(record) + "\n" for record in records)
        ).encode()
        target = NodeTarget("alpha", "node-a", "node-a.example.com")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = CollectorConfig(
                "svc-logread", root / "key", root / "known_hosts", root, root, (target,)
            )
            page = _parse_waf_response(raw, target)
            with self.connect("HAPRION_UI_TEST_COLLECTOR_ROLE") as connection:
                self.assertEqual(_ingest_waf_pages(config, connection, [(target, page)]), (0, 0))
                (root / ".alpha--node-a.waf-cursor").unlink()
                self.assertEqual(_ingest_waf_pages(config, connection, [(target, page)]), (0, 0))
            self.assertEqual((root / ".alpha--node-a.waf-cursor").read_text(), "s=ab;i=2;b=cd\n")
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection, connection.cursor() as cursor:
            cursor.execute(
                "select object, rule_id, field, matched, path, client, occurred_at "
                "from waf_match where cluster = 'alpha' and request_id = %s",
                (request_id,),
            )
            rows = cursor.fetchall()
        self.assertEqual(len(rows), 1, "949110 is not stored, and the repeat is not either")
        self.assertEqual(
            rows[0][:6], ("shop", 942100, "ARGS:id", "1' OR 1=1--\u0007", "/search", "192.0.2.30")
        )
        self.assertEqual(rows[0][6].microsecond, 250_000)

    def test_a_refused_batch_names_its_constraint_and_not_the_row(self) -> None:
        """Review 2026-10-04 F6: the collector's log says why PostgreSQL refused,
        without quoting the requester's text that DETAIL carries."""

        at = int(datetime.now(UTC).timestamp()) * 1_000_000
        match = {
            "rule_id": 942100,
            "data": "Matched Data: s&1c found within ARGS:id: secret-looking-value",
            "uri": "/search",
            "unique_id": f"shop.{uuid4()}",
        }
        raw = (
            json.dumps({"cursor": "s=ab;i=9;b=cd", "eof": True, "reset": False, "sent": 1})
            + "\n"
            + json.dumps(
                {"at": at, "cursor": "s=ab;i=9;b=cd", "message": json.dumps({"match": match})}
            )
            + "\n"
        ).encode()
        # A cluster name the table's check refuses; the collector takes it from its configuration.
        target = NodeTarget("Not-A-Cluster", "node-a", "node-a.example.com")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = CollectorConfig(
                "svc-logread", root / "key", root / "known_hosts", root, root, (target,)
            )
            page = _parse_waf_response(raw, target)
            with (
                self.connect("HAPRION_UI_TEST_COLLECTOR_ROLE") as connection,
                self.assertRaises(psycopg.Error) as refused,
            ):
                _ingest_waf_pages(config, connection, [(target, page)])
        reason = _database_reason(refused.exception)
        self.assertIn("waf_match_cluster_shape", reason)
        self.assertIn("(23514)", reason)
        self.assertNotIn("secret-looking-value", reason)

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
                self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection,
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
            with self.connect("HAPRION_UI_TEST_COLLECTOR_ROLE") as connection:
                _ingest_part(config, connection, target, part)
            with part.open("a") as stream:
                stream.write(line("b.restore.example.com", 2) + "\n")
            with self.connect("HAPRION_UI_TEST_COLLECTOR_ROLE") as connection:
                _ingest_part(config, connection, target, part)
            with self.connect() as connection, connection.cursor() as cursor:
                cursor.execute("delete from traffic_log where host = 'b.restore.example.com'")
            self.assertEqual(count("b.restore.example.com"), 0)

            with self.connect("HAPRION_UI_TEST_COLLECTOR_ROLE") as connection:
                _ingest_part(config, connection, target, part)
            self.assertEqual(count("b.restore.example.com"), 0, "without the replay B stays lost")

            self.assertEqual(forget_database_positions(config), 1)
            with self.connect("HAPRION_UI_TEST_COLLECTOR_ROLE") as connection:
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
            with self.connect("HAPRION_UI_TEST_COLLECTOR_ROLE") as connection:
                skipped = _ingest_part(config, connection, target, part)
            self.assertEqual(skipped, 5)
            checkpoint = root / f".{part.name}.database-offset"
            self.assertEqual(int(checkpoint.read_text()), part.stat().st_size)
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection, connection.cursor() as cursor:
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
            with self.connect("HAPRION_UI_TEST_COLLECTOR_ROLE") as connection:
                self.assertEqual(_ingest_part(config, connection, target, part), 0)
                self.assertFalse(checkpoint.exists())
                part.write_text(line + "\n")
                self.assertEqual(_ingest_part(config, connection, target, part), 0)
            self.assertEqual(int(checkpoint.read_text()), part.stat().st_size)
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection, connection.cursor() as cursor:
            cursor.execute("select count(*) from traffic_log where host = 'partial.example.com'")
            self.assertEqual(cursor.fetchone(), (1,))

    def test_the_database_names_the_days_it_can_still_store(self) -> None:
        """The mirror keeps files for longer than the database keeps rows.

        That difference is deliberate - after a restore the mirror is the only
        thing left to replay from - so the collector asks which days exist
        rather than assuming its own window matches the platform's retention.
        """

        with self.connect("HAPRION_UI_TEST_COLLECTOR_ROLE") as connection:
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
                self.connect("HAPRION_UI_TEST_COLLECTOR_ROLE") as connection,
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
        with self.connect("HAPRION_UI_TEST_COLLECTOR_ROLE") as connection:
            days = _database_days(connection)
        past = sum(1 for day in days if day <= f"{now:%Y%m%d}")
        config = CollectorConfig(
            "svc-logread",
            Path("/nonexistent/key"),
            Path("/nonexistent/known_hosts"),
            Path("/nonexistent/mirror"),
            Path("/nonexistent/staging"),
            (NodeTarget("alpha", "node-a", "node-a.example.com"),),
            os.environ["HAPRION_UI_TEST_DATABASE_NAME"],
            os.environ["HAPRION_UI_TEST_DATABASE_SOCKET"],
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
            "haprion_ui_absent",
            "/nonexistent/socket",
        )
        self.assertEqual(_mirror_window(config, now=datetime.now(UTC)), RETENTION_DAYS)

    def test_database_search_uses_boolean_terms_status_and_newest_first(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temporary,
            self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection,
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

    def test_a_reload_late_in_a_bucket_keeps_what_came_before_it(self) -> None:
        """2026-10-04: the 30-day graph lost a load test the figures beside it counted.

        One six-hour bucket holds a reload, a burst of traffic and a second
        reload, with the address held briefly by the other node. The graph's
        bucket must be what the stored changes sum to - the same figure the
        card's totals give - in UTC buckets, read by a session in the server's
        local zone.
        """

        day = (datetime.now(UTC) - timedelta(days=2)).replace(
            hour=0, minute=0, second=0, microsecond=0
        )

        def at(hour: int, minute: int, second: int = 0) -> datetime:
            return day + timedelta(hours=hour, minutes=minute, seconds=second)

        rows = [
            # (node, observed_at, uptime_sec, req_tot)
            ("node-a", at(11, 59, 40), 100_000, 500),
            ("node-a", at(12, 5), 10, 0),  # reloaded
            ("node-a", at(12, 44), 2_350, 1_000),
            ("node-a", at(12, 48), 2_590, 29_998),  # the burst
            ("node-b", at(13, 0), 10, 7),
            ("node-b", at(13, 0, 20), 30, 9),
            ("node-a", at(14, 5), 5, 0),  # reloaded again, later in the bucket
            ("node-a", at(17, 59), 14_000, 3),
            ("node-a", at(18, 5), 14_360, 4),
        ]
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute("select metric_partition('metric_frontend', %s::date)", (day.date(),))
            cursor.executemany(
                "insert into metric_frontend "
                "(cluster, node, frontend, observed_at, owns_vip, uptime_sec, req_tot) "
                "values ('reload', %s, 'mgd-main-https', %s, true, %s, %s)",
                rows,
            )
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
            connection.execute("set timezone = 'Europe/Stockholm'")
            series = db.read_frontend_series(
                connection,
                cluster="reload",
                frontend="mgd-main-https",
                since=at(6, 0),
                until=at(23, 0),
                width=timedelta(hours=6),
            )
            totals = db.read_frontend_totals(
                connection,
                cluster="reload",
                frontend="mgd-main-https",
                since=at(12, 0),
                until=at(18, 0),
            )
        grid = {
            bucket.at: bucket.counters["req_tot"]
            for bucket in metrics.bucketed(
                series, start=at(6, 0), end=at(23, 0), bucket=timedelta(hours=6)
            )
        }
        # 1 000 + 28 998 + 3 on node-a, 2 on node-b; a reading per bucket said 3.
        self.assertEqual(grid[at(12, 0)], 30_003)
        self.assertEqual(totals.totals[0].value, 30_003)
        self.assertEqual(grid[at(6, 0)], 0)

    def test_the_dashboard_sums_every_frontend_the_way_each_card_counts_one(self) -> None:
        """B220, 2026-10-01: one query for the dashboard, the card's own arithmetic.

        Two frontends in `dash-a` - one restarting part way - a frontend in
        `dash-b` that is not asked for, and a node that does not hold the VIP.
        The sum must be the two cards' figures added, so the dashboard and the
        metrics page cannot disagree about what a counter did.
        """

        start = datetime.now(UTC).replace(second=0, microsecond=0) - timedelta(minutes=30)
        rows = [
            # (cluster, node, frontend, minute, owns_vip, uptime, req_tot, bin, bout)
            ("dash-a", "node-a", "mgd-one-http", 0, True, 1000, 100, 10_000, 90_000),
            ("dash-a", "node-a", "mgd-one-http", 1, True, 1060, 160, 16_000, 150_000),
            ("dash-a", "node-a", "mgd-one-http", 2, True, 1120, 200, 20_000, 190_000),
            ("dash-a", "node-a", "mgd-two-http", 0, True, 1000, 5_000, 1_000, 2_000),
            ("dash-a", "node-a", "mgd-two-http", 1, True, 30, 40, 100, 300),
            ("dash-a", "node-a", "mgd-two-http", 2, True, 90, 70, 400, 900),
            ("dash-a", "node-b", "mgd-one-http", 1, False, 500, 9_999, 9_999, 9_999),
            ("dash-a", "node-b", "mgd-one-http", 2, False, 560, 19_999, 19_999, 19_999),
            ("dash-b", "node-c", "mgd-one-http", 0, True, 1000, 0, 0, 0),
            ("dash-b", "node-c", "mgd-one-http", 2, True, 1120, 777, 777, 777),
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
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
            summed = db.read_traffic_summary(
                connection, clusters=["dash-a"], since=start, until=until
            )
            selected = ["dash-a", "dash-b", "dash-empty"]
            grouped = db.read_traffic_summaries(
                connection, clusters=selected, since=start, until=until
            )
            for name in selected:
                self.assertEqual(
                    grouped[name],
                    db.read_traffic_summary(connection, clusters=[name], since=start, until=until),
                )
            self.assertEqual(
                db.read_traffic_summaries(connection, clusters=[], since=start, until=until), {}
            )
            cards = [
                db.read_frontend_totals(
                    connection, cluster="dash-a", frontend=name, since=start, until=until
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
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
            answered, median, p95 = db.read_response_times(
                connection,
                clusters=["rt-only"],
                since=now - timedelta(minutes=1),
                until=now + timedelta(minutes=1),
            )
            selected = ["rt-only", "rt-other", "rt-empty"]
            grouped = db.read_response_times_by_cluster(
                connection,
                clusters=selected,
                since=now - timedelta(minutes=1),
                until=now + timedelta(minutes=1),
            )
            for name in selected:
                self.assertEqual(
                    grouped[name],
                    db.read_response_times(
                        connection,
                        clusters=[name],
                        since=now - timedelta(minutes=1),
                        until=now + timedelta(minutes=1),
                    ),
                )
            self.assertEqual(
                db.read_response_times_by_cluster(connection, clusters=[], since=now, until=now), {}
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
        role = os.environ["HAPRION_UI_TEST_MIGRATION_ROLE"]
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
        role = os.environ["HAPRION_UI_TEST_WEB_ROLE"]
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

    def connect(self, role_variable: str = "HAPRION_UI_TEST_MIGRATION_ROLE") -> psycopg.Connection:
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
            self.connect("HAPRION_UI_TEST_POLLER_ROLE") as connection,
            connection.cursor() as cursor,
        ):
            cursor.execute(
                "insert into metric_listener "
                "(cluster, node, frontend, owns_vip, uptime_sec, req_tot) "
                "values ('bridge', 'node-a', 'mgd-old-name', true, 60, 7)"
            )
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection, connection.cursor() as cursor:
            cursor.execute(
                "select req_tot, observed_at is not null from metric_frontend "
                "where cluster = 'bridge' and frontend = 'mgd-old-name'"
            )
            self.assertEqual(cursor.fetchall(), [(7, True)])

    def test_the_rollup_boundary_moved_with_the_table(self) -> None:
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection, connection.cursor() as cursor:
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


def _first(cursor: psycopg.Cursor) -> Any:
    """The first column of the row the last statement returned, which it must have."""

    row = cursor.fetchone()
    if row is None:
        raise AssertionError("the statement returned no row")
    return row[0]


def _migration(filename: str, cursor: psycopg.Cursor) -> Any:
    """One migration module, loaded by file, with `op` bound to this cursor."""

    path = Path(__file__).resolve().parents[1] / "migrations" / "versions" / filename
    spec = importlib.util.spec_from_file_location(f"migration_{filename[:4]}", path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load {path}")
    module: Any = importlib.util.module_from_spec(spec)
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

    def connect(self, role_variable: str = "HAPRION_UI_TEST_MIGRATION_ROLE") -> psycopg.Connection:
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
        with self.connect("HAPRION_UI_TEST_MIGRATION_ROLE") as connection:
            with connection.cursor() as cursor:
                cursor.execute("delete from job")
                cursor.execute("delete from dns_provider_profile")
            connection.commit()

    def test_the_web_creates_replaces_and_lists_without_seeing_the_box(self) -> None:
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
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
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
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
        with self.connect("HAPRION_UI_TEST_WORKER_ROLE") as connection:
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
            self.connect("HAPRION_UI_TEST_POLLER_ROLE") as connection,
            connection.cursor() as cursor,
            self.assertRaises(psycopg.errors.InsufficientPrivilege),
        ):
            cursor.execute("select id from dns_provider_profile")

    def test_the_apply_job_is_a_certificate_job(self) -> None:
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
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
        migration: Any = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(migration)

        with self.connect("HAPRION_UI_TEST_MIGRATION_ROLE") as connection:
            with connection.cursor() as cursor:
                migration.op = _Executes(cursor)
                migration.downgrade()
                cursor.execute("select to_regclass('dns_provider_profile')")
                self.assertEqual(cursor.fetchone(), (None,))
                cursor.execute(
                    "select pg_get_constraintdef(oid) from pg_constraint "
                    "where conname = 'job_operation_allowed'"
                )
                self.assertNotIn("dns_profile_apply", _first(cursor))
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
        with self.connect("HAPRION_UI_TEST_MIGRATION_ROLE") as connection:
            with connection.cursor() as cursor:
                cursor.execute("delete from job")
            connection.commit()

    def test_the_delete_job_is_a_clusterless_certificate_job(self) -> None:
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
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
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
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
            self.connect("HAPRION_UI_TEST_WORKER_ROLE") as connection,
            self.assertRaises(psycopg.errors.InsufficientPrivilege),
        ):
            db.live_drafts(connection)
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
            self.assertEqual(db.live_drafts(connection), [])

    def test_the_migration_downgrades_and_upgrades_cleanly_on_an_empty_queue(self) -> None:
        migration_path = (
            Path(__file__).resolve().parents[1] / "migrations" / "versions" / "0026_cert_delete.py"
        )
        spec = importlib.util.spec_from_file_location("migration_0026", migration_path)
        if spec is None or spec.loader is None:
            self.fail(f"cannot load {migration_path}")
        migration: Any = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(migration)

        with self.connect("HAPRION_UI_TEST_MIGRATION_ROLE") as connection:
            with connection.cursor() as cursor:
                migration.op = _Executes(cursor)
                migration.downgrade()
                cursor.execute(
                    "select pg_get_constraintdef(oid) from pg_constraint "
                    "where conname = 'job_operation_allowed'"
                )
                self.assertNotIn("cert_delete", _first(cursor))
                migration.upgrade()
                cursor.execute(
                    "select pg_get_constraintdef(oid) from pg_constraint "
                    "where conname = 'job_operation_allowed'"
                )
                self.assertIn("cert_delete", _first(cursor))
            connection.rollback()


@unittest.skipUnless(DSN, "run through ui/tools/test-database")
class NdesDatabase(unittest.TestCase):
    def connect(self, role_variable: str = "HAPRION_UI_TEST_MIGRATION_ROLE") -> psycopg.Connection:
        return psycopg.connect(f"{DSN} user={os.environ[role_variable]}")

    def setUp(self) -> None:
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute("delete from job")
            cursor.execute("delete from ndes_provider_profile")
            connection.commit()

    def create(self) -> None:
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
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
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
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
        with self.connect("HAPRION_UI_TEST_WORKER_ROLE") as connection:
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
        with self.connect("HAPRION_UI_TEST_POLLER_ROLE") as connection:
            with (
                connection.cursor() as cursor,
                self.assertRaises(psycopg.errors.InsufficientPrivilege),
            ):
                cursor.execute("select id from ndes_provider_profile")
            connection.rollback()

    def test_ndes_apply_uses_the_shared_certificate_slot(self) -> None:
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
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

    def connect(self, role_variable: str = "HAPRION_UI_TEST_MIGRATION_ROLE") -> psycopg.Connection:
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
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
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
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
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
        return self.connect("HAPRION_UI_TEST_WEB_ROLE")

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

        first = self.connect("HAPRION_UI_TEST_WEB_ROLE")
        second = self.connect("HAPRION_UI_TEST_WEB_ROLE")
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
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
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
        migration: Any = importlib.util.module_from_spec(spec)
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
    """Migrations 0040, 0042, 0049, 0051: switches the web flips and nothing more (B193, B204, B224, B231)."""

    def connect(self, role_variable: str = "HAPRION_UI_TEST_MIGRATION_ROLE") -> psycopg.Connection:
        return psycopg.connect(f"{DSN} user={os.environ[role_variable]}")

    def tearDown(self) -> None:
        with self.connect() as connection:
            connection.execute(
                "update feature_switch set enabled = (name = 'cluster_colours'), "
                "remembered = '{}', updated_by = null"
            )
            connection.commit()

    def test_every_switch_exists_and_starts_where_its_migration_put_it(self) -> None:
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
            switches = db.feature_switches(connection)

        self.assertEqual(
            {name: switch.enabled for name, switch in switches.items()},
            {
                "cert_receivers": False,
                "node_backups": False,
                "cluster_colours": True,
                "advanced_config": False,
                "waf_engine": False,
            },
        )

    def test_the_waf_engine_switch_downgrades_and_upgrades_cleanly(self) -> None:
        with self.connect() as connection:
            with connection.cursor() as cursor:
                migration = _migration("0051_waf_engine.py", cursor)
                migration.downgrade()
                with self.assertRaises(psycopg.errors.CheckViolation):
                    cursor.execute("insert into feature_switch (name) values ('waf_engine')")
            connection.rollback()
            with connection.cursor() as cursor:
                migration = _migration("0051_waf_engine.py", cursor)
                migration.downgrade()
                migration.upgrade()
                cursor.execute("select enabled from feature_switch where name = 'waf_engine'")
                self.assertEqual(cursor.fetchone(), (False,))
            connection.rollback()

    def test_the_advanced_config_switch_downgrades_and_upgrades_cleanly(self) -> None:
        with self.connect() as connection:
            with connection.cursor() as cursor:
                _migration("0051_waf_engine.py", cursor).downgrade()
                migration = _migration("0049_advanced_config_switch.py", cursor)
                migration.downgrade()
                cursor.execute("select name from feature_switch order by name")
                self.assertEqual(
                    cursor.fetchall(),
                    [("cert_receivers",), ("cluster_colours",), ("node_backups",)],
                )
                with self.assertRaises(psycopg.errors.CheckViolation):
                    cursor.execute("insert into feature_switch (name) values ('advanced_config')")
            connection.rollback()
            with connection.cursor() as cursor:
                _migration("0051_waf_engine.py", cursor).downgrade()
                migration = _migration("0049_advanced_config_switch.py", cursor)
                migration.downgrade()
                migration.upgrade()
                cursor.execute("select enabled from feature_switch where name = 'advanced_config'")
                self.assertEqual(cursor.fetchone(), (False,))
            connection.rollback()

    def test_the_colours_switch_downgrades_and_upgrades_cleanly(self) -> None:
        with self.connect() as connection:
            with connection.cursor() as cursor:
                _migration("0051_waf_engine.py", cursor).downgrade()
                _migration("0049_advanced_config_switch.py", cursor).downgrade()
                migration = _migration("0042_cluster_colours_switch.py", cursor)
                migration.downgrade()
                cursor.execute("select name from feature_switch order by name")
                self.assertEqual(cursor.fetchall(), [("cert_receivers",), ("node_backups",)])
                with self.assertRaises(psycopg.errors.CheckViolation):
                    cursor.execute("insert into feature_switch (name) values ('cluster_colours')")
            connection.rollback()
            with connection.cursor() as cursor:
                _migration("0051_waf_engine.py", cursor).downgrade()
                _migration("0049_advanced_config_switch.py", cursor).downgrade()
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
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
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
                self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection,
            ):
                connection.execute(statement)

    def test_the_worker_and_the_poller_do_not_read_the_switches(self) -> None:
        for role in ("HAPRION_UI_TEST_WORKER_ROLE", "HAPRION_UI_TEST_POLLER_ROLE"):
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

    def connect(self, role_variable: str = "HAPRION_UI_TEST_MIGRATION_ROLE") -> psycopg.Connection:
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
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
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
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
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
class AccountToolHarness(unittest.TestCase):
    """The account tool against the real schema: as root, as the migration role."""

    HASH = OidcAccounts.HASH

    def connect(self, role_variable: str = "HAPRION_UI_TEST_MIGRATION_ROLE") -> psycopg.Connection:
        return psycopg.connect(f"{DSN} user={os.environ[role_variable]}")

    def setUp(self) -> None:
        from haprion_ui import admin

        self.admin = admin
        with self.connect() as connection:
            connection.execute("truncate app_user cascade")
            connection.commit()
        for patch in (
            mock.patch("os.geteuid", return_value=0),
            mock.patch.object(
                admin,
                "load_environment",
                return_value=admin.Environment(database="test", role="test"),
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


@unittest.skipUnless(DSN, "run through ui/tools/test-database")
class TheAccountToolAgainstARealDatabase(AccountToolHarness):
    """`haprion-user`'s verbs from 0041 (B196, B197), through `main`, on the real schema."""

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

    def connect(self, role_variable: str = "HAPRION_UI_TEST_MIGRATION_ROLE") -> psycopg.Connection:
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
        return self.connect("HAPRION_UI_TEST_WEB_ROLE")

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

    def connect(self, role_variable: str = "HAPRION_UI_TEST_MIGRATION_ROLE") -> psycopg.Connection:
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
        return self.connect("HAPRION_UI_TEST_WEB_ROLE")

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


@unittest.skipUnless(DSN, "run through ui/tools/test-database")
class WhenAnExceptionReachedTheNodes(unittest.TestCase):
    """The first finished deploy carrying an exception (26-10-11), read as web."""

    def connect(self, role_variable: str) -> psycopg.Connection:
        return psycopg.connect(f"{DSN} user={os.environ[role_variable]}")

    def job(
        self, operation: str, cluster: str, created: str, state: str = "done", **payload: Any
    ) -> None:
        with (
            self.connect("HAPRION_UI_TEST_MIGRATION_ROLE") as connection,
            connection.cursor() as cursor,
        ):
            cursor.execute(
                "insert into job (operation, cluster, payload, idempotency_key, state, created_at, "
                "started_at, finished_at) values (%(operation)s, %(cluster)s, %(payload)s, %(key)s, "
                "%(state)s, %(created)s, %(created)s, %(created)s::timestamptz + interval '4 seconds') "
                "returning id",
                {
                    "operation": operation,
                    "cluster": cluster,
                    "payload": json.dumps(payload),
                    "key": uuid4(),
                    "state": state,
                    "created": created,
                },
            )
            job = _first(cursor)
            connection.commit()
        self.addCleanup(self.forget, job)

    def forget(self, job: Any) -> None:
        with (
            self.connect("HAPRION_UI_TEST_MIGRATION_ROLE") as connection,
            connection.cursor() as cursor,
        ):
            cursor.execute("delete from job where id = %s", (job,))
            connection.commit()

    def test_the_first_deploy_after_the_publish_that_took_it(self) -> None:
        self.job("deploy", "ex-a", "2026-10-02 13:00Z")  # before
        #
        # Saved at 14:00 and deployed before it was published: that deploy
        # rolled out the version before the exception (review 26-10-11, F1).
        #
        self.job("deploy", "ex-a", "2026-10-02 14:00:30Z")
        self.job("changes_publish", "ex-a", "2026-10-02 14:01Z")  # a publish alone
        self.job("deploy", "ex-a", "2026-10-02 14:02Z", state="failed")
        self.job("deploy", "ex-b", "2026-10-02 14:03Z")  # another cluster
        self.job("deploy", "ex-a", "2026-10-02 14:04Z")
        self.job("changes_publish", "ex-a", "2026-10-02 14:10Z", deploy=True)
        made = datetime(2026, 10, 2, 14, 0, tzinfo=UTC)
        published_and_deployed = datetime(2026, 10, 2, 14, 9, tzinfo=UTC)
        never_published = datetime(2026, 10, 2, 14, 30, tzinfo=UTC)

        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
            found = db.deploys_carrying(
                connection, cluster="ex-a", moments=[made, published_and_deployed, never_published]
            )
            self.assertEqual(db.deploys_carrying(connection, cluster="ex-a", moments=[]), {})

        self.assertEqual(
            found,
            {
                made: datetime(2026, 10, 2, 14, 4, 4, tzinfo=UTC),
                published_and_deployed: datetime(2026, 10, 2, 14, 10, 4, tzinfo=UTC),
            },
        )


@unittest.skipUnless(DSN, "run through ui/tools/test-database")
class WhatAnExceptionLetThroughIsNoFinding(unittest.TestCase):
    """B273: the counters share the rollup with the rule set's matches, and are read apart.

    And each exception within what it covers (review 26-10-11): a counter's
    number passes to the next exception on the rule when one is removed, and
    the one that stayed showed the removed one's week.
    """

    def connect(self, role_variable: str) -> psycopg.Connection:
        return psycopg.connect(f"{DSN} user={os.environ[role_variable]}")

    def setUp(self) -> None:
        self.now = datetime.now(UTC).replace(microsecond=0)
        rows = (
            # (rule, field, path, client)
            (942100, "ARGS:q", "/search", "192.0.2.1"),
            (342100, "ARGS:q", "/", "192.0.2.2"),
            (342100, "ARGS:q", "/", "192.0.2.2"),
            (342100, "ARGS:q", "//", "192.0.2.3"),
            (342100, "ARGS:q", "/x", "192.0.2.4"),
            (342100, "ARGS:z", "/", "192.0.2.2"),
        )
        with self.connect("HAPRION_UI_TEST_MIGRATION_ROLE") as connection:
            connection.execute("select waf_match_partition(%s::date)", (self.now.date(),))
            for index, (rule, field, path, client) in enumerate(rows):
                connection.execute(
                    "insert into waf_match (event_id, cluster, node, occurred_at, request_id, "
                    "object, rule_id, field, matched, path, client) values "
                    "(%s, 'ct-a', 'node-a', %s, %s, 'shop', %s, %s, 'x', %s, %s)",
                    (
                        os.urandom(32),
                        self.now - timedelta(minutes=len(rows) - index),
                        f"shop.{uuid4()}",
                        rule,
                        field,
                        path,
                        client,
                    ),
                )
            connection.commit()
        self.addCleanup(self.forget)

    def forget(self) -> None:
        with (
            self.connect("HAPRION_UI_TEST_MIGRATION_ROLE") as connection,
            connection.cursor() as cursor,
        ):
            cursor.execute("delete from waf_match where cluster = 'ct-a'")
            cursor.execute("delete from waf_finding_path where cluster = 'ct-a'")
            cursor.execute("delete from waf_finding_client where cluster = 'ct-a'")
            connection.commit()

    def counted(self, *scopes: db.CounterScope) -> dict[db.CounterScope, db.WafCounted]:
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
            return db.waf_counted(connection, scopes=scopes, since=self.now - timedelta(days=1))

    def test_findings_are_the_rule_set_s_and_the_counters_are_apart(self) -> None:
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
            findings = db.waf_findings(
                connection, clusters=["ct-a"], since=self.now - timedelta(days=1)
            )
        self.assertEqual([row.rule_id for row in findings], [942100])

    def test_each_exception_counts_within_its_field_and_paths(self) -> None:
        root = db.CounterScope("ct-a", "shop", 342100, "ARGS:q", ("/",))
        other = db.CounterScope("ct-a", "shop", 342100, "ARGS:q", ("/x",))
        field = db.CounterScope("ct-a", "shop", 342100, "ARGS:q", ())
        anything = db.CounterScope("ct-a", "shop", 342100, "", ())
        found = self.counted(root, other, field, anything)
        # The root also as `//`, which the counter counts.
        self.assertEqual((found[root].requests, found[root].clients), (3, 2))
        # The removed exception's matches on `/` stay off the one on `/x`.
        self.assertEqual((found[other].requests, found[other].clients), (1, 1))
        self.assertEqual((found[field].requests, found[field].clients), (4, 3))
        self.assertEqual((found[anything].requests, found[anything].clients), (5, 3))
        self.assertIsNotNone(found[root].last_seen)
        self.assertEqual(self.counted(), {})

    def test_only_a_counter_s_clients_carry_their_path(self) -> None:
        with (
            self.connect("HAPRION_UI_TEST_MIGRATION_ROLE") as connection,
            connection.cursor() as cursor,
        ):
            cursor.execute(
                "select rule_id, path from waf_finding_client where cluster = 'ct-a' "
                "order by rule_id, path"
            )
            kept = cursor.fetchall()
        self.assertIn((942100, ""), kept)
        self.assertEqual(
            sorted(path for rule, path in kept if rule == 342100), ["/", "/", "//", "/x"]
        )


@unittest.skipUnless(DSN, "run through ui/tools/test-database")
class TheSearchIndex(unittest.TestCase):
    """B222: the poller writes the rows, the web searches them, through the trigram index."""

    def connect(self, role_variable: str) -> psycopg.Connection:
        return psycopg.connect(f"{DSN} user={os.environ[role_variable]}")

    def write(self, cluster: str, source: str, entries: list[Any]) -> None:
        with self.connect("HAPRION_UI_TEST_POLLER_ROLE") as connection:
            db.replace_search_entries(connection, cluster=cluster, source=source, entries=entries)
            connection.commit()

    def search(self, query: str, *, role: str = "admin", page: int = 1) -> Any:
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
            return db.search(connection, query, role=role, clusters=["si-a", "si-b"], page=page)

    def objects(self, cluster: str, *names: str) -> list[Any]:
        return search_index.object_entries(
            cluster,
            {
                "objects": [
                    {
                        "name": name,
                        "hostnames": [f"{name}.example.com"],
                        "vip": {"name": "main", "address": "192.0.2.20", "default": True},
                        "source": {"name": None, "address": "192.0.2.25"},
                        "servers": [f"198.51.100.{index}:8080"],
                    }
                    for index, name in enumerate(names, start=10)
                ]
            },
        )

    def setUp(self) -> None:
        with self.connect("HAPRION_UI_TEST_POLLER_ROLE") as connection:
            db.prune_search_entries(connection, [])
            connection.commit()

    def test_a_backend_is_found_with_what_matched_and_only_by_an_admin(self) -> None:
        self.write("si-a", "objects", self.objects("si-a", "shop", "api"))

        found = self.search("198.51.100.11")
        self.assertEqual(found.total, 1)
        hit = found.groups[0].hits[0]
        self.assertEqual(
            (hit.title, hit.matched, hit.href),
            ("api", "Backend 198.51.100.11:8080", "/proxies/si-a/api"),
        )
        self.assertEqual(self.search("198.51.100.11", role="reader").total, 0)
        self.assertEqual(self.search("api", role="reader").groups[0].hits[0].href, "/proxies")

    def test_an_unchanged_reading_leaves_its_rows_alone(self) -> None:
        """Review 2026-10-03, D5: the same rows are not deleted and inserted again."""

        def versions() -> list[Any]:
            with self.connect("HAPRION_UI_TEST_MIGRATION_ROLE") as connection:
                rows = connection.execute(
                    "select value, xmin::text from search_entry where cluster = 'si-a' order by value"
                ).fetchall()
            return rows

        self.write("si-a", "objects", self.objects("si-a", "shop", "api"))
        before = versions()
        self.write("si-a", "objects", list(reversed(self.objects("si-a", "shop", "api"))))
        self.assertEqual(versions(), before, "rewritten although nothing changed")

        self.write("si-a", "objects", self.objects("si-a", "shop"))
        self.assertNotIn("api", [value for value, _ in versions()])
        self.assertEqual(self.search("api").total, 0)

    def test_like_characters_in_a_query_are_text(self) -> None:
        self.write("si-a", "objects", self.objects("si-a", "a_b", "axb"))

        self.assertEqual([h.title for h in self.search("a_b").groups[0].hits], ["a_b"])
        self.assertEqual(self.search("%").total, 0)

    def test_a_reading_replaces_its_own_rows_and_no_others(self) -> None:
        self.write("si-a", "objects", self.objects("si-a", "shop"))
        self.write(
            "si-a",
            "network",
            search_index.network_entries(
                "si-a", {"default_vip": "main", "vips": [{"name": "main", "address": "192.0.2.20"}]}
            ),
        )
        self.write("si-a", "objects", self.objects("si-a", "api"))

        self.assertEqual(self.search("shop").total, 0)
        self.assertEqual(self.search("api").total, 1)
        groups = {g.label: [h.title for h in g.hits] for g in self.search("192.0.2.20").groups}
        self.assertEqual(groups, {"Proxies": ["api"], "Addresses": ["VIP main (default)"]})

    def test_pages_of_a_hundred_in_the_order_shown(self) -> None:
        names = [f"site{n:03d}" for n in range(250)]
        self.write("si-b", "objects", self.objects("si-b", *names))

        first, third = self.search("site"), self.search("site", page=3)
        self.assertEqual((first.total, first.pages), (250, 3))
        self.assertEqual(first.groups[0].hits[0].title, "site000")
        self.assertEqual([h.title for h in third.groups[0].hits][-1], "site249")
        self.assertEqual(len(third.groups[0].hits), 50)

    def test_a_removed_cluster_leaves_nothing_behind(self) -> None:
        self.write("si-a", "objects", self.objects("si-a", "shop"))
        self.write("si-b", "objects", self.objects("si-b", "shop"))
        with self.connect("HAPRION_UI_TEST_POLLER_ROLE") as connection:
            db.prune_search_entries(connection, ["si-b"])
            connection.commit()

        self.assertEqual([h.cluster for h in self.search("shop").groups[0].hits], ["si-b"])

    def test_the_web_cannot_write_the_index(self) -> None:
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection, connection.cursor() as cursor:
            for statement in (
                "delete from search_entry",
                "insert into search_entry (cluster, source, kind, title, value, href) "
                "values ('si-a', 'objects', 'proxy', 'x', 'x', '/')",
            ):
                with (
                    self.subTest(statement=statement),
                    self.assertRaises(psycopg.errors.InsufficientPrivilege),
                ):
                    cursor.execute(statement)
                connection.rollback()

    def test_the_query_uses_the_trigram_index(self) -> None:
        with (
            self.connect("HAPRION_UI_TEST_MIGRATION_ROLE") as connection,
            connection.cursor() as cursor,
        ):
            cursor.execute("set enable_seqscan = off")
            cursor.execute("explain select 1 from search_entry where lower(value) like '%192.0.2%'")
            plan = "\n".join(row[0] for row in cursor.fetchall())
        self.assertIn("search_entry_value", plan)


@unittest.skipUnless(DSN, "run through ui/tools/test-database")
class AnUnchangedObjectsListing(unittest.TestCase):
    """B222: confirmed rather than rewritten, and the confirmation is a fresh reading."""

    def test_the_poller_reads_back_its_fingerprint_and_confirms_without_rewriting(self) -> None:
        poller = f"{DSN} user={os.environ['HAPRION_UI_TEST_POLLER_ROLE']}"
        listing = {"commit": "a" * 40, "fingerprint": "f" * 64, "objects": [{"name": "shop"}]}
        with psycopg.connect(poller) as connection:
            db.record_cluster_objects(connection, cluster="fp-a", outcome="done", result=listing)
            connection.commit()
            self.assertEqual(db.objects_fingerprint(connection, "fp-a"), "f" * 64)
            self.assertIsNone(db.objects_fingerprint(connection, "fp-none"))
            before = next(r for r in db.cluster_objects(connection) if r.cluster == "fp-a")

            db.record_cluster_objects(
                connection,
                cluster="fp-a",
                outcome="done",
                result={
                    "commit": "a" * 40,
                    "fingerprint": "f" * 64,
                    "unchanged": True,
                    "objects": [],
                },
            )
            connection.commit()
            after = next(r for r in db.cluster_objects(connection) if r.cluster == "fp-a")

        self.assertEqual(after.result, listing)
        self.assertGreater(after.observed_at, before.observed_at)


@unittest.skipUnless(DSN, "run through ui/tools/test-database")
class TheStoredDifferencesAnswerAsThePairingDid(unittest.TestCase):
    """Migration 0048: the figures summed from stored differences, against the old pairing.

    The old queries are kept verbatim in `metric_totals_reference`. Both run
    over the same rows - a restart, a counter that goes backwards without one,
    an unknown counter, a frontend whose holder moves and one whose ownership
    is unknown - and must agree exactly, for ranges inside the raw rows and
    ending in the past. The hourly half before them is read from 0055's sums
    since then, against the same reference (`TheHourlySumsAnswerAsTheReadersDid`).
    """

    MIGRATION = (
        Path(__file__).resolve().parents[1] / "migrations" / "versions" / "0048_metric_deltas.py"
    )
    CLUSTER = "deltas"
    BACKEND = "mgd-shop-web"
    FRONTEND = "mgd-main-https"
    now: datetime
    start: datetime
    raw_from: datetime

    def connect(self, role_variable: str = "HAPRION_UI_TEST_MIGRATION_ROLE") -> psycopg.Connection:
        return psycopg.connect(f"{DSN} user={os.environ[role_variable]}")

    @classmethod
    def setUpClass(cls) -> None:
        cls.now = datetime.now(UTC).replace(microsecond=0)
        cls.start = cls.now - timedelta(days=12)
        cls.raw_from = cls.now - timedelta(days=6, minutes=17)
        with psycopg.connect(
            f"{DSN} user={os.environ['HAPRION_UI_TEST_MIGRATION_ROLE']}"
        ) as connection:
            cursor = connection.cursor()
            day = cls.start.date() - timedelta(days=1)
            while day <= cls.now.date() + timedelta(days=1):
                cursor.execute("select metric_partition('metric_backend_member', %s::date)", (day,))
                cursor.execute("select metric_partition('metric_frontend', %s::date)", (day,))
                cursor.execute(
                    "select metric_month_partition('metric_backend_hour', %s::date)", (day,)
                )
                day += timedelta(days=1)
            cls._backend(cursor)
            cls._frontend(cursor)

    @classmethod
    def _readings(cls, node: str) -> list[tuple[datetime, int, int | None]]:
        """Every 20 minutes for twelve days: (moment, uptime, req_tot).

        Node b restarts on day 8 and again in the raw half; node a's counter
        goes backwards on day 9 without a restart (a `clear counters`), and one
        reading on each node reports no counter at all.
        """

        found = []
        uptime, total = 1000, 0
        at = cls.start + (timedelta(minutes=7) if node == "b" else timedelta())
        index = 0
        while at <= cls.now:
            index += 1
            uptime += 1200
            total += 3 + index % 5
            if node == "b" and index in (560, 790):
                uptime, total = 300, 4
            if node == "a" and index == 650:
                total = 2
            counter: int | None = None if index == 700 else total
            found.append((at, uptime, counter))
            at += timedelta(minutes=20)
        return found

    @classmethod
    def _backend(cls, cursor: psycopg.Cursor[Any]) -> None:
        for node in ("a", "b"):
            hours: dict[datetime, tuple[datetime, int, int, int | None]] = {}
            for at, uptime, total in cls._readings(node):
                if at >= cls.raw_from - timedelta(hours=3):
                    cursor.execute(
                        "insert into metric_backend_member (cluster, node, backend, member, "
                        "observed_at, uptime_sec, req_tot, hrsp_2xx, hrsp_5xx, econ) "
                        "values (%s, %s, %s, 'BACKEND', %s, %s, %s, %s, %s, %s)",
                        (
                            cls.CLUSTER,
                            node,
                            cls.BACKEND,
                            at,
                            uptime,
                            total,
                            None if total is None else total - total // 7,
                            None if total is None else total // 9,
                            1,
                        ),
                    )
                bucket = at.replace(minute=0, second=0)
                if bucket < cls.raw_from:
                    floor = min(uptime, hours[bucket][2]) if bucket in hours else uptime
                    hours[bucket] = (at, uptime, floor, total)
            for bucket, (at, uptime, floor, total) in hours.items():
                cursor.execute(
                    "insert into metric_backend_hour (cluster, node, backend, member, bucket_at, "
                    "observed_at, uptime_sec, floor_uptime_sec, req_tot, hrsp_2xx, hrsp_5xx, econ) "
                    "values (%s, %s, %s, 'BACKEND', %s, %s, %s, %s, %s, %s, %s, %s)",
                    (
                        cls.CLUSTER,
                        node,
                        cls.BACKEND,
                        bucket,
                        at,
                        uptime,
                        floor,
                        total,
                        None if total is None else total - total // 7,
                        None if total is None else total // 9,
                        1,
                    ),
                )

    @classmethod
    def _frontend(cls, cursor: psycopg.Cursor[Any]) -> None:
        for node in ("a", "b"):
            for index, (at, uptime, total) in enumerate(cls._readings(node)):
                if at < cls.now - timedelta(days=8):
                    continue
                #
                # The address moves between the nodes every few hours, and for
                # a while nobody can say who holds it.
                #
                held = (index // 9) % 2 == (0 if node == "a" else 1)
                owns: bool | None = None if 300 <= index < 305 else held
                cursor.execute(
                    "insert into metric_frontend (cluster, node, frontend, observed_at, owns_vip, "
                    "uptime_sec, req_tot, hrsp_2xx, bin, bout) "
                    "values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                    (
                        cls.CLUSTER,
                        node,
                        cls.FRONTEND,
                        at,
                        owns,
                        uptime,
                        total,
                        None if total is None else total // 2,
                        None if total is None else total * 900,
                        None if total is None else total * 5000,
                    ),
                )

    def ranges(self) -> list[tuple[str, datetime, datetime, datetime]]:
        """(name, since, until, raw_from) - inside the raw half, across it, in the past."""

        now, raw_from = self.now, self.raw_from
        return [
            ("last day", now - timedelta(days=1), now, raw_from),
            ("raw week", raw_from, now, raw_from),
            ("thirty days", now - timedelta(days=30), now, raw_from),
            (
                "marked across the boundary",
                now - timedelta(days=9),
                now - timedelta(days=3),
                raw_from,
            ),
            ("marked in the rollup", now - timedelta(days=11), now - timedelta(days=8), raw_from),
            (
                "marked over a restart",
                now - timedelta(days=2, hours=5),
                now - timedelta(days=1),
                raw_from,
            ),
            (
                "boundary moved back",
                now - timedelta(days=10),
                now,
                now - timedelta(days=6, hours=2),
            ),
        ]

    def test_a_backend_s_figures_are_the_same_as_the_pairing_gave(self) -> None:
        from tests import metric_totals_reference as reference

        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
            for name, since, until, _raw_from in self.ranges():
                if until <= self.raw_from:
                    continue
                #
                # The reference reads raw rows from `raw_from` on; from the
                # range's own start, it pairs only raw rows, as the reader does.
                #
                arguments = {
                    "cluster": self.CLUSTER,
                    "backend": self.BACKEND,
                    **db._history(self.BACKEND, ()),
                    "member": "BACKEND",
                    "since": since,
                    "until": until,
                    "raw_from": since,
                }
                with self.subTest(range=name):
                    expected = connection.execute(reference.backend_totals(), arguments).fetchone()
                    actual = connection.execute(db._backend_totals(), arguments).fetchone()
                    self.assertEqual(actual, expected)
                    self.assertGreater(
                        expected[0] if expected else 0,
                        0,
                        "a range that measured nothing proves nothing",
                    )

    def test_a_frontend_s_figures_and_the_dashboard_s_are_the_same_as_the_pairing_gave(
        self,
    ) -> None:
        from haprion_ui import metrics
        from tests import metric_totals_reference as reference

        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
            for name, since, until, _raw_from in self.ranges():
                one = {
                    "cluster": self.CLUSTER,
                    "frontend": self.FRONTEND,
                    "since": since,
                    "until": until,
                }
                every = {"clusters": [self.CLUSTER], "since": since, "until": until}
                with self.subTest(range=name):
                    self.assertEqual(
                        connection.execute(db._frontend_totals(), one).fetchone(),
                        connection.execute(reference.frontend_totals(), one).fetchone(),
                    )
                    self.assertEqual(
                        connection.execute(
                            db._frontend_totals(metrics.SUMMARY_COUNTERS, every_frontend=True),
                            every,
                        ).fetchone(),
                        connection.execute(
                            reference.frontend_totals(
                                metrics.SUMMARY_COUNTERS, every_frontend=True
                            ),
                            every,
                        ).fetchone(),
                    )

    def test_the_rows_filled_in_by_the_migration_are_the_rows_the_trigger_writes(self) -> None:
        specification = importlib.util.spec_from_file_location("metric_deltas", self.MIGRATION)
        if specification is None or specification.loader is None:
            self.fail("migration 0048 could not be loaded")
        migration = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(migration)
        names = ["previous_at", "restarted", *(f"delta_{name}" for name in migration.COUNTERS)]
        stored = psycopg.sql.SQL(", ").join(psycopg.sql.Identifier(name) for name in names)
        with self.connect() as connection:
            for table, series, held in (
                ("metric_backend_member", "cluster, node, backend, member", "true"),
                ("metric_frontend", "cluster, node, frontend", "owns_vip"),
            ):
                with self.subTest(table=table):
                    keys = psycopg.sql.SQL(", ").join(
                        psycopg.sql.Identifier(name.strip()) for name in series.split(",")
                    )
                    order = psycopg.sql.SQL(
                        "select {stored} from {table} where cluster = %s order by {keys}, observed_at"
                    ).format(stored=stored, table=psycopg.sql.Identifier(table), keys=keys)
                    written = connection.execute(order, (self.CLUSTER,)).fetchall()
                    connection.execute(
                        psycopg.sql.SQL("update {table} set {cleared} where cluster = %s").format(
                            table=psycopg.sql.Identifier(table),
                            cleared=psycopg.sql.SQL(", ").join(
                                psycopg.sql.SQL("{} = null").format(psycopg.sql.Identifier(name))
                                for name in names
                            ),
                        ),
                        (self.CLUSTER,),
                    )
                    connection.execute(migration._backfill(table, series, held))
                    self.assertEqual(connection.execute(order, (self.CLUSTER,)).fetchall(), written)
                    self.assertTrue(any(row[0] is not None for row in written))
            connection.rollback()

    def test_the_poller_writes_a_sample_and_may_not_write_what_is_derived_from_it(self) -> None:
        with self.connect("HAPRION_UI_TEST_POLLER_ROLE") as connection:
            connection.execute(
                "insert into metric_backend_member (cluster, node, backend, member, uptime_sec, req_tot) "
                "values (%s, 'a', %s, 'BACKEND', 10000000, 999999)",
                (self.CLUSTER, self.BACKEND),
            )
            connection.commit()
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                connection.execute(
                    "insert into metric_backend_member (cluster, node, backend, member, delta_req_tot) "
                    "values (%s, 'a', %s, 'BACKEND', 5)",
                    (self.CLUSTER, self.BACKEND),
                )
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
            row = connection.execute(
                "select previous_at is not null, restarted, delta_req_tot from metric_backend_member "
                "where cluster = %s and req_tot = 999999",
                (self.CLUSTER,),
            ).fetchone()
        self.assertEqual(row, (True, False, 999999 - self._readings("a")[-1][2]))  # type: ignore[operator]


@unittest.skipUnless(DSN, "run through ui/tools/test-database")
class TheHourlySumsAnswerAsTheReadersDid(unittest.TestCase):
    """Migration 0055: long windows read hourly sums, against the reads they replaced.

    33 days of samples every 20 minutes on two nodes, in two histories:

    - `CARRIED`, a backend as production holds it when 0055 runs: the hourly
      rollup for every hour, raw rows from a midnight about a week back, older
      ones pruned. The migration's own fill builds its sums, and the facit is
      the reader before 0055 (`metric_totals_reference`), rollup half included,
      with its boundary where the raw rows begin.
    - `GROWN`, a backend and a frontend whose every sample arrived after 0055:
      the trigger built their sums and every raw row is kept, so the facit is
      the raw readers themselves.

    Each carries a restart, a counter that goes backwards without one, an
    unknown counter and three hours with no sample, once in the older half and
    once in the last week; the frontend's address moves every three hours.
    """

    MIGRATION = (
        Path(__file__).resolve().parents[1]
        / "migrations"
        / "versions"
        / "0055_metric_hour_delta.py"
    )
    CLUSTER = "hours"
    CARRIED = "mgd-carried-web"
    GROWN = "mgd-grown-web"
    FRONTEND = "mgd-grown-https"
    COLUMNS = (
        "req_tot",
        "hrsp_2xx",
        "hrsp_3xx",
        "hrsp_4xx",
        "hrsp_5xx",
        "econ",
        "wretr",
        "bin",
        "bout",
    )
    RESTARTS = (600, 2000)
    BACKWARDS = (900, 2100)
    UNKNOWN = (1200, 2200)
    GAPS = (range(1500, 1509), range(2250, 2259))
    now: datetime
    start: datetime
    pruned_before: datetime
    migration: Any

    @classmethod
    def connect(cls, role_variable: str = "HAPRION_UI_TEST_MIGRATION_ROLE") -> psycopg.Connection:
        return psycopg.connect(f"{DSN} user={os.environ[role_variable]}")

    @classmethod
    def setUpClass(cls) -> None:
        specification = importlib.util.spec_from_file_location("metric_hour_delta", cls.MIGRATION)
        if specification is None or specification.loader is None:
            raise AssertionError("migration 0055 could not be loaded")
        cls.migration = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(cls.migration)

        cls.now = datetime.now(UTC).replace(microsecond=0)
        cls.start = cls.now - timedelta(days=33)
        #
        # Retention drops whole days; the raw rows begin at a midnight.
        #
        cls.pruned_before = datetime.combine(
            (cls.now - timedelta(days=7)).date(), datetime.min.time(), UTC
        )
        with cls.connect() as connection:
            cursor = connection.cursor()
            day = cls.start.date() - timedelta(days=1)
            while day <= cls.now.date() + timedelta(days=1):
                cursor.execute("select metric_partition('metric_backend_member', %s::date)", (day,))
                cursor.execute("select metric_partition('metric_frontend', %s::date)", (day,))
                cursor.execute(
                    "select metric_month_partition('metric_backend_hour', %s::date)", (day,)
                )
                day += timedelta(days=1)
            for backend in (cls.CARRIED, cls.GROWN):
                cls._backend(cursor, backend)
            cls._frontend(cursor)
            cls._roll_up(cursor)
            connection.commit()
            #
            # What production holds when 0055 runs: a week of raw rows, the
            # rollup, and the migration's fill - not the trigger's sums.
            #
            cursor.execute(
                "delete from metric_backend_member "
                "where cluster = %s and backend = %s and observed_at < %s",
                (cls.CLUSTER, cls.CARRIED, cls.pruned_before),
            )
            cursor.execute(
                "delete from metric_backend_hour_delta where cluster = %s and backend = %s",
                (cls.CLUSTER, cls.CARRIED),
            )
            keys = cls.migration.SERIES["metric_backend_hour_delta"][1]
            scope = f"and cluster = '{cls.CLUSTER}' and backend = '{cls.CARRIED}'"
            cursor.execute(
                cls.migration._summed(
                    "metric_backend_hour_delta", "metric_backend_member", keys, scope
                )
                + cls.migration._merge("metric_backend_hour_delta", keys)
            )
            cursor.execute(
                cls.migration._from_rollup(
                    f"and rolled.cluster = '{cls.CLUSTER}' and rolled.backend = '{cls.CARRIED}'"
                )
            )

    @classmethod
    def _readings(cls, node: str) -> list[tuple[datetime, int, dict[str, int | None]]]:
        found = []
        uptime, total = 1000, 0
        for index in range(33 * 72 + 1):
            at = cls.start + timedelta(minutes=20 * index + (7 if node == "b" else 0))
            if at > cls.now:
                break
            uptime += 1200
            total += 3 + index % 5
            if node == "b" and index in cls.RESTARTS:
                uptime, total = 300, 4
            if node == "a" and index in cls.BACKWARDS:
                total = 2
            if any(index in gap for gap in cls.GAPS):
                continue
            values: dict[str, int | None] = {
                "req_tot": total,
                "hrsp_2xx": total - total // 7,
                "hrsp_3xx": total // 20,
                "hrsp_4xx": total // 11,
                "hrsp_5xx": total // 9,
                "econ": total // 13,
                "wretr": total // 17,
                "bin": total * 900,
                "bout": total * 5000,
            }
            if index in cls.UNKNOWN:
                values["req_tot"] = None
            found.append((at, uptime, values))
        return found

    @classmethod
    def _counted(cls) -> tuple[psycopg.sql.Composable, psycopg.sql.Composable]:
        return (
            psycopg.sql.SQL(", ").join(psycopg.sql.Identifier(name) for name in cls.COLUMNS),
            psycopg.sql.SQL(", ").join(psycopg.sql.Placeholder() for _name in cls.COLUMNS),
        )

    @classmethod
    def _backend(cls, cursor: psycopg.Cursor[Any], backend: str) -> None:
        columns, marks = cls._counted()
        for node in ("a", "b"):
            cursor.executemany(
                psycopg.sql.SQL(
                    "insert into metric_backend_member (cluster, node, backend, member, "
                    "observed_at, uptime_sec, {columns}) "
                    "values (%s, %s, %s, 'BACKEND', %s, %s, {marks})"
                ).format(columns=columns, marks=marks),
                [
                    (cls.CLUSTER, node, backend, at, uptime, *values.values())
                    for at, uptime, values in cls._readings(node)
                ],
            )

    @classmethod
    def _frontend(cls, cursor: psycopg.Cursor[Any]) -> None:
        columns, marks = cls._counted()
        for node in ("a", "b"):
            cursor.executemany(
                psycopg.sql.SQL(
                    "insert into metric_frontend (cluster, node, frontend, observed_at, "
                    "owns_vip, uptime_sec, {columns}) values (%s, %s, %s, %s, %s, %s, {marks})"
                ).format(columns=columns, marks=marks),
                [
                    (
                        cls.CLUSTER,
                        node,
                        cls.FRONTEND,
                        at,
                        (index // 9) % 2 == (0 if node == "a" else 1),
                        uptime,
                        *values.values(),
                    )
                    for index, (at, uptime, values) in enumerate(cls._readings(node))
                ],
            )

    @classmethod
    def _roll_up(cls, cursor: psycopg.Cursor[Any]) -> None:
        """The carried backend's rollup, as retention writes it: each hour's last reading."""

        columns = ", ".join(cls.COLUMNS)
        cursor.execute(
            f"""
            insert into metric_backend_hour (cluster, node, backend, member, bucket_at,
                   observed_at, uptime_sec, floor_uptime_sec, {columns})
            select distinct on (node, date_trunc('hour', observed_at))
                   cluster, node, backend, member, date_trunc('hour', observed_at),
                   observed_at, uptime_sec,
                   min(uptime_sec) over (partition by node, date_trunc('hour', observed_at)),
                   {columns}
              from metric_backend_member
             where cluster = %s and backend = %s
             order by node, date_trunc('hour', observed_at), observed_at desc
            """,  # noqa: S608 - the interpolated names are this class's constants
            (cls.CLUSTER, cls.CARRIED),
        )

    def ranges(self) -> list[tuple[str, datetime, datetime]]:
        """Figures' ranges: the two long windows, and marks mid-hour across every case."""

        now = self.now
        return [
            ("thirty days", now - timedelta(days=30), now),
            ("seven days", now - timedelta(days=7), now),
            (
                "marked across the raw rows' start",
                now - timedelta(days=12, minutes=-17),
                now - timedelta(days=3, minutes=23),
            ),
            (
                "marked in the older half",
                now - timedelta(days=21, minutes=-5),
                now - timedelta(days=15, minutes=41),
            ),
            (
                "marked over a restart",
                now - timedelta(days=6, minutes=-13),
                now - timedelta(days=4, minutes=31),
            ),
            (
                "two days over the gap",
                now - timedelta(days=2, minutes=29),
                now - timedelta(minutes=11),
            ),
        ]

    def windows(self) -> list[tuple[datetime, timedelta]]:
        """The drawings that read hourly sums: 30 days in six hours, 7 days in hours."""

        return [
            (self.now - timedelta(days=30), timedelta(hours=6)),
            (self.now - timedelta(days=7), timedelta(hours=1)),
        ]

    def backend_hours(self) -> psycopg.sql.Composed:
        return db._hour_totals(
            "metric_backend_hour_delta",
            "metric_backend_member",
            db.BACKEND_HOUR_SCOPE,
            db.BACKEND_SCOPE,
        )

    def test_the_carried_backend_s_figures_are_the_reader_s_before_0055(self) -> None:
        from tests import metric_totals_reference as reference

        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
            for name, since, until in self.ranges():
                arguments = {
                    "cluster": self.CLUSTER,
                    "backend": self.CARRIED,
                    **db._history(self.CARRIED, ()),
                    "member": "BACKEND",
                    "since": since,
                    "after": since,
                    "until": until,
                    "raw_from": self.pruned_before,
                }
                with self.subTest(range=name):
                    expected = connection.execute(reference.backend_totals(), arguments).fetchone()
                    actual = connection.execute(self.backend_hours(), arguments).fetchone()
                    self.assertEqual(actual, expected)
                    self.assertGreater(expected[0] if expected else 0, 0)

    def test_the_grown_series_figures_are_the_raw_readers(self) -> None:
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
            for name, since, until in self.ranges():
                backend = {
                    "cluster": self.CLUSTER,
                    "backend": self.GROWN,
                    **db._history(self.GROWN, ()),
                    "member": "BACKEND",
                    "since": since,
                    "after": since,
                    "until": until,
                }
                frontend = {
                    "cluster": self.CLUSTER,
                    "frontend": self.FRONTEND,
                    "since": since,
                    "after": since,
                    "until": until,
                }
                with self.subTest(range=name):
                    expected = connection.execute(db._backend_totals(), backend).fetchone()
                    self.assertEqual(
                        connection.execute(self.backend_hours(), backend).fetchone(), expected
                    )
                    self.assertGreater(expected[0] if expected else 0, 0)
                    expected = connection.execute(db._frontend_totals(), frontend).fetchone()
                    self.assertEqual(
                        connection.execute(
                            db._hour_totals(
                                "metric_frontend_hour_delta",
                                "metric_frontend",
                                db.FRONTEND_SCOPE,
                                db.FRONTEND_HELD,
                            ),
                            frontend,
                        ).fetchone(),
                        expected,
                    )
                    self.assertGreater(expected[0] if expected else 0, 0)

    def test_the_grown_series_drawings_are_the_raw_readers(self) -> None:
        def ordered(found: list[metrics.Interval]) -> list[metrics.Interval]:
            return sorted(found, key=lambda interval: (interval.started_at, interval.ended_at))

        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
            for since, width in self.windows():
                arguments = {
                    "cluster": self.CLUSTER,
                    "backend": self.GROWN,
                    **db._history(self.GROWN, ()),
                    "member": "BACKEND",
                    "frontend": self.FRONTEND,
                    "width": width,
                    "after": since,
                    "until": self.now,
                }
                with self.subTest(width=width):
                    raw = connection.execute(
                        db._bucketed_changes("metric_backend_member", db.BACKEND_SCOPE), arguments
                    ).fetchall()
                    expected = ordered(db._changed_intervals(raw, db.BACKEND_DELTAS))
                    self.assertTrue(expected)
                    self.assertEqual(
                        ordered(
                            db.read_backend_series(
                                connection,
                                cluster=self.CLUSTER,
                                backend=self.GROWN,
                                since=since,
                                until=self.now,
                                width=width,
                            )
                        ),
                        expected,
                    )
                    raw = connection.execute(
                        db._bucketed_changes("metric_frontend", db.FRONTEND_HELD), arguments
                    ).fetchall()
                    expected = ordered(db._changed_intervals(raw, db.STORED_DELTAS))
                    self.assertTrue(expected)
                    self.assertEqual(
                        ordered(
                            db.read_frontend_series(
                                connection,
                                cluster=self.CLUSTER,
                                frontend=self.FRONTEND,
                                since=since,
                                until=self.now,
                                width=width,
                            )
                        ),
                        expected,
                    )

    def test_the_carried_backend_s_drawing_groups_the_old_pairing_as_the_raw_reader_groups(
        self,
    ) -> None:
        """Every pair the reader before 0055 made, grouped the way `_bucketed_changes` groups.

        The hourly half is paired from the rollup by `metrics.intervals`, one
        node at a time, and the raw half is read sample by sample. Grouped per
        node, bucket and whether the pair lies in an earlier bucket - summing
        as SQL sums, where an unknown counter is skipped - that is the drawing
        the raw rows would give if they had been kept.
        """

        from tests import metric_totals_reference as reference

        names = ("req_tot", "hrsp_2xx", "hrsp_3xx", "hrsp_4xx", "hrsp_5xx", "econ", "wretr")
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
            for since, width in self.windows():
                with self.subTest(width=width):
                    pairs: list[tuple[str, metrics.Interval]] = []
                    for node in ("a", "b"):
                        rows = connection.execute(
                            reference._rolled_up(),
                            {
                                "cluster": self.CLUSTER,
                                "backend": self.CARRIED,
                                **db._history(self.CARRIED, ()),
                                "member": "BACKEND",
                                "since": since,
                                "raw_from": self.pruned_before,
                                "until": self.now,
                            },
                        ).fetchall()
                        pairs.extend(
                            (node, interval)
                            for interval in metrics.intervals(
                                [
                                    metrics.Sample(
                                        observed_at=row[1],
                                        member="BACKEND",
                                        uptime_sec=row[2],
                                        floor_uptime_sec=row[3],
                                        node=row[4],
                                        counters=dict(
                                            zip(metrics.METRIC_COUNTERS, row[5:], strict=True)
                                        ),
                                    )
                                    for row in rows
                                    if row[4] == node
                                ]
                            )
                        )
                    columns = ", ".join(f"delta_{name}" for name in names)
                    for row in connection.execute(
                        f"select node, previous_at, observed_at, restarted, {columns} "  # noqa: S608 - constants
                        "  from metric_backend_member "
                        " where cluster = %s and backend = %s and member = 'BACKEND' "
                        "   and previous_at >= %s and observed_at <= %s",
                        (self.CLUSTER, self.CARRIED, since, self.now),
                    ).fetchall():
                        pairs.append(
                            (
                                row[0],
                                metrics.Interval(
                                    started_at=row[1],
                                    ended_at=row[2],
                                    counters=dict(zip(names, row[4:], strict=True)),
                                    restarted=row[3],
                                ),
                            )
                        )

                    groups: dict[tuple[str, int, bool], list[metrics.Interval]] = {}
                    for node, interval in pairs:
                        index = metrics._bucket_of(interval.ended_at, width)
                        crossing = interval.started_at < metrics.BUCKET_EPOCH + width * index
                        groups.setdefault((node, index, crossing), []).append(interval)
                    expected = sorted(
                        (
                            min(interval.started_at for interval in group),
                            max(interval.ended_at for interval in group),
                            any(interval.restarted for interval in group),
                            tuple(
                                None
                                if all(interval.counters.get(name) is None for interval in group)
                                else sum(interval.counters.get(name) or 0 for interval in group)
                                for name in names
                            ),
                        )
                        for group in groups.values()
                    )
                    actual = sorted(
                        (
                            interval.started_at,
                            interval.ended_at,
                            interval.restarted,
                            tuple(interval.counters.get(name) for name in names),
                        )
                        for interval in db.read_backend_series(
                            connection,
                            cluster=self.CLUSTER,
                            backend=self.CARRIED,
                            since=since,
                            until=self.now,
                            width=width,
                        )
                    )
                    self.assertTrue(expected)
                    self.assertEqual(actual, expected)

    def test_the_fill_writes_what_the_trigger_writes(self) -> None:
        with self.connect() as connection:
            for table, (source, keys) in self.migration.SERIES.items():
                series = "backend" if "backend" in keys else "frontend"
                name = self.GROWN if series == "backend" else self.FRONTEND
                with self.subTest(table=table):
                    order = psycopg.sql.SQL(
                        "select * from {table} where cluster = %s and {series} = %s "
                        "order by node, hour, crossing"
                    ).format(
                        table=psycopg.sql.Identifier(table),
                        series=psycopg.sql.Identifier(series),
                    )
                    written = connection.execute(order, (self.CLUSTER, name)).fetchall()
                    #
                    # Both nodes write every hour of a backend; a frontend's hour
                    # only on the node holding the address, which alternates every
                    # three hours. Its count lands around 2 x 33 x 24 and below it
                    # depending on the minute the test starts (1571, 26-10-06 15:01).
                    #
                    self.assertGreater(len(written), (2 if series == "backend" else 1) * 33 * 24)
                    connection.execute(
                        psycopg.sql.SQL(
                            "delete from {table} where cluster = %s and {series} = %s"
                        ).format(
                            table=psycopg.sql.Identifier(table),
                            series=psycopg.sql.Identifier(series),
                        ),
                        (self.CLUSTER, name),
                    )
                    connection.execute(
                        self.migration._summed(
                            table,
                            source,
                            keys,
                            f"and cluster = '{self.CLUSTER}' and {series} = '{name}'",
                        )
                        + self.migration._merge(table, keys)
                    )
                    self.assertEqual(
                        connection.execute(order, (self.CLUSTER, name)).fetchall(), written
                    )
            connection.rollback()

    def test_the_fill_keeps_no_rollup_hour_retention_would_delete(self) -> None:
        with self.connect() as connection:
            oldest = connection.execute(
                "select min(hour) from metric_backend_hour_delta where cluster = %s and backend = %s",
                (self.CLUSTER, self.CARRIED),
            ).fetchone()
        self.assertIsNotNone(oldest)
        self.assertGreaterEqual(oldest[0], self.now - timedelta(days=31, hours=1))  # type: ignore[index]
        self.assertLess(oldest[0], self.now - timedelta(days=30))  # type: ignore[index]

    def test_retention_deletes_the_hours_the_fill_would_not_take(self) -> None:
        script = Path(__file__).resolve().parents[2] / "install/platform/bin/haprion-retention"
        expired = subprocess.run(  # noqa: S603 - fixed interpreter, the repository's script
            [
                "/bin/bash",
                "-c",
                'eval "$(sed -n \'/^METRIC_HOUR_KEEP_DAYS=/p;/^where_metric_hour_expired() {/,/^}/p\' "$0")"; '
                "where_metric_hour_expired",
                str(script),
            ],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        self.assertIn(self.migration.KEPT, expired)
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                psycopg.sql.SQL(
                    "select distinct backend from metric_backend_hour_delta "
                    "where cluster = %s and {expired}"
                ).format(expired=psycopg.sql.SQL(expired)),
                (self.CLUSTER,),
            )
            self.assertEqual(cursor.fetchall(), [(self.GROWN,)])
            connection.rollback()

    def test_the_poller_s_own_insert_is_summed_without_a_grant_on_the_sums(self) -> None:
        backend = "mgd-poller-web"
        with self.connect("HAPRION_UI_TEST_POLLER_ROLE") as connection:
            for total in (10, 25):
                connection.execute(
                    "insert into metric_backend_member (cluster, node, backend, member, "
                    "uptime_sec, req_tot) values (%s, 'a', %s, 'BACKEND', 100, %s)",
                    (self.CLUSTER, backend, total),
                )
                connection.commit()
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                connection.execute("select 1 from metric_backend_hour_delta limit 1")
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
            row = connection.execute(
                "select sum(samples), sum(delta_req_tot) from metric_backend_hour_delta "
                "where cluster = %s and backend = %s",
                (self.CLUSTER, backend),
            ).fetchone()
        self.assertEqual(row, (1, 15))

    def test_one_statement_of_many_samples_is_summed_as_one_sample_at_a_time(self) -> None:
        backend = "mgd-burst-web"
        top = self.now.replace(minute=0, second=0) - timedelta(hours=2)
        moments = [top - timedelta(minutes=40) + timedelta(minutes=20 * step) for step in range(5)]
        with self.connect() as connection:
            connection.execute(
                psycopg.sql.SQL(
                    "insert into metric_backend_member (cluster, node, backend, member, "
                    "observed_at, uptime_sec, req_tot) values {rows}"
                ).format(
                    rows=psycopg.sql.SQL(", ").join(
                        [psycopg.sql.SQL("(%s, %s, %s, 'BACKEND', %s, %s, %s)")] * 10
                    )
                ),
                [
                    value
                    for step, at in enumerate(moments)
                    for node in ("a", "b")
                    for value in (self.CLUSTER, node, backend, at, 5000 + step, 100 * step)
                ],
            )
            connection.commit()
        with self.connect() as connection:
            order = (
                "select * from metric_backend_hour_delta where cluster = %s and backend = %s "
                "order by node, hour, crossing"
            )
            written = connection.execute(order, (self.CLUSTER, backend)).fetchall()
            connection.execute(
                "delete from metric_backend_hour_delta where cluster = %s and backend = %s",
                (self.CLUSTER, backend),
            )
            keys = self.migration.SERIES["metric_backend_hour_delta"][1]
            connection.execute(
                self.migration._summed(
                    "metric_backend_hour_delta",
                    "metric_backend_member",
                    keys,
                    f"and cluster = '{self.CLUSTER}' and backend = '{backend}'",
                )
                + self.migration._merge("metric_backend_hour_delta", keys)
            )
            self.assertEqual(connection.execute(order, (self.CLUSTER, backend)).fetchall(), written)
            self.assertEqual(sum(row[9] for row in written), 8)
            connection.rollback()

    def test_two_inserts_adding_to_one_hour_at_once_lose_neither(self) -> None:
        import threading
        import time

        backend = "mgd-together-web"
        top = self.now.replace(minute=0, second=0) - timedelta(hours=3)
        with self.connect() as connection:
            connection.execute(
                "insert into metric_backend_member (cluster, node, backend, member, observed_at, "
                "uptime_sec, req_tot) values (%s, 'a', %s, 'BACKEND', %s, 100, 10)",
                (self.CLUSTER, backend, top + timedelta(minutes=1)),
            )
            connection.commit()

        insert = (
            "insert into metric_backend_member (cluster, node, backend, member, observed_at, "
            "uptime_sec, req_tot) values (%s, 'a', %s, 'BACKEND', %s, %s, %s)"
        )
        first = self.connect()
        second = self.connect()
        failed: list[BaseException] = []
        try:
            first.execute(insert, (self.CLUSTER, backend, top + timedelta(minutes=21), 1300, 25))

            def add_second() -> None:
                try:
                    second.execute(
                        insert, (self.CLUSTER, backend, top + timedelta(minutes=41), 2500, 47)
                    )
                    second.commit()
                except BaseException as error:  # noqa: BLE001 - handed to the test thread
                    failed.append(error)

            thread = threading.Thread(target=add_second)
            thread.start()
            with self.connect("HAPRION_UI_TEST_MIGRATION_ROLE") as watcher:
                for _ in range(100):
                    waiting = watcher.execute(
                        "select count(*) from pg_stat_activity "
                        "where wait_event_type = 'Lock' and pid = %s",
                        (second.info.backend_pid,),
                    ).fetchone()
                    if waiting and waiting[0]:
                        break
                    time.sleep(0.05)
                else:
                    self.fail("the second insert never waited for the first")
            first.commit()
            thread.join(10)
            self.assertFalse(thread.is_alive())
            self.assertEqual(failed, [])
        finally:
            first.close()
            second.close()

        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
            row = connection.execute(
                "select samples, delta_req_tot from metric_backend_hour_delta "
                "where cluster = %s and backend = %s and not crossing",
                (self.CLUSTER, backend),
            ).fetchone()
        #
        # Both were paired with the committed sample before them (0048 reads
        # what is committed), so each adds its own difference from it.
        #
        self.assertEqual(row, (2, (25 - 10) + (47 - 10)))


@unittest.skipUnless(DSN, "run through ui/tools/test-database")
class MetricsListsWhatTheNodesServeNow(unittest.TestCase):
    """2026-10-06: only the names HAProxy runs now, as the exporter shows.

    A pool renamed (B250) or removed keeps its rows until retention, but its card
    is gone with the deploy that took it away. Measured against the cluster's
    newest poll rather than the clock, so a stopped poller leaves the page as it
    last was.
    """

    def connect(self, role_variable: str = "HAPRION_UI_TEST_MIGRATION_ROLE") -> psycopg.Connection:
        return psycopg.connect(f"{DSN} user={os.environ[role_variable]}")

    def write(self, cluster: str, rows: list[tuple[str, datetime]]) -> None:
        with self.connect() as connection, connection.cursor() as cursor:
            for _name, at in rows:
                cursor.execute("select metric_partition('metric_backend_member', %s::date)", (at,))
                cursor.execute("select metric_partition('metric_frontend', %s::date)", (at,))
            for name, at in rows:
                cursor.execute(
                    "insert into metric_backend_member (cluster, node, backend, member, "
                    "observed_at, uptime_sec, req_tot) values (%s, 'a', %s, 'BACKEND', %s, 1, 1)",
                    (cluster, name, at),
                )
                cursor.execute(
                    "insert into metric_frontend (cluster, node, frontend, observed_at, "
                    "owns_vip, uptime_sec, req_tot) values (%s, 'a', %s, %s, true, 1, 1)",
                    (cluster, f"fe-{name}", at),
                )

    def listed(self, cluster: str, now: datetime) -> tuple[list[str], list[str]]:
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
            since = now - timedelta(days=7)
            backends = db.read_cluster_backends(connection, cluster=cluster, since=since, until=now)
            frontends = db.read_cluster_frontends(
                connection, cluster=cluster, since=since, until=now
            )
        return backends, [name for name, _held in frontends]

    def test_a_renamed_pool_is_gone_once_the_new_name_is_served(self) -> None:
        now = datetime.now(UTC).replace(microsecond=0)
        self.write(
            "renamed",
            [
                ("mgd-shop-web", now - timedelta(hours=2)),
                ("mgd-shop-web", now - timedelta(minutes=3)),
                ("web", now - timedelta(seconds=40)),
                ("web", now - timedelta(seconds=20)),
                ("db", now - timedelta(seconds=21)),
            ],
        )

        self.assertEqual(self.listed("renamed", now), (["db", "web"], ["fe-db", "fe-web"]))

    def test_a_stopped_poller_leaves_the_last_poll_listed(self) -> None:
        now = datetime.now(UTC).replace(microsecond=0)
        self.write(
            "stopped",
            [
                ("old", now - timedelta(days=2)),
                ("web", now - timedelta(hours=5, seconds=10)),
                ("db", now - timedelta(hours=5)),
            ],
        )

        self.assertEqual(self.listed("stopped", now), (["db", "web"], ["fe-db", "fe-web"]))


@unittest.skipUnless(DSN, "run through ui/tools/test-database")
class ARenamedBackendKeepsItsHistory(unittest.TestCase):
    """Migration 0056: the card under a backend's new name reads its earlier names too.

    `old` serves until 10:20 of an hour, `new` from 10:40 of the same hour, on
    the same node - the hour where an edge read matched by node alone would
    count each name's raw rows twice. A later `old` is somebody else's backend
    after the name was given out again, and must not be drawn in.
    """

    CLUSTER = "aliased"
    now: datetime
    rename_hour: datetime
    reused_at: datetime
    rows: list[tuple[str, datetime, int, int]]

    def connect(self, role_variable: str = "HAPRION_UI_TEST_MIGRATION_ROLE") -> psycopg.Connection:
        return psycopg.connect(f"{DSN} user={os.environ[role_variable]}")

    @classmethod
    def setUpClass(cls) -> None:
        cls.now = datetime.now(UTC).replace(minute=0, second=0, microsecond=0)
        cls.rename_hour = cls.now - timedelta(hours=30)
        cls.reused_at = cls.now - timedelta(hours=5)
        rows: list[tuple[str, datetime, int, int]] = []
        at, uptime, total = cls.now - timedelta(days=3), 100, 0
        while at <= cls.rename_hour + timedelta(minutes=20):
            total += 7
            rows.append(("old", at, uptime, total))
            at += timedelta(minutes=10)
            uptime += 600
        at, uptime, total = cls.rename_hour + timedelta(minutes=40), 5, 0
        while at <= cls.now - timedelta(minutes=10):
            total += 3
            rows.append(("new", at, uptime, total))
            at += timedelta(minutes=10)
            uptime += 600
        at, uptime, total = cls.reused_at + timedelta(minutes=10), 5, 0
        while at <= cls.now - timedelta(minutes=10):
            total += 1000
            rows.append(("old", at, uptime, total))
            at += timedelta(minutes=10)
            uptime += 600
        cls.rows = rows
        with (
            psycopg.connect(
                f"{DSN} user={os.environ['HAPRION_UI_TEST_MIGRATION_ROLE']}"
            ) as connection,
            connection.cursor() as cursor,
        ):
            day = (cls.now - timedelta(days=4)).date()
            while day <= cls.now.date() + timedelta(days=1):
                cursor.execute("select metric_partition('metric_backend_member', %s::date)", (day,))
                day += timedelta(days=1)
            for name, at, uptime, total in rows:
                cursor.execute(
                    "insert into metric_backend_member (cluster, node, backend, member, "
                    "observed_at, uptime_sec, req_tot) values (%s, 'a', %s, 'BACKEND', %s, %s, %s)",
                    (cls.CLUSTER, name, at, uptime, total),
                )

    def totals(self, backend: str, since: datetime, earlier: list[db.EarlierName]) -> int:
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
            measured = db.read_backend_totals(
                connection,
                cluster=self.CLUSTER,
                backend=backend,
                since=since,
                until=self.now,
                earlier=earlier,
            )
        return measured.totals[0].value

    def series(self, backend: str, since: datetime, earlier: list[db.EarlierName]) -> int:
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
            found = db.read_backend_series(
                connection,
                cluster=self.CLUSTER,
                backend=backend,
                since=since,
                until=self.now,
                width=timedelta(hours=1),
                earlier=earlier,
            )
        return sum(interval.counters.get("req_tot") or 0 for interval in found)

    def expected(self, since: datetime, *, names: tuple[str, ...], old_until: datetime) -> int:
        """Each name's own stored differences, summed by hand from the raw rows."""

        total = 0
        for name in names:
            readings = [row for row in self.rows if row[0] == name]
            for (_n, at_before, up_before, before), (_m, at, up, value) in zip(
                readings, readings[1:], strict=False
            ):
                if at_before < since or at > self.now:
                    continue
                if name == "old" and at >= old_until:
                    continue
                if at - at_before > timedelta(hours=2):
                    continue
                total += value if up < up_before else value - before
        return total

    def test_the_new_name_reads_the_old_ones_history_and_counts_it_once(self) -> None:
        earlier = [db.EarlierName("old", self.reused_at)]
        for since in (
            self.now - timedelta(days=3),
            self.rename_hour + timedelta(minutes=5),
            self.now - timedelta(hours=20),
        ):
            with self.subTest(since=since):
                want = self.expected(since, names=("old", "new"), old_until=self.reused_at)
                self.assertGreater(want, 0)
                self.assertEqual(self.totals("new", since, earlier), want)
                self.assertEqual(self.series("new", since, earlier), want)

    def test_without_the_alias_the_new_name_starts_empty(self) -> None:
        since = self.now - timedelta(days=3)
        alone = self.totals("new", since, [])

        self.assertEqual(alone, self.expected(since, names=("new",), old_until=self.now))
        self.assertLess(alone, self.totals("new", since, [db.EarlierName("old", self.reused_at)]))

    def test_a_name_given_out_again_keeps_its_newcomer_out(self) -> None:
        since = self.now - timedelta(days=3)
        closed = self.totals("new", since, [db.EarlierName("old", self.reused_at)])
        open_ = self.totals("new", since, [db.EarlierName("old")])

        self.assertGreater(open_ - closed, 1000)

    def test_the_worker_writes_renames_and_the_web_reads_them_back_as_a_chain(self) -> None:
        """B253: the worker writes them once a publish is done; the web reads them."""

        with self.connect("HAPRION_UI_TEST_WORKER_ROLE") as connection:
            db.record_backend_renames(
                connection, cluster="chain", renamed={"a": "b"}, introduced=["b"]
            )
            db.record_backend_renames(
                connection, cluster="chain", renamed={"b": "c"}, introduced=["c"]
            )
            db.record_backend_renames(connection, cluster="chain", renamed={}, introduced=["a"])
            connection.commit()
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
            found = db.read_backend_aliases(connection, cluster="chain")

        names = {item.name: item.until for item in found["c"]}
        self.assertEqual(set(names), {"a", "b"})
        self.assertIsNotNone(names["a"], "a was given out again")
        self.assertIsNone(names["b"])


#
# The latency column 0057 added and summed per hour. Nothing read it after
# B253, and 0059 takes it away; 0057's own downgrade and upgrade still name it.
#
LATENCY_0057 = "dns_latency_us"


@unittest.skipUnless(DSN, "run through ui/tools/test-database")
class TheLatencyIsGoneAndTheWorkerAloneRecordsRenames(unittest.TestCase):
    """Migration 0059 (B253): dnsdist's latency dropped, and the alias table the worker's to write."""

    @staticmethod
    def connect(role_variable: str = "HAPRION_UI_TEST_MIGRATION_ROLE") -> psycopg.Connection:
        return psycopg.connect(f"{DSN} user={os.environ[role_variable]}")

    @staticmethod
    def latency_columns(cursor: psycopg.Cursor) -> set[tuple[str, str]]:
        cursor.execute(
            "select table_name, column_name from information_schema.columns "
            "where column_name like 'dns_latency%%' "
            "  and table_name in ('metric_backend_member', 'metric_backend_hour_delta')"
        )
        return {(row[0], row[1]) for row in cursor.fetchall()}

    def test_no_latency_column_is_left(self) -> None:
        with self.connect() as connection, connection.cursor() as cursor:
            self.assertEqual(self.latency_columns(cursor), set())

    def test_the_web_reads_renames_and_may_not_write_them(self) -> None:
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
            db.read_backend_aliases(connection, cluster="none")
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                db.record_backend_renames(
                    connection, cluster="web-tries", renamed={"a": "b"}, introduced=[]
                )

    def test_the_migration_downgrades_and_upgrades_cleanly(self) -> None:
        with self.connect() as connection:
            with connection.cursor() as cursor:
                migration = _migration("0059_drop_dns_latency.py", cursor)
                migration.downgrade()
                self.assertEqual(
                    self.latency_columns(cursor),
                    {
                        ("metric_backend_member", "dns_latency_us"),
                        ("metric_backend_hour_delta", "dns_latency_us_sum"),
                        ("metric_backend_hour_delta", "dns_latency_us_samples"),
                    },
                )
                migration.upgrade()
                self.assertEqual(self.latency_columns(cursor), set())
            connection.rollback()


@unittest.skipUnless(DSN, "run through ui/tools/test-database")
class ADnsPoolIsCountedAsABackendIs(unittest.TestCase):
    """Migration 0057: dnsdist's counters in the backend rows (Fas 19a B4).

    Three days of a pool's own row and two servers every ten minutes, with a
    dnsdist restart in the middle, read back over the raw rows (a short range)
    and over the hourly sums (a long one), against the same differences summed
    by hand. The poller's own write goes through its grants and the trigger
    that reads the previous row as the poller.
    """

    CLUSTER = "resolving"
    POOL = "resolver"
    RESTART = 200
    now: datetime
    rows: list[tuple[str, datetime, int, dict[str, int]]]

    @staticmethod
    def connect(role_variable: str = "HAPRION_UI_TEST_MIGRATION_ROLE") -> psycopg.Connection:
        return psycopg.connect(f"{DSN} user={os.environ[role_variable]}")

    @classmethod
    def setUpClass(cls) -> None:
        cls.now = datetime.now(UTC).replace(minute=0, second=0, microsecond=0)
        rows: list[tuple[str, datetime, int, dict[str, int]]] = []
        at, uptime, step = cls.now - timedelta(days=3), 100, 0
        totals = {"BACKEND": [0, 0, 0, 0], "s1": [0, 0], "s2": [0, 0]}
        while at <= cls.now - timedelta(minutes=10):
            if step == cls.RESTART:
                uptime = 5
                totals = {key: [0] * len(value) for key, value in totals.items()}
            pool = totals["BACKEND"]
            for index, step_size in enumerate((10, 2, 1, 8)):
                pool[index] += step_size
            rows.append(
                (
                    "BACKEND",
                    at,
                    uptime,
                    dict(zip(metrics.DNS_COUNTERS, pool, strict=True)),
                )
            )
            for member, (asked, answered) in (("s1", (6, 5)), ("s2", (3, 3))):
                served = totals[member]
                served[0] += asked
                served[1] += answered
                rows.append(
                    (
                        member,
                        at,
                        uptime,
                        {"dns_queries": served[0], "dns_answered": served[1]},
                    )
                )
            at += timedelta(minutes=10)
            uptime += 600
            step += 1
        cls.rows = rows
        columns = metrics.DNS_COUNTERS
        with cls.connect() as connection, connection.cursor() as cursor:
            day = (cls.now - timedelta(days=4)).date()
            while day <= cls.now.date() + timedelta(days=1):
                cursor.execute("select metric_partition('metric_backend_member', %s::date)", (day,))
                day += timedelta(days=1)
            for member, at, uptime, counted in rows:
                cursor.execute(
                    "insert into metric_backend_member (cluster, node, backend, member, "
                    "observed_at, uptime_sec, dns_queries, dns_tcp, dns_refused, dns_answered) "
                    "values (%s, 'a', %s, %s, %s, %s, %s, %s, %s, %s)",
                    (
                        cls.CLUSTER,
                        cls.POOL,
                        member,
                        at,
                        uptime,
                        *(counted.get(name) for name in columns),
                    ),
                )
            #
            # An HAProxy backend beside it, which must not be listed as dns.
            #
            cursor.execute(
                "insert into metric_backend_member (cluster, node, backend, member, "
                "observed_at, uptime_sec, req_tot) values (%s, 'a', 'web', 'BACKEND', %s, 1, 1)",
                (cls.CLUSTER, cls.now - timedelta(minutes=10)),
            )

    def expected(self, member: str, name: str, since: datetime) -> int:
        """The stored differences of one counter, summed by hand from the rows."""

        readings = [row for row in self.rows if row[0] == member]
        total = 0
        for (_m, at_before, up_before, before), (_n, at, up, value) in zip(
            readings, readings[1:], strict=False
        ):
            if at_before < since or at > self.now:
                continue
            total += value[name] if up < up_before else value[name] - before[name]
        return total

    def ranges(self) -> tuple[datetime, ...]:
        # A day or less reads the raw rows; longer reads the hourly sums, and
        # one starting inside an hour reads that hour's raw rows at its edge.
        return (
            self.now - timedelta(hours=20),
            self.now - timedelta(days=3),
            self.now - timedelta(days=2, minutes=25),
        )

    def test_the_pool_s_figures_are_its_stored_differences(self) -> None:
        for since in self.ranges():
            with self.subTest(since=since), self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
                found = metrics.dns_measurement(
                    db.read_backend_totals(
                        connection,
                        cluster=self.CLUSTER,
                        backend=self.POOL,
                        since=since,
                        until=self.now,
                        counters=metrics.DNS_SUMMED,
                    )
                )
                figures = {total.label: total.value for total in found.totals}
                asked = self.expected("BACKEND", "dns_queries", since)
                refused = self.expected("BACKEND", "dns_refused", since)
                answered = self.expected("BACKEND", "dns_answered", since)
                self.assertGreater(asked, 0)
                self.assertEqual(
                    figures,
                    {
                        "Queries": asked,
                        "Answered": answered,
                        "Refused": refused,
                        "Unanswered": asked - refused - answered,
                        "Over TCP": self.expected("BACKEND", "dns_tcp", since),
                    },
                )

    def test_the_line_is_drawn_from_the_same_differences(self) -> None:
        for since in self.ranges():
            with self.subTest(since=since), self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
                drawn = db.read_backend_series(
                    connection,
                    cluster=self.CLUSTER,
                    backend=self.POOL,
                    since=since,
                    until=self.now,
                    width=timedelta(hours=1),
                )
                self.assertEqual(
                    sum(interval.counters.get("dns_queries") or 0 for interval in drawn),
                    self.expected("BACKEND", "dns_queries", since),
                )

    def test_the_pool_is_listed_as_dns_and_not_among_the_backends(self) -> None:
        since = self.now - timedelta(days=7)
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
            dns = db.read_cluster_backends(
                connection, cluster=self.CLUSTER, since=since, until=self.now, kind="dns"
            )
            backends = db.read_cluster_backends(
                connection, cluster=self.CLUSTER, since=since, until=self.now
            )
        self.assertEqual((dns, backends), ([self.POOL], ["web"]))

    def test_the_poller_writes_a_node_s_counters_and_the_trigger_pairs_them(self) -> None:
        def reading(queries: int, answered: int) -> dict[str, Any]:
            return {
                "nodes": [
                    {
                        "name": "a",
                        "status": {
                            "vip": {"owner": True},
                            "dns_listener": {
                                "version": "2.1.2",
                                "active": True,
                                "counters": {
                                    "uptime_sec": 60 + queries,
                                    "pools": [
                                        {
                                            "pool": "polled",
                                            "queries": queries,
                                            "tcp_queries": 1,
                                            "refused": 0,
                                            "answered": answered,
                                        }
                                    ],
                                    "servers": [
                                        {
                                            "pool": "polled",
                                            "server": "s1",
                                            "status": "UP",
                                            "queries": queries,
                                            "answered": answered,
                                            "latency_us": 420,
                                        }
                                    ],
                                },
                            },
                        },
                    }
                ]
            }

        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute("select metric_partition('metric_backend_member', current_date)")
        for queries, answered in ((10, 9), (25, 22)):
            with self.connect("HAPRION_UI_TEST_POLLER_ROLE") as connection:
                written = db.record_metric_samples(
                    connection, cluster="polled", result=reading(queries, answered)
                )
                self.assertEqual(written, 2)
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "select member, delta_dns_queries, delta_dns_answered, status "
                "  from metric_backend_member where cluster = 'polled' "
                " order by observed_at desc, member limit 2"
            )
            #
            # An older node still sends its latency; nothing keeps it (B253),
            # and since 0059 there is no column to keep it in.
            #
            self.assertEqual(cursor.fetchall(), [("BACKEND", 15, 13, None), ("s1", 15, 13, "UP")])

    def test_the_migration_downgrades_and_upgrades_cleanly(self) -> None:
        def columns(cursor: psycopg.Cursor, table: str) -> set[str]:
            cursor.execute(
                "select column_name from information_schema.columns "
                "where table_name = %s and column_name like %s",
                (table, "%dns%"),
            )
            return {row[0] for row in cursor.fetchall()}

        now = datetime.now(UTC).replace(microsecond=0)
        with self.connect() as connection:
            with connection.cursor() as cursor:
                migration = _migration("0057_metric_dns_counters.py", cursor)
                migration.downgrade()
                self.assertEqual(columns(cursor, "metric_backend_member"), set())
                self.assertEqual(columns(cursor, "metric_backend_hour_delta"), set())
                #
                # HAProxy's rows still pair and sum under 0048's and 0055's functions.
                #
                for minutes, total in ((20, 5), (10, 12)):
                    cursor.execute(
                        "insert into metric_backend_member (cluster, node, backend, member, "
                        "observed_at, uptime_sec, req_tot) "
                        "values ('down', 'a', 'web', 'BACKEND', %s, %s, %s)",
                        (now - timedelta(minutes=minutes), 100 - minutes, total),
                    )
                cursor.execute(
                    "select sum(delta_req_tot) from metric_backend_hour_delta where cluster = 'down'"
                )
                self.assertEqual(cursor.fetchone(), (7,))
                migration.upgrade()
                self.assertEqual(
                    columns(cursor, "metric_backend_member"),
                    {
                        *metrics.DNS_COUNTERS,
                        LATENCY_0057,
                        *(f"delta_{name}" for name in metrics.DNS_COUNTERS),
                    },
                )
            connection.rollback()


@unittest.skipUnless(DSN, "run through ui/tools/test-database")
class ASyslogPoolIsCountedAsABackendIs(unittest.TestCase):
    """Migration 0061: IPVS's counters in the backend rows (Fas 19b B3).

    Three days of a pool's own row and two receivers every ten minutes. IPVS
    reports no uptime, and halfway the second receiver is taken out and put
    back by keepalived, so its counters start again from nought: that interval
    has no figure, the ones around it do, and the pool's own row - the virtual
    server, which keepalived does not touch - counts straight through. Read
    back over the raw rows and over the hourly sums against the same
    differences summed by hand.
    """

    CLUSTER = "logging"
    POOL = "receivers"
    READDED = 200
    now: datetime
    rows: list[tuple[str, datetime, dict[str, int]]]

    @staticmethod
    def connect(role_variable: str = "HAPRION_UI_TEST_MIGRATION_ROLE") -> psycopg.Connection:
        return psycopg.connect(f"{DSN} user={os.environ[role_variable]}")

    @classmethod
    def setUpClass(cls) -> None:
        cls.now = datetime.now(UTC).replace(minute=0, second=0, microsecond=0)
        rows: list[tuple[str, datetime, dict[str, int]]] = []
        at, step = cls.now - timedelta(days=3), 0
        totals = {"BACKEND": [0, 0], "s1": [0, 0], "s2": [0, 0]}
        while at <= cls.now - timedelta(minutes=10):
            if step == cls.READDED:
                totals["s2"] = [0, 0]
            for member, (messages, size) in (("s1", (7, 700)), ("s2", (5, 450))):
                totals[member][0] += messages
                totals[member][1] += size
                totals["BACKEND"][0] += messages
                totals["BACKEND"][1] += size
            for member in ("BACKEND", "s1", "s2"):
                rows.append(
                    (member, at, dict(zip(metrics.SYSLOG_COUNTERS, totals[member], strict=True)))
                )
            at += timedelta(minutes=10)
            step += 1
        cls.rows = rows
        with cls.connect() as connection, connection.cursor() as cursor:
            day = (cls.now - timedelta(days=4)).date()
            while day <= cls.now.date() + timedelta(days=1):
                cursor.execute("select metric_partition('metric_backend_member', %s::date)", (day,))
                day += timedelta(days=1)
            for member, at, counted in rows:
                cursor.execute(
                    "insert into metric_backend_member (cluster, node, backend, member, "
                    "observed_at, status, syslog_messages, syslog_bytes) "
                    "values (%s, 'a', %s, %s, %s, %s, %s, %s)",
                    (
                        cls.CLUSTER,
                        cls.POOL,
                        member,
                        at,
                        None if member == "BACKEND" else "UP",
                        counted["syslog_messages"],
                        counted["syslog_bytes"],
                    ),
                )
            #
            # An HAProxy backend and a dns pool beside it, neither listed as syslog.
            #
            cursor.execute(
                "insert into metric_backend_member (cluster, node, backend, member, "
                "observed_at, uptime_sec, req_tot) values (%s, 'a', 'web', 'BACKEND', %s, 1, 1)",
                (cls.CLUSTER, cls.now - timedelta(minutes=10)),
            )
            cursor.execute(
                "insert into metric_backend_member (cluster, node, backend, member, "
                "observed_at, uptime_sec, dns_queries) "
                "values (%s, 'a', 'resolver', 'BACKEND', %s, 1, 1)",
                (cls.CLUSTER, cls.now - timedelta(minutes=10)),
            )

    def expected(self, member: str, name: str, since: datetime) -> int:
        """The stored differences of one counter, by hand: a fall is no figure."""

        readings = [row for row in self.rows if row[0] == member]
        total = 0
        for (_m, at_before, before), (_n, at, value) in zip(readings, readings[1:], strict=False):
            if at_before < since or at > self.now or value[name] < before[name]:
                continue
            total += value[name] - before[name]
        return total

    def ranges(self) -> tuple[datetime, ...]:
        return (
            self.now - timedelta(hours=20),
            self.now - timedelta(days=3),
            self.now - timedelta(days=2, minutes=25),
        )

    def test_the_pool_s_figures_are_its_stored_differences(self) -> None:
        for since in self.ranges():
            with self.subTest(since=since), self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
                found = metrics.measured(
                    metrics.SYSLOG_FIGURES,
                    db.read_backend_totals(
                        connection,
                        cluster=self.CLUSTER,
                        backend=self.POOL,
                        since=since,
                        until=self.now,
                        counters=metrics.summed(metrics.SYSLOG_FIGURES),
                    ),
                )
                figures = {total.label: total.value for total in found.totals}
                self.assertGreater(figures["Messages"], 0)
                self.assertEqual(
                    figures,
                    {
                        "Messages": self.expected("BACKEND", "syslog_messages", since),
                        "Bytes": self.expected("BACKEND", "syslog_bytes", since),
                    },
                )

    def test_a_receiver_put_back_has_no_figure_for_the_interval_it_fell_in(self) -> None:
        since = self.now - timedelta(days=3)
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
            found = db.read_backend_totals(
                connection,
                cluster=self.CLUSTER,
                backend=self.POOL,
                member="s2",
                since=since,
                until=self.now,
                counters=metrics.SYSLOG_CARD_COUNTERS,
            )
        messages = found.totals[0].value
        self.assertEqual(messages, self.expected("s2", "syslog_messages", since))
        #
        # One interval of five messages fewer than the pool's share - the one
        # the receiver was put back in - and not a negative one.
        #
        intervals = len([row for row in self.rows if row[0] == "s2"]) - 1
        self.assertEqual(messages, 5 * (intervals - 1))

    def test_the_line_is_drawn_from_the_same_differences(self) -> None:
        for since in self.ranges():
            with self.subTest(since=since), self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
                drawn = db.read_backend_series(
                    connection,
                    cluster=self.CLUSTER,
                    backend=self.POOL,
                    since=since,
                    until=self.now,
                    width=timedelta(hours=1),
                )
                self.assertEqual(
                    sum(interval.counters.get("syslog_messages") or 0 for interval in drawn),
                    self.expected("BACKEND", "syslog_messages", since),
                )

    def test_each_kind_of_pool_is_listed_apart(self) -> None:
        since = self.now - timedelta(days=7)
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
            listed = {
                kind: db.read_cluster_backends(
                    connection, cluster=self.CLUSTER, since=since, until=self.now, kind=kind
                )
                for kind in ("haproxy", "dns", "syslog")
            }
        self.assertEqual(listed, {"haproxy": ["web"], "dns": ["resolver"], "syslog": [self.POOL]})

    def test_the_poller_writes_a_node_s_counters_and_the_trigger_pairs_them(self) -> None:
        def reading(messages: int) -> dict[str, Any]:
            receiver = {
                "address": "192.0.2.71",
                "port": 514,
                "server": "s1",
                "status": "UP",
                "packets": messages,
                "bytes": messages * 100,
            }
            down = dict(receiver, address="192.0.2.72", server="s2", status="DOWN")
            down.update(packets=None, bytes=None)
            return {
                "nodes": [
                    {
                        "name": "a",
                        "status": {
                            "vip": {"owner": True},
                            "ipvs": {
                                "services": [
                                    {
                                        "protocol": "udp",
                                        "address": "192.0.2.20",
                                        "port": 514,
                                        "packets": messages,
                                        "bytes": messages * 100,
                                        "object": "logs",
                                        "pool": "polled",
                                        "receivers": [receiver, down],
                                    }
                                ]
                            },
                        },
                    }
                ]
            }

        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute("select metric_partition('metric_backend_member', current_date)")
        for messages in (10, 25):
            with self.connect("HAPRION_UI_TEST_POLLER_ROLE") as connection:
                written = db.record_metric_samples(
                    connection, cluster="polling", result=reading(messages)
                )
                self.assertEqual(written, 3)
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "select member, delta_syslog_messages, delta_syslog_bytes, status "
                "  from metric_backend_member where cluster = 'polling' "
                " order by observed_at desc, member limit 3"
            )
            self.assertEqual(
                cursor.fetchall(),
                [("BACKEND", 15, 1500, None), ("s1", 15, 1500, "UP"), ("s2", None, None, "DOWN")],
            )

    def test_the_migration_downgrades_and_upgrades_cleanly(self) -> None:
        def columns(cursor: psycopg.Cursor, table: str) -> set[str]:
            cursor.execute(
                "select column_name from information_schema.columns "
                "where table_name = %s and column_name like %s",
                (table, "%syslog%"),
            )
            return {row[0] for row in cursor.fetchall()}

        now = datetime.now(UTC).replace(microsecond=0)
        with self.connect() as connection:
            with connection.cursor() as cursor:
                migration = _migration("0061_metric_syslog_counters.py", cursor)
                migration.downgrade()
                self.assertEqual(columns(cursor, "metric_backend_member"), set())
                self.assertEqual(columns(cursor, "metric_backend_hour_delta"), set())
                #
                # dnsdist's rows still pair and sum under 0057's functions.
                #
                for minutes, total in ((20, 5), (10, 12)):
                    cursor.execute(
                        "insert into metric_backend_member (cluster, node, backend, member, "
                        "observed_at, uptime_sec, dns_queries) "
                        "values ('down', 'a', 'resolver', 'BACKEND', %s, %s, %s)",
                        (now - timedelta(minutes=minutes), 100 - minutes, total),
                    )
                cursor.execute(
                    "select sum(delta_dns_queries) from metric_backend_hour_delta "
                    " where cluster = 'down'"
                )
                self.assertEqual(cursor.fetchone(), (7,))
                migration.upgrade()
                self.assertEqual(
                    columns(cursor, "metric_backend_member"),
                    {*metrics.SYSLOG_COUNTERS, *(f"delta_{n}" for n in metrics.SYSLOG_COUNTERS)},
                )
                self.assertEqual(
                    columns(cursor, "metric_backend_hour_delta"),
                    {
                        *(f"delta_{n}" for n in metrics.SYSLOG_COUNTERS),
                        *(f"span_{n}_sec" for n in metrics.SYSLOG_COUNTERS),
                    },
                )
            connection.rollback()


@unittest.skipUnless(DSN, "run through ui/tools/test-database")
class AReloadThatKeepsTheCountersIsNoRestart(unittest.TestCase):
    """Migration 0065: `shm-stats-file` keeps the counters while the uptime starts again (N3).

    Each series is a run of samples as the poller writes them, uptime, one
    counter and whether the node said its counters were kept, with what the
    trigger must store for each: whether it is a restart and the difference.
    The figures are the ones measured on 3.4.6 in kind: a reload takes the
    uptime from minutes to seconds and leaves a kept counter where it was.
    """

    CLUSTER = "kept"
    #
    # (member, kept, [(uptime, req_tot, restarted, delta), ...]); the first
    # sample has nothing to pair with.
    #
    SERIES: tuple[tuple[str, bool | None, list[tuple[int, int, bool | None, int | None]]], ...] = (
        #
        # A server on a node with the file: a reload keeps the count, so the
        # difference is only what came after; a real stop and start releases
        # the file, the count falls, and that is a restart again.
        #
        (
            "s1",
            True,
            [
                (100, 50, None, None),
                (160, 70, False, 20),
                (5, 75, False, 5),
                (2, 3, True, 3),
                (62, 9, False, 6),
            ],
        ),
        #
        # The pool's own row, which has no GUID and starts again on every reload.
        #
        ("BACKEND", False, [(100, 50, None, None), (160, 70, False, 20), (5, 4, True, 4)]),
        #
        # A node or poller from before: today's rule, unchanged.
        #
        ("s2", None, [(100, 50, None, None), (5, 8, True, 8)]),
    )

    @staticmethod
    def connect(role_variable: str = "HAPRION_UI_TEST_MIGRATION_ROLE") -> psycopg.Connection:
        return psycopg.connect(f"{DSN} user={os.environ[role_variable]}")

    def setUp(self) -> None:
        self.start = datetime.now(UTC).replace(minute=0, second=0, microsecond=0) - timedelta(
            hours=2
        )
        with self.connect() as connection:
            for table in ("metric_backend_member", "metric_frontend"):
                for day in (self.start.date(), (self.start + timedelta(hours=3)).date()):
                    connection.execute("select metric_partition(%s, %s::date)", (table, day))
                connection.execute(
                    psycopg.sql.SQL("delete from {} where cluster = %s").format(
                        psycopg.sql.Identifier(table)
                    ),
                    (self.CLUSTER,),
                )

    def stored(self, table: str, where: str, value: str) -> list[tuple[bool | None, int | None]]:
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
            rows = connection.execute(
                psycopg.sql.SQL(
                    "select restarted, delta_req_tot from {} where cluster = %s and {} = %s "
                    "order by observed_at"
                ).format(psycopg.sql.Identifier(table), psycopg.sql.Identifier(where)),
                (self.CLUSTER, value),
            ).fetchall()
        return [(row[0], row[1]) for row in rows]

    def test_the_backend_rows_count_what_came_after_a_kept_reload(self) -> None:
        with self.connect() as connection:
            for member, kept, samples in self.SERIES:
                for step, (uptime, count, _restarted, _delta) in enumerate(samples):
                    connection.execute(
                        "insert into metric_backend_member (cluster, node, backend, member, "
                        "observed_at, uptime_sec, counters_kept, req_tot) "
                        "values (%s, 'a', 'web', %s, %s, %s, %s, %s)",
                        (
                            self.CLUSTER,
                            member,
                            self.start + timedelta(minutes=step),
                            uptime,
                            kept,
                            count,
                        ),
                    )
        for member, _kept, samples in self.SERIES:
            with self.subTest(member=member):
                self.assertEqual(
                    self.stored("metric_backend_member", "member", member),
                    [(restarted, delta) for _uptime, _count, restarted, delta in samples],
                )

    def test_a_frontend_counts_the_same_way(self) -> None:
        _member, kept, samples = self.SERIES[0]
        with self.connect() as connection:
            for step, (uptime, count, _restarted, _delta) in enumerate(samples):
                connection.execute(
                    "insert into metric_frontend (cluster, node, frontend, owns_vip, "
                    "observed_at, uptime_sec, counters_kept, req_tot) "
                    "values (%s, 'a', 'mgd-vip-https', true, %s, %s, %s, %s)",
                    (self.CLUSTER, self.start + timedelta(minutes=step), uptime, kept, count),
                )
        self.assertEqual(
            self.stored("metric_frontend", "frontend", "mgd-vip-https"),
            [(restarted, delta) for _uptime, _count, restarted, delta in samples],
        )

    def test_a_reload_is_summed_into_the_hour_as_traffic_not_as_a_restart(self) -> None:
        """0055's sums read `restarted`; a kept reload leaves the hour clean."""

        with self.connect() as connection:
            for step, (uptime, count) in enumerate(((100, 50), (160, 70), (5, 75))):
                connection.execute(
                    "insert into metric_backend_member (cluster, node, backend, member, "
                    "observed_at, uptime_sec, counters_kept, req_tot) "
                    "values (%s, 'a', 'web', 's3', %s, %s, true, %s)",
                    (self.CLUSTER, self.start + timedelta(minutes=step), uptime, count),
                )
        with self.connect() as connection:
            row = connection.execute(
                "select sum(delta_req_tot), bool_or(restarted) from metric_backend_hour_delta "
                "where cluster = %s and member = 's3'",
                (self.CLUSTER,),
            ).fetchone()
        self.assertEqual(row, (25, False))

    def test_the_poller_may_say_whether_the_counters_were_kept(self) -> None:
        with self.connect("HAPRION_UI_TEST_POLLER_ROLE") as connection:
            connection.execute(
                "insert into metric_backend_member (cluster, node, backend, member, "
                "uptime_sec, counters_kept, req_tot) values (%s, 'p', 'web', 's1', 1, true, 1)",
                (self.CLUSTER,),
            )
            connection.execute(
                "insert into metric_frontend (cluster, node, frontend, owns_vip, "
                "uptime_sec, counters_kept, req_tot) values (%s, 'p', 'fe', true, 1, true, 1)",
                (self.CLUSTER,),
            )

    def test_downgrade_restores_the_old_rule_and_upgrade_the_new(self) -> None:
        with self.connect() as connection:
            with connection.cursor() as cursor:
                migration = _migration("0065_metric_counters_kept.py", cursor)
                migration.downgrade()
                for minutes, uptime, count in ((2, 100, 50), (3, 5, 60)):
                    cursor.execute(
                        "insert into metric_backend_member (cluster, node, backend, member, "
                        "observed_at, uptime_sec, req_tot) "
                        "values (%s, 'b', 'web', 's1', %s, %s, %s)",
                        (self.CLUSTER, self.start + timedelta(minutes=minutes), uptime, count),
                    )
                cursor.execute(
                    "select restarted, delta_req_tot from metric_backend_member "
                    "where cluster = %s and node = 'b' order by observed_at desc limit 1",
                    (self.CLUSTER,),
                )
                self.assertEqual(cursor.fetchone(), (True, 60))
                migration.upgrade()
                cursor.execute(
                    "insert into metric_backend_member (cluster, node, backend, member, "
                    "observed_at, uptime_sec, counters_kept, req_tot) "
                    "values (%s, 'b', 'web', 's1', %s, 2, true, 64)",
                    (self.CLUSTER, self.start + timedelta(minutes=4)),
                )
                cursor.execute(
                    "select restarted, delta_req_tot from metric_backend_member "
                    "where cluster = %s and node = 'b' order by observed_at desc limit 1",
                    (self.CLUSTER,),
                )
                self.assertEqual(cursor.fetchone(), (False, 4))
            connection.rollback()


@unittest.skipUnless(DSN, "run through ui/tools/test-database")
class WhatTheNodesDidIsWrittenByThePollerAndReadByTheWeb(unittest.TestCase):
    """Migration 0071: *Events → Nodes* through the roles' own grants (26-10-12).

    Three readings as the poller: a starting point that writes nothing, a
    server going down twelve seconds before the second, and the VIP moving
    with the standby gone silent. The web reads them back a page at a time.
    """

    CLUSTER = "eventful"

    @staticmethod
    def connect(role_variable: str) -> psycopg.Connection:
        return psycopg.connect(f"{DSN} user={os.environ[role_variable]}")

    @staticmethod
    def reading(holder: str, status: str, *, other_ok: bool = True) -> dict[str, Any]:
        def entry(name: str) -> dict[str, Any]:
            ok = name == holder or other_ok
            return {
                "name": name,
                "status_ok": ok,
                "status": {
                    "vip": {"owner": name == holder},
                    "servers": [
                        {
                            "backend": "shop",
                            "server": "s1",
                            "status": status if name == holder else "DOWN",
                            "last_change_sec": 12,
                            "check_status": "L4CON",
                        }
                    ],
                }
                if ok
                else None,
            }

        return {"nodes": [entry("node-a"), entry("node-b")]}

    def test_three_readings_and_a_page(self) -> None:
        written = []
        for result in (
            self.reading("node-a", "UP"),
            self.reading("node-a", "DOWN"),
            self.reading("node-b", "DOWN", other_ok=False),
        ):
            with self.connect("HAPRION_UI_TEST_POLLER_ROLE") as connection:
                written.append(
                    db.record_node_events(connection, cluster=self.CLUSTER, result=result)
                )
                connection.commit()

        self.assertEqual(written, [0, 1, 2])
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
            self.assertEqual(db.node_event_count(connection, cluster=self.CLUSTER), 3)
            page = db.node_event_page(connection, cluster=self.CLUSTER, limit=2, order="what")
            self.assertEqual(len(page), 2)
            events = db.node_event_page(connection, cluster=self.CLUSTER, search="s1")
            (down,) = events
            self.assertEqual(
                (down.event, down.node, down.subject), ("server_down", "node-a", "shop/s1")
            )
            self.assertEqual(down.detail, {"check_status": "L4CON"})
            with connection.cursor() as cursor:
                cursor.execute(
                    "select event, node, detail from node_event "
                    " where cluster = %s and event <> 'server_down' order by event",
                    (self.CLUSTER,),
                )
                self.assertEqual(
                    cursor.fetchall(),
                    [("node_silent", "node-a", {}), ("vip_moved", "node-b", {"from": "node-a"})],
                )
        with (
            self.connect("HAPRION_UI_TEST_MIGRATION_ROLE") as connection,
            connection.cursor() as cursor,
        ):
            cursor.execute(
                "select extract(epoch from (max(at) filter (where event = 'vip_moved') "
                "                         - max(at) filter (where event = 'server_down')))"
                "  from node_event where cluster = %s",
                (self.CLUSTER,),
            )
            #
            # Dated by HAProxy's own count, not by the reading.
            #
            self.assertGreaterEqual(float(_first(cursor)), 12)

    def test_the_web_cannot_write_and_the_poller_cannot_read_the_events(self) -> None:
        for role, statement in (
            (
                "HAPRION_UI_TEST_WEB_ROLE",
                "insert into node_event (cluster, node, event, subject) values ('x', 'n', 'node_back', 'n')",
            ),
            ("HAPRION_UI_TEST_WEB_ROLE", "select value from node_event_state"),
            ("HAPRION_UI_TEST_POLLER_ROLE", "select id from node_event"),
            ("HAPRION_UI_TEST_POLLER_ROLE", "delete from node_event"),
        ):
            with (
                self.subTest(role=role, statement=statement),
                self.connect(role) as connection,
                self.assertRaises(psycopg.errors.InsufficientPrivilege),
            ):
                connection.execute(statement)


@unittest.skipUnless(DSN, "run through ui/tools/test-database")
class TheAccountsFromAFile(AccountToolHarness):
    """`haprion-user apply`, `role` and `--password-stdin` (Fas 23, B293), on the real schema."""

    def write(self, text: str, mode: int = 0o600) -> str:
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory)
        path = Path(directory) / "accounts.yaml"
        path.write_text(text)
        path.chmod(mode)
        return str(path)

    FILE = """accounts:
  - username: admin
    role: admin
    break_glass: true
    password: first password
  - username: viewer
    role: reader
    password: viewer password
"""

    def test_a_file_creates_and_the_same_file_again_changes_nothing(self) -> None:
        path = self.write(self.FILE)

        first = self.run_tool("apply", path, "--json")
        second = self.run_tool("apply", path, "--json")

        self.assertEqual((first[0], second[0]), (0, 0))
        one, two = json.loads(first[1]), json.loads(second[1])
        self.assertEqual(one["result"]["created"], ["admin", "viewer"])
        self.assertEqual(
            (two["result"]["changed"], two["result"]["unchanged"]), (False, ["admin", "viewer"])
        )
        role, _source, break_glass, password_hash = self.account("admin") or ()
        self.assertEqual((role, break_glass), ("admin", True))
        self.assertTrue(auth.verify_password(password_hash, "first password"))
        with self.connect() as connection:
            actions = [
                row[0]
                for row in connection.execute(
                    "select action from audit_event where detail->>'via' = 'cli' order by id"
                ).fetchall()
            ]
        self.assertEqual(actions, ["account_created", "account_created"])

    def test_only_what_differs_is_written(self) -> None:
        self.run_tool("apply", self.write(self.FILE))
        changed = self.FILE.replace("role: reader", "role: admin").replace(
            "first password", "second password"
        )

        code, output = self.run_tool("apply", self.write(changed), "--json")

        self.assertEqual(code, 0)
        self.assertEqual(
            json.loads(output)["result"]["updated"],
            [
                {"username": "admin", "fields": ["password"]},
                {"username": "viewer", "fields": ["role"]},
            ],
        )
        self.assertTrue(auth.verify_password((self.account("admin") or ())[3], "second password"))

    def test_check_writes_nothing(self) -> None:
        code, output = self.run_tool("apply", self.write(self.FILE), "--check")

        self.assertEqual(code, 0)
        self.assertIn("would create admin", output)
        self.assertIsNone(self.account("admin"))

    def test_a_file_others_may_read_is_refused_when_it_carries_passwords(self) -> None:
        code, output = self.run_tool("apply", self.write(self.FILE, mode=0o644))

        self.assertNotEqual(code, 0)
        self.assertIn("0600", output)
        self.assertIsNone(self.account("admin"))

    def test_prune_removes_local_accounts_and_never_the_last_admin(self) -> None:
        self.add("operator", role="admin")
        self.add("sso-person", role="reader", source="oidc", password_hash=None)
        path = self.write(self.FILE)

        code, output = self.run_tool("apply", path, "--prune", "--json")

        self.assertEqual(code, 0, output)
        self.assertEqual(json.loads(output)["result"]["deleted"], ["operator"])
        self.assertIsNotNone(self.account("sso-person"))
        only_reader = self.write(
            "accounts:\n  - username: viewer\n    role: reader\n    password: viewer password\n"
        )
        code, output = self.run_tool("apply", only_reader, "--prune", "--json")
        self.assertEqual(code, 65)
        self.assertIn("last active admin", json.loads(output)["error"]["message"])
        self.assertIsNotNone(self.account("admin"))

    def test_role_and_a_piped_password(self) -> None:
        self.add("admin", role="admin")
        self.add("operator", role="admin")

        code, _ = self.run_tool("role", "operator", "reader")
        with mock.patch("sys.stdin", io.StringIO("piped password\n")):
            reset, _ = self.run_tool("reset", "operator", "--password-stdin")

        self.assertEqual((code, reset), (0, 0))
        role, _source, _glass, password_hash = self.account("operator") or ()
        self.assertEqual(role, "reader")
        self.assertTrue(auth.verify_password(password_hash, "piped password"))
        code, output = self.run_tool("role", "admin", "reader")
        self.assertNotEqual(code, 0)
        self.assertIn("last active admin", output)
