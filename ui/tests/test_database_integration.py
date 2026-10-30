"""Checks that need PostgreSQL rather than an imitation of its cursor."""

from __future__ import annotations

import ast
import contextlib
import io
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest import mock
from uuid import uuid4

import psycopg
import psycopg.sql
from haprion import exit_codes
from haprion.config import CLUSTER_ID
from haprion.traffic_collector import (
    RETENTION_DAYS,
    CollectorConfig,
    NodeTarget,
    _database_days,
    _database_reason,
    _database_window,
    _ingest_part,
    _ingest_waf_pages,
    _mirror_window,
    _parse_waf_response,
    forget_database_positions,
)
from psycopg.types.json import Jsonb

from haprion_ui import attention, auth, db, metrics, search_index, timing, traffic_logs
from haprion_ui import jobs as jobs_module
from haprion_ui.metrics import METRIC_COUNTERS

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

    def running(self, operation: str, lease: str, cluster: str = "alpha") -> int:
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "insert into job (operation, cluster, payload, idempotency_key, state, "
                "claim_token, worker_id, lease_until, started_at) values (%s, %s, '{}', "
                "%s, 'running', %s, 'w', now() + %s::interval, now()) returning id",
                (operation, cluster, uuid4(), uuid4(), lease),
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

    def waiting_drain(self, seconds: int) -> subprocess.Popen[str]:
        """`haprion-drain pause --wait` started, and returned once it has paused."""

        directory = Path(tempfile.mkdtemp(prefix="drain-"))
        self.addCleanup(shutil.rmtree, directory)
        (directory / "ui-admin.conf").write_text(
            f"DB_NAME={os.environ['HAPRION_UI_TEST_DATABASE_NAME']}\n"
            f"DB_ROLE={os.environ['HAPRION_UI_TEST_MIGRATION_ROLE']}\n"
        )
        script = Path(__file__).resolve().parents[2] / "install/platform/bin/haprion-drain"
        drain = subprocess.Popen(  # noqa: S603 - fixed interpreter, the repository's script
            ["/bin/bash", str(script), "pause", "--wait", str(seconds)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env={
                **os.environ,
                "HAPRION_UI_DRAIN_CONFIG": str(directory),
                "PGHOST": os.environ["HAPRION_UI_TEST_DATABASE_SOCKET"],
            },
            # A group of its own, as a terminal's job is: Ctrl-C reaches all of it.
            start_new_session=True,
        )
        self.addCleanup(drain.communicate)
        if drain.stdout is None:
            self.fail("no output from haprion-drain")
        while "waiting for" not in drain.stdout.readline():
            if drain.poll() is not None:
                self.fail("haprion-drain ended before it waited")
        return drain

    def test_a_pause_stopped_during_its_wait_is_lifted(self) -> None:
        """Review 26-10-29, A5: Ctrl-C during the wait left the queue paused up to 20 min."""

        self.running("node_restore", "10 minutes")
        drain = self.waiting_drain(60)
        self.assertIsNotNone(self.paused_until())

        os.killpg(drain.pid, signal.SIGINT)

        self.assertNotEqual(drain.wait(timeout=20), 0)
        self.assertIsNone(self.paused_until())

    def test_the_pause_s_margin_is_counted_from_the_end_of_its_wait(self) -> None:
        """Review 26-10-29, A5: set when the wait began, a long wait spent the margin
        the dump and the migration have before claims start again."""

        job = self.running("node_restore", "10 minutes")
        drain = self.waiting_drain(60)
        time.sleep(6)
        with self.connect() as connection:
            connection.execute(
                "update job set lease_until = now() - interval '1 second' where id = %s", (job,)
            )
            connection.commit()
        self.assertEqual(drain.wait(timeout=30), 0)
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "select extract(epoch from paused_until - statement_timestamp()) from job_claim_gate"
            )
            left = float(_first(cursor))
        self.assertGreater(left, 60 + 300 - 3)

    def test_a_job_whose_lease_ran_out_is_not_waited_for(self) -> None:
        self.running("backup_run", "-1 minute")

        answer = self.drain("pause", "--wait", "3")

        self.assertEqual(answer.returncode, 0, answer.stderr)
        self.assertIsNotNone(self.paused_until())
        self.assertEqual(self.drain("resume").returncode, 0)
        self.assertIsNone(self.paused_until())

    def test_a_form_sent_again_is_one_queued_job_in_the_record(self) -> None:
        """Review 26-10-29, Q05: the second send returned the first job and wrote a second row."""

        key = uuid4()
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
            for _ in range(2):
                job = db.queue_job(
                    connection, operation="deploy", cluster="qfive", payload={}, idempotency_key=key
                )
                db.record_audit_event(
                    connection,
                    actor="admin",
                    action="queue_job",
                    cluster="qfive",
                    request_id=job.request_id,
                    detail={"operation": "deploy", "job": job.id},
                )
                connection.commit()
        self.addCleanup(self.forget_job, job.id)
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "select action from audit_event where request_id = %s order by id",
                (job.request_id,),
            )
            rows = [action for (action,) in cursor.fetchall()]
            cursor.execute("delete from audit_event where request_id = %s", (job.request_id,))
            connection.commit()
        self.assertEqual(rows, ["queue_job"])

    def test_the_web_sees_a_lease_that_ran_out_and_a_release_s_pause(self) -> None:
        """Review 26-10-29, Q01/Q06: a job no worker holds, and a queue a release holds."""

        gone = self.running("backup_run", "-30 minutes")
        held = self.running("deploy", "1 minute", cluster="beta")
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
            rows = {job.id: job for job in db.recent_jobs(connection, limit=1000)}
            self.assertIsNone(db.claim_pause(connection))
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                connection.execute("select claim_token from job")
            connection.rollback()
        lapsed = rows[gone].lease_lapsed_since
        self.assertIsNotNone(lapsed)
        if lapsed is not None:
            self.assertLess(lapsed, datetime.now(UTC) - timedelta(minutes=29))
        self.assertIsNone(rows[held].lease_lapsed_since)
        #
        # A job under a living lease is a worker alive: every row says so, and
        # the one it lapsed beside is not said to have none (review 26-10-29, A2).
        #
        self.assertTrue(rows[gone].worker_busy)

        self.forget_job(held)
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
            (alone,) = [job for job in db.recent_jobs(connection, limit=1000) if job.id == gone]
            active = db.active_job(connection, "alpha")
        self.assertFalse(alone.worker_busy)
        self.assertEqual((active.id, active.worker_busy) if active else None, (gone, False))
        self.assertEqual(self.drain("pause", "--wait", "3").returncode, 0)
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
            pause = db.claim_pause(connection)
        self.assertIsNotNone(pause)
        if pause is not None:
            self.assertTrue(pause.by.startswith("release on "), pause.by)
            self.assertGreater(pause.until, datetime.now(UTC))
        #
        # A pause past its end holds nothing, as the worker's claim reads it.
        #
        with self.connect() as connection:
            connection.execute("update job_claim_gate set paused_until = now() - interval '1 s'")
            connection.commit()
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
            self.assertIsNone(db.claim_pause(connection))

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

    def adopt(self, job: int) -> db.ClaimedJob | None:
        with self.connect("HAPRION_UI_TEST_WORKER_ROLE") as worker:
            attempts = worker.execute("select attempts from job where id = %s", (job,)).fetchone()
            adopted = db.adopt_expired(
                worker,
                job_id=job,
                attempts=int(attempts[0]) if attempts else -1,
                worker_id="w2",
                lease_seconds=60,
            )
            worker.commit()
        return adopted

    def test_a_held_job_is_adopted_only_after_an_admin_s_answer(self) -> None:
        """Review 2026-10-28, F01: recovery took a held job over on its kept answer
        and ran the deploy after it, with no admin's Run."""

        free = self.running("cluster_node", "-1 minute")
        run = self.running("cluster_node", "-1 minute", cluster="beta")
        discard = self.running("cluster_node", "-1 minute", cluster="gamma")
        with self.connect() as connection:
            connection.execute(
                "update job set held_since = now() where id = any(%s)", ([run, discard],)
            )
            connection.commit()

        adopted = self.adopt(free)
        self.assertIsNotNone(adopted)
        self.assertIsNone(self.adopt(free), "a second worker adopted the same job")
        self.assertIsNone(self.adopt(run))
        self.assertIsNone(self.adopt(discard))

        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
            self.assertTrue(
                db.decide_held_job(connection, job_id=run, decision="run", actor="admin")
            )
            self.assertTrue(
                db.decide_held_job(connection, job_id=discard, decision="discard", actor="admin")
            )
            connection.commit()
        answered = {job: self.adopt(job) for job in (run, discard)}
        self.assertEqual(
            {job: claimed.held_decision if claimed else None for job, claimed in answered.items()},
            {run: "run", discard: "discard"},
        )

    def test_a_job_given_up_keeps_its_helper_s_answer_beside_why(self) -> None:
        """Review 26-10-29, R03: the answer a helper kept was thrown away."""

        job = self.running("cluster_node", "-1 minute")
        with self.connect("HAPRION_UI_TEST_WORKER_ROLE") as worker:
            attempts = worker.execute("select attempts from job where id = %s", (job,)).fetchone()
            self.assertTrue(
                db.abandon_expired(
                    worker,
                    job_id=job,
                    attempts=int(attempts[0]) if attempts else -1,
                    code="follow_up_exhausted",
                    message="its helper answered",
                    answer={"outcome": "done"},
                )
            )
            worker.commit()
        with self.connect() as connection:
            row = connection.execute(
                "select state, result from job where id = %s", (job,)
            ).fetchone()
        self.assertEqual(
            row,
            (
                "unknown",
                {
                    "error": {"code": "follow_up_exhausted", "message": "its helper answered"},
                    "answer": {"outcome": "done"},
                },
            ),
        )

    def test_an_adoption_waits_while_a_release_has_paused_claims(self) -> None:
        """Review 2026-10-28, F03: the pause stopped a claim and not an adoption."""

        job = self.running("cluster_node", "-1 minute")
        self.assertEqual(self.drain("pause", "--wait", "3").returncode, 0)
        self.assertIsNone(self.adopt(job))
        self.assertEqual(self.drain("resume").returncode, 0)
        self.assertIsNotNone(self.adopt(job))

    def test_an_adoption_in_flight_is_either_finished_before_the_pause_or_waited_for(
        self,
    ) -> None:
        """Review 2026-10-28, F03: as a claim in flight is, by the same SHARE lock."""

        job = self.running("cluster_node", "-1 minute")
        script = Path(__file__).resolve().parents[2] / "install/platform/bin/haprion-drain"
        with self.connect("HAPRION_UI_TEST_WORKER_ROLE") as worker:
            adopted = db.adopt_expired(
                worker, job_id=job, attempts=0, worker_id="w2", lease_seconds=60
            )
            self.assertIsNotNone(adopted)
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
        self.assertIn(f"cluster_node (job {job})", stderr)

    def test_a_nul_in_what_a_helper_said_is_stored_shown_rather_than_refused(self) -> None:
        """Review 26-10-24, 05-08: PostgreSQL refused the NUL, and the worker died on it."""

        from haprion_ui import diagnostics

        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "insert into job (operation, cluster, payload, idempotency_key) "
                "values ('backup_run', 'alpha', '{}', %s) returning id",
                (uuid4(),),
            )
            job_id = int(_first(cursor))
            connection.commit()
        self.addCleanup(self.forget_job, job_id)
        said = {
            "outcome": "failed",
            "error": {"code": "x\x00", "details": {"diagnostics": "a\x00b"}},
        }
        with self.connect("HAPRION_UI_TEST_WORKER_ROLE") as worker:
            claimed = db.claim_job(worker, worker_id="w", lease_seconds=60)
            if claimed is None or claimed.id != job_id:
                self.fail("the worker did not claim the job this test made")
            worker.commit()
            with self.assertRaises(psycopg.DataError):
                db.finish_job(
                    worker, job_id=job_id, claim_token=claimed.claim_token, state="failed",
                    exit_code=1, outcome="failed", result=said, stderr_excerpt="stderr\x00",
                )  # fmt: skip
            worker.rollback()
            self.assertTrue(
                db.finish_job(
                    worker,
                    job_id=job_id,
                    claim_token=claimed.claim_token,
                    state="failed",
                    exit_code=1,
                    outcome="failed",
                    result=diagnostics.redact_result(said),
                    stderr_excerpt=diagnostics.safe_excerpt("stderr\x00"),
                )  # fmt: skip
            )
            worker.commit()
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute("select stderr_excerpt, result from job where id = %s", (job_id,))
            stored = cursor.fetchone()
        if stored is None:
            self.fail("the job is gone")
        self.assertEqual(stored[0], "stderr\ufffd")
        self.assertEqual(stored[1]["error"]["code"], "x\ufffd")

    def test_a_nul_in_a_helper_s_codes_is_stored_by_the_worker_with_its_audit_row(self) -> None:
        """Review 26-10-25, 5-02: the audit row took the codes unredacted and the end was lost."""

        from haprion_ui import worker as worker_module

        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "insert into job (operation, cluster, payload, idempotency_key) "
                "values ('backup_run', 'alpha', '{}', %s) returning id",
                (uuid4(),),
            )
            job_id = int(_first(cursor))
            connection.commit()
        self.addCleanup(self.forget_job, job_id)
        said = {
            "outcome": "failed",
            "error": {"code": "x\x00"},
            "warnings": [{"code": "w\x00", "message": "m"}],
        }
        with self.connect("HAPRION_UI_TEST_WORKER_ROLE") as worker:
            claimed = db.claim_job(worker, worker_id="w", lease_seconds=60)
            if claimed is None or claimed.id != job_id:
                self.fail("the worker did not claim the job this test made")
            worker.commit()
            self.assertTrue(
                worker_module._finish(
                    worker,
                    claimed,
                    state="failed",
                    outcome="failed",
                    exit_code=1,
                    result=said,
                    stderr_excerpt=None,
                    worker="w",
                )  # fmt: skip
            )
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "select state, result->'error'->>'code' from job where id = %s", (job_id,)
            )
            self.assertEqual(cursor.fetchone(), ("failed", "x\ufffd"))
            cursor.execute(
                "select detail->>'error_code' from audit_event "
                "where action = 'job_finished' and detail->>'job' = %s",
                (str(job_id),),
            )
            self.assertEqual(cursor.fetchone(), ("x\ufffd",))

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

    def test_retention_keeps_each_external_certificate_s_newest_download(self) -> None:
        """26-10-18: the registry reads the version last taken out from that row."""

        clause = self.retention_clause("where_audit_old", "AUDIT_KEEP_DAYS")
        with self.connect() as connection, connection.cursor() as cursor:
            ids = {}
            for label, age, action, certificate in (
                ("older-download", "900 days", "certificate_download", "bmc.example.com"),
                ("newest-export", "800 days", "certificate_export", "bmc.example.com"),
                ("only-download", "800 days", "certificate_download", "nas.example.com"),
                ("old-login", "800 days", "login", None),
            ):
                cursor.execute(
                    "insert into audit_event (at, actor, action, detail) "
                    "values (now() - %s::interval, 'admin', %s, %s) returning id",
                    (age, action, Jsonb({"certificate": certificate} if certificate else {})),
                )
                ids[_first(cursor)] = label
            cursor.execute(f"select id from audit_event where {clause}")  # noqa: S608 - the script's own
            removable = {ids[row[0]] for row in cursor.fetchall() if row[0] in ids}
            self.assertEqual(removable, {"older-download", "old-login"})
            connection.rollback()

    def test_the_newest_download_of_each_external_certificate(self) -> None:
        """26-10-18 (0077): read by the web, either kind of event, the newest winning."""

        with self.connect() as connection, connection.cursor() as cursor:
            for actor, action, certificate, fingerprint in (
                ("alice", "certificate_download", "bmc.example.com", "a" * 64),
                ("bob", "certificate_export", "bmc.example.com", "b" * 64),
                ("carol", "certificate_download", "nas.example.com", "c" * 64),
                ("dave", "queue_job", "bmc.example.com", "d" * 64),
            ):
                cursor.execute(
                    "insert into audit_event (actor, action, detail) values (%s, %s, %s)",
                    (
                        actor,
                        action,
                        Jsonb({"certificate": certificate, "fingerprint_sha256": fingerprint}),
                    ),
                )
            connection.commit()
        with psycopg.connect(f"{DSN} user={os.environ['HAPRION_UI_TEST_WEB_ROLE']}") as connection:
            taken = db.certificate_takeouts(connection)

        self.assertEqual(
            {name: (row.actor, row.fingerprint) for name, row in taken.items()
             if name in ("bmc.example.com", "nas.example.com")},
            {"bmc.example.com": ("bob", "b" * 64), "nas.example.com": ("carol", "c" * 64)},
        )  # fmt: skip

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
                " '/^[a-z_]*_evidence() {/,/^}/p;"
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
            ("older-deploy", "deploy", {}),
            ("deploy", "deploy", {}),
            # The newest apply of all, which Needs attention reads (05-01).
            ("newest-of-the-step", "dns_profile_apply", {"profile": "other", "revision": 1}),
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
            # The newest deploy stays for WAF's Not working (05-02), and the
            # newest apply of each profile, a removed one's too, is that
            # profile's Needs attention evidence (0091, B366).
            self.assertEqual(removable, {"old-apply", "older-deploy"})
            connection.rollback()

    def test_retention_keeps_the_newest_publish_and_deploy_of_each_cluster(self) -> None:
        """Review 26-10-24, 05-02: with both pruned, a WAF exception that did not work hid its finding."""

        script = Path(__file__).resolve().parents[2] / "install/platform/bin/haprion-retention"
        clause = subprocess.run(  # noqa: S603 - fixed interpreter, the repository's script
            [
                "/bin/bash",
                "-c",
                'KEEP_DAYS=7; KEEP_MINIMUM=0; eval "$(sed -n'
                " '/^[a-z_]*_evidence() {/,/^}/p;"
                "/^where_removable() {/,/^}/p'"
                ' "$0")"; where_removable',
                str(script),
            ],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        jobs: tuple[tuple[str, str, str, dict[str, object], int], ...] = (
            ("alpha-old-publish", "alpha", "changes_publish", {}, 40),
            ("alpha-publish", "alpha", "changes_publish", {}, 30),
            ("alpha-old-deploy", "alpha", "deploy", {}, 39),
            ("alpha-deploy", "alpha", "deploy", {}, 29),
            ("beta-publish-and-deploy", "beta", "changes_publish", {"deploy": True}, 30),
        )
        with self.connect() as connection, connection.cursor() as cursor:
            named = {}
            for name, cluster, operation, payload, days in jobs:
                cursor.execute(
                    "insert into job (operation, cluster, payload, idempotency_key, state, "
                    "started_at, finished_at) values (%(operation)s, %(cluster)s, %(payload)s, "
                    "%(key)s, 'done', now() - make_interval(days => %(days)s), "
                    "now() - make_interval(days => %(days)s)) returning id",
                    {
                        "operation": operation,
                        "cluster": cluster,
                        "payload": json.dumps(payload),
                        "key": uuid4(),
                        "days": days,
                    },
                )
                named[_first(cursor)] = name
            cursor.execute(f"select id from job where {clause}")  # noqa: S608 - the script's own
            removable = {named[row[0]] for row in cursor.fetchall() if row[0] in named}
            self.assertEqual(removable, {"alpha-old-publish", "alpha-old-deploy"})
            connection.rollback()

    def test_retention_keeps_the_publish_the_newest_deploy_carried(self) -> None:
        """Review 26-10-25, 4-01: a later publish nobody deployed pushed it out.

        Saved, published and deployed weeks ago, then published again and not
        deployed. With the carried publish pruned the web found no deploy
        after the publish that took the exception, and read it as covering.
        """

        script = Path(__file__).resolve().parents[2] / "install/platform/bin/haprion-retention"
        clause = subprocess.run(  # noqa: S603 - fixed interpreter, the repository's script
            [
                "/bin/bash",
                "-c",
                'KEEP_DAYS=7; KEEP_MINIMUM=0; eval "$(sed -n'
                " '/^[a-z_]*_evidence() {/,/^}/p;"
                "/^where_removable() {/,/^}/p'"
                ' "$0")"; where_removable',
                str(script),
            ],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        jobs = (("carried", "changes_publish", 20), ("deploy", "deploy", 19),
                ("later", "changes_publish", 8))  # fmt: skip
        with self.connect() as connection, connection.cursor() as cursor:
            named = {}
            for name, operation, days in jobs:
                cursor.execute(
                    "insert into job (operation, cluster, payload, idempotency_key, state, "
                    "created_at, started_at, finished_at) values (%(operation)s, 'gamma', '{}', "
                    "%(key)s, 'done', now() - make_interval(days => %(days)s), "
                    "now() - make_interval(days => %(days)s), "
                    "now() - make_interval(days => %(days)s) + interval '1 minute') returning id",
                    {"operation": operation, "key": uuid4(), "days": days},
                )
                named[_first(cursor)] = name
            cursor.execute(f"delete from job where {clause} and cluster = 'gamma'")  # noqa: S608
            cursor.execute("select id from job where cluster = 'gamma'")
            self.assertEqual({named[row[0]] for row in cursor.fetchall()}, set(named.values()))
            saved = datetime.now(UTC) - timedelta(days=21)
            carrying = db.deploys_carrying(connection, cluster="gamma", moments=[saved])
            self.assertIn(saved, carrying)
            connection.rollback()

    #
    # (operation, cluster, payload, state, result) in the order they were made.
    # Each step and subject of what Needs attention keys a failure on, and the
    # shapes the Python reading tells apart: lists in another order, a list with
    # a number in it, a field that is no string, Publish & deploy with and
    # without its deploy's answer, a held job discarded, a job still queued.
    #
    ATTENTION_JOBS: tuple[tuple[str, str | None, dict[str, Any], str, Any], ...] = (
        ("cert_issue", None, {"domain": "a.example.com"}, "failed", None),
        ("cert_issue", None, {"domain": "b.example.com"}, "done", None),
        ("cert_publish", None, {"certificates": ["b", "a"]}, "failed", None),
        ("cert_publish", None, {"certificates": ["a", "b"]}, "done", None),
        ("cert_delete", None, {"certificates": ["a", 1]}, "failed", None),
        ("cert_delete", None, {}, "done", None),
        ("cert_target", None, {"certificates": []}, "partial", None),
        ("server_state", "alpha", {"object": "shop"}, "partial", None),
        ("dynamic_unblock", "alpha", {"object": {"name": "shop"}}, "failed", None),
        ("changes_publish", "alpha", {"deploy": True}, "failed",
         {"publish": {"outcome": "done"}, "step": "deploy"}),
        ("changes_publish", "alpha", {"deploy": True}, "done", {"publish": "not an answer"}),
        ("deploy", "alpha", {}, "done", None),
        ("changes_publish", "beta", {"deploy": True}, "blocked",
         {"publish": {}, "operation": "cert_deploy"}),
        ("cluster_node", "beta", {"deploy": True}, "unknown", {"node": {}}),
        ("cluster_node", "beta", {"deploy": False}, "done", {"node": {}}),
        ("deploy", "beta", {}, "done", None),
        ("deploy", "beta", {}, "blocked", {"error": {"code": "held_discarded"}}),
        ("deploy", "beta", {}, "pending", None),
        ("cert_delete", None, {"certificates": ["x", "y", "z"]}, "partial",
         {"result": {"refused": ["z"]}}),
        ("cert_delete", None, {"certificates": ["z"]}, "done", None),
        ("dns_profile_apply", None, {"profile": "p-a"}, "failed", None),
        ("dns_profile_apply", None, {"profile": "p-b"}, "done", None),
        # A later publish on beta: the blocked one above is then kept by its
        # certificate deploy alone, which is how 07-06 shows (0091).
        ("changes_publish", "beta", {"deploy": False}, "done", None),
    )  # fmt: skip

    def _attention_jobs(self, cursor: Any) -> dict[int, int]:
        """The jobs above, a minute apart and a month old; position by id."""

        made = {}
        for position, (operation, cluster, payload, state, result) in enumerate(
            self.ATTENTION_JOBS
        ):
            finished = state not in ("pending", "running")
            cursor.execute(
                "insert into job (operation, cluster, payload, idempotency_key, state, result, "
                "created_at, started_at, finished_at) values (%(operation)s, %(cluster)s, "
                "%(payload)s, %(key)s, %(state)s, %(result)s, %(at)s, %(started)s, %(finished)s) "
                "returning id",
                {
                    "operation": operation,
                    "cluster": cluster,
                    "payload": json.dumps(payload),
                    "key": uuid4(),
                    "state": state,
                    "result": None if result is None else json.dumps(result),
                    "at": datetime.now(UTC) - timedelta(days=30) + timedelta(minutes=position),
                    "started": None
                    if state == "pending"
                    else datetime.now(UTC) - timedelta(days=30),
                    "finished": datetime.now(UTC) - timedelta(days=30) if finished else None,
                },
            )
            made[_first(cursor)] = position
        return made

    def test_the_attention_evidence_is_the_interface_s_own_reading(self) -> None:
        """0089, 0091: the SQL function and `from_jobs`' keying name the same jobs (05-01, 2-02)."""

        with self.connect() as connection, connection.cursor() as cursor:
            made = self._attention_jobs(cursor)
            connection.commit()
        try:
            with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
                rows = [job for job in db.recent_jobs(connection, limit=1000) if job.id in made]
                evidence = {job.id for job in db.attention_evidence(connection) if job.id in made}
            newest: dict[tuple[str | None, str, str], int] = {}
            for job in sorted(rows, key=lambda row: (row.created_at, row.id), reverse=True):
                if not jobs_module.ran(job):
                    continue
                for operation, subject, _state in jobs_module.keyed_states(job):
                    newest.setdefault((job.cluster, operation, subject), job.id)
            self.assertEqual(len(rows), len(self.ATTENTION_JOBS))
            self.assertEqual(
                sorted(made[job_id] for job_id in evidence),
                sorted({made[job_id] for job_id in newest.values()}),
            )
            # The cases above meant something: each kind of key is in it.
            self.assertEqual(sorted(made[job_id] for job_id in evidence),
                             [0, 1, 3, 5, 6, 7, 8, 10, 11, 12, 14, 15, 18, 19, 20, 21, 22])  # fmt: skip
        finally:
            with self.connect() as connection:
                connection.execute("delete from job where id = any(%s)", (list(made),))
                connection.commit()

    def test_a_finished_run_is_recorded_and_the_web_reads_it(self) -> None:
        """05-09: the prune's last act, as the command runs it, read as the web reads it."""

        script = Path(__file__).resolve().parents[2] / "install/platform/bin/haprion-retention"
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
            before = db.retention_completed(connection)
        self.assertIsNotNone(before)
        subprocess.run(  # noqa: S603 - fixed interpreter, the repository's script
            [
                "/bin/bash",
                "-c",
                'log() { :; }; psql_as() { psql -U "$DB_ROLE" -d "$DB_NAME" -qtAX "$@"; }; '
                'eval "$(sed -n \'/^record_completed() {/,/^}/p\' "$0")"; record_completed',
                str(script),
            ],
            env={
                **os.environ,
                "DB_ROLE": os.environ["HAPRION_UI_TEST_MIGRATION_ROLE"],
                "DB_NAME": os.environ["HAPRION_UI_TEST_DATABASE_NAME"],
                "PGHOST": os.environ["HAPRION_UI_TEST_DATABASE_SOCKET"],
            },
            check=True,
        )
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
            after = db.retention_completed(connection)
        if before is None or after is None:
            self.fail("the migration's row is gone")
        self.assertGreater(after, before)
        prune = script.read_text().split("        prune)", 1)[1].split(";;", 1)[0]
        self.assertTrue(prune.rstrip().endswith("record_completed"), prune[-200:])

    def test_a_failure_nothing_settled_outlives_the_pruning_and_the_newest_200(self) -> None:
        """Review 26-10-24, 05-01: a month old under 25 newer jobs, and still listed."""

        script = Path(__file__).resolve().parents[2] / "install/platform/bin/haprion-retention"
        clause = subprocess.run(  # noqa: S603 - fixed interpreter, the repository's script
            [
                "/bin/bash",
                "-c",
                'KEEP_DAYS=7; KEEP_MINIMUM=20; eval "$(sed -n'
                " '/^[a-z_]*_evidence() {/,/^}/p;"
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
                "insert into job (operation, cluster, payload, idempotency_key, state, "
                "created_at, started_at, finished_at) values ('server_state', 'alpha', "
                "%(payload)s, %(key)s, 'failed', now() - interval '30 days', "
                "now() - interval '30 days', now() - interval '30 days') returning id",
                {"payload": json.dumps({"object": "shop"}), "key": uuid4()},
            )
            failed = _first(cursor)
            for _ in range(25):
                cursor.execute(
                    "insert into job (operation, cluster, payload, idempotency_key, state, "
                    "created_at, started_at, finished_at) values ('server_state', 'alpha', "
                    "%(payload)s, %(key)s, 'done', now() - interval '20 days', "
                    "now() - interval '20 days', now() - interval '20 days')",
                    {"payload": json.dumps({"object": "api"}), "key": uuid4()},
                )
            cursor.execute(f"select id from job where {clause}")  # noqa: S608 - the script's own
            removable = {row[0] for row in cursor.fetchall()}
            self.assertNotIn(failed, removable)
            self.assertEqual(len(removable & set(range(failed + 1, failed + 26))), 5)
            connection.commit()
        try:
            with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
                recent = db.recent_jobs(connection, limit=10)
                evidence = db.attention_evidence(connection)
            known = {job.id for job in recent}
            listed = attention.from_jobs(recent + [job for job in evidence if job.id not in known])
            self.assertIn(f"job {failed}", [item.subject for item in listed])
            self.assertNotIn(failed, known)
        finally:
            with self.connect() as connection:
                connection.execute("delete from job where id >= %s", (failed,))
                connection.commit()

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
                " '/^[a-z_]*_evidence() {/,/^}/p;"
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
            # The last is the step's newest, which Needs attention reads (05-01).
            for name, draft in (
                ("kept", kept),
                ("gone", str(uuid4())),
                ("newest", str(uuid4())),
            ):
                cursor.execute(
                    "insert into job (operation, cluster, payload, idempotency_key, state, "
                    "started_at, finished_at) values ('changes_publish', 'alpha', %(payload)s, "
                    "%(key)s, 'done', now() - interval '30 days', now() - interval '30 days') "
                    "returning id",
                    {
                        "payload": json.dumps({"drafts": [{"id": draft, "revision": 1}]}),
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
                " '/^[a-z_]*_evidence() {/,/^}/p;"
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
            # The last is the step's newest, which Needs attention reads (05-01).
            for name, change in (
                ("kept", kept),
                ("gone", str(uuid4())),
                ("newest", str(uuid4())),
            ):
                cursor.execute(
                    "insert into job (operation, cluster, payload, idempotency_key, state, "
                    "started_at, finished_at) values ('changes_publish', 'alpha', %(payload)s, "
                    "%(key)s, 'done', now() - interval '30 days', now() - interval '30 days') "
                    "returning id",
                    {
                        "payload": json.dumps({"changes": [{"id": change, "revision": 1}]}),
                        "key": uuid4(),
                    },
                )
                named[_first(cursor)] = name
            cursor.execute(f"select id from job where {clause}")  # noqa: S608 - the script's own
            removable = {named[row[0]] for row in cursor.fetchall() if row[0] in named}
            self.assertEqual(removable, {"gone"})
            found = db.change_publishes(connection, cluster="alpha", change_ids={kept})
            self.assertEqual([job.payload["changes"][0]["id"] for job in found], [kept])
            connection.rollback()

    def test_a_package_s_publish_is_the_evidence_for_each_row_it_carried(self) -> None:
        """B257: `drafts` and `changes` lists, read and kept as one object's `draft` is."""

        script = Path(__file__).resolve().parents[2] / "install/platform/bin/haprion-retention"
        clause = subprocess.run(  # noqa: S603 - fixed interpreter, the repository's script
            [
                "/bin/bash",
                "-c",
                'KEEP_DAYS=7; KEEP_MINIMUM=0; eval "$(sed -n'
                " '/^[a-z_]*_evidence() {/,/^}/p;"
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
            # "gone" first: the newest publish is kept for WAF's Not working (05-02).
            for name, payload in (
                ("gone", {"drafts": [{"id": str(uuid4()), "revision": 1}]}),
                ("objects", {"drafts": [{"id": draft, "revision": 1}]}),
                ("settings", {"changes": [{"id": change, "revision": 1}]}),
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
                    "started_at, finished_at) values ('changes_publish', 'alpha', %(payload)s, "
                    "%(key)s, %(state)s, now(), now())",
                    {
                        "payload": json.dumps({"drafts": [{"id": draft, "revision": 1}]}),
                        "key": uuid4(),
                        "state": state,
                    },
                )
            connection.commit()
        try:
            with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
                found = db.draft_publishes(connection, cluster="alpha", draft_ids={mine})
            self.assertEqual([job.payload["drafts"][0]["id"] for job in found], [mine])
        finally:
            with self.connect() as connection, connection.cursor() as cursor:
                cursor.execute(
                    "delete from job where payload->'drafts'->0->>'id' = any(%s)", ([mine, other],)
                )
                connection.commit()

    def test_every_cluster_check_holds_the_engines_cluster_id(self) -> None:
        """Migration 0084: the database takes what the engine makes (2026-10-22).

        The CHECKs said the UI's own 32 characters with an underscore, so a
        cluster the engine accepted with a longer ID could not be cached or
        queued. Read from the catalogue, so a later migration that copies an
        old pattern fails here.
        """

        with self.connect() as connection:
            rows = connection.execute(
                "select conrelid::regclass::text, pg_get_constraintdef(oid) from pg_constraint "
                "where contype = 'c' and pg_get_constraintdef(oid) ~ '\\mcluster ~'"
            ).fetchall()
            self.assertGreaterEqual(len({table for table, _ in rows}), 21)
            for table, definition in rows:
                with self.subTest(table=table):
                    (pattern,) = re.findall(r"cluster ~ '([^']*)'", definition)
                    self.assertEqual(pattern, CLUSTER_ID.pattern)
            longest = "edge-" + "a" * 58
            connection.execute(
                "insert into cluster_pass (cluster, began_at) values (%s, now())", (longest,)
            )
            with self.assertRaises(psycopg.errors.CheckViolation):
                connection.execute(
                    "insert into cluster_pass (cluster, began_at) values ('1alpha', now())"
                )
            connection.rollback()

    def test_every_column_the_interface_writes_is_granted_to_one_of_its_roles(self) -> None:
        """A write no role may make is a refusal waiting for its first use.

        `rename_draft` set `object_id`, and no migration granted that column:
        every test of the rename imitated the cursor, so the first real rename
        of an unpublished draft was refused by the database (found
        2026-10-08). Read here from the statements themselves, so the next
        such column fails this test and not a person's save.
        """

        package = Path(__file__).resolve().parents[1] / "src/haprion_ui/db"
        statements = [
            node.value
            for module in sorted(package.glob("*.py"))
            for node in ast.walk(ast.parse(module.read_text()))
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        ]
        self.assertGreater(len(statements), 500)
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

    def test_the_poller_keeps_the_update_check_and_the_web_reads_it(self) -> None:
        """0081: the switch, an answer, then failures - the answer stays, the first failure's time too."""

        first = datetime(2026, 10, 20, 12, 0, tzinfo=UTC)
        url = "https://github.com/haprion/haprion/releases/tag/v0.9.3"
        try:
            with self.connect("HAPRION_UI_TEST_POLLER_ROLE") as connection:
                self.assertFalse(db.switch_enabled(connection, "update_check"))
                db.record_update_answer(connection, tag="v0.9.3", url=url, at=first)
                db.record_update_failure(
                    connection, error="timed out", at=first + timedelta(hours=25)
                )
                db.record_update_failure(
                    connection, error="timed out", at=first + timedelta(hours=26)
                )
                connection.commit()
            with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
                kept = db.update_check(connection)
            assert kept is not None  # noqa: S101 - written just above
            self.assertEqual(
                (kept.latest_tag, kept.latest_url, kept.checked_at), ("v0.9.3", url, first)
            )
            self.assertEqual(kept.failing_since, first + timedelta(hours=25))
            self.assertEqual(kept.attempted_at, first + timedelta(hours=26))
            with self.connect("HAPRION_UI_TEST_POLLER_ROLE") as connection:
                db.record_update_answer(
                    connection,
                    tag="v0.9.4",
                    url=url.replace("3", "4"),
                    at=first + timedelta(hours=27),
                )
                connection.commit()
                self.assertIsNone(db.update_check(connection).failing_since)  # type: ignore[union-attr]
            with (
                self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection,
                self.assertRaises(psycopg.errors.InsufficientPrivilege),
            ):
                connection.execute("update update_check set latest_tag = 'v9.9.9'")
        finally:
            with self.connect() as connection:
                connection.execute("delete from update_check")
                connection.commit()

    def test_the_poller_replaces_the_packages_waiting_and_the_web_reads_them(self) -> None:
        """0088: replaced whole by the poller, read by the web, written by nothing else."""

        at = datetime(2026, 10, 23, 22, 0, tzinfo=UTC)
        try:
            with self.connect("HAPRION_UI_TEST_POLLER_ROLE") as connection:
                db.replace_package_waiting(
                    connection,
                    [("haprion-cli", "0.99.0", "0.99.1"), ("haprion-ui", "0.99.0", "0.99.1")],
                    at=at,
                )
                db.replace_package_waiting(connection, [("haprion-ui", "0.99.0", "0.99.1")], at=at)
                connection.commit()
            with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
                self.assertEqual(
                    db.package_waiting(connection),
                    [db.PackageWaiting("haprion-ui", "0.99.0", "0.99.1", at)],
                )
            with (
                self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection,
                self.assertRaises(psycopg.errors.InsufficientPrivilege),
            ):
                connection.execute("delete from package_waiting")
            with (
                self.connect("HAPRION_UI_TEST_POLLER_ROLE") as connection,
                self.assertRaises(psycopg.errors.CheckViolation),
            ):
                db.replace_package_waiting(connection, [("haproxy", "1", "2")], at=at)
        finally:
            with self.connect() as connection:
                connection.execute("delete from package_waiting")
                connection.commit()

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
                    base_document="",
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
                    base_document="name: console\n",
                    expected_revision=draft.revision,
                )
                connection.commit()
            self.assertEqual((moved.object_id, moved.id), ("terminal", draft.id))
            # 0080: written and read back by the web role, as the editor does.
            self.assertEqual(draft.base_document, "")
            self.assertEqual(moved.base_document, "name: console\n")
        finally:
            with self.connect() as connection:
                connection.execute("delete from proxy_draft where cluster = 'alpha'")
                connection.commit()

    def test_a_cluster_no_longer_listed_holds_nothing_back(self) -> None:
        """Review 26-10-24, 11-02: a removed cluster's draft refused a certificate's deletion."""

        try:
            with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
                db.save_draft(
                    connection,
                    cluster="alpha",
                    object_id="console",
                    yaml="name: console\n",
                    base_version=None,
                    base_hash="a" * 40,
                    updated_by="admin",
                    base_document="",
                    expected_revision=None,
                )
                connection.commit()
                self.assertEqual(
                    [draft.object_id for draft in db.live_drafts(connection, ["alpha"])],
                    ["console"],
                )
                self.assertEqual(db.live_drafts(connection, ["beta"]), [])
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
            "base_document": "",
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
                    base_document="",
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

    def test_healthz_reads_what_it_judges_as_the_web_and_only_the_web_passes(self) -> None:
        """B332: the web role reads the revision, and the grant is the web's alone."""

        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute("select version_num from alembic_version")
            (head,) = cursor.fetchone() or (None,)
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
            web = db.health(connection)
        self.assertEqual((web.web, web.revision), (True, head))
        with (
            self.connect("HAPRION_UI_TEST_WORKER_ROLE") as connection,
            self.assertRaises(psycopg.errors.InsufficientPrivilege),
        ):
            db.health(connection)

    def test_a_lost_lock_session_is_seen_and_the_lock_can_be_taken_again(self) -> None:
        """Review 2026-10-18, A1: the poller asks again before every pass."""

        role = os.environ["HAPRION_UI_TEST_POLLER_ROLE"]
        key = 0x48415052
        with (
            psycopg.connect(f"{DSN} user={role}", autocommit=True) as holder,
            psycopg.connect(f"{DSN} user={role}", autocommit=True) as other,
        ):
            self.assertTrue(db.try_singleton_lock(holder, key))
            self.assertTrue(db.holds_singleton_lock(holder, key))
            self.assertFalse(db.holds_singleton_lock(other, key))
            self.assertFalse(db.try_singleton_lock(other, key))

            with contextlib.suppress(psycopg.OperationalError), holder.cursor() as cursor:
                cursor.execute("select pg_terminate_backend(pg_backend_pid())")

            self.assertFalse(db.holds_singleton_lock(holder, key))
            self.assertTrue(db.try_singleton_lock(other, key))

    def test_the_web_reads_the_traces_of_the_manager_s_services(self) -> None:
        """B333: the poller's cluster list and the partitions' horizon, as the web."""

        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute("select traffic_log_partition(current_date + 3)")
            cursor.execute("select metric_partition('metric_frontend', current_date + 9)")
            connection.commit()
        with self.connect("HAPRION_UI_TEST_POLLER_ROLE") as connection:
            db.record_cluster_list(connection, ["alpha"])
            connection.commit()
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
            self.assertIsNotNone(db.cluster_list_observed(connection))
            horizons = db.partition_horizons(connection, ["traffic_log", "metric_frontend", "nope"])
        today = datetime.now(UTC).date()
        traffic, metric = horizons["traffic_log"], horizons["metric_frontend"]
        self.assertTrue(traffic is not None and traffic >= today + timedelta(days=3))
        self.assertTrue(metric is not None and metric >= today + timedelta(days=9))
        self.assertIsNone(horizons["nope"])

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

    def test_step_7_sees_the_pass_of_a_poller_with_no_cluster(self) -> None:
        # Fas 18 (26-10-13): platform step 7's own query, as the poller, after a
        # pass that recorded no cluster.
        step = (
            Path(__file__).resolve().parents[2] / "install/platform/07-platform-services"
        ).read_text()
        match = re.search(r'"(select count\(\*\) from cluster_list where [^"]*)"', step)
        if match is None:
            self.fail("step 7 has no cluster_list query")
        for existing in (False, True):
            with self.subTest(row_already_there=existing):
                with self.connect("HAPRION_UI_TEST_POLLER_ROLE") as connection:
                    if existing:
                        db.record_cluster_list(connection, [])
                        connection.commit()
                    row = connection.execute("select statement_timestamp()::text").fetchone()
                    if row is None:
                        self.fail("no statement_timestamp")
                    connection.commit()
                    db.record_cluster_list(connection, [])
                    connection.commit()
                    query = match.group(1).replace("${started_at}", row[0])
                    counted = connection.execute(query).fetchone()
                    self.assertEqual(counted, (1,))
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

    def test_one_name_s_sign_ins_are_counted_one_at_a_time(self) -> None:
        """Review 2026-10-22, 3-3: the lock the sign-in takes holds a second attempt for
        the same name until the first is written down, and lets another name pass."""

        import threading

        with (
            self.connect("HAPRION_UI_TEST_WEB_ROLE") as first,
            self.connect("HAPRION_UI_TEST_WEB_ROLE") as second,
            self.connect("HAPRION_UI_TEST_WEB_ROLE") as other,
        ):
            db.lock_sign_in(first, username="Operator")
            db.lock_sign_in(other, username="admin")
            done = threading.Event()

            def again() -> None:
                db.lock_sign_in(second, username="operator")
                done.set()
                second.rollback()

            waiting = threading.Thread(target=again)
            waiting.start()
            self.assertFalse(done.wait(timeout=1), "the same name went through at once")
            first.rollback()
            self.assertTrue(done.wait(timeout=10))
            waiting.join(timeout=10)
            other.rollback()

    def test_a_sign_in_s_lock_cannot_meet_the_worker_s_or_the_poller_s(self) -> None:
        """Review 26-10-29, A4: `hashtext` of a name is an int4, and the one-key form took
        it in the singleton locks' space: a name hashed to the worker's key waited 5 s."""

        from haprion_ui import poller, worker

        role = os.environ["HAPRION_UI_TEST_WORKER_ROLE"]
        with (
            psycopg.connect(f"{DSN} user={role}", autocommit=True) as held,
            self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection,
        ):
            self.assertTrue(db.try_singleton_lock(held, worker.WORKER_LOCK_KEY))
            db.lock_sign_in(connection, username="Operator")
            taken = connection.execute(
                "select classid::bigint, objsubid from pg_locks"
                " where locktype = 'advisory' and pid = pg_backend_pid()"
            ).fetchall()
            one_key, two_keys = connection.execute(
                "select pg_try_advisory_xact_lock(%(key)s::integer),"
                " pg_try_advisory_xact_lock(%(space)s::integer, %(key)s::integer)",
                {"key": worker.WORKER_LOCK_KEY, "space": db.SIGN_IN_LOCKS},
            ).fetchone() or (None, None)
            kept = connection.execute("select hashtext('app_user_keep_an_admin')").fetchone()
            connection.rollback()
        self.assertEqual(taken, [(db.SIGN_IN_LOCKS, 2)])
        self.assertEqual((one_key, two_keys), (False, True))
        # The last-admin guard keeps the one-key form, which 0100's trigger takes as
        # well, on a fixed name whose hash is neither singleton key.
        self.assertNotIn(kept, ((worker.WORKER_LOCK_KEY,), (poller.POLLER_LOCK_KEY,)))

    def test_two_saves_of_the_status_list_at_once_both_finish(self) -> None:
        """Review 2026-10-22, 3-9: both saw the address missing, and the second met the
        unique index - a 500 for somebody saving the same list a moment later."""

        import threading

        errors: list[BaseException] = []
        with (
            self.connect("HAPRION_UI_TEST_WEB_ROLE") as first,
            self.connect("HAPRION_UI_TEST_WEB_ROLE") as second,
        ):
            db.set_status_access(first, networks=("192.0.2.30/32",), actor="admin")

            def save() -> None:
                try:
                    db.set_status_access(second, networks=("192.0.2.30/32",), actor="operator")
                    second.commit()
                except BaseException as error:  # noqa: BLE001 - reported below
                    errors.append(error)

            other = threading.Thread(target=save)
            other.start()
            other.join(timeout=1)
            self.assertTrue(other.is_alive(), "the second save should wait for the first")
            first.commit()
            other.join(timeout=10)
            listed = {entry.network: entry.added_by for entry in db.status_access(first)}
            db.set_status_access(first, networks=(), actor="admin")
            first.commit()

        self.assertEqual(errors, [])
        self.assertEqual(listed, {"192.0.2.30/32": "admin"})

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
                "select host, path, status from traffic_log_read "
                "where cluster = 'alpha' and host = 'service.example.com'"
            )
            self.assertEqual(cursor.fetchall(), [("service.example.com", "/health", 200)])
            # A collector that knows nothing of `rule` still writes "no rule" (0050).
            cursor.execute("select rule from traffic_log_read where host = 'service.example.com'")
            self.assertEqual(cursor.fetchall(), [("",)])
            # ... and "nothing found" for the engine's fields (0051).
            cursor.execute(
                "select waf_rules, waf_score from traffic_log_read where host = 'service.example.com'"
            )
            self.assertEqual(cursor.fetchall(), [("", 0)])
            # ... and no engine transaction (0052).
            cursor.execute("select waf_id from traffic_log_read where host = 'service.example.com'")
            self.assertEqual(cursor.fetchall(), [("",)])
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                cursor.execute(statement, values)
        # The web reads the view and nothing of the table itself (the baseline, B369).
        with (
            self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection,
            connection.cursor() as cursor,
            self.assertRaises(psycopg.errors.InsufficientPrivilege),
        ):
            cursor.execute("select host from traffic_log limit 0")
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
        # A small cluster beside a large one, in the page's order (0083).
        self.assertIn(f"traffic_log_{suffix}_cluster", indexes)

    def test_the_web_reads_the_traffic_log_through_a_view_and_holds_nothing_on_the_table(
        self,
    ) -> None:
        """The view shows every column but the collector's bookkeeping (0083; the baseline, B369)."""

        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "select attname from pg_attribute"
                " where attrelid = 'traffic_log_read'::regclass and attnum > 0 order by 1"
            )
            shown = [row[0] for row in cursor.fetchall()]
            cursor.execute(
                "select attname from pg_attribute where attrelid = 'traffic_log'::regclass"
                " and attnum > 0 and not attisdropped order by 1"
            )
            columns = [row[0] for row in cursor.fetchall()]
            cursor.execute(
                "select count(*) from information_schema.column_privileges"
                " where table_name = 'traffic_log' and grantee = 'app_web'"
            )
            granted = _first(cursor)
            cursor.execute("select traffic_log_partition(current_date)")
            cursor.execute(
                "select to_regclass(%s)::text",
                (f"public.traffic_log_{datetime.now(UTC):%Y%m%d}_cluster",),
            )
            indexed = _first(cursor)
            connection.rollback()
        self.assertEqual(shown, sorted(set(columns) - {"event_id", "inserted_at"}))
        self.assertEqual(granted, 0)
        self.assertEqual(indexed, f"traffic_log_{datetime.now(UTC):%Y%m%d}_cluster")

    def test_the_planner_sees_the_search_index_statistics_for_the_web(self) -> None:
        """Through the view, the web's estimate of a search is the owner's (0083, D1).

        With column grants alone PostgreSQL hides an expression index's
        statistics from the planner, which then guessed a search matches about
        1 % of the rows and read the whole table for one that matched nothing -
        past the web's statement timeout from a week of busy traffic.
        """

        now = datetime.now(UTC).replace(microsecond=0)
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute("select traffic_log_partition(%s::date)", (now.date(),))
            cursor.execute(
                "insert into traffic_log (event_id, cluster, node, occurred_at, request_number,"
                " client, method, host, path, frontend, backend, server, status, request_time,"
                " queue_time, connect_time, response_time, total_time, bytes)"
                " select sha256(('estimate' || i)::bytea), 'alpha', 'node-a', %s, i,"
                " '192.0.2.10', 'GET', 'app' || i %% 20 || '.example.com',"
                " '/api/v1/items/' || i %% 300, 'f', 'be-' || i %% 10, 's',"
                " 200, 0, 0, 0, 0, 0, 0 from generate_series(1, 5000) as i",
                (now,),
            )
            connection.commit()
            cursor.execute(f"analyze traffic_log_{now:%Y%m%d}")
            connection.commit()

        #
        # A short term over repeated values, as hostnames and paths are: there
        # the planner's guess without statistics is furthest from the truth.
        #
        search = "(host || ' ' || path || ' ' || backend) ilike '%zzqx%'"
        partition = f"traffic_log_{now:%Y%m%d}"

        def estimate(role: str, relation: str) -> int:
            def rows(node: dict[str, Any]) -> int | None:
                if node.get("Relation Name") == partition:
                    return int(node["Plan Rows"])
                return next(
                    (
                        found
                        for child in node.get("Plans", [])
                        if (found := rows(child)) is not None
                    ),
                    None,
                )

            with self.connect(role) as connection, connection.cursor() as cursor:
                statement = f"explain (format json) select host from {relation} where {search}"  # noqa: S608 - fixed literals
                cursor.execute(statement)
                plan: Any = cursor.fetchone()
                found = rows(plan[0][0]["Plan"])
                self.assertIsNotNone(found, f"no scan of {partition}")
                return int(found or 0)

        self.assertEqual(
            estimate("HAPRION_UI_TEST_WEB_ROLE", "traffic_log_read"),
            estimate("HAPRION_UI_TEST_MIGRATION_ROLE", "traffic_log"),
        )

    def test_the_roles_carry_the_limits_the_installation_sets(self) -> None:
        """test-database sets what `02-platform-database` sets, read out of the step (review D2)."""

        step = Path(__file__).resolve().parents[2] / "install/platform/02-platform-database"
        limits = re.findall(
            r'^set_limits "\$(\w+)_USER"\s+"([^"]+)"$', step.read_text(), re.MULTILINE
        )
        self.assertEqual(
            [role for role, _ in limits],
            ["WEB", "WORKER", "POLLER", "COLLECTOR"],
            "the step's shape",
        )
        for role, timeout in limits:
            with (
                self.subTest(role=role),
                self.connect(f"HAPRION_UI_TEST_{role}_ROLE") as connection,
            ):
                self.assertEqual(
                    connection.execute("show statement_timeout").fetchone(), (timeout,)
                )
                self.assertEqual(
                    connection.execute("show idle_in_transaction_session_timeout").fetchone(),
                    ("10s",),
                )

    def test_a_log_query_past_the_web_role_limit_is_cancelled_as_the_503_page_expects(self) -> None:
        """The installation's 5 s limit, held by test-database too, stops a reading (review D2).

        `refusals.database_unavailable` turns `QueryCanceled` into the page that
        says to narrow the filter (U2, `test_database_unavailable`); this is
        the real server raising it for the log page's own query. A lock held
        by another session keeps the query waiting, so the limit is what ends
        it, whatever the table holds.
        """

        with self.connect() as holder:
            holder.execute("lock table traffic_log in access exclusive mode")
            with (
                tempfile.TemporaryDirectory() as temporary,
                self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection,
            ):
                started = datetime.now(UTC)
                with self.assertRaises(psycopg.errors.QueryCanceled):
                    traffic_logs.read_database(connection, Path(temporary), ("alpha",))
                waited = (datetime.now(UTC) - started).total_seconds()
            holder.rollback()
        self.assertGreaterEqual(waited, 4.5)
        self.assertLess(waited, 15)

    def test_traffic_rule_is_bounded_and_each_day_indexes_it(self) -> None:
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
            cursor.execute("select rule from traffic_log_read where host = 'rule.example.com'")
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
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "select count(*) from pg_indexes where indexname = %s",
                (f"traffic_log_{suffix}_rule",),
            )
            self.assertEqual(cursor.fetchone(), (1,))

    def test_waf_findings_are_bounded(self) -> None:
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
                "select waf_rules, waf_score from traffic_log_read where host = 'waf.example.com'"
            )
            self.assertEqual(cursor.fetchall(), [("930120,932160", 43)])

    def test_waf_matches_are_bounded_and_joined(self) -> None:
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
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "select t.path, m.object, m.rule_id, m.field, m.matched from traffic_log t "
                "join waf_match m on m.cluster = t.cluster and m.request_id = t.waf_id "
                "where t.host = 'match.example.com'"
            )
            self.assertEqual(cursor.fetchall(), [("/search", "shop", 942100, "ARGS:q", good[4])])
        #
        # The web reads the hourly findings (0054), not the matches: what a
        # requester sent is no page's (review 2026-10-22, 3-6, 0086).
        #
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection, connection.cursor() as cursor:
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                cursor.execute("select matched from waf_match limit 0")
            connection.rollback()
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
            cursor.execute("select count(*) from traffic_log_read where host = 'copy.example.com'")
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
        with self.connect() as connection, connection.cursor() as cursor:
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
                cursor.execute("select count(*) from traffic_log_read where host = %s", (host,))
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
            cursor.execute(
                "select count(*) from traffic_log_read where host = 'skipped.example.com'"
            )
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
            cursor.execute(
                "select count(*) from traffic_log_read where host = 'partial.example.com'"
            )
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

    def test_the_queue_refuses_an_operation_the_worker_cannot_prepare(self) -> None:
        """0087 (review 2026-10-22, 6-6), for every row since the baseline (B369)."""

        insert = (
            "insert into job (operation, cluster, payload, idempotency_key, state) "
            "values (%s, %s, '{}', %s, 'pending')"
        )
        with self.connect() as connection, connection.cursor() as cursor:
            for retired in ("network_publish", "objects_publish", "cluster_settings_publish"):
                with self.subTest(operation=retired):
                    cursor.execute("savepoint refused")
                    with self.assertRaises(psycopg.errors.CheckViolation):
                        cursor.execute(insert, (retired, "beta", uuid4()))
                    cursor.execute("rollback to savepoint refused")
            cursor.execute(insert, ("dynamic_unblock", "gamma", uuid4()))
            connection.rollback()

    def test_what_nothing_reads_is_not_there(self) -> None:
        """0086 (review 2026-10-22, 3-6, 3-7): no 0023 views, no request index on the
        matches, and no web grant on them."""

        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute("select to_regclass('public.metric_listener') is not null")
            views = _first(cursor)
            cursor.execute(
                "select count(*) from pg_indexes "
                " where tablename like 'waf_match\\_%%' and indexname like '%%\\_request'"
            )
            indexes = int(_first(cursor))
            cursor.execute("select has_table_privilege('app_web', 'waf_match', 'select')")
            web = _first(cursor)
            cursor.execute(
                "select has_column_privilege('app_web', 'waf_match', 'matched', 'select')"
            )
            matched = _first(cursor)
        self.assertEqual((views, indexes > 0, web, matched), (False, False, False, False))

    def test_the_partitions_bounds_are_read_whatever_the_server_s_zone(self) -> None:
        """Review 2026-10-22, 3-4: west of UTC a day partition starts at 05:00Z, and the
        collector chose rows by the partition's name, which is the UTC day."""

        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute("set timezone = 'America/New_York'")
            cursor.execute("select waf_match_partition('2030-01-10')")
            window = _database_window(connection, "waf_match")
            connection.rollback()

        if window is None:
            self.fail("the partitions' bounds were not read")
        self.assertEqual(window[1], datetime(2030, 1, 11, 5, tzinfo=UTC))
        self.assertLess(window[0], datetime.now(UTC))

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

    def test_database_search_finds_the_text_as_the_files_do(self) -> None:
        """Review 2026-10-20, D1: `_` and `%` were LIKE's wildcards in the database.

        `api_v1` found `/apiXv1` there and not in the files, and `foo\\bar` found
        nothing. A term is text, the same in both readers.
        """

        now = datetime.now(UTC).replace(microsecond=0)
        paths = ["/api_v1", "/apiXv1", "/a%2fb", "/abc2f", "/foo\\bar", "/fooXbar"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            part = root / f"alpha--node-a--{now:%Y-%m-%d}.jsonl"
            part.write_text(
                "".join(
                    json.dumps(
                        {
                            "schema": 1,
                            "at": int(now.timestamp()),
                            "request": 900 + number,
                            "client": "192.0.2.21",
                            "method": "GET",
                            "host": "literal.example.com",
                            "path": path,
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
                    + "\n"
                    for number, path in enumerate(paths)
                )
            )
            target = NodeTarget("alpha", "node-a", "node-a.example.com")
            config = CollectorConfig(
                "svc-logread", root / "key", root / "known_hosts", root, root, (target,)
            )
            with self.connect("HAPRION_UI_TEST_COLLECTOR_ROLE") as connection:
                _ingest_part(config, connection, target, part)
            for search in ("api_v1", "%2f", "foo\\bar", "NOT api_v1", "api_v1 OR %2f"):
                with (
                    self.subTest(search=search),
                    self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection,
                ):
                    reading = traffic_logs.read_database(
                        connection,
                        root,
                        ("alpha",),
                        substring=f"literal.example.com AND ({search})",
                    )
                    expression = traffic_logs._Parser(traffic_logs._tokens(search)).parse()
                    self.assertEqual(
                        sorted(entry.path for entry in reading.entries),
                        sorted(path for path in paths if _contains(expression, path)),
                    )

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

    def test_the_worker_may_run_the_claim_probe_as_the_step_runs_it(self) -> None:
        """05-05: the probe is the worker's claim, and the worker's role may run it."""

        from tests.test_verify_claim_probe import verify_probe

        role = os.environ["HAPRION_UI_TEST_WORKER_ROLE"]
        with psycopg.connect(f"{DSN} user={role}") as connection:
            connection.execute(verify_probe())
            connection.rollback()

    def test_the_table_level_grants_are_the_ones_the_step_expects(self) -> None:
        """Review 26-10-24, 05-03: `delete on job` would have passed the column matrix."""

        text = self.SCRIPT.read_text()
        listed = re.search(
            r"^expected_table_grants=\$\(cat <<'EOF'\n(.*?)\nEOF$", text, re.MULTILINE | re.DOTALL
        )
        if listed is None:
            self.fail("03-verify no longer states its table grants in the shape this reads")
        role = os.environ["HAPRION_UI_TEST_MIGRATION_ROLE"]
        with psycopg.connect(f"{DSN} user={role}") as connection, connection.cursor() as cursor:
            cursor.execute(
                "select grantee, table_name, privilege_type"
                "  from information_schema.table_privileges"
                " where table_schema = 'public' and grantee like 'app\\_%'"
                "   and privilege_type in ('DELETE', 'TRUNCATE', 'TRIGGER', 'REFERENCES')"
                " order by grantee, table_name, privilege_type"
            )
            actual = ["\t".join(row) for row in cursor.fetchall()]
        self.assertEqual(actual, listed.group(1).split("\n"))
        evidence = {"job", "audit_event", "login_attempt", "login_unlock"}
        self.assertEqual([line for line in actual if line.split("\t")[1] in evidence], [])

    def test_the_functions_the_roles_may_call_are_the_ones_the_step_expects(self) -> None:
        text = self.SCRIPT.read_text()
        listed = re.search(r"^expected_routines=\$'([^']*)'$", text, re.MULTILINE)
        if listed is None:
            self.fail("03-verify no longer states its function list in the shape this reads")
        expected = [line.replace("\\t", "\t") for line in listed.group(1).split("\\n")]
        role = os.environ["HAPRION_UI_TEST_MIGRATION_ROLE"]
        with psycopg.connect(f"{DSN} user={role}") as connection, connection.cursor() as cursor:
            cursor.execute(
                "select grantee, routine_name, privilege_type"
                "  from information_schema.routine_privileges"
                " where routine_schema = 'public' and grantee like 'app\\_%'"
                " order by grantee, routine_name, privilege_type"
            )
            actual = ["\t".join(row) for row in cursor.fetchall()]
            cursor.execute(
                "select p.proname from pg_proc p join pg_namespace n on n.oid = p.pronamespace"
                " where n.nspname = 'public' and p.prosecdef"
                "   and has_function_privilege('public', p.oid, 'EXECUTE')"
            )
            open_to_all = cursor.fetchall()
        self.assertEqual(actual, expected)
        self.assertEqual(open_to_all, [])

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


def _contains(expression: Any, text: str) -> bool:
    """What a search means, said plainly, for the database's answer to be held to."""

    if isinstance(expression, traffic_logs._Term):
        return expression.value in text
    if isinstance(expression, traffic_logs._Not):
        return not _contains(expression.value, text)
    if isinstance(expression, traffic_logs._And):
        return _contains(expression.left, text) and _contains(expression.right, text)
    return _contains(expression.left, text) or _contains(expression.right, text)


def _first(cursor: psycopg.Cursor) -> Any:
    """The first column of the row the last statement returned, which it must have."""

    row = cursor.fetchone()
    if row is None:
        raise AssertionError("the statement returned no row")
    return row[0]


@unittest.skipUnless(DSN, "run through ui/tools/test-database")
class TheMetricTablesKeepWhatTheReaderReads(unittest.TestCase):
    """The metric tables as migrated, held to the lists the node, reader and rollup use.

    Read from the catalogue rather than from a migration's text, so a later
    migration that adds or drops a counter is held here too (the baseline, B369).
    """

    def connect(self) -> psycopg.Connection:
        return psycopg.connect(f"{DSN} user={os.environ['HAPRION_UI_TEST_MIGRATION_ROLE']}")

    def columns(self, table: str) -> list[tuple[str, str, str, str | None]]:
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "select column_name, data_type, is_nullable, column_default"
                "  from information_schema.columns where table_name = %s order by ordinal_position",
                (table,),
            )
            return [(name, kind, nullable, default) for name, kind, nullable, default in cursor]

    def counters(self, table: str) -> list[str]:
        """The cumulative counters: bigint, and none of uptime, deltas or another source's."""

        other = {"uptime_sec", "floor_uptime_sec", *metrics.DNS_COUNTERS, *metrics.SYSLOG_COUNTERS}
        return [
            name
            for name, kind, _nullable, _default in self.columns(table)
            if kind == "bigint" and not name.startswith("delta_") and name not in other
        ]

    def deltas(self, table: str) -> tuple[str, ...]:
        return tuple(
            name.removeprefix("delta_")
            for name, *_ in self.columns(table)
            if name.startswith("delta_")
        )

    def test_the_tables_store_exactly_what_the_reader_keeps(self) -> None:
        for table in ("metric_frontend", "metric_backend_member", "metric_backend_hour"):
            with self.subTest(table=table):
                self.assertEqual(tuple(self.counters(table)), METRIC_COUNTERS)
        names = [name for name, *_ in self.columns("metric_backend_member")]
        self.assertEqual(tuple(n for n in names if n in metrics.DNS_COUNTERS), metrics.DNS_COUNTERS)
        self.assertEqual(
            tuple(n for n in names if n in metrics.SYSLOG_COUNTERS), metrics.SYSLOG_COUNTERS
        )
        self.assertNotIn("dns_latency_us", names)

    def test_the_differences_stored_are_the_ones_the_readers_sum(self) -> None:
        self.assertEqual(self.deltas("metric_frontend"), db.STORED_DELTAS)
        self.assertEqual(self.deltas("metric_frontend_hour_delta"), db.STORED_DELTAS)
        self.assertEqual(self.deltas("metric_backend_member"), db.BACKEND_DELTAS)
        self.assertEqual(self.deltas("metric_backend_hour_delta"), db.BACKEND_DELTAS)
        self.assertEqual(
            (*db.STORED_DELTAS, *metrics.DNS_COUNTERS, *metrics.SYSLOG_COUNTERS), db.BACKEND_DELTAS
        )
        with self.connect() as connection, connection.cursor() as cursor:
            for function, deltas in (
                ("metric_frontend_delta", db.STORED_DELTAS),
                ("metric_backend_member_delta", db.BACKEND_DELTAS),
            ):
                cursor.execute("select pg_get_functiondef(%s::regproc)", (function,))
                body = _first(cursor)
                for counter in deltas:
                    with self.subTest(function=function, counter=counter):
                        self.assertIn(f"delta_{counter}", body)

    def test_every_counter_is_nullable_and_has_no_default(self) -> None:
        """Null is "not applicable"; zero is a measurement. See the node script."""

        for table in ("metric_frontend", "metric_backend_member"):
            for name, kind, nullable, default in self.columns(table):
                if kind == "bigint":
                    with self.subTest(table=table, column=name):
                        self.assertEqual((nullable, default), ("YES", None))

    def test_the_samples_are_partitioned_by_day_with_no_default_partition(self) -> None:
        with self.connect() as connection, connection.cursor() as cursor:
            for table, key in (
                ("metric_frontend", "RANGE (observed_at)"),
                ("metric_backend_member", "RANGE (observed_at)"),
                ("metric_backend_hour", "RANGE (bucket_at)"),
            ):
                cursor.execute("select pg_get_partkeydef(%s::regclass)", (table,))
                self.assertEqual(_first(cursor), key)
                cursor.execute(
                    "select count(*) from pg_inherits i join pg_class c on c.oid = i.inhrelid"
                    " where i.inhparent = %s::regclass"
                    "   and pg_get_expr(c.relpartbound, c.oid) = 'DEFAULT'",
                    (table,),
                )
                self.assertEqual(_first(cursor), 0)
            with self.assertRaisesRegex(psycopg.errors.RaiseException, "not a metric table"):
                cursor.execute("select metric_partition('job', current_date)")

    def test_one_poll_is_one_instant_and_a_cache_keeps_the_statement_clock(self) -> None:
        """`executemany` sends a statement per row; the rows of one poll are one reading."""

        observed = {
            table: next(d for name, _k, _n, d in self.columns(table) if name == "observed_at")
            for table in ("metric_frontend", "metric_backend_member", "cluster_status")
        }
        self.assertEqual(observed["metric_frontend"], "transaction_timestamp()")
        self.assertEqual(observed["metric_backend_member"], "transaction_timestamp()")
        self.assertNotEqual(observed["cluster_status"], "transaction_timestamp()")

    def test_the_poller_writes_samples_and_never_their_time_and_nobody_changes_one(self) -> None:
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "select table_name, column_name, grantee, privilege_type"
                "  from information_schema.column_privileges"
                " where table_name in ('metric_frontend', 'metric_backend_member',"
                "                      'metric_backend_hour', 'metric_rollup_state')"
                "   and grantee like 'app\\_%%'"
            )
            granted = set(cursor.fetchall())
            cursor.execute(
                "select table_name, privilege_type from information_schema.table_privileges"
                " where table_name like 'metric\\_%%' and grantee like 'app\\_%%'"
                "   and privilege_type in ('DELETE', 'UPDATE', 'TRUNCATE')"
            )
            changed = cursor.fetchall()
        self.assertEqual(changed, [])
        writes = {(t, c, g, k) for t, c, g, k in granted if k != "SELECT"}
        self.assertTrue(writes)
        self.assertEqual({(g, k) for _t, _c, g, k in writes}, {("app_poller", "INSERT")})
        self.assertEqual({t for t, *_ in writes}, {"metric_frontend", "metric_backend_member"})
        self.assertNotIn("observed_at", {c for _t, c, *_ in writes})
        self.assertEqual(
            {(c, g) for t, c, g, _k in granted if t == "metric_rollup_state"},
            {("rollup_name", "app_web"), ("complete_before", "app_web")},
        )

    def test_a_rollup_row_is_an_hour_with_its_reading_and_its_floor(self) -> None:
        names = {name for name, *_ in self.columns("metric_backend_hour")}
        self.assertLessEqual({"uptime_sec", "floor_uptime_sec", "bucket_at"}, names)
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "select pg_get_constraintdef(oid) from pg_constraint"
                " where conrelid = 'metric_backend_hour'::regclass and contype = 'c'"
            )
            checks = " ".join(row[0] for row in cursor.fetchall())
        self.assertIn("date_trunc('hour'::text, bucket_at)", checks)


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

    def test_a_cluster_s_job_in_flight_is_read_behind_any_number_of_newer_jobs(self) -> None:
        """Review 2026-10-22, 1B-4: a pending deploy older than the newest twenty was not
        in the list every page reads the busy badge from - the cluster looked idle and
        its buttons were refused by the queue."""

        from haprion_ui import jobs

        deploying = self.queue("deploy", "alpha")
        for index in range(25):
            self.finish(self.queue("cert_publish", None, certificates=[f"cert-{index}.example"]))

        recent = db.recent_jobs(self.connection)

        self.assertIn(deploying.id, [job.id for job in recent])
        self.assertEqual(len(recent), 21)
        self.assertIn("alpha", jobs.in_flight(recent, writes=True))
        self.assertEqual([job.id for job in db.recent_jobs(self.connection, cluster="beta")], [])

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

    def test_a_drawn_payload_s_second_click_finds_the_job_its_key_queued(self) -> None:
        """Review 26-10-24, 02-06: other bytes under the key meet the first job as busy."""

        key = uuid4()
        first = db.queue_job(
            self.connection,
            operation="cert_import",
            cluster=None,
            payload={"id": "example.com", "box": "first"},
            idempotency_key=key,
        )
        with self.assertRaises((db.CertificateBusy, db.RequestConflict)):
            db.queue_job(
                self.connection,
                operation="cert_import",
                cluster=None,
                payload={"id": "example.com", "box": "second"},
                idempotency_key=key,
            )

        found = db.job_for_key(self.connection, key, operation="cert_import", cluster=None)
        self.assertEqual(found.id if found else None, first.id)
        self.assertIsNone(
            db.job_for_key(self.connection, key, operation="cert_publish", cluster=None)
        )
        self.assertIsNone(
            db.job_for_key(self.connection, key, operation="cert_import", cluster="alpha")
        )
        self.assertIsNone(
            db.job_for_key(self.connection, uuid4(), operation="cert_import", cluster=None)
        )


@unittest.skipUnless(DSN, "run through ui/tools/test-database")
class AProfileIdMayHoldADot(unittest.TestCase):
    """Migration 0101 (B380): `.` and `_` in a DNS or NDES profile ID, nothing more."""

    def connect(self) -> psycopg.Connection:
        return psycopg.connect(f"{DSN} user={os.environ['HAPRION_UI_TEST_MIGRATION_ROLE']}")

    def insert(self, table: str, profile_id: str) -> None:
        provider = "ndes" if table == "ndes_provider_profile" else "cloudflare"
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                f"insert into {table} (id, name, provider_id, schema_version, key_id, "  # noqa: S608 - the test's own table names
                "ciphertext, created_by, updated_by) values (%(id)s, %(id)s, %(provider)s, 1, "
                "'0123456789abcdef', %(blob)s, 'a', 'a')",
                {"id": profile_id, "provider": provider, "blob": b"x" * 48},
            )
            connection.rollback()

    def test_both_tables_take_a_server_s_name_and_refuse_a_leading_dot(self) -> None:
        for table in ("dns_provider_profile", "ndes_provider_profile"):
            with self.subTest(table=table):
                self.insert(table, "cs2.example.com")
                self.insert(table, "cs2_example-com")
                with self.assertRaises(psycopg.errors.CheckViolation):
                    self.insert(table, ".hidden")


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

    def test_a_profile_whose_job_is_refused_is_not_stored(self) -> None:
        """Review 2026-10-22, 3-1: `connection.transaction()` on a connection just taken
        from the pool was the outermost transaction and committed the profile; the
        refused job's rollback undid nothing, and the profile stood with no apply job -
        the gap B147 closed. The page's own sequence, against PostgreSQL."""

        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
            db.queue_job(
                connection,
                operation="cert_publish",
                cluster=None,
                payload={"certificates": ["example.com"]},
                idempotency_key=uuid4(),
            )
            connection.commit()

        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
            db.create_dns_profile(
                connection,
                profile_id="probe",
                name="Probe",
                provider_id="cloudflare",
                key_id="0123456789abcdef",
                ciphertext=b"x" * 48,
                actor="operator",
            )
            self.assertEqual(
                connection.info.transaction_status, psycopg.pq.TransactionStatus.INTRANS
            )
            with self.assertRaises(db.CertificateBusy):
                db.queue_job(
                    connection,
                    operation="dns_profile_apply",
                    cluster=None,
                    payload={"profile": "probe", "revision": 1},
                    idempotency_key=uuid4(),
                )
            connection.rollback()

        with self.connect("HAPRION_UI_TEST_MIGRATION_ROLE") as connection:
            self.assertIsNone(db.dns_profile(connection, "probe"))

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
            db.live_drafts(connection, ["alpha"])
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
            self.assertEqual(db.live_drafts(connection, ["alpha"]), [])


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
class JobsFromBeforeTheBoot(unittest.TestCase):
    """0082, review 2026-10-20 R1: a restored manager's old jobs wait for an admin."""

    BOOT = datetime(2000, 1, 2, tzinfo=UTC)

    def connect(self, role: str = "HAPRION_UI_TEST_MIGRATION_ROLE") -> psycopg.Connection:
        return psycopg.connect(f"{DSN} user={os.environ[role]}")

    def setUp(self) -> None:
        self.ids: list[int] = []
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
            for cluster in ("helda", "heldb", "heldc"):
                job = db.queue_job(
                    connection,
                    operation="deploy",
                    cluster=cluster,
                    payload={},
                    idempotency_key=uuid4(),
                )
                self.ids.append(job.id)
            connection.commit()
        with self.connect() as connection:
            connection.execute(
                "update job set created_at = '2000-01-01T00:00:00Z' where id = any(%s)", (self.ids,)
            )
            connection.commit()
        self.addCleanup(self.remove)

    def remove(self) -> None:
        with self.connect() as connection:
            connection.execute("delete from job where id = any(%s)", (self.ids,))
            connection.commit()

    def test_held_jobs_wait_and_an_admin_s_answer_lets_the_worker_end_them(self) -> None:
        run, discard, waiting = self.ids
        with self.connect("HAPRION_UI_TEST_WORKER_ROLE") as connection:
            held = db.hold_jobs_queued_before(connection, boot=self.BOOT)
            connection.commit()
            self.assertTrue({run, discard, waiting} <= set(held))
            claimed = db.claim_job(connection, worker_id="w", lease_seconds=60)
            connection.rollback()
            self.assertTrue(claimed is None or claimed.id not in self.ids)
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
            self.assertTrue(
                db.decide_held_job(connection, job_id=run, decision="run", actor="admin")
            )
            self.assertTrue(
                db.decide_held_job(connection, job_id=discard, decision="discard", actor="admin")
            )
            self.assertFalse(
                db.decide_held_job(connection, job_id=run, decision="discard", actor="admin")
            )
            connection.commit()
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                connection.execute("update job set held_since = null where id = %s", (waiting,))
        taken = {}
        with self.connect("HAPRION_UI_TEST_WORKER_ROLE") as connection:
            for _ in range(2):
                claimed = db.claim_job(connection, worker_id="w", lease_seconds=60)
                connection.commit()
                if claimed is None:
                    self.fail("an answered job was not taken")
                taken[claimed.id] = claimed.held_decision
        self.assertEqual(taken, {run: "run", discard: "discard"})

    def test_the_queue_says_a_held_job_holds_the_cluster(self) -> None:
        """Review 26-10-29, Q07/R05: "try again when it has finished" of a job that never will."""

        held, *_ = self.ids
        with self.connect("HAPRION_UI_TEST_WORKER_ROLE") as connection:
            db.hold_jobs_queued_before(connection, boot=self.BOOT)
            connection.commit()
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
            with self.assertRaises(db.ClusterBusy) as refused:
                db.queue_job(
                    connection,
                    operation="deploy",
                    cluster="helda",
                    payload={"other": True},
                    idempotency_key=uuid4(),
                )
            connection.rollback()
        active = refused.exception.active
        self.assertEqual(active.id if active else None, held)
        self.assertTrue(active is not None and active.waits_for_decision)

    def test_an_answer_holds_until_the_next_boot_not_beyond(self) -> None:
        """Logic review 26-10-22, L2: a job answered Run and still running when
        a backup was taken came back from it and ran again on the old answer."""

        run = self.ids[0]
        with self.connect("HAPRION_UI_TEST_WORKER_ROLE") as connection:
            db.hold_jobs_queued_before(connection, boot=self.BOOT)
            connection.commit()
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
            self.assertTrue(
                db.decide_held_job(connection, job_id=run, decision="run", actor="admin")
            )
            connection.commit()
        with self.connect("HAPRION_UI_TEST_WORKER_ROLE") as connection:
            #
            # The worker started again on the same boot: the answer stands.
            #
            self.assertNotIn(run, db.hold_jobs_queued_before(connection, boot=self.BOOT))
            connection.commit()
            #
            # The machine booted again - restored from an image taken while
            # the job waited or ran: asked again.
            #
            later = datetime.now(UTC) + timedelta(days=1)
            self.assertIn(run, db.hold_jobs_queued_before(connection, boot=later))
            connection.commit()
            claimed = db.claim_job(connection, worker_id="w", lease_seconds=60)
            connection.rollback()
            self.assertTrue(claimed is None or claimed.id not in self.ids)
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                connection.execute(
                    "update job set held_decision = 'run', held_decided_by = 'w' where id = %s",
                    (run,),
                )
        with self.connect() as connection:
            row = connection.execute(
                "select held_decision, held_decided_by from job where id = %s", (run,)
            ).fetchone()
        self.assertEqual(row, (None, None))

    def test_a_job_queued_after_the_boot_is_not_held(self) -> None:
        with self.connect("HAPRION_UI_TEST_WORKER_ROLE") as connection:
            held = db.hold_jobs_queued_before(connection, boot=datetime(1999, 1, 1, tzinfo=UTC))
            connection.rollback()
        self.assertFalse(set(held) & set(self.ids))

    def test_after_restore_holds_every_job_and_ends_every_session(self) -> None:
        script = (
            Path(__file__).resolve().parents[2] / "install/platform/bin/haprion-backup"
        ).read_text()
        statement = re.search(r"<<'SQL'\n(.*?)\nSQL\n", script, re.DOTALL)
        if statement is None:
            self.fail("haprion-backup after-restore has no statement")
        body = statement[1].replace("begin;\n", "").replace("commit;", "")
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute(body)
            cursor.execute(
                "select count(*) from job where id = any(%s) and held_since is null", (self.ids,)
            )
            self.assertEqual(cursor.fetchone(), (0,))
            #
            # An answer given before the dump is cleared too (0085).
            #
            cursor.execute(
                "update job set held_decision = 'run', held_decided_by = 'admin' where id = %s",
                (self.ids[0],),
            )
            cursor.execute(body)
            cursor.execute("select held_decision from job where id = %s", (self.ids[0],))
            self.assertEqual(cursor.fetchone(), (None,))
            cursor.execute("select count(*) from app_session where revoked_at is null")
            self.assertEqual(cursor.fetchone(), (0,))
            cursor.execute(
                "select action from audit_event where actor = 'haprion-backup' order by id desc limit 2"
            )
            self.assertEqual(
                sorted(row[0] for row in cursor.fetchall()), ["all_sessions_revoked", "jobs_held"]
            )
            connection.rollback()


@unittest.skipUnless(DSN, "run through ui/tools/test-database")
class ARestoreRunReadsItsHold(unittest.TestCase):
    """Review 26-10-29, C06: the restore page reads whether its job is held, as the web."""

    def test_the_web_reads_the_hold_of_a_run_s_jobs(self) -> None:
        run = "r260101-0000cccc"
        with psycopg.connect(f"{DSN} user={os.environ['HAPRION_UI_TEST_MIGRATION_ROLE']}") as owner:
            job = db.queue_job(
                owner,
                operation="node_restore_prepare",
                cluster="alpha",
                payload={"run": run},
                idempotency_key=uuid4(),
            )
            owner.execute("update job set held_since = now() where id = %s", (job.id,))
            owner.commit()
            try:
                with psycopg.connect(f"{DSN} user={os.environ['HAPRION_UI_TEST_WEB_ROLE']}") as web:
                    (read,) = db.restore_jobs(web, run)
                    listed = [
                        found
                        for found in db.operation_jobs(web, "node_restore_prepare")
                        if found.id == job.id
                    ]
                self.assertTrue(read.waits_for_decision)
                self.assertTrue(listed[0].waits_for_decision)
            finally:
                owner.execute("delete from job where id = %s", (job.id,))
                owner.commit()

    def test_the_web_reads_when_a_run_s_job_lost_its_worker(self) -> None:
        """Review 26-10-29, B2: the restore page said working for a job no worker held."""

        run = "r260101-0000dddd"
        with psycopg.connect(f"{DSN} user={os.environ['HAPRION_UI_TEST_MIGRATION_ROLE']}") as owner:
            job = db.queue_job(
                owner,
                operation="node_restore",
                cluster="alpha",
                payload={"run": run},
                idempotency_key=uuid4(),
            )
            owner.execute(
                "update job set state = 'running', claim_token = %s, worker_id = 'w', "
                "started_at = now() - interval '1 hour', lease_until = now() - interval '50 minutes' "
                " where id = %s",
                (uuid4(), job.id),
            )
            owner.commit()
            try:
                with psycopg.connect(f"{DSN} user={os.environ['HAPRION_UI_TEST_WEB_ROLE']}") as web:
                    (read,) = db.restore_jobs(web, run)
                    (listed,) = [
                        found
                        for found in db.operation_jobs(web, "node_restore")
                        if found.id == job.id
                    ]
                for found in (read, listed):
                    self.assertIsNotNone(found.lease_lapsed_since)
                    self.assertFalse(found.worker_busy)
            finally:
                owner.execute("delete from job where id = %s", (job.id,))
                owner.commit()


@unittest.skipUnless(DSN, "run through ui/tools/test-database")
class TheBackupsHashCheck(unittest.TestCase):
    """Review 2026-10-20, R2: the restore check's query against the real schema."""

    HASH = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA"

    def test_an_oidc_account_first_is_passed_over_for_the_local_one(self) -> None:
        script = (
            Path(__file__).resolve().parents[2] / "install/platform/bin/haprion-backup"
        ).read_text()
        query = re.search(r'"(select password_hash from app_user[^"]*)"', script)
        if query is None:
            self.fail("haprion-backup no longer reads a password hash")
        with (
            psycopg.connect(
                f"{DSN} user={os.environ['HAPRION_UI_TEST_MIGRATION_ROLE']}"
            ) as connection,
            connection.cursor() as cursor,
        ):
            cursor.execute("truncate app_user cascade")
            cursor.execute(
                "insert into app_user (username, password_hash, role, source)"
                " values ('sso-admin', null, 'admin', 'oidc')"
            )
            cursor.execute(
                "insert into app_user (username, password_hash, role, break_glass)"
                " values ('admin', %s, 'admin', true)",
                (self.HASH,),
            )
            cursor.execute(query[1])
            self.assertEqual(cursor.fetchall(), [(self.HASH,)])
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

    def test_an_ipv6_source_is_its_prefix_and_an_account_counts_every_source(self) -> None:
        """B305 (security review S02): each address of a prefix was its own budget,
        and an account guessed at from many sources was never stopped."""

        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
            for address in ("2001:db8:1:2::a", "2001:db8:1:2::b", "2001:db8:1:3::a"):
                db.record_login_attempt(
                    connection, username="dave", client_ip=address, succeeded=False
                )
            db.record_login_attempt(
                connection, username="dave", client_ip="192.0.2.8", succeeded=False
            )
            connection.commit()

            def per_source(address: str) -> int:
                return db.failures_since_last_success(
                    connection, username="dave", client_ip=address, window_minutes=15
                )

            self.assertEqual(per_source("2001:db8:1:2::ffff"), 2)
            self.assertEqual(per_source("2001:db8:1:3::1"), 1)
            self.assertEqual(per_source("192.0.2.8"), 1)
            self.assertEqual(per_source("192.0.2.9"), 0)
            self.assertEqual(
                db.account_failures_since_last_success(
                    connection, username="Dave", window_minutes=15
                ),
                4,
            )
            db.record_login_attempt(
                connection, username="dave", client_ip="192.0.2.9", succeeded=True
            )
            connection.commit()
            self.assertEqual(
                db.account_failures_since_last_success(
                    connection, username="dave", window_minutes=15
                ),
                0,
            )

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
                "update_check": False,
            },
        )

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

    def test_the_worker_does_not_read_the_switches_and_the_poller_only_whether_one_is_on(
        self,
    ) -> None:
        # The poller asks whether the update check is on (0081, B342), and
        # nothing else: not what a switch remembers, nor who flipped it.
        for role, statement in (
            ("HAPRION_UI_TEST_WORKER_ROLE", "select enabled from feature_switch"),
            ("HAPRION_UI_TEST_POLLER_ROLE", "select remembered from feature_switch"),
            ("HAPRION_UI_TEST_POLLER_ROLE", "select updated_by from feature_switch"),
            ("HAPRION_UI_TEST_POLLER_ROLE", "update feature_switch set enabled = true"),
        ):
            with (
                self.subTest(role=role, statement=statement),
                self.assertRaises(psycopg.errors.InsufficientPrivilege),
                self.connect(role) as connection,
            ):
                connection.execute(statement)
        with self.connect("HAPRION_UI_TEST_POLLER_ROLE") as connection:
            self.assertFalse(db.switch_enabled(connection, "update_check"))


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
        #
        # Both streams, as a terminal shows them: the tests read the sentence
        # wherever it went. `apply --json` is read from stdout alone.
        #
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = self.admin.main(list(argv))
        if "--json" in argv:
            return code, out.getvalue()
        return code, out.getvalue() + err.getvalue()

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
        self.assertEqual(code, exit_codes.REFUSED)
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

    def test_off_ends_the_provider_s_sessions_and_only_those(self) -> None:
        # They lived on for up to `oidc_absolute_hours` after Off (review
        # 26-10-24, 09-05); a password account keeps its own.
        with self.web() as connection:
            db.save_oidc_provider(connection, settings=self.SETTINGS, actor="alice")
            db.record_oidc_verified(connection, revision=self.row(connection).revision)
            db.set_oidc_enabled(connection, enabled=True, actor="alice")
            db.create_oidc_account(
                connection,
                username="carol",
                role="admin",
                issuer=self.SETTINGS["issuer"],
                subject="s1",
            )
            carol = db.account_by_oidc(connection, issuer=self.SETTINGS["issuer"], subject="s1")
            alice = db.account_by_username(connection, "alice")
            if carol is None or alice is None:
                self.fail("no accounts")
            later = datetime.now(UTC) + timedelta(hours=1)
            for user, token in ((carol, "sso-1"), (carol, "sso-2"), (alice, "local")):
                db.create_session(
                    connection, token_hash=auth.token_hash(token), user_id=user.id, expires_at=later
                )
            connection.commit()

            ended = db.set_oidc_enabled(connection, enabled=False, actor="alice")
            connection.commit()

            def revoked(token: str) -> bool:
                session = db.session_by_hash(connection, auth.token_hash(token))
                if session is None:
                    self.fail(f"no session {token}")
                return session.revoked_at is not None

            self.assertEqual(ended, 2)
            self.assertEqual(
                [revoked("sso-1"), revoked("sso-2"), revoked("local")], [True, True, False]
            )
            self.assertEqual(db.set_oidc_enabled(connection, enabled=False, actor="alice"), 0)

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

    def test_0079_takes_the_setting_and_the_binding_away(self) -> None:
        """B297: no `auto_create`, no binding by the web; the revision still moves."""

        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "select count(*) from information_schema.columns "
                "where table_name = 'oidc_provider' and column_name = 'auto_create'"
            )
            self.assertEqual(_first(cursor), 0)
            cursor.execute("select revision from oidc_provider")
            before = _first(cursor)
            cursor.execute("update oidc_provider set button_text = 'Sign in elsewhere'")
            cursor.execute("select revision from oidc_provider")
            self.assertEqual(_first(cursor), before + 1)
            connection.rollback()
            cursor.execute(
                "insert into app_user (username, role, source, oidc_issuer, oidc_subject) "
                "values ('carol', 'reader', 'oidc', 'https://id.example/', 's1')"
            )
            connection.commit()
        with self.web() as connection:
            connection.execute("update app_user set role = 'admin' where username = 'carol'")
            connection.rollback()
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                connection.execute(
                    "update app_user set oidc_subject = 's2' where username = 'carol'"
                )

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
        self,
        operation: str,
        cluster: str,
        created: str,
        state: str = "done",
        result: dict[str, Any] | None = None,
        **payload: Any,
    ) -> None:
        with (
            self.connect("HAPRION_UI_TEST_MIGRATION_ROLE") as connection,
            connection.cursor() as cursor,
        ):
            cursor.execute(
                "insert into job (operation, cluster, payload, idempotency_key, state, created_at, "
                "started_at, finished_at, result) values (%(operation)s, %(cluster)s, %(payload)s, "
                "%(key)s, %(state)s, %(created)s, %(created)s, "
                "%(created)s::timestamptz + interval '4 seconds', %(result)s) "
                "returning id",
                {
                    "operation": operation,
                    "cluster": cluster,
                    "payload": json.dumps(payload),
                    "key": uuid4(),
                    "state": state,
                    "created": created,
                    "result": None if result is None else json.dumps(result),
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

    def test_a_publish_that_was_done_in_a_job_whose_deploy_was_not(self) -> None:
        # Review 26-10-13, D1: Publish & deploy ending partial has published,
        # and the deploy after it carries the exception.
        self.job(
            "changes_publish",
            "ex-c",
            "2026-10-02 15:01Z",
            state="partial",
            result={"outcome": "partial", "publish": {"outcome": "done"}},
            deploy=True,
        )
        self.job("deploy", "ex-c", "2026-10-02 15:03Z")
        made = datetime(2026, 10, 2, 15, 0, tzinfo=UTC)

        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
            found = db.deploys_carrying(connection, cluster="ex-c", moments=[made])

        self.assertEqual(found, {made: datetime(2026, 10, 2, 15, 3, 4, tzinfo=UTC)})

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
        #
        # Inside one hour, which the rollup counts by: from "now" two equal
        # matches minutes apart fell either side of an hour when the suite ran
        # just after one, and were kept as two (26-10-21).
        #
        self.now = datetime.now(UTC).replace(minute=0, second=0, microsecond=0) - timedelta(
            minutes=30
        )
        rows = (
            # (rule, field, path, client)
            (190002, "", "/api", "192.0.2.5"),
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
        # Newest first; the installation's own rule (1900xx) is a finding too.
        self.assertEqual([row.rule_id for row in findings], [942100, 190002])

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

    def test_the_objects_that_name_a_server_in_one_cluster(self) -> None:
        """26-10-18: the object page's *Also in*, read by the web role from the same rows."""

        self.write("si-a", "objects", self.objects("si-a", "shop", "api"))
        self.write("si-b", "objects", self.objects("si-b", "shop"))
        with self.connect("HAPRION_UI_TEST_WEB_ROLE") as connection:
            rows = db.backend_rows(
                connection, cluster="si-a", addresses=["198.51.100.10:8080", "192.0.2.1:80"]
            )
            nothing = db.backend_rows(connection, cluster="si-a", addresses=[])

        self.assertEqual(rows, [("198.51.100.10:8080", "shop", "/proxies/si-a/shop")])
        self.assertEqual(nothing, [])

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

    33 days of samples every 20 minutes on two nodes: a backend and a frontend
    whose every sample the trigger summed, with every raw row kept, so the facit
    is the raw readers themselves.

    Each carries a restart, a counter that goes backwards without one, an
    unknown counter and three hours with no sample, once in the older half and
    once in the last week; the frontend's address moves every three hours.
    """

    CLUSTER = "hours"
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
    migration: Any

    @classmethod
    def connect(cls, role_variable: str = "HAPRION_UI_TEST_MIGRATION_ROLE") -> psycopg.Connection:
        return psycopg.connect(f"{DSN} user={os.environ[role_variable]}")

    @classmethod
    def setUpClass(cls) -> None:
        cls.now = datetime.now(UTC).replace(microsecond=0)
        cls.start = cls.now - timedelta(days=33)
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
            cls._backend(cursor, cls.GROWN)
            cls._frontend(cursor)
            connection.commit()

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

    def test_retention_deletes_the_hours_past_the_longest_window(self) -> None:
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
        self.assertIn("interval '31 days'", expired)  # the longest window a card draws, and a day
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
                    db.record_node_events(connection, cluster=self.CLUSTER, result=result).events
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


@unittest.skipUnless(DSN, "run through ui/tools/test-database")
class TheSettingsFromAFile(unittest.TestCase):
    """`haprion-settings apply` (Fas 23, B293): External monitoring, switches, OIDC, for real."""

    PROVIDER = """oidc:
  issuer: https://auth.example/application/o/app/
  client_id: client
  client_secret: the client secret
  auth_method: client_secret_basic
  scopes: openid profile
  username_claim: preferred_username
  groups_claim: groups
  admin_group: haproxy-admins
  reader_group: null
  button_text: Sign in with SSO
  prompt_login: false
  logout_mode: app
  local_login: break_glass_only
  enabled: true
  interface_url: https://mgr.example.com
"""

    def connect(self) -> psycopg.Connection:
        return psycopg.connect(f"{DSN} user={os.environ['HAPRION_UI_TEST_MIGRATION_ROLE']}")

    def setUp(self) -> None:
        from dataclasses import replace

        from haprion.dns_profile_keys import write_key_pair

        from haprion_ui import admin, settings_apply, settings_tool
        from haprion_ui import config as ui_config
        from tests.test_login import configuration

        self.tool = settings_tool
        keys = Path(tempfile.mkdtemp(prefix="settings-keys-"))
        self.addCleanup(shutil.rmtree, keys, True)
        write_key_pair(keys / "k.key", keys / "k.pub")
        self.verified: list[str] = []

        def verify(provider: db.OidcProvider, redirect: str) -> tuple[bool, list[Any], str]:
            self.verified.append(redirect)
            return self.verify_answer, [], ""

        self.verify_answer = True
        self.reset()
        with self.connect() as connection:
            connection.execute(
                "insert into app_user (username, password_hash, role, break_glass) "
                "values ('admin', %s, 'admin', true)",
                (OidcAccounts.HASH,),
            )
            connection.commit()
        for patch in (
            mock.patch("os.geteuid", return_value=0),
            mock.patch.object(
                settings_tool,
                "load_environment",
                return_value=admin.Environment(database="test", role="test"),
            ),
            mock.patch.object(settings_tool, "connect", side_effect=lambda _e: self.connect()),
            mock.patch.object(
                ui_config,
                "load",
                return_value=replace(
                    configuration(), clusters=("alpha", "beta"), oidc_public_key=keys / "k.pub"
                ),
            ),
            mock.patch.object(settings_apply, "verify_with_helper", side_effect=verify),
            mock.patch.object(db, "cluster_list", return_value=None),
            mock.patch.dict(os.environ, {"SUDO_USER": "operator"}),
        ):
            patch.start()
            self.addCleanup(patch.stop)

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
            cursor.execute("update feature_switch set enabled = true, remembered = '{}'")
            cursor.execute("truncate status_access, app_user cascade")
            cursor.execute("delete from audit_event where detail->>'via' = 'cli'")
            connection.commit()

    def write(self, text: str, mode: int = 0o600) -> str:
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory)
        path = Path(directory) / "settings.yaml"
        path.write_text(text)
        path.chmod(mode)
        return str(path)

    def run_tool(self, *argv: str) -> tuple[int, dict[str, Any]]:
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = self.tool.main(list(argv))
        return code, json.loads(out.getvalue())

    def provider(self) -> db.OidcProvider:
        with self.connect() as connection:
            row = db.oidc_provider(connection)
        if row is None:
            raise AssertionError("no provider row")
        return row

    def cli_audit(self) -> list[str]:
        with self.connect() as connection:
            return [
                row[0]
                for row in connection.execute(
                    "select action from audit_event where detail->>'via' = 'cli' order by id"
                ).fetchall()
            ]

    def test_addresses_and_switches_once_and_the_same_file_again_changes_nothing(self) -> None:
        path = self.write(
            "status_access: [192.0.2.10, 198.51.100.0/24]\nfeatures:\n  advanced_config: false\n"
        )

        first = self.run_tool("apply", path, "--json")
        second = self.run_tool("apply", path, "--json")

        self.assertEqual((first[0], second[0]), (0, 0))
        self.assertEqual(
            first[1]["result"]["status_access"]["added"], ["192.0.2.10/32", "198.51.100.0/24"]
        )
        self.assertEqual(first[1]["result"]["features"], {"advanced_config": False})
        self.assertFalse(second[1]["result"]["changed"])
        with self.connect() as connection:
            self.assertEqual(
                connection.execute(
                    "select enabled, updated_by from feature_switch where name = 'advanced_config'"
                ).fetchone(),
                (False, "operator"),
            )
        self.assertEqual(self.cli_audit(), ["status_access_changed", "feature_switched"])

    def test_check_runs_the_refusals_and_keeps_nothing(self) -> None:
        path = self.write("status_access: [192.0.2.10]\nfeatures:\n  advanced_config: false\n")

        code, answer = self.run_tool("apply", path, "--check", "--json")

        self.assertEqual(code, 0)
        self.assertTrue(answer["result"]["changed"])
        with self.connect() as connection:
            self.assertEqual(
                connection.execute("select count(*) from status_access").fetchone(), (0,)
            )
            self.assertEqual(
                connection.execute(
                    "select enabled from feature_switch where name = 'advanced_config'"
                ).fetchone(),
                (True,),
            )
        self.assertEqual(self.cli_audit(), [])

    def test_a_switch_is_refused_as_the_page_refuses_it(self) -> None:
        with self.connect() as connection:
            connection.execute(
                "update feature_switch set enabled = false where name = 'cluster_colours'"
            )
            connection.commit()
        many = tuple(f"c{number}" for number in range(7))
        path = self.write("status_access: [192.0.2.10]\nfeatures:\n  cluster_colours: true\n")

        with mock.patch.object(db, "cluster_list", return_value=many):
            code, answer = self.run_tool("apply", path, "--json")

        self.assertEqual(code, 65)
        self.assertIn("Cluster colours cover", answer["error"]["message"])
        with self.connect() as connection:
            self.assertEqual(
                connection.execute("select count(*) from status_access").fetchone(), (0,)
            )

    def test_sign_in_through_a_provider_is_set_verified_and_turned_on_once(self) -> None:
        path = self.write(self.PROVIDER)

        first = self.run_tool("apply", path, "--json")
        second = self.run_tool("apply", path, "--json")

        self.assertEqual((first[0], second[0]), (0, 0), (first, second))
        self.assertEqual(first[1]["result"]["oidc"]["enabled"], True)
        self.assertEqual(first[1]["result"]["oidc"]["sealing"], "replaced")
        self.assertEqual(
            second[1]["result"]["oidc"], {"fields": [], "enabled": None, "sealing": "kept"}
        )
        self.assertFalse(second[1]["result"]["changed"])
        self.assertEqual(self.verified, ["https://mgr.example.com/login/oidc/callback"])
        provider = self.provider()
        self.assertTrue(provider.enabled and provider.verified)
        self.assertEqual(self.cli_audit(), ["oidc_configured", "oidc_verified", "oidc_enabled"])

    def test_a_secret_is_replaced_only_when_asked_and_verified_first_while_on(self) -> None:
        path = self.write(self.PROVIDER)
        self.run_tool("apply", path, "--json")
        before = self.provider()

        code, answer = self.run_tool("apply", path, "--json", "--replace-oidc-secret")

        self.assertEqual(code, 0)
        self.assertEqual(answer["result"]["oidc"]["fields"], ["client_secret"])
        after = self.provider()
        self.assertNotEqual(before.client_secret_sealed, after.client_secret_sealed)
        self.assertTrue(after.enabled and after.verified)
        self.assertEqual(len(self.verified), 2)

    def test_a_provider_that_fails_verify_stays_off_with_its_settings_saved(self) -> None:
        self.verify_answer = False

        code, answer = self.run_tool("apply", self.write(self.PROVIDER), "--json")

        self.assertEqual(code, 65)
        self.assertIn("stays off", answer["error"]["message"])
        provider = self.provider()
        self.assertEqual((provider.enabled, provider.client_id), (False, "client"))

    def test_a_secret_others_may_read_is_refused(self) -> None:
        code, answer = self.run_tool("apply", self.write(self.PROVIDER, mode=0o644), "--json")

        self.assertEqual(code, 65)
        self.assertIn("0600", answer["error"]["message"])
        self.assertIsNone(self.provider().issuer)

    def test_node_backups_on_waits_for_the_schedules_it_starts_again(self) -> None:
        schedule: dict[str, Any] = {
            "time": "03:30",
            "frequency": "daily",
            "weekdays": [],
            "day_of_month": None,
            "retention": 14,
        }
        with self.connect() as connection:
            connection.execute(
                "update feature_switch set enabled = false, remembered = %s "
                " where name = 'node_backups'",
                (Jsonb({"schedules": {"alpha": schedule}}),),
            )
            connection.commit()
        waited: list[str] = []

        def worker(_seconds: float) -> None:
            with self.connect() as connection:
                waited.extend(
                    row[0]
                    for row in connection.execute(
                        "update job set state = 'done', outcome = 'done', exit_code = 0, "
                        "       finished_at = now() "
                        " where state = 'pending' and operation = 'backup_schedule' "
                        "returning cluster"
                    ).fetchall()
                )
                connection.commit()

        args = self.tool.build_parser().parse_args(
            ["apply", self.write("features:\n  node_backups: true\n"), "--json"]
        )
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = self.tool.command_apply(args, sleep=worker)

        self.assertEqual(code, 0, out.getvalue())
        self.assertEqual(waited, ["alpha"])

    def test_settings_saved_whose_schedule_job_failed_are_partial(self) -> None:
        """1B-3: written, then a refusal "before anything was changed"."""

        schedule: dict[str, Any] = {
            "time": "03:30",
            "frequency": "daily",
            "weekdays": [],
            "day_of_month": None,
            "retention": 14,
        }
        with self.connect() as connection:
            connection.execute(
                "update feature_switch set enabled = false, remembered = %s "
                " where name = 'node_backups'",
                (Jsonb({"schedules": {"alpha": schedule}}),),
            )
            connection.commit()

        def worker(_seconds: float) -> None:
            with self.connect() as connection:
                connection.execute(
                    "update job set state = 'failed', outcome = 'failed', exit_code = 1, "
                    "       finished_at = now(), stderr_excerpt = 'the timer would not start' "
                    " where state = 'pending' and operation = 'backup_schedule'"
                )
                connection.commit()

        args = self.tool.build_parser().parse_args(
            ["apply", self.write("features:\n  node_backups: true\n"), "--json"]
        )
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = self.tool.command_apply(args, sleep=worker)
        answer = json.loads(out.getvalue())

        self.assertEqual((code, answer["outcome"]), (exit_codes.PARTIAL, "partial"))
        self.assertEqual(answer["result"]["features"], {"node_backups": True})
        self.assertEqual(answer["warnings"][0]["code"], "job_not_done")
        with self.connect() as connection:
            self.assertEqual(
                connection.execute(
                    "select enabled from feature_switch where name = 'node_backups'"
                ).fetchone(),
                (True,),
            )
            connection.execute("delete from job where operation = 'backup_schedule'")
            connection.commit()
        with self.connect() as connection:
            self.assertEqual(
                connection.execute(
                    "select count(*) from job where operation = 'backup_schedule' "
                    "   and state = 'pending'"
                ).fetchone(),
                (0,),
            )
            connection.execute("delete from job where operation = 'backup_schedule'")
            connection.commit()


@unittest.skipUnless(DSN, "run through ui/tools/test-database")
class TheProfilesFromAFile(unittest.TestCase):
    """`haprion-profiles` (Fas 23, B293): rows and jobs as the web writes them, for real.

    The worker is played by the wait: each time the command waits for a job,
    the pending one is finished as the worker would leave it - `done`, and for
    a removal the row gone.
    """

    FILE = """dns_profiles:
  - id: cf-main
    provider: cloudflare
    fields: {api_token: the token}
ndes_profiles:
  - id: corp-ca
    endpoint: https://ndes.example.com/certsrv/mscep/mscep.dll
    challenge: the challenge
"""

    def connect(self) -> psycopg.Connection:
        return psycopg.connect(f"{DSN} user={os.environ['HAPRION_UI_TEST_MIGRATION_ROLE']}")

    def setUp(self) -> None:
        from dataclasses import replace

        from haprion.dns_profile_keys import write_key_pair

        from haprion_ui import admin, profile_apply
        from haprion_ui import config as ui_config
        from tests.test_login import configuration

        self.tool = profile_apply
        keys = Path(tempfile.mkdtemp(prefix="profile-keys-"))
        self.addCleanup(shutil.rmtree, keys, True)
        write_key_pair(keys / "k.key", keys / "k.pub")
        self.worker_result = "done"
        self.reset()
        for patch in (
            mock.patch("os.geteuid", return_value=0),
            mock.patch.object(
                profile_apply,
                "load_environment",
                return_value=admin.Environment(database="test", role="test"),
            ),
            mock.patch.object(profile_apply, "connect", side_effect=lambda _e: self.connect()),
            mock.patch.object(
                profile_apply,
                "confirmed_servers",
                return_value=[
                    "https://ndes.example.com/certsrv/mscep/mscep.dll",
                    "https://ca.example.com/certsrv/mscep/mscep.dll",
                ],
            ),
            mock.patch.object(
                ui_config,
                "load",
                return_value=replace(configuration(), dns_profiles_public_key=keys / "k.pub"),
            ),
            mock.patch.dict(os.environ, {"SUDO_USER": "operator"}),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def tearDown(self) -> None:
        self.reset()

    def reset(self) -> None:
        with self.connect() as connection:
            connection.execute("delete from job where operation like '%%_profile_apply'")
            connection.execute("truncate dns_provider_profile, ndes_provider_profile")
            connection.execute("delete from audit_event where detail->>'via' = 'cli'")
            connection.commit()

    def work(self, _seconds: float) -> None:
        with self.connect() as connection:
            for operation, payload in connection.execute(
                "select operation, payload from job where state = 'pending'"
            ).fetchall():
                if payload.get("remove") and self.worker_result == "done":
                    table = operation.removesuffix("_apply").replace(
                        "_profile", "_provider_profile"
                    )
                    connection.execute(
                        f"delete from {table} where id = %s",  # noqa: S608 - our own names
                        (payload["profile"],),
                    )
            connection.execute(
                "update job set state = %s, outcome = %s, exit_code = 0, "
                "       finished_at = now(), stderr_excerpt = 'the helper refused' "
                " where state = 'pending'",
                (self.worker_result, self.worker_result),
            )
            connection.commit()

    def write(self, text: str, mode: int = 0o600) -> str:
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory)
        path = Path(directory) / "profiles.yaml"
        path.write_text(text)
        path.chmod(mode)
        return str(path)

    def apply(self, path: str, *extra: str) -> tuple[int, dict[str, Any]]:
        args = self.tool.build_parser().parse_args(["apply", path, "--json", *extra])
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = self.tool.command_apply(args, sleep=self.work)
        return code, json.loads(out.getvalue())

    def stored(self) -> list[tuple[str, str, int]]:
        with self.connect() as connection:
            return [
                (row[0], row[1], row[2])
                for row in connection.execute(
                    "select 'dns', id, revision from dns_provider_profile "
                    "union all select 'ndes', id, revision from ndes_provider_profile order by 1, 2"
                ).fetchall()
            ]

    def test_a_file_creates_and_the_same_file_again_changes_nothing(self) -> None:
        path = self.write(self.FILE)

        first = self.apply(path)
        second = self.apply(path)

        self.assertEqual((first[0], second[0]), (0, 0), (first, second))
        self.assertEqual(
            [(job["kind"], job["state"]) for job in first[1]["result"]["jobs"]],
            [("dns", "done"), ("ndes", "done")],
        )
        self.assertFalse(second[1]["result"]["changed"])
        self.assertEqual(second[1]["result"]["unchanged"], ["dns/cf-main", "ndes/corp-ca"])
        self.assertEqual(self.stored(), [("dns", "cf-main", 1), ("ndes", "corp-ca", 1)])

    def test_replace_and_a_moved_endpoint_store_a_new_revision(self) -> None:
        path = self.write(self.FILE)
        self.apply(path)
        moved = self.write(self.FILE.replace("ndes.example.com", "ca.example.com"))

        code, answer = self.apply(moved, "--replace", "cf-main")

        self.assertEqual(code, 0)
        self.assertEqual(
            [(c["profile"], c["action"]) for c in answer["result"]["changes"]],
            [("cf-main", "replace"), ("corp-ca", "replace")],
        )
        self.assertEqual(self.stored(), [("dns", "cf-main", 2), ("ndes", "corp-ca", 2)])

    def test_prune_and_remove_take_profiles_away_through_the_job(self) -> None:
        self.apply(self.write(self.FILE))

        code, answer = self.apply(self.write("ndes_profiles: []\n"), "--prune")
        args = self.tool.build_parser().parse_args(["remove", "dns", "cf-main", "--json"])
        first, second = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(first):
            removed = self.tool.command_remove(args, sleep=self.work)
        with contextlib.redirect_stdout(second):
            again = self.tool.command_remove(args, sleep=self.work)

        self.assertEqual((code, removed, again), (0, 0, 0))
        self.assertTrue(json.loads(first.getvalue())["result"]["changed"])
        self.assertFalse(json.loads(second.getvalue())["result"]["changed"])
        self.assertEqual(answer["result"]["changes"][0]["action"], "remove")
        self.assertEqual(self.stored(), [])

    def test_a_job_that_does_not_apply_stops_the_run_and_says_why(self) -> None:
        self.worker_result = "failed"

        code, answer = self.apply(self.write(self.FILE))

        #
        # The job ran and failed: not "refused before anything was changed"
        # (review 2026-10-22, 1B-3), and the job it ran is in the answer.
        #
        self.assertEqual((code, answer["outcome"]), (exit_codes.FAILED, "failed"))
        self.assertEqual(answer["error"]["code"], "job_not_done")
        self.assertIn("the helper refused", answer["error"]["message"])
        self.assertEqual([job["state"] for job in answer["result"]["jobs"]], ["failed"])
        with self.connect() as connection:
            self.assertEqual(
                connection.execute(
                    "select count(*) from job where operation like '%%_profile_apply'"
                ).fetchone(),
                (1,),
            )

    def test_a_run_that_stops_after_a_profile_applied_is_partial(self) -> None:
        """1B-3: the first profile was applied, and the answer was a refusal with no result."""

        ended = iter(["done", "failed"])
        played = self.work

        def work(seconds: float) -> None:
            self.worker_result = next(ended)
            played(seconds)

        self.work = work  # type: ignore[method-assign, assignment]

        code, answer = self.apply(self.write(self.FILE))

        self.assertEqual((code, answer["outcome"]), (exit_codes.PARTIAL, "partial"))
        self.assertEqual(
            [(job["kind"], job["state"]) for job in answer["result"]["jobs"]],
            [("dns", "done"), ("ndes", "failed")],
        )
        self.assertEqual(answer["warnings"][0]["code"], "job_not_done")

    def test_another_provider_and_credentials_others_may_read_are_refused(self) -> None:
        self.apply(self.write(self.FILE))

        moved = self.apply(
            self.write(self.FILE.replace("provider: cloudflare", "provider: route53"))
        )
        loose = self.apply(self.write(self.FILE, mode=0o644))

        self.assertIn("keeps its provider", moved[1]["error"]["message"])
        self.assertIn("0600", loose[1]["error"]["message"])
        self.assertEqual(self.stored(), [("dns", "cf-main", 1), ("ndes", "corp-ca", 1)])


@unittest.skipUnless(DSN, "run through ui/tools/test-database")
class TheExportAppliesUnchanged(unittest.TestCase):
    """`haprion-export` (Fas 23, B293): its files, applied where they came from, change nothing.

    The interface's three files against the real schema, through each apply
    command's `main`; the clusters' files are held against their readers in
    `test_export_tool`.
    """

    def connect(self) -> psycopg.Connection:
        return psycopg.connect(f"{DSN} user={os.environ['HAPRION_UI_TEST_MIGRATION_ROLE']}")

    def setUp(self) -> None:
        from dataclasses import replace

        from haprion.dns_profile_keys import write_key_pair

        from haprion_ui import (
            admin,
            export_tool,
            profile_apply,
            settings_apply,
            settings_tool,
        )
        from haprion_ui import config as ui_config
        from tests.test_login import configuration

        self.admin, self.export_tool = admin, export_tool
        self.settings_tool, self.profile_apply = settings_tool, profile_apply
        self.directory = Path(tempfile.mkdtemp(prefix="export-"))
        self.addCleanup(shutil.rmtree, self.directory, True)
        keys = self.directory / "keys"
        keys.mkdir()
        write_key_pair(keys / "k.key", keys / "k.pub")
        self.reset()
        environment = admin.Environment(database="test", role="test")
        patches: list[Any] = [
            mock.patch.object(module, name, **how)
            for module in (admin, settings_tool, profile_apply, export_tool)
            for name, how in (
                ("load_environment", {"return_value": environment}),
                ("connect", {"side_effect": lambda _e: self.connect()}),
            )
        ]
        patches += [
            mock.patch("os.geteuid", return_value=0),
            mock.patch.object(
                ui_config,
                "load",
                return_value=replace(
                    configuration(),
                    clusters=("alpha",),
                    oidc_public_key=keys / "k.pub",
                    dns_profiles_public_key=keys / "k.pub",
                ),
            ),
            mock.patch.object(settings_apply, "verify_with_helper", return_value=(True, [], "")),
            mock.patch.object(db, "cluster_list", return_value=None),
            mock.patch.object(
                profile_apply,
                "confirmed_servers",
                return_value=["https://ndes.example.com/certsrv/mscep/mscep.dll"],
            ),
            mock.patch.dict(os.environ, {"SUDO_USER": "operator"}),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

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
            cursor.execute("update feature_switch set enabled = true, remembered = '{}'")
            cursor.execute("truncate status_access, app_user cascade")
            cursor.execute("delete from job where operation like '%%_profile_apply'")
            cursor.execute("truncate dns_provider_profile, ndes_provider_profile")
            cursor.execute("delete from audit_event where detail->>'via' = 'cli'")
            connection.commit()

    def write(self, name: str, text: str) -> str:
        path = self.directory / name
        path.write_text(text)
        path.chmod(0o600)
        return str(path)

    def run_main(self, module: Any, *argv: str) -> dict[str, Any]:
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = module.main(list(argv))
        answer: dict[str, Any] = json.loads(out.getvalue())
        self.assertEqual(code, 0, answer)
        return answer

    def apply_profiles(self, path: str) -> dict[str, Any]:
        args = self.profile_apply.build_parser().parse_args(["apply", path, "--json"])
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = self.profile_apply.command_apply(args, sleep=self.work)
        answer: dict[str, Any] = json.loads(out.getvalue())
        self.assertEqual(code, 0, answer)
        return answer

    def work(self, _seconds: float) -> None:
        """The worker, as `TheProfilesFromAFile` plays it: every pending job done."""

        with self.connect() as connection:
            connection.execute(
                "update job set state = 'done', outcome = 'done', exit_code = 0, "
                "       finished_at = now() where state = 'pending'"
            )
            connection.commit()

    @staticmethod
    def read_engine(argv: Any) -> dict[str, Any]:
        readings: dict[str, dict[str, Any]] = {
            "haprion-objects": {"objects": []},
            "haprion-network": {"origin": "cluster_file", "document": None},
            "haprion-cluster-settings": {
                "log_targets": [],
                "not_logged_from": [],
                "metrics": None,
                "peers": None,
            },
            "haprion-list-backups": {"schedule": None},
        }
        return readings[argv[0]]

    def test_accounts_settings_and_profiles_come_back_as_they_were_set(self) -> None:
        self.run_main(
            self.admin,
            "apply",
            self.write(
                "accounts-in.yaml",
                "accounts:\n"
                "  - {username: admin, role: admin, break_glass: true, password: admin password}\n"
                "  - {username: viewer, role: reader, disabled: true, password: viewer password}\n",
            ),
            "--json",
        )
        with self.connect() as connection:
            connection.execute(
                "insert into app_user (username, role, source) values ('sso-person', 'reader', 'oidc')"
            )
            connection.commit()
        self.run_main(
            self.settings_tool,
            "apply",
            self.write(
                "settings-in.yaml",
                TheSettingsFromAFile.PROVIDER
                + "status_access: [192.0.2.10, 198.51.100.0/24]\n"
                + "features:\n  advanced_config: false\n",
            ),
            "--json",
        )
        self.apply_profiles(self.write("profiles-in.yaml", TheProfilesFromAFile.FILE))
        with self.connect() as connection:
            sealed = connection.execute("select client_secret_sealed from oidc_provider").fetchone()

        target = self.directory / "export"
        args = self.export_tool.build_parser().parse_args([str(target), "--json"])
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = self.export_tool.command_export(args, read=self.read_engine)
        self.assertEqual(code, 0, out.getvalue())

        accounts = self.run_main(
            self.admin, "apply", str(target / "accounts.yaml"), "--prune", "--json"
        )
        settings = self.run_main(
            self.settings_tool, "apply", str(target / "settings.yaml"), "--json"
        )
        profiles = self.apply_profiles(str(target / "profiles.yaml"))

        self.assertFalse(accounts["result"]["changed"], accounts)
        self.assertFalse(settings["result"]["changed"], settings)
        self.assertFalse(profiles["result"]["changed"], profiles)
        with self.connect() as connection:
            self.assertEqual(
                connection.execute("select client_secret_sealed from oidc_provider").fetchone(),
                sealed,
            )
        written = (target / "settings.yaml").read_text() + (target / "profiles.yaml").read_text()
        for secret in ("the client secret", "the token", "the challenge"):
            self.assertNotIn(secret, written)
        exported = (target / "accounts.yaml").read_text()
        self.assertNotIn("password", exported)
        self.assertNotIn("sso-person", exported)
        self.assertIn("viewer", exported)


@unittest.skipUnless(DSN, "run through ui/tools/test-database")
class AcknowledgedAttention(unittest.TestCase):
    """0073 (B299): the web acknowledges a row once, reads it back and forgets it."""

    def connect(self, role: str = "HAPRION_UI_TEST_WEB_ROLE") -> psycopg.Connection:
        return psycopg.connect(f"{DSN} user={os.environ[role]}")

    def tearDown(self) -> None:
        with self.connect("HAPRION_UI_TEST_MIGRATION_ROLE") as connection:
            connection.execute("truncate attention_ack")
            connection.commit()

    def test_once_read_back_and_forgotten(self) -> None:
        job = ("job", "alpha", "job 7")
        node = ("node", "", "node-b")
        with self.connect() as connection:
            self.assertTrue(db.acknowledge_attention(connection, job, actor="operator"))
            self.assertFalse(db.acknowledge_attention(connection, job, actor="other"))
            self.assertTrue(db.acknowledge_attention(connection, node, actor="operator"))
            self.assertEqual(db.attention_acks(connection), {job, node})
            db.forget_attention_acks(connection, {node})
            self.assertEqual(db.attention_acks(connection), {job})
            connection.commit()
            by = connection.execute("select acknowledged_by from attention_ack").fetchone()
        self.assertEqual(by, ("operator",))

    def test_the_web_cannot_rewrite_who_acknowledged(self) -> None:
        with self.connect() as connection:
            db.acknowledge_attention(connection, ("job", "alpha", "job 7"), actor="operator")
            connection.commit()
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                connection.execute("update attention_ack set acknowledged_by = 'x'")


@unittest.skipUnless(DSN, "run through ui/tools/test-database")
class GettingStartedHidden(unittest.TestCase):
    """0075 (B316): the web hides the list once; 0076 lets it show it again."""

    def connect(self, role: str = "HAPRION_UI_TEST_WEB_ROLE") -> psycopg.Connection:
        return psycopg.connect(f"{DSN} user={os.environ[role]}")

    def tearDown(self) -> None:
        with self.connect("HAPRION_UI_TEST_MIGRATION_ROLE") as connection:
            connection.execute("truncate getting_started")
            connection.commit()

    def test_hidden_once_and_for_good(self) -> None:
        with self.connect() as connection:
            self.assertIsNone(db.getting_started_hidden_at(connection))
            self.assertTrue(db.hide_getting_started(connection, actor="operator"))
            self.assertFalse(db.hide_getting_started(connection, actor="other"))
            self.assertIsNotNone(db.getting_started_hidden_at(connection))
            connection.commit()
            by = connection.execute("select hidden_by from getting_started").fetchall()
        self.assertEqual(by, [("operator",)])
        with self.connect() as connection, self.assertRaises(psycopg.errors.InsufficientPrivilege):
            connection.execute("update getting_started set hidden_at = now()")

    def test_shown_again_and_hidden_anew(self) -> None:
        with self.connect() as connection:
            self.assertFalse(db.show_getting_started(connection))
            db.hide_getting_started(connection, actor="operator")
            self.assertTrue(db.show_getting_started(connection))
            self.assertIsNone(db.getting_started_hidden_at(connection))
            self.assertTrue(db.hide_getting_started(connection, actor="other"))
            connection.commit()
            by = connection.execute("select hidden_by from getting_started").fetchall()
        self.assertEqual(by, [("other",)])


@unittest.skipUnless(DSN, "run through ui/tools/test-database")
class TheTrafficLogPageReadsWhatPostgresqlMatches(unittest.TestCase):
    """The traffic log's filters, held to the server that evaluates them (review 2026-10-22, 1B-8).

    They were proven against a file reader that matched in Python, across eleven
    fields, while the page asks PostgreSQL and its index three. Each case here
    is a row set of its own cluster in the shared database, asked as the web
    role asks it.
    """

    def setUp(self) -> None:
        self.cluster = f"search-{uuid4().hex[:8]}"
        # Noon of today: a minute either side is still today's partition.
        self.now = datetime.now(UTC).replace(hour=12, minute=0, second=0, microsecond=0)
        self.directory = Path(tempfile.mkdtemp(prefix="traffic-"))
        self.addCleanup(shutil.rmtree, self.directory, True)
        with psycopg.connect(f"{DSN} user={os.environ['HAPRION_UI_TEST_MIGRATION_ROLE']}") as c:
            c.execute("select traffic_log_partition(%s::date)", (self.now.date(),))
        self.request = 0

    def store(self, **fields: Any) -> None:
        self.request += 1
        row = {
            "occurred_at": self.now,
            "request_number": self.request,
            "client": "192.0.2.10",
            "method": "GET",
            "host": "app.example.com",
            "path": "/index.html",
            "frontend": "fe-https",
            "backend": "be-app",
            "server": "srv1",
            "status": 200,
            "rule": "",
        } | fields
        with psycopg.connect(f"{DSN} user={os.environ['HAPRION_UI_TEST_COLLECTOR_ROLE']}") as c:
            c.execute(
                "insert into traffic_log (event_id, cluster, node, occurred_at, request_number,"
                " client, method, host, path, frontend, backend, server, status, request_time,"
                " queue_time, connect_time, response_time, total_time, bytes, rule)"
                " values (%s, %s, 'node-a', %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,"
                " 0, 0, 0, 0, 0, 0, %s)",
                (
                    uuid4().bytes * 2,
                    self.cluster,
                    row["occurred_at"],
                    row["request_number"],
                    row["client"],
                    row["method"],
                    row["host"],
                    row["path"],
                    row["frontend"],
                    row["backend"],
                    row["server"],
                    row["status"],
                    row["rule"],
                ),
            )

    def read(self, **filters: Any) -> traffic_logs.Reading:
        with psycopg.connect(f"{DSN} user={os.environ['HAPRION_UI_TEST_WEB_ROLE']}") as c:
            return traffic_logs.read_database(c, self.directory, (self.cluster,), **filters)

    def paths(self, **filters: Any) -> list[str]:
        return [entry.path for entry in self.read(**filters).entries]

    def test_newest_first_and_a_busy_second_by_the_request_counter(self) -> None:
        self.store(path="/old", occurred_at=self.now - timedelta(seconds=5))
        self.store(path="/seventh", request_number=7)
        self.store(path="/ninth", request_number=9)
        self.store(path="/eighth", request_number=8)

        self.assertEqual(self.paths(), ["/ninth", "/eighth", "/seventh", "/old"])

    def test_status_narrows_by_code_or_class_and_nothing_else_is_a_status(self) -> None:
        self.store(path="/ok")
        self.store(path="/down", status=503)

        self.assertEqual(self.paths(status="5xx"), ["/down"])
        self.assertEqual(self.paths(status="503"), ["/down"])
        self.assertEqual(self.paths(status="99"), [])

    def test_search_is_the_host_the_path_and_the_backend_whatever_their_case(self) -> None:
        self.store(path="/ok", host="Shop.Example.com", backend="be-other")
        self.store(path="/elsewhere")

        self.assertEqual(self.paths(substring="be-other"), ["/ok"])
        self.assertEqual(self.paths(substring="/OK"), ["/ok"])
        self.assertEqual(self.paths(substring="shop.example"), ["/ok"])
        # Not a client, a method or a status: the three the index holds.
        self.assertEqual(self.paths(substring="192.0.2.10"), [])

    def test_terms_combine_with_case_insensitive_boolean_operators(self) -> None:
        self.store(path="/api/orders", backend="be-orders")
        self.store(path="/api/health", backend="be-orders")
        self.store(path="/login", backend="be-login")

        self.assertEqual(
            self.paths(substring="be-orders aNd (/orders OR /missing) AND not /health"),
            ["/api/orders"],
        )

    def test_adjacent_terms_are_an_implicit_and_and_quotes_keep_a_phrase(self) -> None:
        self.store(host="first.example.com", path="/rock and roll")
        self.store(host="second.example.com", path="/rock")

        self.assertEqual(self.paths(substring="first rock"), ["/rock and roll"])
        self.assertEqual(self.paths(substring='"rock and roll"'), ["/rock and roll"])

    def test_time_bounds_are_inclusive(self) -> None:
        self.store(path="/before", occurred_at=self.now - timedelta(seconds=60))
        self.store(path="/inside")
        self.store(path="/after", occurred_at=self.now + timedelta(seconds=60))

        self.assertEqual(self.paths(from_at=self.now, to_at=self.now), ["/inside"])

    def test_the_limit_keeps_the_newest(self) -> None:
        for number in range(12):
            self.store(path=f"/{number}", request_number=number)

        self.assertEqual(self.paths(limit=5), ["/11", "/10", "/9", "/8", "/7"])

    def test_a_cluster_not_among_those_listed_reads_nothing(self) -> None:
        self.store()
        with psycopg.connect(f"{DSN} user={os.environ['HAPRION_UI_TEST_WEB_ROLE']}") as c:
            elsewhere = traffic_logs.read_database(
                c, self.directory, ("alpha",), cluster=self.cluster
            )
            unlisted = traffic_logs.read_database(c, self.directory, ("alpha",))
        self.assertEqual(elsewhere.entries, ())
        self.assertNotIn(self.cluster, {entry.cluster for entry in unlisted.entries})

    def test_a_subdomain_is_one_label_under_it_less_the_names_it_yields(self) -> None:
        for host in (
            "Shop.Apps.Example.com:80",
            "grafana.apps.example.com",
            "a.b.apps.example.com",
            "apps.example.com",
        ):
            self.store(host=host, backend="fe-https", path="/" + host)

        owned = ((), ("*.apps.example.com", "!grafana.apps.example.com"))
        self.assertEqual(self.paths(owned=owned), ["/Shop.Apps.Example.com:80"])


@unittest.skipUnless(DSN, "run through ui/tools/test-database")
class ADumpFromBeforeTheHead(unittest.TestCase):
    """Review 26-10-29, A1/B1: a dump from before 0102 stopped `restore` on 03-verify.

    `haprion-backup restore` itself, stubbed only where it reaches the machine:
    the units, sudo, the release on disk, and `migrate` and `03-verify`, which
    run alembic and 03-verify's own grant list against a database of their own.
    """

    NAME = "haprion_restore_check_a1"
    REPOSITORY = Path(__file__).resolve().parents[2]
    GRANTS = (
        "select grantee, table_name, privilege_type,"
        "       string_agg(column_name, ', ' order by column_name)"
        "  from information_schema.column_privileges"
        " where table_schema = 'public' and grantee like 'app\\_%'"
        " group by grantee, table_name, privilege_type"
        " order by grantee, table_name, privilege_type"
    )

    def setUp(self) -> None:
        self.bindir = os.environ["HAPRION_UI_TEST_PG_BINDIR"]
        self.socket = os.environ["HAPRION_UI_TEST_DATABASE_SOCKET"]
        self.role = os.environ["HAPRION_UI_TEST_MIGRATION_ROLE"]
        self.directory = Path(tempfile.mkdtemp(prefix="restore-"))
        self.addCleanup(shutil.rmtree, self.directory)
        self.superuser(f'drop database if exists "{self.NAME}"')
        self.superuser(f'create database "{self.NAME}" owner "{self.role}"')
        self.addCleanup(self.superuser, f'drop database if exists "{self.NAME}" with (force)')
        with psycopg.connect(f"dbname={self.NAME} host={self.socket}", autocommit=True) as c:
            c.execute("create extension pg_trgm")
        verify = (self.REPOSITORY / "install/platform/03-verify").read_text()
        listed = re.search(r"^expected_grants=\$\(cat <<'EOF'\n(.*?)^EOF$", verify, re.M | re.S)
        if listed is None:
            self.fail("03-verify no longer lists its grants in the shape this reads")
        self.expected = listed.group(1).strip()

    def superuser(self, statement: str) -> None:
        with psycopg.connect(DSN, autocommit=True) as connection:
            connection.execute(statement)

    def alembic(self, *arguments: str) -> None:
        subprocess.run(  # noqa: S603 - this environment's alembic, fixed arguments
            [sys.executable, "-m", "alembic", *arguments],
            cwd=self.REPOSITORY / "ui",
            env={
                **os.environ,
                "HAPRION_UI_DATABASE_URL": (
                    f"postgresql+psycopg://{self.role}@/{self.NAME}?host={self.socket}"
                ),
            },
            check=True,
            capture_output=True,
        )

    def scratch(self) -> psycopg.Connection:
        return psycopg.connect(f"dbname={self.NAME} host={self.socket} user={self.role}")

    def granted(self) -> str:
        with self.scratch() as connection, connection.cursor() as cursor:
            cursor.execute(self.GRANTS)
            return "\n".join("\t".join(row) for row in cursor.fetchall())

    def step(self, name: str, body: str) -> None:
        path = self.directory / "steps" / name
        path.parent.mkdir(exist_ok=True)
        path.write_text(f"#!/bin/bash\nset -e\n{body}")
        path.chmod(0o755)

    def restore(self, dump: Path) -> subprocess.CompletedProcess[str]:
        source = (self.REPOSITORY / "install/platform/bin/haprion-backup").read_text()

        def function(name: str) -> str:
            found = re.search(rf"^{name}\(\) \{{\n.*?^\}}\n", source, re.M | re.S)
            if found is None:
                self.fail(f"haprion-backup has no {name}")
            return found.group(0)

        units = re.search(r"^RESTORE_UNITS=\(\n.*?^\)\n", source, re.M | re.S)
        if units is None:
            self.fail("haprion-backup has no RESTORE_UNITS")
        root = self.directory / "platform"
        site = root / "releases/new/venv/lib/python3/site-packages"
        (site / "haprion_ui").mkdir(parents=True)
        shutil.copy(self.REPOSITORY / "ui/src/haprion_ui/compatibility.json", site / "haprion_ui")
        (site / "haprion_ui-0.1.0.dist-info").mkdir()
        (site / "haprion_ui-0.1.0.dist-info/entry_points.txt").write_text(
            "[console_scripts]\nhaprion-worker = haprion_ui.worker:_entry\n"
        )
        (root / "current").symlink_to(root / "releases/new")
        expected = self.directory / "expected-grants"
        expected.write_text(self.expected)
        self.step(
            "migrate",
            f'echo "migrate $*"\ncd {self.REPOSITORY / "ui"}\nexport HAPRION_UI_DATABASE_URL='
            f"postgresql+psycopg://{self.role}@/{self.NAME}?host={self.socket}\n"
            f"exec {sys.executable} -m alembic upgrade head\n",
        )
        self.step(
            "03-verify",
            f'actual="$(psql -U {self.role} -d {self.NAME} -qtAX -F "$(printf "\\t")" '
            f'-c "{self.GRANTS}")"\n'
            f'[[ "$actual" == "$(cat {expected})" ]] || {{ echo "grants differ" >&2; exit 1; }}\n',
        )
        program = (
            "set -Eeuo pipefail\n"
            'log() { echo "$*"; }; warn() { echo "WARNING: $*" >&2; }; step_log() { :; }\n'
            'die() { echo "ERROR: $*" >&2; exit 1; }\n'
            # Nothing runs, and the dump is opened by this account, not by postgres.
            'systemctl() { [[ "$1" != is-active ]] || return 1; }\n'
            'sudo() { shift 2; "$@"; }\n'
            f"schema_plan() {{ {sys.executable} -m haprion_ui.restore_schema --platform-root {root}"
            ' --packaged new --revision "$1"; }\n'
            f"DB_NAME={self.NAME}\nDB_ROLE={self.role}\n"
            + "".join(
                re.search(rf"^{name}\(\) .*\n", source, re.M).group(0)  # type: ignore[union-attr]
                for name in ("counted", "psql_as", "psql_scratch")
            )
            + units.group(0)
            + f"RESTORE_STOPPED={self.directory / 'restore-stopped'}\n"
            f"PLATFORM_STEPS={self.directory / 'steps'}\n"
            f"COLLECTOR_CONFIG={self.directory / 'none'}\nCOLLECTOR_COMMAND=/bin/false\n"
            f"RETENTION_COMMAND=/bin/false\nRETENTION_TIMER={self.directory / 'none'}\n"
            + "".join(
                function(name)
                for name in (
                    "dump_revision",
                    "do_after_restore",
                    "stopped_before",
                    "remember_stopped",
                    "restore_stopped",
                    "do_restore",
                    "start_units",
                )
            )
            + 'do_restore "$1"\n'
        )
        return subprocess.run(  # noqa: S603 - fixed program
            ["/bin/bash", "-c", program, "bash", str(dump)],
            capture_output=True,
            text=True,
            check=False,
            env={
                **os.environ,
                "PATH": f"{self.bindir}:{os.environ['PATH']}",
                "PGHOST": self.socket,
            },
        )

    def test_a_dump_at_0101_restored_under_the_head_is_migrated_proved_and_held(self) -> None:
        self.alembic("upgrade", "0101")
        with self.scratch() as connection:
            connection.execute(
                "insert into job (operation, cluster, payload, idempotency_key)"
                " values ('deploy', 'alpha', '{}', %s)",
                (uuid4(),),
            )
            connection.commit()
        self.assertNotEqual(self.granted(), self.expected, "0101 already grants what 0102 does")
        dump = self.directory / "before-0102.dump"
        subprocess.run(  # noqa: S603 - this cluster's pg_dump, fixed arguments
            [f"{self.bindir}/pg_dump", "-h", self.socket, "-U", self.role, "-d", self.NAME,
             "--format=custom", f"--file={dump}"],
            check=True,
        )  # fmt: skip
        self.alembic("upgrade", "head")
        self.assertEqual(self.granted(), self.expected)

        done = self.restore(dump)

        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        head = json.loads((self.REPOSITORY / "ui/src/haprion_ui/compatibility.json").read_text())
        head = head["requires"]["database_head"]
        self.assertIn(f"the dump is at 0101; migrated to {head}", done.stdout)
        self.assertEqual(self.granted(), self.expected)
        with self.scratch() as connection, connection.cursor() as cursor:
            cursor.execute("select version_num from alembic_version")
            self.assertEqual(_first(cursor), head)
            cursor.execute("select count(*) from job where held_since is null")
            self.assertEqual(_first(cursor), 0)
            cursor.execute("select count(*) from audit_event where action = 'jobs_held'")
            self.assertEqual(_first(cursor), 1)
