"""What the job queue's write path must say, checked where a database cannot be.

These are assertions about the statements themselves, and that is a weaker kind
of test than running them - it is written down here so nobody reads a green
result as proof that the SQL works. The behaviour needs PostgreSQL, and is
proved on the development platform.

What this does catch is the failure that would otherwise be silent: the fencing
predicate quietly disappearing from a write. A worker whose stale token no longer
appears in the WHERE clause overwrites the result of the worker that took the job
over, and nothing about that looks wrong in a diff.
"""

from __future__ import annotations

import re
import unittest
from contextlib import nullcontext
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest import mock
from uuid import UUID, uuid4

import psycopg

from haproxy_ui import db, jobs, operations
from haproxy_ui.db import Job

TOKEN = uuid4()


class FakeCursor:
    def __init__(self, row: Any) -> None:
        self.row = row
        self.statements: list[str] = []

    def __enter__(self) -> FakeCursor:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def execute(self, statement: str, parameters: Any = None) -> None:
        self.statements.append(" ".join(statement.split()))
        self.parameters = parameters

    def fetchone(self) -> Any:
        return self.row

    def fetchall(self) -> list[Any]:
        return [] if self.row is None else [self.row]


class FakeConnection:
    def __init__(self, row: Any = None) -> None:
        self.last = FakeCursor(row)

    def cursor(self, **_: object) -> FakeCursor:
        return self.last


class FakeUniqueViolation(Exception):
    """A database constraint error with the part `queue_job` inspects."""

    def __init__(self, constraint: str) -> None:
        super().__init__(constraint)
        self.diag = SimpleNamespace(constraint_name=constraint)


class RaisingCursor(FakeCursor):
    def __init__(self, constraint: str) -> None:
        super().__init__(row=None)
        self.constraint = constraint

    def execute(self, statement: str, parameters: Any = None) -> None:
        super().execute(statement, parameters)
        raise FakeUniqueViolation(self.constraint)


class QueueConnection:
    """An insert that conflicts, followed by the idempotency lookup."""

    def __init__(self, constraint: str, existing: db.Job | None) -> None:
        self.insert = RaisingCursor(constraint)
        self.lookup = FakeCursor(existing)
        self.cursors = iter((self.insert, self.lookup))

    def transaction(self) -> Any:
        return nullcontext()

    def cursor(self, **_: object) -> FakeCursor:
        return next(self.cursors)


def queued_job() -> db.Job:
    return db.Job(
        id=7,
        request_id=uuid4(),
        operation="deploy",
        cluster="alpha",
        payload={},
        state="pending",
        created_at=datetime.now(UTC),
        started_at=None,
        finished_at=None,
        exit_code=None,
        outcome=None,
        result=None,
        stderr_excerpt=None,
        idempotency_key=uuid4(),
        attempts=1,
    )


class ClaimingIsOneStatement(unittest.TestCase):
    def test_the_claim_is_a_single_update_that_skips_locked_rows(self) -> None:
        connection = FakeConnection(row=None)
        db.claim_job(connection, worker_id="worker-a", lease_seconds=30)  # type: ignore[arg-type]
        statement = connection.last.statements[0]

        self.assertTrue(statement.startswith("update job"))
        self.assertIn("for update skip locked", statement)
        #
        # Read-then-write is the bug this shape exists to avoid, so a second
        # statement here would mean the claim had grown one.
        #
        self.assertEqual(len(connection.last.statements), 1)

    def test_every_claim_rotates_the_fencing_token(self) -> None:
        connection = FakeConnection(row=None)
        db.claim_job(connection, worker_id="worker-a", lease_seconds=30)  # type: ignore[arg-type]

        self.assertIn("claim_token = gen_random_uuid()", connection.last.statements[0])

    def test_nothing_to_claim_is_an_answer_and_not_an_error(self) -> None:
        connection = FakeConnection(row=None)

        self.assertIsNone(
            db.claim_job(connection, worker_id="worker-a", lease_seconds=30)  # type: ignore[arg-type]
        )


class QueueConflictsAreClassifiedAfterTheKeyLookup(unittest.TestCase):
    def queue(self, constraint: str, existing: db.Job | None) -> db.Job:
        connection = QueueConnection(constraint, existing)
        with mock.patch.object(psycopg.errors, "UniqueViolation", FakeUniqueViolation):
            result = db.queue_job(
                connection,  # type: ignore[arg-type]
                operation="deploy",
                cluster="alpha",
                payload={},
                idempotency_key=uuid4(),
            )
        self.assertIn("idempotency_key = %(key)s", connection.lookup.statements[0])
        return result

    def test_a_same_request_is_returned_when_the_cluster_index_reports_first(self) -> None:
        existing = queued_job()

        self.assertIs(
            self.queue("job_one_active_per_cluster", existing),
            existing,
        )

    def test_a_different_request_still_reports_a_busy_cluster(self) -> None:
        with self.assertRaises(db.ClusterBusy):
            self.queue("job_one_active_per_cluster", None)


class WritesAreFenced(unittest.TestCase):
    def test_renewing_a_lease_names_the_claim_token(self) -> None:
        connection = FakeConnection(row=(1,))
        db.renew_lease(connection, job_id=1, claim_token=TOKEN, lease_seconds=30)  # type: ignore[arg-type]
        statement = connection.last.statements[0]

        self.assertIn("claim_token = %(claim_token)s", statement)
        self.assertIn("state = 'running'", statement)
        self.assertIn("lease_until >= statement_timestamp()", statement)

    def test_finishing_a_job_names_the_claim_token_and_clears_the_lease(self) -> None:
        connection = FakeConnection(row=(1,))
        db.finish_job(
            connection,  # type: ignore[arg-type]
            job_id=1,
            claim_token=TOKEN,
            state="done",
            exit_code=0,
            outcome="done",
            result={"ok": True},
            stderr_excerpt=None,
        )
        statement = connection.last.statements[0]

        self.assertIn("claim_token = %(claim_token)s", statement)
        self.assertIn("lease_until = null", statement)
        self.assertIn("lease_until >= statement_timestamp()", statement)

    def test_finishing_a_job_wakes_the_poller(self) -> None:
        #
        # The page reads the poller's cache, so a publish that changed a cluster
        # used to sit invisible until the next tick - a page saying "observed
        # just now" about a reading taken before the change it was consulted
        # about. In the transaction, so it cannot arrive before the row it is
        # about is visible.
        #
        connection = FakeConnection(row=(1,))
        db.finish_job(
            connection,  # type: ignore[arg-type]
            job_id=1,
            claim_token=TOKEN,
            state="done",
            exit_code=0,
            outcome="done",
            result={"ok": True},
            stderr_excerpt=None,
        )

        self.assertIn("notify cluster_changed", connection.last.statements)
        # The two ends must name the same channel. Renaming one of them is the
        # failure this catches: nothing errors, the poller simply never wakes.
        self.assertIn(f"notify {db.CLUSTER_CHANNEL}", connection.last.statements)

    def test_a_job_that_changed_nothing_does_not_wake_the_poller(self) -> None:
        #
        # The lease had elapsed and the update matched no row. Waking the poller
        # anyway is a helper run against every node to re-read a world nothing
        # touched.
        #
        connection = FakeConnection(row=None)
        db.finish_job(
            connection,  # type: ignore[arg-type]
            job_id=1,
            claim_token=TOKEN,
            state="failed",
            exit_code=1,
            outcome="failed",
            result=None,
            stderr_excerpt=None,
        )

        self.assertNotIn("notify cluster_changed", connection.last.statements)

    def test_a_lost_lease_is_reported_rather_than_raised(self) -> None:
        #
        # No row came back, so another worker holds the job. The caller has to be
        # able to tell that apart from a failure to reach the database, because
        # the correct response is to stop rather than to retry.
        #
        connection = FakeConnection(row=None)

        self.assertFalse(
            db.renew_lease(connection, job_id=1, claim_token=TOKEN, lease_seconds=30)  # type: ignore[arg-type]
        )
        self.assertFalse(
            db.finish_job(
                connection,  # type: ignore[arg-type]
                job_id=1,
                claim_token=TOKEN,
                state="failed",
                exit_code=1,
                outcome="failed",
                result=None,
                stderr_excerpt=None,
            )
        )


class ExpiredLeasesAreRead(unittest.TestCase):
    def test_listing_expired_leases_writes_nothing(self) -> None:
        #
        # The plan allows a requeue only for an operation proved not to have
        # started or proved idempotent, and that proof does not exist yet. A
        # select here is the whole point: an update would be the blind retry.
        #
        connection = FakeConnection(row=None)
        db.expired_leases(connection)  # type: ignore[arg-type]
        statement = connection.last.statements[0]

        self.assertTrue(statement.startswith("select"))
        self.assertIn("lease_until < statement_timestamp()", statement)


class TokensAreSentAsText(unittest.TestCase):
    def test_a_uuid_reaches_the_database_as_its_string_form(self) -> None:
        connection = FakeConnection(row=(1,))
        db.renew_lease(connection, job_id=1, claim_token=TOKEN, lease_seconds=30)  # type: ignore[arg-type]

        self.assertEqual(connection.last.parameters["claim_token"], str(TOKEN))
        self.assertIsInstance(TOKEN, UUID)


if __name__ == "__main__":
    unittest.main()


class WhatEachClusterIsBusyWith(unittest.TestCase):
    """One state per cluster, which is what lets a page draw it instead of the buttons.

    The queue permits one pending job per cluster. So a page does not need a
    list here - it needs the answer to "is this cluster busy, and with what",
    and it can replace the actions with it rather than leaving them drawn to
    offer something the queue would refuse with a 409.
    """

    def job(self, cluster: str, operation: str, state: str) -> Job:
        return Job(
            id=1,
            request_id=uuid4(),
            operation=operation,
            cluster=cluster,
            payload={},
            state=state,
            created_at=datetime(2026, 9, 3, tzinfo=UTC),
            started_at=None,
            finished_at=None,
            exit_code=None,
            outcome=None,
            result=None,
            stderr_excerpt=None,
            idempotency_key=None,
            attempts=0,
        )

    def test_a_running_job_names_what_it_is_doing(self) -> None:
        busy = jobs.in_flight([self.job("alpha", "deploy", "running")])

        self.assertEqual(busy, {"alpha": "Deploying"})

    def test_a_queued_job_counts_as_busy_too(self) -> None:
        busy = jobs.in_flight([self.job("alpha", "cert_deploy", "pending")])

        self.assertEqual(busy, {"alpha": "Deploying certificates"})

    def test_a_finished_job_leaves_the_cluster_free(self) -> None:
        self.assertEqual(jobs.in_flight([self.job("alpha", "deploy", "done")]), {})

    def test_each_cluster_answers_for_itself(self) -> None:
        busy = jobs.in_flight(
            [
                self.job("alpha", "deploy", "running"),
                self.job("beta", "objects_publish", "pending"),
            ]
        )

        self.assertEqual(busy, {"alpha": "Deploying", "beta": "Publishing"})

    def test_an_operation_without_a_label_is_still_busy(self) -> None:
        """A cluster that looks idle while it is not is the worse mistake."""

        busy = jobs.in_flight([self.job("alpha", "something_new", "running")])

        self.assertEqual(busy, {"alpha": "something_new"})

    def test_every_operation_the_code_prepares_has_a_word_for_it(self) -> None:
        source = Path(operations.__file__).read_text(encoding="utf-8")
        for operation in sorted(set(re.findall(r'if operation == "([a-z_]+)"', source))):
            with self.subTest(operation=operation):
                self.assertIn(operation, jobs.RUNNING_LABELS)


class WhatTheLastJobLeftBehind(unittest.TestCase):
    """The one fact about a cluster that no reading of the cluster can find.

    A refused job changes nothing: the configuration is as it was, the nodes
    are content, and a page built from status alone reports a healthy cluster
    precisely because the work never happened.
    """

    def job(self, cluster: str, operation: str, state: str, code: str | None = None) -> Job:
        return Job(
            id=1,
            request_id=uuid4(),
            operation=operation,
            cluster=cluster,
            payload={},
            state=state,
            created_at=datetime(2026, 9, 3, tzinfo=UTC),
            started_at=None,
            finished_at=datetime(2026, 9, 3, tzinfo=UTC),
            exit_code=1,
            outcome=state,
            result={"error": {"code": code}} if code else None,
            stderr_excerpt=None,
            idempotency_key=None,
            attempts=1,
        )

    def test_a_failed_job_is_reported_with_the_code_it_blamed(self) -> None:
        verdicts = jobs.last_failure([self.job("alpha", "deploy", "failed", "deploy_refused")])

        self.assertEqual(verdicts["alpha"].label, "Deploy failed")
        self.assertEqual(verdicts["alpha"].code, "deploy_refused")

    def test_a_newer_job_that_worked_ends_the_verdict(self) -> None:
        """Newest first, so a failure the next attempt fixed is history."""

        verdicts = jobs.last_failure(
            [
                self.job("alpha", "deploy", "done"),
                self.job("alpha", "deploy", "failed", "deploy_refused"),
            ]
        )

        self.assertEqual(verdicts, {})

    def test_a_job_still_running_decides_nothing(self) -> None:
        """The spinner is that state, and it is read from `in_flight`."""

        verdicts = jobs.last_failure(
            [
                self.job("alpha", "deploy", "running"),
                self.job("alpha", "deploy", "failed", "deploy_refused"),
            ]
        )

        self.assertEqual(verdicts["alpha"].code, "deploy_refused")

    def test_a_node_restore_neither_sets_nor_ends_the_verdict(self) -> None:
        """Its jobs hold the cluster's lock; they are about a VM, not the configuration."""

        self.assertEqual(
            jobs.last_failure(
                [self.job("alpha", "node_restore_preview", "blocked", "restore_blocked")]
            ),
            {},
        )
        verdicts = jobs.last_failure(
            [
                self.job("alpha", "node_restore", "done"),
                self.job("alpha", "deploy", "failed", "deploy_refused"),
            ]
        )
        self.assertEqual(verdicts["alpha"].code, "deploy_refused")

    def test_another_cluster_s_failure_stays_with_that_cluster(self) -> None:
        verdicts = jobs.last_failure(
            [
                self.job("beta", "network_publish", "blocked", "network_invalid"),
                self.job("alpha", "deploy", "done"),
            ]
        )

        self.assertEqual(set(verdicts), {"beta"})
        self.assertEqual(verdicts["beta"].label, "Publish failed")


class WhatAFailureIsAllowedToSay(unittest.TestCase):
    """The most important refusal in the system carries the compiler's answer."""

    def failed(self, *, result: object, stderr: str | None) -> db.Job:
        return replace(
            queued_job(),
            state="failed",
            result=result,  # type: ignore[arg-type]
            stderr_excerpt=stderr,
        )

    def test_the_envelope_diagnostics_win_over_the_stderr_line(self) -> None:
        """`candidate_invalid` puts the whole `haproxy -c` output in the envelope.

        The stderr line is `ERROR: [code] message` and says nothing about which
        line HAProxy would not accept - which is the only thing the person
        reading it needs.
        """

        job = self.failed(
            result={
                "error": {
                    "code": "candidate_invalid",
                    "details": {"diagnostics": "conf.d/1001-shop.cfg:4 unknown keyword"},
                }
            },
            stderr="ERROR: [candidate_invalid] these objects did not produce a valid candidate.",
        )

        self.assertEqual(jobs.diagnostics_of(job), "conf.d/1001-shop.cfg:4 unknown keyword")

    def test_the_stderr_excerpt_is_the_fallback(self) -> None:
        """A helper that died has no envelope, and its stderr is the whole account."""

        job = self.failed(result=None, stderr="Traceback ...")

        self.assertEqual(jobs.diagnostics_of(job), "Traceback ...")

    def test_an_envelope_without_diagnostics_falls_back_rather_than_going_blank(self) -> None:
        job = self.failed(result={"error": {"code": "busy"}}, stderr="ERROR: [busy] try again")

        self.assertEqual(jobs.diagnostics_of(job), "ERROR: [busy] try again")

    def test_a_blank_diagnostics_string_is_not_an_answer(self) -> None:
        job = self.failed(
            result={"error": {"details": {"diagnostics": "   "}}}, stderr="ERROR: [x] y"
        )

        self.assertEqual(jobs.diagnostics_of(job), "ERROR: [x] y")
