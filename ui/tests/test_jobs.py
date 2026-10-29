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
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest import mock
from uuid import UUID, uuid4

import psycopg
from haprion import node_enrollment

from haprion_ui import attention, db, jobs, operations
from haprion_ui.db import Job
from tests.test_queue_route import queued
from tests.test_worker import claimed, result_document

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

    autocommit = True

    def __init__(
        self, constraint: str, existing: db.Job | None, active: db.Job | None = None
    ) -> None:
        self.insert = RaisingCursor(constraint)
        self.lookup = FakeCursor(existing)
        #
        # What holds the cluster, read for the refusal's sentence (Q07).
        #
        self.holder = FakeCursor(active)
        self.cursors = iter((self.insert, self.lookup, self.holder))

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
    def queue(
        self, constraint: str, existing: db.Job | None, active: db.Job | None = None
    ) -> db.Job:
        connection = QueueConnection(constraint, existing, active)
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

    def test_a_busy_cluster_names_the_job_that_holds_it(self) -> None:
        """Review 26-10-29, Q07/R05: a held job holds it until an admin answers."""

        holder = replace(queued_job(), held_since=datetime.now(UTC))
        with self.assertRaises(db.ClusterBusy) as refused:
            self.queue("job_one_active_per_cluster", None, holder)
        self.assertIs(refused.exception.active, holder)


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

    def job(
        self,
        cluster: str | None,
        operation: str,
        state: str,
        payload: dict[str, Any] | None = None,
    ) -> Job:
        return Job(
            id=1,
            request_id=uuid4(),
            operation=operation,
            cluster=cluster,
            payload=payload or {},
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

    def test_a_node_or_cluster_job_is_named_by_its_action(self) -> None:
        # One operation, several things done (Fas 18, 26-10-15): "Changing
        # nodes" for an added node told nobody which.
        for operation, action, running, failed in (
            ("cluster_node", "add", "Adding node", "Adding the node failed"),
            ("cluster_node", "remove", "Removing node", "Removing the node failed"),
            ("cluster_node", "host", "Changing node host", "Host change failed"),
            ("cluster_define", "add", "Creating cluster", "Creating the cluster failed"),
            ("cluster_define", "remove", "Removing cluster", "Removing the cluster failed"),
        ):
            with self.subTest(operation=operation, action=action):
                payload = {"action": action}
                busy = jobs.in_flight([self.job("alpha", operation, "running", payload)])
                self.assertEqual(busy, {"alpha": running})
                failure = jobs.failure_label(self.job("alpha", operation, "failed", payload))
                self.assertEqual(failure, failed)

    def test_an_abandoned_ndes_request_is_named_so_not_an_enrollment(self) -> None:
        """B388: the abandon runs as cert_scep, and was drawn "Enrolling certificate"."""

        payload = {"id": "web.example.com", "action": "abandon"}
        running = self.job(None, "cert_scep", "running", payload)
        self.assertEqual(jobs.certificate_in_flight([running]), "Abandoning request")
        unknown = self.job(None, "cert_scep", "unknown", payload)
        self.assertNotIn("issued", jobs.unknown_note(unknown) or "")
        enrolling = self.job(None, "cert_scep", "running", {"id": "x"})
        self.assertEqual(jobs.certificate_in_flight([enrolling]), "Enrolling certificate")

    def test_without_an_action_the_operation_names_it(self) -> None:
        busy = jobs.in_flight([self.job("alpha", "cluster_node", "running")])
        self.assertEqual(busy, {"alpha": "Changing nodes"})

    def test_a_running_job_names_what_it_is_doing(self) -> None:
        busy = jobs.in_flight([self.job("alpha", "deploy", "running")])

        self.assertEqual(busy, {"alpha": "Deploying"})

    def test_a_job_held_for_an_answer_says_held(self) -> None:
        """Review 26-10-22, 1B-4: held after a restart, it waits for Run or Discard and
        was drawn as "Deploying" with a spinner until somebody answered."""

        held = replace(
            self.job("alpha", "deploy", "pending"), held_since=datetime(2026, 10, 22, tzinfo=UTC)
        )
        self.assertEqual(jobs.in_flight([held]), {"alpha": jobs.HELD})
        answered = replace(held, held_decision="run", held_decided_by="admin")
        self.assertEqual(jobs.in_flight([answered]), {"alpha": "Deploying"})

    def test_a_queued_job_counts_as_busy_too(self) -> None:
        busy = jobs.in_flight([self.job("alpha", "cert_deploy", "pending")])

        self.assertEqual(busy, {"alpha": "Deploying certificates"})

    def test_a_finished_job_leaves_the_cluster_free(self) -> None:
        self.assertEqual(jobs.in_flight([self.job("alpha", "deploy", "done")]), {})

    def test_each_cluster_answers_for_itself(self) -> None:
        busy = jobs.in_flight(
            [
                self.job("alpha", "deploy", "running"),
                self.job("beta", "changes_publish", "pending"),
            ]
        )

        self.assertEqual(busy, {"alpha": "Deploying", "beta": "Publishing"})

    def test_publish_and_deploy_names_both_halves(self) -> None:
        """One job publishes, then deploys; "Publishing" alone hid the deploy."""

        busy = jobs.in_flight(
            [
                self.job("alpha", "changes_publish", "running", {"deploy": True}),
                self.job("beta", "changes_publish", "running", {"deploy": False}),
                self.job("gamma", "deploy", "running"),
            ]
        )

        self.assertEqual(
            busy,
            {"alpha": "Publishing and deploying", "beta": "Publishing", "gamma": "Deploying"},
        )

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

    def test_the_deploy_cell_is_told_by_the_configuration_s_jobs_alone(self) -> None:
        """Review 26-10-29, O05: a backup after a failed deploy ended its verdict."""

        failed = self.job("alpha", "deploy", "failed", "deploy_refused")
        backup = replace(self.job("alpha", "backup_run", "done"), id=2)
        self.assertEqual(jobs.last_failure([backup, failed])["alpha"].code, "deploy_refused")
        self.assertEqual(
            jobs.last_failure([self.job("alpha", "server_state", "failed", "node_unreachable")]),
            {},
        )

    def test_need_review_counts_what_needs_attention_lists(self) -> None:
        failed = self.job("alpha", "deploy", "failed", "deploy_refused")
        backup = replace(
            self.job("alpha", "backup_run", "done"),
            id=2,
            created_at=failed.created_at + timedelta(minutes=1),
        )
        rows = [backup, failed]
        self.assertEqual([item.cluster for item in attention.from_jobs(rows)], ["alpha"])
        self.assertEqual(jobs.build_job_overview(rows).attention_count, 1)

    def test_another_cluster_s_failure_stays_with_that_cluster(self) -> None:
        verdicts = jobs.last_failure(
            [
                self.job("beta", "changes_publish", "blocked", "network_invalid"),
                self.job("alpha", "deploy", "done"),
            ]
        )

        self.assertEqual(set(verdicts), {"beta"})
        self.assertEqual(verdicts["beta"].label, "Publish was refused")

    def test_a_publish_and_deploy_that_published_failed_its_deploy(self) -> None:
        published = replace(
            self.job("alpha", "changes_publish", "failed", "node_unreachable"),
            payload={"deploy": True},
            result={"error": {"code": "node_unreachable"}, "publish": {"outcome": "done"}},
        )
        refused = replace(
            self.job("beta", "changes_publish", "blocked", "changes_invalid"),
            payload={"deploy": True},
        )

        verdicts = jobs.last_failure([published, refused])

        self.assertEqual(verdicts["alpha"], jobs.Failure("Deploy failed", "node_unreachable"))
        self.assertEqual(verdicts["beta"].label, "Publish was refused")


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


class ANodeChangeThatWasNotPublished(unittest.TestCase):
    """B318: the change stands and the job is done; the page says what did not happen."""

    def test_the_helper_s_reason_is_the_note(self) -> None:
        job = replace(
            queued(operation="cluster_node", cluster="alpha"),
            state="done",
            outcome="done",
            result={
                "result": {
                    "action": "added",
                    "publication": {
                        "error": {
                            "code": "dirty_worktree",
                            "message": "there are unsaved changes in the cluster worktree.",
                        }
                    },
                }
            },
        )
        self.assertEqual(
            jobs.publication_note(job),
            "The node list was not published: there are unsaved changes in the cluster worktree.",
        )

    def test_a_cloned_host_key_is_the_note(self) -> None:
        """Fynd 43 (B335): the addition stands; the job says why it should not stay so."""

        job = replace(
            queued(operation="cluster_node", cluster="alpha"),
            state="done",
            outcome="done",
            result={
                "result": {"action": "added", "node": "node-c", "shares_host_key_with": ["node-a"]}
            },
        )
        self.assertEqual(
            jobs.publication_note(job),
            node_enrollment.shared_key_warning("node-c", ["node-a"]) + ".",
        )
        created = replace(
            job,
            operation="cluster_define",
            result={"result": {"action": "added", "warnings": ["a timer could not be stopped"]}},
        )
        self.assertEqual(jobs.publication_note(created), "a timer could not be stopped.")

    def test_a_published_list_needs_no_note(self) -> None:
        job = replace(
            queued(operation="cluster_node", cluster="alpha"),
            result={"result": {"publication": {"version": 2, "hash": "c" * 40, "changed": True}}},
        )
        self.assertIsNone(jobs.publication_note(job))
        stopped = replace(
            job,
            result={
                "result": {
                    "publication": {"version": 2, "hash": "c" * 40, "changed": True},
                    "step_down": {"stopped": True},
                }
            },
        )
        self.assertIsNone(jobs.publication_note(stopped))

    def test_a_removed_node_that_did_not_stop_is_the_note(self) -> None:
        """B319: started again, it takes the cluster's addresses; the job says so."""

        message = "node-b did not answer (exit 255). Stop keepalived and HAProxy on node-b."
        job = replace(
            queued(operation="cluster_node", cluster="alpha"),
            result={
                "result": {
                    "action": "removed",
                    "publication": {"version": 4, "hash": "d" * 40, "changed": True},
                    "step_down": {"stopped": False, "message": message},
                }
            },
        )
        self.assertEqual(jobs.publication_note(job), message)

    def test_a_published_name_the_manager_cannot_resolve_is_the_note(self) -> None:
        """Finding 72: said on the publish, also when it was deployed in the same job."""

        alone = replace(
            queued(operation="changes_publish", cluster="alpha"),
            state="done",
            outcome="done",
            result={"result": {"version": 7, "unresolved_servers": ["typo.example.com"]}},
        )
        deployed = replace(
            alone,
            result={"result": {"converged": True}, "publish": alone.result},
        )
        for job in (alone, deployed):
            with self.subTest(embedded=job is deployed):
                self.assertIn(
                    "typo.example.com is not in DNS as the manager sees it",
                    jobs.unresolved_note(job) or "",
                )
        self.assertIsNone(
            jobs.unresolved_note(replace(alone, result={"result": {"unresolved_servers": []}}))
        )

    def test_a_removal_deployed_in_its_job_is_read_beside_the_deploy(self) -> None:
        """B321: the job ends as its deploy ended, with the node change under `node`."""

        message = "node-b did not answer (exit 255). Stop keepalived and HAProxy on node-b."
        job = replace(
            queued(operation="cluster_node", cluster="alpha"),
            state="done",
            outcome="done",
            result={
                "operation": "deploy",
                "result": {"converged": True},
                "node": {
                    "result": {
                        "action": "removed",
                        "publication": {"version": 4, "hash": "d" * 40, "changed": True},
                        "step_down": {"stopped": False, "message": message},
                    }
                },
            },
        )
        self.assertEqual(jobs.publication_note(job), message)


class AnUnknownOutcomeSaysWhatToCheck(unittest.TestCase):
    """Review 2026-10-20, V1: *Outcome unknown* said what happened, not what to do."""

    def job(self, operation: str, state: str = "unknown", **payload: Any) -> Job:
        moment = datetime(2026, 10, 20, tzinfo=UTC)
        return Job(
            id=1,
            request_id=uuid4(),
            operation=operation,
            cluster="alpha",
            payload=payload,
            state=state,
            created_at=moment,
            started_at=moment,
            finished_at=moment,
            exit_code=None,
            outcome=None,
            result=None,
            stderr_excerpt=None,
            idempotency_key=None,
            attempts=1,
        )

    def test_every_operation_the_worker_runs_has_its_own_sentence(self) -> None:
        from haprion_ui import worker

        self.assertEqual(set(jobs.UNKNOWN_NEXT), set(worker._OPERATION_OUTCOMES))

    def test_a_certificate_request_warns_against_a_second_certificate(self) -> None:
        self.assertIn(
            "a second request issues a second certificate",
            jobs.unknown_note(self.job("cert_issue")) or "",
        )

    def test_a_profile_is_looked_for_where_its_page_is(self) -> None:
        """Review 26-10-24, 16-05: the note sent the reader to Settings, which has no profiles."""

        for operation, page in (
            ("dns_profile_apply", "Certificates → DNS profiles"),
            ("ndes_profile_apply", "Certificates → NDES profiles"),
        ):
            with self.subTest(operation):
                self.assertIn(page, jobs.unknown_note(self.job(operation)) or "")

    def test_a_publish_that_also_deploys_points_at_the_step_that_did_not_answer(self) -> None:
        """1B-2: a publish that never answered sent the reader to the nodes."""

        deployed = replace(
            self.job("changes_publish", deploy=True),
            result={"publish": {"outcome": "done"}, "step": "deploy"},
        )
        self.assertIn("Dashboard", jobs.unknown_note(deployed) or "")
        self.assertIn("Versions", jobs.unknown_note(self.job("changes_publish", deploy=True)) or "")
        self.assertIn("Versions", jobs.unknown_note(self.job("changes_publish")) or "")

    def test_only_an_unknown_outcome_gets_one(self) -> None:
        self.assertIsNone(jobs.unknown_note(self.job("deploy", "failed")))


class EveryOperationHasAName(unittest.TestCase):
    """Review 2026-10-22, 2-2: the fallback showed "Cert scep" and "Dns profile apply"."""

    def test_every_operation_the_worker_runs_is_named(self) -> None:
        missing = sorted(operations.OPERATIONS - set(jobs.OPERATION_LABELS))
        self.assertEqual(missing, [])


class AJobInTwoStepsIsToldOneWay(unittest.TestCase):
    """Review 2026-10-22, 1B-2: the dashboard, Needs attention and the jobs page
    named the same Publish & deploy, and the same node added before its deploy
    failed, three different ways."""

    def job(self, operation: str, state: str, payload: dict[str, Any], result: Any, at: int) -> Job:
        moment = datetime(2026, 10, 22, 12, at, tzinfo=UTC)
        return queued(
            id=at,
            operation=operation,
            payload=payload,
            state=state,
            outcome=state,
            result=result,
            created_at=moment,
            finished_at=moment,
        )

    def publish_and_deploy(self, state: str = "failed", at: int = 1) -> Job:
        return self.job(
            "changes_publish",
            state,
            {"deploy": True},
            {
                "outcome": state,
                "error": {"code": "node_unreachable", "message": "node-b did not answer"},
                "publish": {"outcome": "done", "result": {"version": 27}},
                "step": "deploy",
            },
            at,
        )

    def added(self, step: str, at: int = 1) -> Job:
        return self.job(
            "cluster_node",
            "failed",
            {"action": "add", "deploy": True},
            {
                "outcome": "failed",
                "error": {"code": "node_unreachable", "message": "node-c did not answer"},
                "node": {"outcome": "done", "result": {"action": "added"}},
                "step": step,
            },
            at,
        )

    def told(self, job: Job) -> tuple[str, str, str | None]:
        (row,) = attention.from_jobs([job])
        view = jobs.build_job_overview([job]).jobs[0]
        return jobs.last_failure([job])["alpha"].label, row.message, view.note

    def test_a_publish_whose_deploy_failed_is_a_failed_deploy_everywhere(self) -> None:
        dashboard, listed, note = self.told(self.publish_and_deploy())

        self.assertEqual((dashboard, listed), ("Deploy failed", "Deploy failed"))
        self.assertEqual(note, "Published as version 27; the deploy failed.")

    def test_a_node_added_before_its_deploy_failed_was_added(self) -> None:
        for step, label, noun in (
            ("cert_deploy", "Certificate deploy failed", "certificate deploy"),
            ("deploy", "Deploy failed", "deploy"),
        ):
            with self.subTest(step):
                dashboard, listed, note = self.told(self.added(step))

                self.assertEqual((dashboard, listed), (label, label))
                self.assertEqual(note, f"The node was added; the {noun} failed.")

    def test_a_job_finished_before_the_worker_named_the_step_is_read_by_its_answer(self) -> None:
        older = self.added("cert_deploy")
        #
        # Stored as the worker stored it then: the certificate deploy's own
        # envelope, which names `cert_deploy` and never the request's
        # `cert_deploy_cluster`, with the node change beside it and no step
        # (review 26-10-24, 07-06).
        #
        envelope = result_document(claimed(operation="cert_deploy"), "failed")
        result = {**envelope, "node": (older.result or {})["node"]}
        self.assertEqual(jobs.ending_step(replace(older, result=result)), "cert_deploy")

    def test_a_later_deploy_that_worked_ends_the_attention_row(self) -> None:
        fixed = self.job("deploy", "done", {}, {"outcome": "done"}, 2)

        self.assertEqual(attention.from_jobs([self.publish_and_deploy(), fixed]), [])

    def test_a_publish_and_deploy_that_worked_ends_an_older_publish_failure(self) -> None:
        refused = self.job("changes_publish", "blocked", {}, {"outcome": "blocked"}, 1)
        worked = self.publish_and_deploy("done", at=2)

        self.assertEqual(attention.from_jobs([refused, worked]), [])

    def test_a_publish_that_failed_is_still_a_failed_publish(self) -> None:
        refused = self.job(
            "changes_publish", "blocked", {"deploy": True}, {"outcome": "blocked"}, 1
        )

        dashboard, listed, note = self.told(refused)

        self.assertEqual(
            (dashboard, listed, note), ("Publish was refused", "Publish was refused", None)
        )


class ThePublishAnswerIsReadInOnePlace(unittest.TestCase):
    """Review 26-10-24, 07-11: six readers each knew where the publish's answer was."""

    def test_its_three_places(self) -> None:
        own = {"outcome": "done", "result": {"version": 27}}
        self.assertEqual(jobs.publish_answer(own), own)
        self.assertEqual(jobs.publish_answer({"outcome": "failed", "publish": own}), own)
        self.assertIsNone(jobs.publish_answer({"error": {"code": "exit_mismatch"}, "answer": own}))
        self.assertIsNone(jobs.publish_answer(None))

    def test_no_other_reader_digs_it_out(self) -> None:
        source = Path(jobs.__file__).parent
        readers = [
            f"{path.relative_to(source)}:{number}"
            for path in sorted(source.rglob("*.py"))
            for number, line in enumerate(path.read_text().splitlines(), 1)
            if re.search(r"""\.get\(\s*["']publish["']""", line)
        ]
        self.assertEqual(readers, ["jobs.py:" + str(self.line_of_the_one_reader())])

    @staticmethod
    def line_of_the_one_reader() -> int:
        lines = Path(jobs.__file__).read_text().splitlines()
        return next(
            n for n, line in enumerate(lines, 1) if 'embedded = result.get("publish")' in line
        )
