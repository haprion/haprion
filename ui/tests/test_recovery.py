"""What may be done with a job whose worker stopped answering.

Every case here is a rule about entitlement, not about SQL: what the evidence
licenses, and what it does not. The database is replaced, because the question
is never "did the update run" but "was this decision allowed to be made".
"""

from __future__ import annotations

import ast
import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest import mock
from uuid import UUID, uuid4

from haprion import answer_receipt

from haprion_ui import db, operations, recovery

REQUEST = uuid4()
EXPIRED = datetime.now(UTC) - timedelta(minutes=5)
WORKER = "mgr/4242"


def abandoned(
    operation: str = "changes_publish", *, attempts: int = 1, request_id: UUID = REQUEST
) -> db.AbandonedJob:
    return db.AbandonedJob(
        id=7,
        request_id=request_id,
        operation=operation,
        cluster="alpha",
        state="running",
        attempts=attempts,
        lease_until=EXPIRED,
    )


def history(
    *,
    versions: list[dict[str, Any]] | None = None,
    published_hash: str | None = None,
    truncated: bool = False,
    observed_at: datetime | None = None,
    outcome: str = "done",
    poll_error: str | None = None,
) -> db.ClusterHistory:
    return db.ClusterHistory(
        cluster="alpha",
        observed_at=observed_at or (EXPIRED + timedelta(minutes=1)),
        outcome=outcome,
        result={
            "versions": versions if versions is not None else [],
            "published_hash": published_hash,
            "truncated": truncated,
        },
        warnings=[],
        error=None,
        poll_error=poll_error,
    )


def version(
    request_id: UUID | None = REQUEST, *, number: int = 8, commit: str = "a" * 40
) -> dict[str, Any]:
    return {
        "version": number,
        "hash": commit,
        "request_id": None if request_id is None else str(request_id),
    }


class RepeatableOperations(unittest.TestCase):
    def test_a_reconcile_operation_is_requeued_without_asking_for_evidence(self) -> None:
        """Deploy reads the cluster before it acts, so running it again
        establishes the truth rather than assuming it."""

        for operation in ("deploy", "cert_deploy"):
            with self.subTest(operation=operation):
                judgement = recovery.judge(abandoned(operation), None)
                self.assertEqual(judgement.verdict, "requeue")
                self.assertEqual(judgement.code, "operation_repeatable")


class RecordedOperations(unittest.TestCase):
    def test_a_publish_of_saved_changes_uses_the_same_version_evidence_as_a_revert(self) -> None:
        for operation in ("changes_publish",):
            with self.subTest(operation=operation):
                judgement = recovery.judge(
                    abandoned(operation), history(versions=[version()], published_hash="a" * 40)
                )

                self.assertEqual(judgement.verdict, "requeue")
                self.assertEqual(judgement.code, "version_recorded")

    def test_a_version_carrying_this_request_is_safe_to_re_run(self) -> None:
        judgement = recovery.judge(
            abandoned(), history(versions=[version()], published_hash="a" * 40)
        )

        self.assertEqual(judgement.verdict, "requeue")
        self.assertEqual(judgement.code, "version_recorded")

    def test_a_recorded_version_that_was_never_published_is_named_as_such(self) -> None:
        """The half-finished case: the commit landed, the release did not.

        Still a requeue - the retry repairs it from the same commit - but the
        code says which of the two situations it was, because they read very
        differently in a trail six months later.
        """

        judgement = recovery.judge(
            abandoned(), history(versions=[version()], published_hash="b" * 40)
        )

        self.assertEqual(judgement.verdict, "requeue")
        self.assertEqual(judgement.code, "release_incomplete")

    def test_a_recorded_version_with_a_later_one_is_superseded_not_unpublished(self) -> None:
        """The review's revert: version 4 for this request, version 5 published since (CR-09).

        Requeued, it reverted again on top of 5. Neither "never published" nor a
        retry: the later version is the configuration, and the job ends saying so.
        """

        for operation in ("revert", "changes_publish"):
            with self.subTest(operation=operation):
                judgement = recovery.judge(
                    abandoned(operation),
                    history(
                        versions=[
                            version(None, number=5, commit="b" * 40),
                            version(number=4, commit="a" * 40),
                        ],
                        published_hash="b" * 40,
                    ),
                )

                self.assertEqual(judgement.verdict, "abandon")
                self.assertEqual(judgement.code, "superseded")
                self.assertIn("version 5 has been recorded since", judgement.reason)

    def test_nothing_recorded_in_a_complete_listing_means_it_never_started(self) -> None:
        judgement = recovery.judge(
            abandoned(), history(versions=[version(None)], published_hash="a" * 40)
        )

        self.assertEqual(judgement.verdict, "requeue")
        self.assertEqual(judgement.code, "nothing_recorded")

    def test_a_truncated_listing_cannot_rule_a_version_out(self) -> None:
        """ "Not found" and "not there" are different answers, and only the
        second one licenses a retry."""

        judgement = recovery.judge(abandoned(), history(versions=[version(None)], truncated=True))

        self.assertEqual(judgement.verdict, "abandon")
        self.assertEqual(judgement.code, "evidence_truncated")


class EvidenceThatSettlesNothing(unittest.TestCase):
    def test_a_listing_read_before_the_lease_expired_is_not_evidence(self) -> None:
        """The reading happened while the operation could still have been
        recording a version, so its silence proves nothing."""

        judgement = recovery.judge(
            abandoned(), history(versions=[], observed_at=EXPIRED - timedelta(seconds=1))
        )

        self.assertEqual(judgement.verdict, "wait")
        self.assertEqual(judgement.code, "evidence_too_old")

    def test_a_cluster_that_could_not_be_polled_is_waited_for(self) -> None:
        for label, cached in (
            ("missing", None),
            ("poll error", history(poll_error="ssh: connection refused")),
            ("failed read", history(outcome="failed")),
        ):
            with self.subTest(label):
                judgement = recovery.judge(abandoned(), cached)
                self.assertEqual(judgement.verdict, "wait")
                self.assertEqual(judgement.code, "evidence_unavailable")

    def test_a_job_taken_twice_is_never_taken_a_third_time(self) -> None:
        """`unknown` is what a job that keeps killing its worker ends as. The
        alternative is retrying it forever while nothing says the system gave
        up."""

        judgement = recovery.judge(abandoned("deploy", attempts=recovery.MAX_ATTEMPTS), None)

        self.assertEqual(judgement.verdict, "abandon")
        self.assertEqual(judgement.code, "attempts_exhausted")

    def test_an_operation_with_no_defined_evidence_is_never_retried(self) -> None:
        judgement = recovery.judge(abandoned("publish_something_else"), None)

        self.assertEqual(judgement.verdict, "abandon")
        self.assertEqual(judgement.code, "operation_unknown")


class Adjudicating(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = mock.MagicMock()
        self.audited: list[dict[str, Any]] = []

        def audit(_c: object, **fields: Any) -> None:
            self.audited.append(fields)

        patch = mock.patch("haprion_ui.db.record_audit_event", side_effect=audit)
        patch.start()
        self.addCleanup(patch.stop)

    def test_a_requeue_is_written_with_the_attempt_count_it_was_judged_on(self) -> None:
        """The guard against a worker claiming the row between the reading and
        the write: the update names the attempt count the decision was made
        about, so a row that moved is not touched."""

        with (
            mock.patch.object(db, "expired_leases", return_value=[abandoned("deploy")]),
            mock.patch.object(db, "requeue_expired", return_value=True) as requeue,
        ):
            moved = recovery.adjudicate(self.connection, worker=WORKER)

        self.assertEqual(moved, 1)
        self.assertEqual(requeue.call_args.kwargs, {"job_id": 7, "attempts": 1})
        self.assertEqual(self.audited[0]["action"], "job_requeued")
        self.assertEqual(self.audited[0]["detail"]["code"], "operation_repeatable")
        self.connection.commit.assert_called_once_with()

    def test_a_row_that_moved_while_it_was_judged_is_left_alone(self) -> None:
        with (
            mock.patch.object(db, "expired_leases", return_value=[abandoned("deploy")]),
            mock.patch.object(db, "requeue_expired", return_value=False),
        ):
            moved = recovery.adjudicate(self.connection, worker=WORKER)

        self.assertEqual(moved, 0)
        self.assertEqual(self.audited, [])
        self.connection.commit.assert_not_called()
        self.connection.rollback.assert_called_once_with()

    def test_an_abandoned_job_records_why_it_was_given_up_on(self) -> None:
        job = abandoned("deploy", attempts=recovery.MAX_ATTEMPTS)
        with (
            mock.patch.object(db, "expired_leases", return_value=[job]),
            mock.patch.object(db, "abandon_expired", return_value=True) as abandon,
        ):
            recovery.adjudicate(self.connection, worker=WORKER)

        self.assertEqual(abandon.call_args.kwargs["code"], "attempts_exhausted")
        self.assertEqual(self.audited[0]["action"], "job_abandoned")
        self.assertEqual(self.audited[0]["cluster"], "alpha")

    def test_an_undecidable_job_is_neither_moved_nor_recorded(self) -> None:
        with (
            mock.patch.object(db, "expired_leases", return_value=[abandoned("changes_publish")]),
            mock.patch.object(db, "cluster_history", return_value=None),
            mock.patch.object(db, "requeue_expired") as requeue,
            mock.patch.object(db, "abandon_expired") as abandon,
        ):
            moved = recovery.adjudicate(self.connection, worker=WORKER)

        self.assertEqual(moved, 0)
        requeue.assert_not_called()
        abandon.assert_not_called()
        self.assertEqual(self.audited, [])

    def test_a_reconcile_operation_never_reads_the_history_cache(self) -> None:
        """It needs no evidence, and a read taken anyway would be a claim that
        the decision depended on it."""

        with (
            mock.patch.object(db, "expired_leases", return_value=[abandoned("deploy")]),
            mock.patch.object(db, "cluster_history") as cached,
            mock.patch.object(db, "requeue_expired", return_value=True),
        ):
            recovery.adjudicate(self.connection, worker=WORKER)

        cached.assert_not_called()


if __name__ == "__main__":
    unittest.main()


class AHelperThatOutlivedItsWorker(unittest.TestCase):
    """The helpers behind sockets keep a receipt of their answer (B367)."""

    def test_a_helper_still_running_is_waited_for_however_often_it_was_taken(self) -> None:
        running = answer_receipt.Receipt("running")
        for attempts in (1, recovery.MAX_ATTEMPTS):
            with self.subTest(attempts=attempts):
                judgement = recovery.judge(
                    abandoned("node_restore", attempts=attempts), None, running
                )
                self.assertEqual((judgement.verdict, judgement.code), ("wait", "helper_running"))

    def test_a_kept_answer_is_adopted_and_not_run_again(self) -> None:
        answered = answer_receipt.Receipt("answered", stdout="{}", exit_code=0)

        judgement = recovery.judge(abandoned("cluster_node"), None, answered)

        self.assertEqual((judgement.verdict, judgement.code), ("adopt", "answer_kept"))

    def test_a_job_adopted_once_too_often_is_given_up(self) -> None:
        answered = answer_receipt.Receipt("answered", stdout="{}", exit_code=0)

        judgement = recovery.judge(
            abandoned("cluster_node", attempts=recovery.MAX_ATTEMPTS + 1), None, answered
        )

        self.assertEqual((judgement.verdict, judgement.code), ("abandon", "attempts_exhausted"))

    def test_a_helper_that_ended_without_an_answer_is_unknown(self) -> None:
        judgement = recovery.judge(abandoned("backup_run"), None, answer_receipt.Receipt("silent"))

        self.assertEqual((judgement.verdict, judgement.code), ("abandon", "helper_silent"))

    def test_without_a_receipt_the_rules_before_it_decide(self) -> None:
        for state in ("absent", "unavailable"):
            with self.subTest(state=state):
                receipt = answer_receipt.Receipt(state)
                self.assertEqual(
                    recovery.judge(abandoned("deploy"), None, receipt).code,
                    "operation_repeatable",
                )
        self.assertEqual(
            recovery.judge(
                abandoned("cluster_node"), None, answer_receipt.Receipt("unavailable")
            ).code,
            "operation_unknown",
        )

    def test_an_answer_no_longer_kept_is_said_as_such(self) -> None:
        """Review 26-10-29, C03: a held job's answer was removed after two weeks, and the
        job ended blaming an operation that has no evidence."""

        held = replace(abandoned("cluster_node"), held_since=EXPIRED)

        judgement = recovery.judge(held, None, answer_receipt.Receipt("absent"))

        self.assertEqual((judgement.verdict, judgement.code), ("abandon", "answer_absent"))
        self.assertEqual(
            judgement.reason,
            "its helper kept no answer: it never began, or its answer was removed 14 days"
            " after it ended, so what it did is not known",
        )

    def test_the_operations_that_keep_an_answer_are_the_ones_whose_helper_does(self) -> None:
        """Read from `operations`: an operation whose job asks a helper that keeps receipts."""

        source = ast.parse(Path(operations.__file__).read_text(encoding="utf-8"))
        clients = {"NODE_CLIENT", "BACKUP_CLIENT", "RESTORE_CLIENT", "RECEIVER_CLIENT", "_restore"}
        keeping: set[str] = set()
        for node in ast.walk(source):
            if not (isinstance(node, ast.If) and isinstance(node.test, ast.Compare)):
                continue
            if not (isinstance(node.test.left, ast.Name) and node.test.left.id == "operation"):
                continue
            named = {
                constant.value
                for constant in ast.walk(node.test.comparators[0])
                if isinstance(constant, ast.Constant) and isinstance(constant.value, str)
            }
            used = {
                name.id
                for statement in node.body
                for name in ast.walk(statement)
                if isinstance(name, ast.Name)
            }
            if used & clients:
                keeping |= named
        self.assertEqual(sorted(recovery.KEEPS_ANSWER), sorted(keeping))
        #
        # And the clients are the helpers that keep receipts: a fifth one is a
        # fifth client to name above.
        #
        helpers = Path(answer_receipt.__file__).parent / "cli"
        self.assertEqual(
            sorted(
                path.name
                for path in helpers.glob("*.py")
                if "@answer_receipt.keeps_answer" in path.read_text(encoding="utf-8")
            ),
            [
                "backup_job_helper.py",
                "cert_receiver_helper.py",
                "node_helper.py",
                "node_restore_helper.py",
            ],
        )


class AdoptingAJob(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = mock.MagicMock()
        self.audited: list[dict[str, Any]] = []
        patch = mock.patch(
            "haprion_ui.db.record_audit_event",
            side_effect=lambda _c, **fields: self.audited.append(fields),
        )
        patch.start()
        self.addCleanup(patch.stop)
        self.answered = answer_receipt.Receipt("answered", stdout="{}", exit_code=0)

    def test_the_job_is_claimed_committed_and_then_ended_on_the_answer(self) -> None:
        claimed = mock.sentinel.claimed
        order: list[str] = []
        self.connection.commit.side_effect = lambda: order.append("commit")

        def resume(job: object, receipt: answer_receipt.Receipt) -> None:
            order.append("resume")
            self.assertIs(job, claimed)
            self.assertIs(receipt, self.answered)

        with (
            mock.patch.object(db, "expired_leases", return_value=[abandoned("cluster_node")]),
            mock.patch.object(db, "adopt_expired", return_value=claimed) as adopt,
        ):
            moved = recovery.adjudicate(
                self.connection,
                worker=WORKER,
                resume=resume,
                lease_seconds=60,
                receipts=lambda _request_id: self.answered,
            )

        self.assertEqual(moved, 1)
        self.assertEqual(
            adopt.call_args.kwargs,
            {"job_id": 7, "attempts": 1, "worker_id": WORKER, "lease_seconds": 60},
        )
        self.assertEqual(order, ["commit", "resume"])
        self.assertEqual(self.audited[0]["action"], "job_adopted")

    def test_a_held_job_s_kept_answer_waits_for_an_admin(self) -> None:
        """Review 2026-10-28, F01: adopted at boot, its deploy ran with no Run."""

        held = replace(abandoned("cluster_node"), held_since=EXPIRED)
        resume = mock.Mock()
        with (
            mock.patch.object(db, "expired_leases", return_value=[held]),
            mock.patch.object(db, "adopt_expired") as adopt,
        ):
            moved = recovery.adjudicate(
                self.connection,
                worker=WORKER,
                resume=resume,
                receipts=lambda _request_id: self.answered,
            )

        self.assertEqual(moved, 0)
        adopt.assert_not_called()
        resume.assert_not_called()
        self.assertEqual(self.audited, [])

        answered = replace(held, held_decision="discard")
        with (
            mock.patch.object(db, "expired_leases", return_value=[answered]),
            mock.patch.object(db, "adopt_expired", return_value=mock.sentinel.claimed),
        ):
            moved = recovery.adjudicate(
                self.connection,
                worker=WORKER,
                resume=resume,
                receipts=lambda _request_id: self.answered,
            )
        self.assertEqual(moved, 1)
        resume.assert_called_once()

    def test_without_a_worker_to_end_it_the_job_is_left_alone(self) -> None:
        with (
            mock.patch.object(db, "expired_leases", return_value=[abandoned("cluster_node")]),
            mock.patch.object(db, "adopt_expired") as adopt,
        ):
            moved = recovery.adjudicate(
                self.connection, worker=WORKER, receipts=lambda _request_id: self.answered
            )

        self.assertEqual(moved, 0)
        adopt.assert_not_called()
        self.assertEqual(self.audited, [])
