"""What may be done with a job whose worker stopped answering.

Every case here is a rule about entitlement, not about SQL: what the evidence
licenses, and what it does not. The database is replaced, because the question
is never "did the update run" but "was this decision allowed to be made".
"""

from __future__ import annotations

import unittest
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest import mock
from uuid import UUID, uuid4

from haproxy_ui import db, recovery

REQUEST = uuid4()
EXPIRED = datetime.now(UTC) - timedelta(minutes=5)
WORKER = "mgr/4242"


def abandoned(
    operation: str = "publish", *, attempts: int = 1, request_id: UUID = REQUEST
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
    def test_the_managed_publishes_use_the_same_version_evidence_as_a_revert(self) -> None:
        for operation in ("network_publish", "cluster_settings_publish", "objects_publish"):
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

        for operation in ("revert", "publish", "objects_publish"):
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

        patch = mock.patch("haproxy_ui.db.record_audit_event", side_effect=audit)
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
            mock.patch.object(db, "expired_leases", return_value=[abandoned("publish")]),
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
