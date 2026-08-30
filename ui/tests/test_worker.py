"""How a claimed job ends, and what the worker is entitled to write.

The database and the command are both replaced here, because what is being
tested is the decision between four endings - done, blocked, unknown, and
writing nothing at all - and each of them is a rule about entitlement rather
than about SQL.
"""

from __future__ import annotations

import json
import unittest
from datetime import UTC, datetime
from typing import Any
from unittest import mock
from uuid import uuid4

from haproxy_ui import db, execution, worker

TOKEN = uuid4()
WORKER = "mgr/4242"


def claimed(operation: str = "deploy", payload: dict[str, Any] | None = None) -> db.ClaimedJob:
    return db.ClaimedJob(
        id=7,
        request_id=uuid4(),
        operation=operation,
        cluster="alpha",
        payload={} if payload is None else payload,
        state="running",
        created_at=datetime.now(UTC),
        started_at=datetime.now(UTC),
        finished_at=None,
        exit_code=None,
        outcome=None,
        result=None,
        stderr_excerpt=None,
        idempotency_key=uuid4(),
        claim_token=TOKEN,
    )


def completed(
    ending: str = "finished",
    exit_code: int | None = 0,
    stdout: str = "",
    stderr: str = "",
    stdout_error: str | None = None,
) -> execution.Completed:
    return execution.Completed(
        ending=ending,  # type: ignore[arg-type]
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        stdout_error=stdout_error,  # type: ignore[arg-type]
    )


def result_document(job: db.ClaimedJob, outcome: str = "done") -> dict[str, Any]:
    return {
        "schema_version": 1,
        "ok": outcome == "done",
        "outcome": outcome,
        "operation": job.operation,
        "cluster": job.cluster,
        "request_id": str(job.request_id),
        "result": {} if outcome in {"done", "partial"} else None,
        "warnings": (
            [{"code": "synthetic_warning", "message": "synthetic warning"}]
            if outcome == "partial"
            else []
        ),
        "error": (
            {"code": "synthetic_failure", "message": "synthetic failure"}
            if outcome in {"failed", "blocked"}
            else None
        ),
    }


def answer(job: db.ClaimedJob, outcome: str = "done") -> str:
    return json.dumps(result_document(job, outcome))


class WorkerTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.finished: list[dict[str, Any]] = []
        self.connection = mock.MagicMock()

        def finish(_c: object, **fields: Any) -> bool:
            self.finished.append(fields)
            return True

        patch = mock.patch("haproxy_ui.db.finish_job", side_effect=finish)
        patch.start()
        self.addCleanup(patch.stop)

        self.audited: list[dict[str, Any]] = []

        def audit(_c: object, **fields: Any) -> None:
            self.audited.append(fields)

        trail = mock.patch("haproxy_ui.db.record_audit_event", side_effect=audit)
        trail.start()
        self.addCleanup(trail.stop)


class GoodAnswers(WorkerTestCase):
    def test_the_envelopes_outcome_becomes_the_jobs_state(self) -> None:
        job = claimed()
        document = result_document(job)
        with mock.patch.object(
            execution, "run", return_value=completed(stdout=json.dumps(document))
        ):
            worker.run_one_job(self.connection, job, worker=WORKER)

        self.assertEqual(self.finished[0]["state"], "done")
        self.assertEqual(self.finished[0]["outcome"], "done")
        self.assertEqual(self.finished[0]["result"], document)

    def test_partial_is_carried_through_and_not_flattened(self) -> None:
        job = claimed()
        with mock.patch.object(
            execution, "run", return_value=completed(exit_code=69, stdout=answer(job, "partial"))
        ):
            worker.run_one_job(self.connection, job, worker=WORKER)

        self.assertEqual(self.finished[0]["state"], "partial")
        self.assertEqual(self.finished[0]["exit_code"], 69)

    def test_the_claim_token_is_passed_to_the_write(self) -> None:
        job = claimed()
        with mock.patch.object(execution, "run", return_value=completed(stdout=answer(job))):
            worker.run_one_job(self.connection, job, worker=WORKER)

        self.assertEqual(self.finished[0]["claim_token"], TOKEN)


class UndeterminedEndings(WorkerTestCase):
    def test_output_that_is_not_an_envelope_is_unknown(self) -> None:
        #
        # The command said something this process cannot describe. Calling that
        # failed would claim knowledge the worker does not have: the operation
        # may well have taken effect.
        #
        with mock.patch.object(
            execution, "run", return_value=completed(stdout="Segmentation fault")
        ):
            worker.run_one_job(self.connection, claimed(), worker=WORKER)

        self.assertEqual(self.finished[0]["state"], "unknown")

    def test_a_timeout_is_unknown_rather_than_failed(self) -> None:
        with mock.patch.object(
            execution, "run", return_value=completed(ending="timeout", exit_code=None)
        ):
            worker.run_one_job(self.connection, claimed(), worker=WORKER)

        self.assertEqual(self.finished[0]["state"], "unknown")

    def test_an_outcome_the_contract_does_not_define_is_unknown(self) -> None:
        job = claimed()
        document = result_document(job)
        document["outcome"] = "probably fine"
        with mock.patch.object(
            execution, "run", return_value=completed(stdout=json.dumps(document))
        ):
            worker.run_one_job(self.connection, job, worker=WORKER)

        self.assertEqual(self.finished[0]["state"], "unknown")

    def test_an_envelope_for_another_job_is_never_accepted(self) -> None:
        for field, wrong in (
            ("schema_version", 2),
            ("operation", "cert_deploy"),
            ("cluster", "beta"),
            ("request_id", str(uuid4())),
            ("ok", False),
        ):
            with self.subTest(field=field):
                job = claimed()
                document = result_document(job)
                document[field] = wrong
                self.finished.clear()
                with mock.patch.object(
                    execution, "run", return_value=completed(stdout=json.dumps(document))
                ):
                    worker.run_one_job(self.connection, job, worker=WORKER)

                self.assertEqual(self.finished[0]["state"], "unknown")
                self.assertEqual(self.finished[0]["result"]["error"]["code"], "internal_error")

    def test_a_partial_revert_is_not_part_of_its_contract(self) -> None:
        job = claimed(operation="revert", payload={"version": 1, "expected_commit": "a" * 40})
        with mock.patch.object(
            execution, "run", return_value=completed(stdout=answer(job, "partial"))
        ):
            worker.run_one_job(self.connection, job, worker=WORKER)

        self.assertEqual(self.finished[0]["state"], "unknown")

    def test_oversized_stdout_is_an_internal_error_without_being_parsed(self) -> None:
        with mock.patch.object(
            execution,
            "run",
            return_value=completed(stdout='{"outcome":"done"}', stdout_error="too_large"),
        ):
            worker.run_one_job(self.connection, claimed(), worker=WORKER)

        self.assertEqual(self.finished[0]["state"], "unknown")
        self.assertEqual(self.finished[0]["outcome"], "unknown")
        self.assertEqual(
            self.finished[0]["result"]["error"]["code"],
            "internal_error",
        )


class ThingsThatNeverRan(WorkerTestCase):
    def test_a_refused_payload_blocks_the_job_without_running_it(self) -> None:
        with mock.patch.object(execution, "run") as run:
            worker.run_one_job(self.connection, claimed(payload={"force": True}), worker=WORKER)

        run.assert_not_called()
        self.assertEqual(self.finished[0]["state"], "blocked")
        self.assertIsNone(self.finished[0]["exit_code"])

    def test_an_unknown_operation_blocks_the_job(self) -> None:
        with mock.patch.object(execution, "run") as run:
            worker.run_one_job(self.connection, claimed(operation="publish"), worker=WORKER)

        run.assert_not_called()
        self.assertEqual(self.finished[0]["state"], "blocked")


class LosingTheLease(WorkerTestCase):
    def test_a_lost_lease_writes_nothing_at_all(self) -> None:
        #
        # The row belongs to whoever claimed it next. Writing here is the double
        # write the fencing token exists to prevent, and the fact that the
        # database would refuse it is not a reason to try.
        #
        with mock.patch.object(execution, "run", return_value=completed(ending="lease_lost")):
            worker.run_one_job(self.connection, claimed(), worker=WORKER)

        self.assertEqual(self.finished, [])
        self.connection.commit.assert_not_called()

    def test_a_successful_renewal_is_committed_before_the_command_finishes(self) -> None:
        job = claimed()

        def run(*_: object, still_ours: Any, **__: object) -> execution.Completed:
            self.assertTrue(still_ours())
            self.connection.commit.assert_called_once_with()
            return completed(stdout=answer(job))

        with (
            mock.patch.object(execution, "run", side_effect=run),
            mock.patch.object(db, "renew_lease", return_value=True),
        ):
            worker.run_one_job(self.connection, job, worker=WORKER)

        self.assertEqual(self.connection.commit.call_count, 2)

    def test_a_refused_renewal_rolls_back_its_transaction(self) -> None:
        def run(*_: object, still_ours: Any, **__: object) -> execution.Completed:
            self.assertFalse(still_ours())
            return completed(ending="lease_lost")

        with (
            mock.patch.object(execution, "run", side_effect=run),
            mock.patch.object(db, "renew_lease", return_value=False),
        ):
            worker.run_one_job(self.connection, claimed(), worker=WORKER)

        self.connection.rollback.assert_called_once_with()
        self.connection.commit.assert_not_called()


class StoredDiagnosticsAreBounded(WorkerTestCase):
    def test_a_long_stderr_keeps_both_edges_before_the_write(self) -> None:
        job = claimed()
        with mock.patch.object(
            execution,
            "run",
            return_value=completed(
                stdout=answer(job, "failed"), stderr="first" + ("x" * 90000) + "last"
            ),
        ):
            worker.run_one_job(self.connection, job, worker=WORKER)

        excerpt = self.finished[0]["stderr_excerpt"]
        self.assertLessEqual(len(excerpt.encode("utf-8")), worker.STDERR_LIMIT)
        self.assertTrue(excerpt.startswith("first"))
        self.assertTrue(excerpt.endswith("last"))
        self.assertIn("diagnostics truncated", excerpt)


class TheAuditTrail(WorkerTestCase):
    """Every terminal outcome leaves a row, and none of them leaks diagnostics.

    The trail already knew who asked for a job. Until now it did not know how any
    of them ended, which made it a record of intentions rather than of what the
    system did.
    """

    def test_each_terminal_outcome_is_recorded_with_its_stable_code(self) -> None:
        for outcome, state in (
            ("done", "done"),
            ("partial", "partial"),
            ("failed", "failed"),
            ("blocked", "blocked"),
        ):
            with self.subTest(outcome=outcome):
                self.audited.clear()
                job = claimed()
                with mock.patch.object(
                    execution, "run", return_value=completed(stdout=answer(job, outcome))
                ):
                    worker.run_one_job(self.connection, job, worker=WORKER)

                entry = self.audited[0]
                self.assertEqual(entry["action"], "job_finished")
                self.assertEqual(entry["actor"], WORKER)
                self.assertEqual(entry["cluster"], "alpha")
                self.assertEqual(entry["request_id"], job.request_id)
                self.assertEqual(entry["detail"]["state"], state)
                self.assertEqual(entry["detail"]["outcome"], outcome)
                self.assertEqual(entry["detail"]["job"], job.id)
                self.assertEqual(
                    entry["detail"]["error_code"],
                    "synthetic_failure" if outcome in {"failed", "blocked"} else None,
                )

    def test_an_undetermined_ending_is_recorded_rather_than_left_out(self) -> None:
        """`unknown` is the outcome most worth finding later.

        It is the one nothing may retry automatically, so somebody has to go and
        establish what happened - and a trail that recorded only the tidy
        endings would be silent exactly where it is needed.
        """

        with mock.patch.object(
            execution, "run", return_value=completed(ending="timeout", exit_code=None)
        ):
            worker.run_one_job(self.connection, claimed(), worker=WORKER)

        self.assertEqual(self.audited[0]["detail"]["state"], "unknown")
        self.assertIsNone(self.audited[0]["detail"]["exit_code"])

    def test_a_job_refused_before_it_ran_is_recorded_as_blocked(self) -> None:
        with mock.patch.object(execution, "run") as never:
            worker.run_one_job(self.connection, claimed(operation="publish"), worker=WORKER)

        never.assert_not_called()
        self.assertEqual(self.audited[0]["detail"]["state"], "blocked")
        self.assertEqual(self.audited[0]["detail"]["operation"], "publish")

    def test_the_trail_carries_no_stderr_and_no_result_document(self) -> None:
        job = claimed()
        with mock.patch.object(
            execution,
            "run",
            return_value=completed(
                exit_code=70,
                stdout=answer(job, "failed"),
                stderr="ssh: /root/.ssh/id_ed25519 permission denied",
            ),
        ):
            worker.run_one_job(self.connection, job, worker=WORKER)

        detail = self.audited[0]["detail"]
        self.assertNotIn("stderr_excerpt", detail)
        self.assertNotIn("result", detail)
        self.assertNotIn("payload", detail)
        self.assertNotIn("id_ed25519", json.dumps(detail))
        #
        # The job row holds the diagnostics, and holds them redacted: the key
        # path is masked before it is persisted at all. Two separate rules, both
        # worth stating - the trail carries no diagnostics, and the diagnostics
        # that are kept carry no private paths.
        #
        excerpt = self.finished[0]["stderr_excerpt"]
        self.assertNotIn("id_ed25519", excerpt)
        self.assertIn("[REDACTED]", excerpt)

    def test_nothing_is_recorded_when_the_lease_was_already_gone(self) -> None:
        """No result, no trail entry. The row belongs to another worker now, and
        an audit line claiming this one finished it would be the double write
        the fencing token exists to prevent."""

        job = claimed()
        with (
            mock.patch.object(db, "finish_job", return_value=False),
            mock.patch.object(execution, "run", return_value=completed(stdout=answer(job))),
        ):
            worker.run_one_job(self.connection, job, worker=WORKER)

        self.assertEqual(self.audited, [])
        self.connection.rollback.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
