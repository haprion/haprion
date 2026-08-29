"""How a claimed job ends, and what the worker is entitled to write.

The database and the command are both replaced here, because what is being
tested is the decision between four endings - done, blocked, unknown, and
writing nothing at all - and each of them is a rule about entitlement rather
than about SQL.
"""

from __future__ import annotations

import unittest
from datetime import UTC, datetime
from typing import Any
from unittest import mock
from uuid import uuid4

from haproxy_ui import db, execution, worker

TOKEN = uuid4()


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
    ending: str = "finished", exit_code: int | None = 0, stdout: str = "", stderr: str = ""
) -> execution.Completed:
    return execution.Completed(
        ending=ending,  # type: ignore[arg-type]
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
    )


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


class GoodAnswers(WorkerTestCase):
    def test_the_envelopes_outcome_becomes_the_jobs_state(self) -> None:
        with mock.patch.object(
            execution, "run", return_value=completed(stdout='{"outcome": "done", "ok": true}')
        ):
            worker.run_one_job(self.connection, claimed())

        self.assertEqual(self.finished[0]["state"], "done")
        self.assertEqual(self.finished[0]["outcome"], "done")
        self.assertEqual(self.finished[0]["result"], {"outcome": "done", "ok": True})

    def test_partial_is_carried_through_and_not_flattened(self) -> None:
        with mock.patch.object(
            execution, "run", return_value=completed(exit_code=1, stdout='{"outcome": "partial"}')
        ):
            worker.run_one_job(self.connection, claimed())

        self.assertEqual(self.finished[0]["state"], "partial")
        self.assertEqual(self.finished[0]["exit_code"], 1)

    def test_the_claim_token_is_passed_to_the_write(self) -> None:
        with mock.patch.object(
            execution, "run", return_value=completed(stdout='{"outcome":"done"}')
        ):
            worker.run_one_job(self.connection, claimed())

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
            worker.run_one_job(self.connection, claimed())

        self.assertEqual(self.finished[0]["state"], "unknown")

    def test_a_timeout_is_unknown_rather_than_failed(self) -> None:
        with mock.patch.object(
            execution, "run", return_value=completed(ending="timeout", exit_code=None)
        ):
            worker.run_one_job(self.connection, claimed())

        self.assertEqual(self.finished[0]["state"], "unknown")

    def test_an_outcome_the_contract_does_not_define_is_unknown(self) -> None:
        with mock.patch.object(
            execution, "run", return_value=completed(stdout='{"outcome": "probably fine"}')
        ):
            worker.run_one_job(self.connection, claimed())

        self.assertEqual(self.finished[0]["state"], "unknown")


class ThingsThatNeverRan(WorkerTestCase):
    def test_a_refused_payload_blocks_the_job_without_running_it(self) -> None:
        with mock.patch.object(execution, "run") as run:
            worker.run_one_job(self.connection, claimed(payload={"force": True}))

        run.assert_not_called()
        self.assertEqual(self.finished[0]["state"], "blocked")
        self.assertIsNone(self.finished[0]["exit_code"])

    def test_an_unknown_operation_blocks_the_job(self) -> None:
        with mock.patch.object(execution, "run") as run:
            worker.run_one_job(self.connection, claimed(operation="publish"))

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
            worker.run_one_job(self.connection, claimed())

        self.assertEqual(self.finished, [])
        self.connection.commit.assert_not_called()


class StoredDiagnosticsAreBounded(WorkerTestCase):
    def test_a_long_stderr_is_cut_before_the_write(self) -> None:
        with mock.patch.object(
            execution,
            "run",
            return_value=completed(stdout='{"outcome":"failed"}', stderr="x" * 90000),
        ):
            worker.run_one_job(self.connection, claimed())

        self.assertEqual(len(self.finished[0]["stderr_excerpt"]), worker.STDERR_LIMIT)


if __name__ == "__main__":
    unittest.main()
