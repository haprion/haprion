"""How a claimed job ends, and what the worker is entitled to write.

The database and the command are both replaced here, because what is being
tested is the decision between four endings - done, blocked, unknown, and
writing nothing at all - and each of them is a rule about entitlement rather
than about SQL.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from collections.abc import Iterator
from contextlib import nullcontext
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, ClassVar, cast
from unittest import mock
from uuid import uuid4

import psycopg
from haprion import answer_receipt

from haprion_ui import db, execution, operations, worker

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
        attempts=1,
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

        patch = mock.patch("haprion_ui.db.finish_job", side_effect=finish)
        patch.start()
        self.addCleanup(patch.stop)

        self.audited: list[dict[str, Any]] = []

        def audit(_c: object, **fields: Any) -> None:
            self.audited.append(fields)

        trail = mock.patch("haprion_ui.db.record_audit_event", side_effect=audit)
        trail.start()
        self.addCleanup(trail.stop)

        # The machine's own sudo is not asked; `ASudoThatRefuses` asks a stand-in.
        sudo = mock.patch.object(execution, "sudo_refusal", return_value=None)
        sudo.start()
        self.addCleanup(sudo.stop)


class TheResultIsRedactedBeforeItIsStored(WorkerTestCase):
    """Review 2026-10-22, 5-9: a refusal's diagnostics reached the job row as they came."""

    def test_a_password_in_a_refusal_s_diagnostics_is_masked(self) -> None:
        job = claimed()
        refused = result_document(job, "failed")
        refused["error"] = {
            "code": "candidate_invalid",
            "message": "refused",
            "details": {"diagnostics": "pass" + "word=synthetic-password-value\nline 3"},
        }
        worker._finish(
            self.connection,
            job,
            state="failed",
            outcome="failed",
            exit_code=1,
            result=refused,
            stderr_excerpt=None,
            worker="worker-a",
        )
        stored = self.finished[0]["result"]["error"]["details"]["diagnostics"]
        self.assertNotIn("synthetic-password-value", stored)
        self.assertIn("line 3", stored)


class GoodAnswers(WorkerTestCase):
    def test_done_profile_removal_deletes_the_fenced_row_in_the_finish_transaction(self) -> None:
        job = replace(
            claimed(
                operation="dns_profile_apply",
                payload={"profile": "cf-main", "revision": 4, "remove": True},
            ),
            cluster=None,
        )
        with mock.patch.object(db, "delete_dns_profile", return_value=True) as delete:
            finished = worker._finish(
                self.connection,
                job,
                state="done",
                outcome="done",
                exit_code=0,
                result=result_document(job),
                stderr_excerpt=None,
                worker=WORKER,
            )

        self.assertTrue(finished)
        delete.assert_called_once_with(self.connection, "cf-main", 4)
        self.assertEqual(self.audited[0]["detail"]["removed_profile"], "cf-main")

    def test_done_ndes_profile_removal_deletes_its_own_table_row(self) -> None:
        job = replace(
            claimed(
                operation="ndes_profile_apply",
                payload={"profile": "internal-ca", "revision": 2, "remove": True},
            ),
            cluster=None,
        )
        with (
            mock.patch.object(db, "delete_ndes_profile", return_value=True) as delete,
            mock.patch.object(db, "delete_dns_profile") as wrong_table,
        ):
            finished = worker._finish(
                self.connection,
                job,
                state="done",
                outcome="done",
                exit_code=0,
                result=result_document(job),
                stderr_excerpt=None,
                worker=WORKER,
            )

        self.assertTrue(finished)
        delete.assert_called_once_with(self.connection, "internal-ca", 2)
        wrong_table.assert_not_called()
        self.assertEqual(self.audited[0]["detail"]["removed_profile"], "internal-ca")

    def test_a_done_publish_writes_its_renames_in_the_finish_transaction(self) -> None:
        """B253: the alias is written once the publish is done, and never before."""

        renames = {"renamed": {"web": "shop-front"}, "introduced": ["shop-front"]}
        for state, written in (("done", True), ("failed", False), ("blocked", False)):
            with self.subTest(state=state):
                job = claimed(
                    operation="changes_publish", payload={"objects": {}, "backend_renames": renames}
                )
                with mock.patch.object(db, "record_backend_renames") as record:
                    finished = worker._finish(
                        self.connection,
                        job,
                        state=state,
                        outcome=state,
                        exit_code=0 if state == "done" else 1,
                        result=result_document(job, state),
                        stderr_excerpt=None,
                        worker=WORKER,
                    )

                self.assertTrue(finished)
                if written:
                    record.assert_called_once_with(
                        self.connection,
                        cluster=job.cluster,
                        renamed={"web": "shop-front"},
                        introduced=["shop-front"],
                    )
                else:
                    record.assert_not_called()

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

    def test_the_job_runs_under_its_own_operation_s_budget(self) -> None:
        job = replace(
            claimed(
                "cert_issue",
                {"domain": "app.example.com", "method": "http-01", "clusters": ["alpha"]},
            ),
            cluster=None,
        )
        with mock.patch.object(execution, "run", return_value=completed(stdout=answer(job))) as run:
            worker.run_one_job(self.connection, job, worker=WORKER)

        self.assertEqual(run.call_args.kwargs["timeout_seconds"], operations.CERT_TIMEOUT_SECONDS)

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

    def test_a_network_publish_done_result_is_accepted(self) -> None:
        job = claimed(
            operation="changes_publish",
            payload={
                "network": "vips: {}\n",
                "expected_head": "a" * 40,
                "comment": "test",
            },
        )
        with mock.patch.object(execution, "run", return_value=completed(stdout=answer(job))):
            worker.run_one_job(self.connection, job, worker=WORKER)

        self.assertEqual(self.finished[0]["state"], "done")


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

    def test_an_answer_written_before_a_timeout_is_judged_on_what_it_says(self) -> None:
        """Review 26-10-24, 02-04: the checkpoint's blocked was thrown away as unknown."""

        job = claimed()
        with mock.patch.object(
            execution,
            "run",
            return_value=completed(ending="timeout", exit_code=None, stdout=answer(job, "blocked")),
        ):
            worker.run_one_job(self.connection, job, worker=WORKER)

        self.assertEqual(self.finished[0]["state"], "blocked")

    def test_an_outcome_the_contract_does_not_define_is_unknown(self) -> None:
        job = claimed()
        document = result_document(job)
        document["outcome"] = "probably fine"
        with mock.patch.object(
            execution, "run", return_value=completed(stdout=json.dumps(document))
        ):
            worker.run_one_job(self.connection, job, worker=WORKER)

        self.assertEqual(self.finished[0]["state"], "unknown")

    def test_done_with_a_failed_process_is_unknown(self) -> None:
        # Review 26-10-13, L2: the envelope was believed over the exit code.
        for exit_code in (70, None):
            with self.subTest(exit_code=exit_code):
                job = claimed()
                self.finished.clear()
                with mock.patch.object(
                    execution,
                    "run",
                    return_value=completed(stdout=answer(job), exit_code=exit_code),
                ):
                    worker.run_one_job(self.connection, job, worker=WORKER)

                (finished,) = self.finished
                self.assertEqual(finished["state"], "unknown")
                self.assertEqual(finished["exit_code"], exit_code)
                self.assertEqual(finished["result"]["error"]["code"], "exit_mismatch")
                self.assertEqual(finished["result"]["answer"]["outcome"], "done")

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

    def test_no_document_at_all_is_unknown_and_says_it_may_have_acted(self) -> None:
        """A helper behind a socket that went quiet leaves nothing on purpose.

        Its reason is on stderr; the result must not call it an invalid
        document, which reads as a bug rather than an answer that never came.
        """

        with mock.patch.object(
            execution, "run", return_value=completed(stdout="", stderr="ERROR: [helper_silent] x")
        ):
            worker.run_one_job(self.connection, claimed(), worker=WORKER)

        self.assertEqual(self.finished[0]["state"], "unknown")
        self.assertIn("may have acted", self.finished[0]["result"]["error"]["message"])

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


class ASudoThatRefuses(WorkerTestCase):
    """Review 2026-10-22, 6-8: a missing rule was recorded as an operation that may have acted."""

    def test_the_job_is_blocked_and_the_helper_never_started(self) -> None:
        with (
            mock.patch.object(
                execution, "sudo_refusal", return_value="sudo: a password is required"
            ),
            mock.patch.object(execution, "run") as run,
        ):
            worker.run_one_job(self.connection, claimed(), worker=WORKER)

        run.assert_not_called()
        finished = self.finished[0]
        self.assertEqual((finished["state"], finished["outcome"]), ("blocked", "blocked"))
        error = finished["result"]["error"]
        self.assertEqual(error["code"], "dependency_unavailable")
        self.assertIn("nothing ran", error["message"])
        self.assertIn("a password is required", error["message"])


class TheSudoCheck(unittest.TestCase):
    def test_the_check_lists_the_command_and_runs_nothing(self) -> None:
        argv = ("/usr/bin/sudo", "-n", "--", "/opt/haprion/current/bin/haprion-deploy-helper")
        refused = subprocess.CompletedProcess(
            [], 1, stdout="", stderr="sudo: a password is required\n"
        )
        with mock.patch("haprion_ui.execution.subprocess.run", return_value=refused) as ran:
            said = execution.sudo_refusal(argv)

        self.assertEqual(said, "sudo: a password is required")
        self.assertEqual(
            ran.call_args.args[0],
            ["/usr/bin/sudo", "-n", "-l", "/opt/haprion/current/bin/haprion-deploy-helper"],
        )

    def test_a_command_that_is_not_sudo_is_not_asked_about(self) -> None:
        with mock.patch("haprion_ui.execution.subprocess.run") as ran:
            self.assertIsNone(execution.sudo_refusal(("/usr/bin/haprion-cert-receiver-ask",)))
        ran.assert_not_called()


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


class RequestsFromBeforeARestore(WorkerTestCase):
    """Review 26-10-13, R1: a job from a restored backup is not a new request."""

    def test_a_job_older_than_any_queue_is_not_run(self) -> None:
        job = replace(
            claimed(operation="server_state"),
            created_at=datetime.now(UTC) - timedelta(seconds=worker.MAX_PENDING_SECONDS + 60),
        )
        with mock.patch.object(execution, "run") as never:
            worker.run_one_job(self.connection, job, worker=WORKER)

        never.assert_not_called()
        (finished,) = self.finished
        self.assertEqual(finished["state"], "blocked")
        self.assertEqual(finished["result"]["error"]["code"], "request_expired")

    def test_a_job_recovery_requeued_is_judged_already(self) -> None:
        job = replace(
            claimed(),
            attempts=2,
            created_at=datetime.now(UTC) - timedelta(seconds=worker.MAX_PENDING_SECONDS + 60),
        )
        with mock.patch.object(execution, "run", return_value=completed(stdout=answer(job))):
            worker.run_one_job(self.connection, job, worker=WORKER)

        self.assertEqual(self.finished[0]["state"], "done")

    def test_a_job_that_waited_in_an_ordinary_queue_runs(self) -> None:
        job = replace(claimed(), created_at=datetime.now(UTC) - timedelta(minutes=45))
        with mock.patch.object(execution, "run", return_value=completed(stdout=answer(job))):
            worker.run_one_job(self.connection, job, worker=WORKER)

        self.assertEqual(self.finished[0]["state"], "done")


class JobsHeldSinceTheBoot(WorkerTestCase):
    """0082, review 2026-10-20 R1: what an admin said about a held job."""

    def test_a_discarded_job_ends_blocked_and_never_runs(self) -> None:
        job = replace(claimed(), held_decision="discard", held_decided_by="admin")
        with mock.patch.object(execution, "run") as never:
            worker.run_one_job(self.connection, job, worker=WORKER)

        never.assert_not_called()
        (finished,) = self.finished
        self.assertEqual(finished["state"], "blocked")
        self.assertEqual(finished["result"]["error"]["code"], "held_discarded")
        self.assertIn("admin", finished["result"]["error"]["message"])

    def test_a_job_an_admin_let_run_is_not_held_to_the_two_hours(self) -> None:
        job = replace(
            claimed(),
            held_decision="run",
            held_decided_by="admin",
            created_at=datetime.now(UTC) - timedelta(days=3),
        )
        with mock.patch.object(execution, "run", return_value=completed(stdout=answer(job))):
            worker.run_one_job(self.connection, job, worker=WORKER)

        self.assertEqual(self.finished[0]["state"], "done")

    def test_the_boot_is_read_from_the_kernel_and_a_missing_one_holds_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            stat = Path(directory) / "stat"
            stat.write_text("cpu  1 2 3\nbtime 1792526400\nprocesses 9\n")
            self.assertEqual(worker.boot_time(stat), datetime.fromtimestamp(1792526400, UTC))
            self.assertIsNone(worker.boot_time(Path(directory) / "absent"))
        with mock.patch.object(db, "hold_jobs_queued_before") as hold:
            self.assertEqual(
                worker.hold_from_before_boot(self.connection, worker=WORKER, boot=None), []
            )
        hold.assert_not_called()

    def test_held_jobs_are_written_to_the_audit_record(self) -> None:
        boot = datetime(2026, 10, 20, tzinfo=UTC)
        with (
            mock.patch.object(db, "hold_jobs_queued_before", return_value=[4, 7]) as hold,
            mock.patch.object(db, "record_audit_event") as audit,
        ):
            self.assertEqual(
                worker.hold_from_before_boot(self.connection, worker=WORKER, boot=boot), [4, 7]
            )
        hold.assert_called_once_with(self.connection, boot=boot)
        self.assertEqual(audit.call_args.kwargs["action"], "jobs_held")
        self.assertEqual(audit.call_args.kwargs["detail"]["jobs"], [4, 7])

    def test_the_held_jobs_line_agrees_with_its_count(self) -> None:
        """R2 26-10-27 (F20): *1 job ... are held*."""

        boot = datetime(2026, 10, 20, tzinfo=UTC)
        for held, line in (
            ([54], "1 job queued before the manager started is held for an admin: 54"),
            ([4, 7], "2 jobs queued before the manager started are held for an admin: 4, 7"),
        ):
            with (
                self.subTest(held=held),
                mock.patch.object(db, "hold_jobs_queued_before", return_value=held),
                mock.patch.object(db, "record_audit_event"),
                self.assertLogs(worker.logger, "WARNING") as logged,
            ):
                worker.hold_from_before_boot(self.connection, worker=WORKER, boot=boot)
            self.assertEqual(logged.records[0].getMessage(), line)


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


class StoppedUnderARun(WorkerTestCase):
    """Review 26-10-24, 02-01: a stop of the worker kills its helper, and that is not `unknown`."""

    def test_a_helper_silenced_by_the_stop_leaves_the_job_to_recovery(self) -> None:
        with mock.patch.object(execution, "run", return_value=completed(exit_code=-15)):
            worker.run_one_job(self.connection, claimed(), worker=WORKER, stopping=lambda: True)

        self.assertEqual(self.finished, [])

    def test_a_helper_that_answered_before_the_stop_is_judged_on_its_answer(self) -> None:
        job = claimed()
        with mock.patch.object(execution, "run", return_value=completed(stdout=answer(job))):
            worker.run_one_job(self.connection, job, worker=WORKER, stopping=lambda: True)

        (finished,) = self.finished
        self.assertEqual(finished["state"], "done")

    def test_without_a_stop_a_silent_helper_is_still_unknown(self) -> None:
        with mock.patch.object(execution, "run", return_value=completed(exit_code=-15)):
            worker.run_one_job(self.connection, claimed(), worker=WORKER)

        (finished,) = self.finished
        self.assertEqual(finished["state"], "unknown")


class ADatabaseThatDropsUnderARun(WorkerTestCase):
    """Review 2026-10-22, 1B-6: one failed renewal stopped the operation and the worker."""

    def test_a_failed_renewal_is_not_a_lost_lease_while_the_lease_holds(self) -> None:
        job = claimed()

        def run(*_: object, still_ours: Any, **__: object) -> execution.Completed:
            self.assertTrue(still_ours())
            return completed(stdout=answer(job))

        with (
            mock.patch.object(execution, "run", side_effect=run),
            mock.patch.object(
                db, "renew_lease", side_effect=psycopg.OperationalError("server closed")
            ),
        ):
            worker.run_one_job(self.connection, job, worker=WORKER)

        self.assertEqual(self.finished[0]["state"], "done")

    def test_renewals_that_keep_failing_stop_the_run_before_the_lease_runs_out(self) -> None:
        clock = iter((1000.0, 1000.0 + worker.LEASE_SECONDS - worker.LEASE_MARGIN_SECONDS))

        def run(*_: object, still_ours: Any, **__: object) -> execution.Completed:
            self.assertFalse(still_ours())
            return completed(ending="lease_lost")

        with (
            mock.patch("haprion_ui.worker.time.monotonic", side_effect=lambda: next(clock)),
            mock.patch.object(execution, "run", side_effect=run),
            mock.patch.object(
                db, "renew_lease", side_effect=psycopg.OperationalError("server closed")
            ),
        ):
            worker.run_one_job(self.connection, claimed(), worker=WORKER)

        self.assertEqual(self.finished, [])

    def test_a_dropped_connection_is_renewed_and_finished_on_a_fresh_one(self) -> None:
        job = claimed()
        self.connection.broken = True
        fresh = mock.MagicMock()
        renewed_on: list[object] = []

        def renew(connection: object, **_: object) -> bool:
            renewed_on.append(connection)
            return True

        def run(*_: object, still_ours: Any, **__: object) -> execution.Completed:
            self.assertTrue(still_ours())
            return completed(stdout=answer(job))

        with (
            mock.patch.object(execution, "run", side_effect=run),
            mock.patch.object(db, "renew_lease", side_effect=renew),
        ):
            worker.run_one_job(
                self.connection, job, worker=WORKER, connect=lambda: nullcontext(fresh)
            )

        self.assertEqual(renewed_on, [fresh])
        self.assertEqual(self.finished[0]["state"], "done")
        fresh.commit.assert_called()
        self.connection.commit.assert_not_called()

    def test_an_end_that_cannot_be_written_yet_is_tried_again_while_the_lease_holds(
        self,
    ) -> None:
        job = claimed()
        tries: list[str] = []

        def finish(_c: object, **fields: Any) -> bool:
            tries.append(fields["state"])
            if len(tries) == 1:
                raise psycopg.OperationalError("the database system is starting up")
            self.finished.append(fields)
            return True

        with (
            mock.patch.object(execution, "run", return_value=completed(stdout=answer(job))),
            mock.patch.object(db, "finish_job", side_effect=finish),
            mock.patch("haprion_ui.worker.time.sleep") as slept,
        ):
            worker.run_one_job(
                self.connection, job, worker=WORKER, connect=lambda: nullcontext(self.connection)
            )

        self.assertEqual(tries, ["done", "done"])
        slept.assert_called_once_with(worker.FINISH_RETRY_SECONDS)
        self.assertEqual(self.finished[0]["state"], "done")


class AnEndTheDatabaseWillNotStore(WorkerTestCase):
    """Review 26-10-24, 07-03: a DataError in the finish stopped the worker and lost the job."""

    def test_the_job_ends_unknown_without_the_answer(self) -> None:
        job = claimed()
        tries: list[dict[str, Any]] = []

        def finish(_c: object, **fields: Any) -> bool:
            tries.append(fields)
            if len(tries) == 1:
                raise psycopg.DataError("unsupported Unicode escape sequence")
            self.finished.append(fields)
            return True

        with (
            mock.patch.object(execution, "run", return_value=completed(stdout=answer(job))),
            mock.patch.object(db, "finish_job", side_effect=finish),
        ):
            worker.run_one_job(self.connection, job, worker=WORKER)

        self.assertEqual(len(tries), 2)
        (finished,) = self.finished
        self.assertEqual(finished["state"], "unknown")
        self.assertEqual(finished["outcome"], "unknown")
        self.assertEqual(finished["result"]["error"]["code"], "result_unstorable")
        self.assertIsNone(finished["stderr_excerpt"])
        self.connection.rollback.assert_called()

    def test_an_end_refused_twice_is_not_tried_a_third_time(self) -> None:
        job = claimed()
        with (
            mock.patch.object(execution, "run", return_value=completed(stdout=answer(job))),
            mock.patch.object(db, "finish_job", side_effect=psycopg.DataError("no")) as finish,
            self.assertRaises(psycopg.DataError),
        ):
            worker.run_one_job(self.connection, job, worker=WORKER)

        self.assertEqual(finish.call_count, 2)


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
                #
                # Review 26-10-24, 02-03: a partial run's reason is a warning.
                #
                self.assertEqual(
                    entry["detail"].get("warning_codes"),
                    ["synthetic_warning"] if outcome == "partial" else None,
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


class FakeListener:
    """A listener that yields what it was told to, and records its waits."""

    def __init__(self, notifications: list[list[object]]) -> None:
        self._notifications = notifications
        self.waits: list[float | None] = []

    def notifies(
        self, *, timeout: float | None = None, stop_after: int | None = None
    ) -> Iterator[object]:
        self.waits.append(timeout)
        if not self._notifications:
            return
        yield from self._notifications.pop(0)[:stop_after]


class FakeStop:
    """Stops after a given number of checks, the way a signal would."""

    def __init__(self, stop_at: int | None = None) -> None:
        self.stop_at = stop_at
        self.checks = 0

    def requested(self) -> bool:
        self.checks += 1
        return self.stop_at is not None and self.checks > self.stop_at


class WaitingForWork(unittest.TestCase):
    """The wait ends on a job, on the interval, or on a stop - and on nothing else."""

    def test_a_notification_ends_the_wait_immediately(self) -> None:
        listener = FakeListener([[object()]])

        worker._wait_for_work(listener, FakeStop(), 30)  # type: ignore[arg-type]

        # One second-long wait, not thirty: the point of the change.
        self.assertEqual(listener.waits, [1.0])

    def test_no_notification_still_returns_after_the_interval(self) -> None:
        """A lost notification costs latency and nothing else."""

        listener = FakeListener([])

        worker._wait_for_work(listener, FakeStop(), 5)  # type: ignore[arg-type]

        self.assertEqual(len(listener.waits), 5)

    def test_a_stop_is_answered_within_a_second(self) -> None:
        """systemd waits for a service to go; a long interval must not delay it."""

        listener = FakeListener([])

        worker._wait_for_work(listener, FakeStop(stop_at=2), 3600)  # type: ignore[arg-type]

        self.assertLessEqual(len(listener.waits), 2)


class TheWorkerKeepsOutOfTheDraftTable(unittest.TestCase):
    def test_prepare_is_never_handed_a_draft_lookup(self) -> None:
        """The worker holds no grant on `proxy_draft`; a lookup handed in here
        is a crash at run time, not a refusal (2026-09-13)."""

        source = Path(worker.__file__).read_text(encoding="utf-8")
        self.assertNotIn("draft_references", source)
        self.assertNotIn("live_drafts", source)


class NodeChangeAndDeploy(WorkerTestCase):
    """B321: a node change that is all a deploy would roll out is deployed in the same job."""

    def run_job(
        self,
        job: db.ClaimedJob,
        answers: list[Any],
        *,
        stopping: bool = False,
        kept: answer_receipt.Receipt | None = None,
    ) -> list[dict[str, Any]]:
        """Run the job, or with `kept` end it as recovery's adoption does (B367)."""

        calls: list[dict[str, Any]] = []

        def run(_argv: Any, **kwargs: Any) -> execution.Completed:
            request = json.loads(kwargs["request"])
            calls.append(request)
            return cast(execution.Completed, answers.pop(0)(request))

        with mock.patch.object(execution, "run", side_effect=run):
            if kept is not None:
                worker.resume_adopted(self.connection, job, kept, worker=WORKER)
            else:
                worker.run_one_job(self.connection, job, worker=WORKER, stopping=lambda: stopping)
        return calls

    @staticmethod
    def changed(
        job: db.ClaimedJob, *, converged: bool = True, publication: dict[str, Any] | None = None
    ) -> Any:
        def answer_for(_request: dict[str, Any]) -> execution.Completed:
            document = result_document(job)
            document["result"] = {
                "action": "added" if job.payload["action"] == "add" else "removed",
                "converged_before": converged,
                "publication": publication or {"version": 5, "hash": "c" * 40, "changed": True},
            }
            return completed(stdout=json.dumps(document))

        return answer_for

    @staticmethod
    def ran(operation: str, outcome: str = "done") -> Any:
        def answer_for(request: dict[str, Any]) -> execution.Completed:
            document = {
                **result_document(claimed(operation=operation), outcome),
                "request_id": request["request_id"],
            }
            return completed(stdout=json.dumps(document), exit_code=0 if outcome == "done" else 1)

        return answer_for

    def job(self, action: str, **payload: Any) -> db.ClaimedJob:
        fields: dict[str, Any] = {"action": action, "deploy": True}
        fields.update(payload)
        if action == "remove":
            fields.setdefault("node", "node-b")
        else:
            fields.setdefault("block", "block")
            fields.setdefault("host", "node-c.example.com")
        return claimed(operation="cluster_node", payload=fields)

    def test_a_removal_is_deployed_and_the_job_ends_as_the_deploy(self) -> None:
        job = self.job("remove")

        calls = self.run_job(job, [self.changed(job), self.ran("deploy")])

        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[1]["parameters"]["expected_version"], 5)
        (finished,) = self.finished
        self.assertEqual(finished["state"], "done")
        self.assertEqual(finished["result"]["operation"], "deploy")
        self.assertEqual(finished["result"]["step"], "deploy")
        self.assertEqual(finished["result"]["node"]["result"]["action"], "removed")

    def test_an_addition_deploys_certificates_first(self) -> None:
        job = self.job("add")

        calls = self.run_job(job, [self.changed(job), self.ran("cert_deploy"), self.ran("deploy")])

        self.assertEqual(
            [call["operation"] for call in calls[1:]], ["cert_deploy_cluster", "deploy_cluster"]
        )
        self.assertNotEqual(calls[1]["request_id"], calls[2]["request_id"])
        self.assertEqual(self.finished[0]["result"]["operation"], "deploy")

    def test_certificates_that_did_not_deploy_end_the_job_there(self) -> None:
        job = self.job("add")

        calls = self.run_job(job, [self.changed(job), self.ran("cert_deploy", "failed")])

        self.assertEqual(len(calls), 2)
        (finished,) = self.finished
        self.assertEqual(finished["state"], "failed")
        self.assertEqual(finished["result"]["step"], "cert_deploy")
        self.assertEqual(finished["result"]["node"]["result"]["action"], "added")

    def test_a_worker_stopped_during_the_deploy_leaves_the_job_and_the_kept_answer_ends_it(
        self,
    ) -> None:
        """Review 26-10-25 2-01, B367: the node change stands and its deploy is still run.

        The deploy runs under the worker and stops with it; the node helper
        runs behind its socket and kept its answer. Recovery adopts the job,
        and it ends as it would have: the deploy run, the change beside it.
        """

        job = self.job("remove")
        change = self.changed(job)({})

        calls = self.run_job(
            job, [lambda _request: change, lambda _request: completed(exit_code=-15)], stopping=True
        )

        self.assertEqual(len(calls), 2)
        self.assertEqual(self.finished, [])

        kept = answer_receipt.Receipt("answered", stdout=change.stdout, exit_code=0)
        calls = self.run_job(job, [self.ran("deploy")], kept=kept)

        self.assertEqual([call["operation"] for call in calls], ["deploy_cluster"])
        (finished,) = self.finished
        self.assertEqual(finished["state"], "done")
        self.assertEqual(finished["result"]["step"], "deploy")
        self.assertEqual(finished["result"]["node"]["result"]["action"], "removed")

    def test_a_kept_answer_that_says_the_change_failed_ends_the_job_on_it(self) -> None:
        job = self.job("remove")
        refused = result_document(job, "failed")
        refused["error"] = {"code": "node_unreachable", "message": "node-b did not answer"}
        kept = answer_receipt.Receipt("answered", stdout=json.dumps(refused), exit_code=69)

        calls = self.run_job(job, [], kept=kept)

        self.assertEqual(calls, [])
        (finished,) = self.finished
        self.assertEqual((finished["state"], finished["exit_code"]), ("failed", 69))

    def test_what_is_left_to_a_person(self) -> None:
        cases: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {
            "not converged before": ({}, {"converged": False}),
            "publication failed": (
                {},
                {"publication": {"error": {"code": "dirty_worktree", "message": "unsaved"}}},
            ),
            "not asked for": ({"deploy": False}, {}),
        }
        for name, (payload, answer) in cases.items():
            with self.subTest(name):
                self.finished.clear()
                job = self.job("remove", **payload)

                calls = self.run_job(job, [self.changed(job, **answer)])

                self.assertEqual(len(calls), 1)
                self.assertEqual(self.finished[0]["result"]["operation"], "cluster_node")


class PublishAndDeploy(WorkerTestCase):
    """B257: a publish of saved changes asked to deploy runs the deploy in the same job."""

    PAYLOAD: ClassVar[dict[str, Any]] = {
        "objects": {"shop": "schema: 1\n"},
        "expected_head": "a" * 40,
        "comment": "Move the shop",
        "deploy": True,
    }

    def run_job(
        self, job: db.ClaimedJob, answers: list[Any], stopping: Any = lambda: False
    ) -> list[Any]:
        calls: list[Any] = []

        def run(argv: Any, **kwargs: Any) -> execution.Completed:
            calls.append((argv, kwargs["request"]))
            produced = answers.pop(0)
            if callable(produced):
                return cast(execution.Completed, produced(json.loads(kwargs["request"])))
            return cast(execution.Completed, produced)

        with mock.patch.object(execution, "run", side_effect=run):
            worker.run_one_job(self.connection, job, worker=WORKER, stopping=stopping)
        return calls

    def published(self, job: db.ClaimedJob, outcome: str = "done") -> execution.Completed:
        document = result_document(job, outcome)
        if outcome == "done":
            document["result"] = {"version": 27, "changed": True}
        return completed(stdout=json.dumps(document))

    @staticmethod
    def deployed(outcome: str = "done") -> Any:
        def answer_for(request: dict[str, Any]) -> execution.Completed:
            document = {
                **result_document(claimed(), outcome),
                "request_id": request["request_id"],
            }
            return completed(stdout=json.dumps(document), exit_code=0 if outcome == "done" else 1)

        return answer_for

    def test_a_deploy_silenced_by_a_stop_leaves_the_job_to_recovery(self) -> None:
        """02-01: the publish is recorded; the deploy after it is a reconcile, safe to repeat."""

        job = claimed(operation="changes_publish", payload=dict(self.PAYLOAD))

        calls = self.run_job(
            job, [self.published(job), completed(exit_code=-15)], stopping=lambda: True
        )

        self.assertEqual(len(calls), 2)
        self.assertEqual(self.finished, [])

    def test_a_silent_deploy_after_it_is_no_result_not_an_invalid_document(self) -> None:
        """Review 26-10-24, 02-05: the second step's silence was called a wrong answer."""

        job = claimed(operation="changes_publish", payload=dict(self.PAYLOAD))

        self.run_job(job, [self.published(job), completed(exit_code=1)])

        (finished,) = self.finished
        self.assertEqual(finished["state"], "unknown")
        self.assertIn("without a result document", finished["result"]["error"]["message"])

    def test_the_deploy_follows_the_publish_and_ends_the_job(self) -> None:
        job = claimed(operation="changes_publish", payload=dict(self.PAYLOAD))

        calls = self.run_job(job, [self.published(job), self.deployed()])

        self.assertEqual(len(calls), 2)
        deploy = json.loads(calls[1][1])
        self.assertEqual(deploy["operation"], "deploy_cluster")
        self.assertEqual(deploy["parameters"]["expected_version"], 27)
        self.assertNotEqual(deploy["request_id"], str(job.request_id))
        (finished,) = self.finished
        self.assertEqual(finished["state"], "done")
        self.assertEqual(finished["result"]["operation"], "deploy")
        self.assertEqual(finished["result"]["publish"]["result"]["version"], 27)

    def test_a_failed_deploy_keeps_the_publish_beside_it(self) -> None:
        job = claimed(operation="changes_publish", payload=dict(self.PAYLOAD))

        self.run_job(job, [self.published(job), self.deployed("failed")])

        (finished,) = self.finished
        self.assertEqual(finished["state"], "failed")
        self.assertEqual(finished["result"]["error"]["code"], "synthetic_failure")
        self.assertEqual(finished["result"]["step"], "deploy")
        self.assertEqual(finished["result"]["publish"]["outcome"], "done")

    def test_a_refused_publish_deploys_nothing(self) -> None:
        job = claimed(operation="changes_publish", payload=dict(self.PAYLOAD))

        calls = self.run_job(job, [self.published(job, "blocked")])

        self.assertEqual(len(calls), 1)
        self.assertEqual(self.finished[0]["state"], "blocked")

    def test_without_the_flag_only_the_publish_runs(self) -> None:
        payload = {key: value for key, value in self.PAYLOAD.items() if key != "deploy"}
        job = claimed(operation="changes_publish", payload=payload)

        calls = self.run_job(job, [self.published(job)])

        self.assertEqual(len(calls), 1)
        self.assertEqual(self.finished[0]["result"]["operation"], "changes_publish")

    def test_a_retry_asks_the_deploy_under_the_same_id(self) -> None:
        job = claimed(operation="changes_publish", payload=dict(self.PAYLOAD))
        first = self.run_job(job, [self.published(job), self.deployed()])
        second = self.run_job(job, [self.published(job), self.deployed()])

        self.assertEqual(
            json.loads(first[1][1])["request_id"], json.loads(second[1][1])["request_id"]
        )

    def test_a_publish_done_with_a_failed_process_deploys_nothing(self) -> None:
        job = claimed(operation="changes_publish", payload=dict(self.PAYLOAD))
        document = result_document(job)
        document["result"] = {"version": 27, "changed": True}

        calls = self.run_job(job, [completed(stdout=json.dumps(document), exit_code=70)])

        self.assertEqual(len(calls), 1)
        self.assertEqual(self.finished[0]["state"], "unknown")

    def test_a_deploy_done_with_a_failed_process_is_unknown(self) -> None:
        job = claimed(operation="changes_publish", payload=dict(self.PAYLOAD))

        def failed_after(request: dict[str, Any]) -> execution.Completed:
            done = cast(execution.Completed, self.deployed()(request))
            return completed(stdout=done.stdout, exit_code=70)

        self.run_job(job, [self.published(job), failed_after])

        (finished,) = self.finished
        self.assertEqual(finished["state"], "unknown")
        self.assertEqual(finished["result"]["error"]["code"], "exit_mismatch")
        self.assertEqual(finished["result"]["publish"]["outcome"], "done")

    def test_a_deploy_answer_for_another_request_is_not_accepted(self) -> None:
        job = claimed(operation="changes_publish", payload=dict(self.PAYLOAD))
        wrong = completed(stdout=json.dumps(result_document(claimed())))

        self.run_job(job, [self.published(job), wrong])

        self.assertEqual(self.finished[0]["state"], "unknown")

    def test_renames_are_written_when_the_publish_was_done_and_the_deploy_was_not(self) -> None:
        renames = {"renamed": {"web": "shop-front"}, "introduced": ["shop-front"]}
        job = claimed(
            operation="changes_publish", payload={**self.PAYLOAD, "backend_renames": renames}
        )
        with mock.patch.object(db, "record_backend_renames") as record:
            self.run_job(job, [self.published(job), self.deployed("failed")])

        record.assert_called_once()

    def test_a_refused_deploy_after_it_is_said_as_the_job_s_own_refusal_is(self) -> None:
        """Review 26-10-24, 07-05: an invalid result document, with the reason in the log only."""

        job = claimed(operation="changes_publish", payload=dict(self.PAYLOAD))
        prepare = operations.prepare

        def refuse_the_deploy(**fields: Any) -> operations.Prepared:
            if fields["operation"] == "deploy":
                raise operations.BadPayload("expected_version must be a version")
            return prepare(**fields)

        with (
            mock.patch.object(operations, "prepare", side_effect=refuse_the_deploy),
            self.assertLogs("haprion_ui.worker", "ERROR"),
        ):
            calls = self.run_job(job, [self.published(job)])

        self.assertEqual(len(calls), 1)
        (finished,) = self.finished
        self.assertEqual(finished["state"], "blocked")
        self.assertNotIn("error", finished["result"])
        self.assertEqual(finished["result"]["step"], "deploy")
        self.assertEqual(finished["stderr_excerpt"], "expected_version must be a version")

    def test_a_run_after_it_is_judged_as_the_job_s_own_run_is(self) -> None:
        """Review 26-10-24, 07-05: one table of endings, held to both paths."""

        def deploy_said(outcome: str, exit_code: int) -> Any:
            def answer_for(request: dict[str, Any]) -> execution.Completed:
                document = {
                    **result_document(claimed(), outcome),
                    "request_id": request["request_id"],
                }
                return completed(stdout=json.dumps(document), exit_code=exit_code)

            return answer_for

        endings: dict[str, Any] = {
            "done": deploy_said("done", 0),
            "failed": deploy_said("failed", 1),
            "done but exited 70": deploy_said("done", 70),
            "silent": lambda _r: completed(exit_code=1),
            "not a document": lambda _r: completed(stdout="Segmentation fault", exit_code=1),
            "timed out": lambda _r: completed(ending="timeout", exit_code=None),
            "not UTF-8": lambda _r: completed(stdout_error="not_utf8"),
        }
        for ending, answer_for in endings.items():
            with self.subTest(ending):
                self.finished.clear()
                own = claimed()
                self.run_job(own, [answer_for({"request_id": str(own.request_id)})])
                (alone,) = self.finished

                self.finished.clear()
                job = claimed(operation="changes_publish", payload=dict(self.PAYLOAD))
                self.run_job(job, [self.published(job), answer_for])
                (after,) = self.finished

                self.assertEqual(after["state"], alone["state"])
                self.assertEqual(after["outcome"], alone["outcome"])
                self.assertEqual(
                    (after["result"] or {}).get("error"), (alone["result"] or {}).get("error")
                )


class FakeConnection:
    """A listening connection that fails its waits as a restarted server does."""

    def __init__(self, fails: bool) -> None:
        self.fails = fails
        self.closed = False
        self.executed: list[object] = []

    def execute(self, statement: object) -> None:
        self.executed.append(statement)

    def notifies(self, *, timeout: float, stop_after: int | None = None) -> Iterator[object]:
        if self.fails:
            raise psycopg.OperationalError("server closed the connection unexpectedly")
        yield object()

    def close(self) -> None:
        self.closed = True


class AListenerOutlivesARestart(unittest.TestCase):
    """Review 26-10-24, 07-04: a PostgreSQL restart ended the worker and the poller."""

    def test_the_wait_is_slept_and_the_next_one_listens_again(self) -> None:
        dropped, fresh = FakeConnection(fails=True), FakeConnection(fails=False)
        database = mock.Mock(connection_string="dbname=haprion")
        with (
            mock.patch("haprion_ui.db.core.psycopg.connect", side_effect=[dropped, fresh]),
            mock.patch("haprion_ui.db.core.time.sleep") as slept,
            self.assertLogs("haprion_ui.db", "WARNING"),
        ):
            listener = db.listener(database)
            worker._wait_for_work(listener, FakeStop(stop_at=1), 30)  # type: ignore[arg-type]
            slept.assert_called_once_with(1.0)
            self.assertTrue(dropped.closed)

            self.assertEqual(len(list(listener.notifies(timeout=1.0, stop_after=1))), 1)
        self.assertEqual(len(fresh.executed), 1)

    def test_a_server_still_down_is_waited_out_and_never_raised(self) -> None:
        database = mock.Mock(connection_string="dbname=haprion")
        with (
            mock.patch(
                "haprion_ui.db.core.psycopg.connect",
                side_effect=[FakeConnection(fails=True), psycopg.OperationalError("refused")],
            ),
            mock.patch("haprion_ui.db.core.time.sleep") as slept,
            self.assertLogs("haprion_ui.db", "WARNING"),
        ):
            listener = db.listener(database)
            worker._wait_for_work(listener, FakeStop(stop_at=2), 30)  # type: ignore[arg-type]
        self.assertEqual(slept.call_count, 2)


class TheWebPoolTriesAConnectionBeforeLendingIt(unittest.TestCase):
    """Review 26-10-24, 07-04: after a restart the pool lent out dead connections."""

    def test_the_pool_checks(self) -> None:
        with mock.patch("haprion_ui.db.core.ConnectionPool") as made:
            db.pool(mock.Mock(connection_string="dbname=haprion"))
        self.assertIs(made.call_args.kwargs.get("check"), made.check_connection)


if __name__ == "__main__":
    unittest.main()
