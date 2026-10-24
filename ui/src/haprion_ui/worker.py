"""The worker: the only identity that may turn a queued job into an operation.

One job at a time, claimed atomically, run under a lease, and finished with a
write the database refuses if the lease was lost meanwhile. Management writes
stay switched off until an installation turns them on, and with them off the
worker is installed, running and provably unable to act - which is a stronger
statement than not installing it, because it is the state a rollback returns to.

How a run ends and what the operation said are two different questions. A
command that was stopped because this worker lost its lease has no result worth
storing, and a command that ran and failed has one. `unknown` is reserved for
the case that is neither: the operation may or may not have taken effect, and
saying anything more definite would be a guess written into a table.

Why the worker exists at all, when the web process could call the same commands:
it could not. The web identity holds no sudo rule, no membership of the
management group, and no path to a key. A web intrusion can therefore ask for
one of the operations the web role is allowed to queue - that is what makes the
interface work - and cannot choose the command, the arguments, the cluster's
lock, or what the result says happened.
"""

from __future__ import annotations

import logging
import os
import socket
import sys
import time
from collections.abc import Callable, Sequence
from contextlib import AbstractContextManager, suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from uuid import UUID, uuid5

import psycopg

from haprion_ui import answers, db, diagnostics, execution, labels, operations, recovery, service
from haprion_ui.config import DEFAULT_CONFIG_PATH
from haprion_ui.config import load as load_config
from haprion_ui.service import StopRequest

logger = logging.getLogger("haprion_ui.worker")

IDLE_SECONDS = 30

#
# The lease is short relative to the renewal tick, so a worker that dies takes a
# predictable and small amount of time to be recognised as gone - and long enough
# that a slow database round trip does not cost a worker its own job.
#
# It also has to outlast the slowest way a run can end, which is a number that
# lives in `execution.py` rather than here: a tick's wait since the last
# renewal, the lifeline's grace, a SIGTERM grace, a SIGKILL grace, and two
# thread joins. If the stop path outlives the lease, `finish_job` is refused and
# an operation that actually completed is re-adjudicated instead of recorded.
#
# That fails in the safe direction, and the measured stop was two seconds rather
# than the arithmetic's worst case - so this is 60 rather than something with
# more headroom, because doubling it would double how long an abandoned job
# blocks its cluster to buy margin against a case that has not happened.
# `tests/test_execution.py` holds the two files to the arithmetic instead.
#
LEASE_SECONDS = 60

#
# How old a job may be when it is first taken. A database brought back from a
# dump or the host from an image holds the jobs that were waiting at that
# moment, and those ran then: a Drain since replaced by Ready would run again
# as a new request (review 26-10-13, R1). Two hours is above the longest
# queue that happens - one job per cluster, 900 s each, a certificate job
# longer - and below the age of any backup worth restoring.
#
MAX_PENDING_SECONDS = 2 * 60 * 60

#
# The contract's cap on stored diagnostics, applied before the write rather than
# discovered at the constraint.
#
STDERR_LIMIT = diagnostics.LIMIT_BYTES


def worker_identity() -> str:
    """Who is holding a job, in a form that means something during an incident.

    Host and process, because "which worker" is a question somebody asks while
    looking at a row that has been running for too long, and the answer has to
    lead to a process on a machine.
    """

    return f"{socket.gethostname()}/{os.getpid()}"


_OPERATION_OUTCOMES = {
    "backup_run": frozenset({"done", "partial", "failed"}),
    "backup_schedule": frozenset({"done", "failed"}),
    #
    # A restore that undid itself is `failed` with `rolled_back` in its result
    # (B176), not a status of its own; `blocked` is a refusal before anything
    # was written on the target.
    #
    "node_restore_prepare": frozenset({"done", "failed", "blocked"}),
    "node_restore_preview": frozenset({"done", "failed", "blocked"}),
    "node_restore": frozenset({"done", "failed", "blocked"}),
    "node_restore_discard": frozenset({"done", "failed", "blocked"}),
    "node_restore_status": frozenset({"done", "failed", "blocked"}),
    "deploy": frozenset({"done", "partial", "failed", "blocked"}),
    "cert_deploy": frozenset({"done", "partial", "failed", "blocked"}),
    "revert": frozenset({"done", "failed", "blocked"}),
    "changes_publish": frozenset({"done", "failed", "blocked"}),
    #
    # `cert_publish` and `cert_target` can end `partial`, and the reason is one
    # real registry entry rather than a theory: a certificate whose source is an
    # import whose material has not arrived yet is skipped with a warning instead
    # of failing the run, and a registry holding one reaches this on every run.
    #
    # `cert_issue` cannot. It publishes exactly the certificate it has just
    # obtained, and that one is never skipped for missing material - so the
    # narrower set is the true one, and a `partial` from that helper would mean
    # something nobody has thought about.
    #
    "cert_issue": frozenset({"done", "failed", "blocked"}),
    #
    # `cert_import` publishes exactly the certificate it has just written,
    # as `cert_issue` does, so the same narrower set is the true one.
    #
    "cert_import": frozenset({"done", "failed", "blocked"}),
    #
    # `cert_request` makes a key and a CSR or refuses to; nothing is
    # published, so there is no half.
    #
    "cert_request": frozenset({"done", "failed", "blocked"}),
    #
    # `dns_profile_apply` writes one file or refuses to; there is no half.
    #
    "ndes_profile_apply": frozenset({"done", "failed", "blocked"}),
    "dns_profile_apply": frozenset({"done", "failed", "blocked"}),
    #
    # `cert_scep` has a real half: the CA holding the request. That is
    # `partial` - the key is kept and the same request is resumed later.
    #
    "cert_scep": frozenset({"done", "partial", "failed", "blocked"}),
    #
    # `cert_delete` answers per certificate: `partial` is the normal shape of
    # a batch with one refusal in it, `blocked` a batch where every row was
    # refused and nothing touched.
    #
    "cert_delete": frozenset({"done", "partial", "failed", "blocked"}),
    "cert_publish": frozenset({"done", "partial", "failed", "blocked"}),
    "cert_target": frozenset({"done", "partial", "failed", "blocked"}),
    #
    # `cert_receiver` registers or removes one receiver. `partial` is a
    # removal whose account or directory could not be taken away after the
    # registry and the lock already were; there is no `blocked`, because a
    # refusal is a `failed` envelope with the command's own code.
    #
    "cert_receiver": frozenset({"done", "partial", "failed"}),
    #
    # `cluster_node` adds or removes one node, all six files or none. `blocked`
    # is a node that did not answer as itself (every file put back), the node
    # holding the VIP, or the cluster busy; the helper has no half to answer
    # `partial` with. The deploy that follows a node change (B321) is judged on
    # its own, and that one can leave the job `partial`.
    #
    "cluster_node": frozenset({"done", "failed", "blocked"}),
    #
    # `cluster_define` creates or removes a whole cluster as one change: a node
    # that does not answer as itself (`blocked`) takes back the repository and
    # every file with it. A timer that would not stop is a warning on `done`.
    #
    "cluster_define": frozenset({"done", "failed", "blocked"}),
    #
    # `server_state` sets servers on every node: `partial` is a node that did
    # not take one while another did. No `blocked` - there is no lock to meet,
    # and a refused request fails before any node is asked.
    #
    "server_state": frozenset({"done", "partial", "failed"}),
    #
    # `dynamic_unblock` lifts a block on every node, the same way (B271).
    #
    "dynamic_unblock": frozenset({"done", "partial", "failed"}),
}


def _envelope(
    stdout: str, job: db.ClaimedJob, *, operation: str | None = None, request_id: str | None = None
) -> dict[str, Any] | None:
    """Accept only the common v1 envelope bound to this exact claimed job.

    The operation helpers own their operation-specific result schemas. The
    worker still owns the boundary that says whose answer this is: accepting a
    valid deploy result carrying another request ID would turn request binding
    into decoration rather than fencing. The check itself is shared with the
    poller (`answers`).
    """

    expected = operation or job.operation
    return answers.accepted(
        stdout,
        operation=expected,
        cluster=job.cluster,
        request_id=request_id or str(job.request_id),
        outcomes=_OPERATION_OUTCOMES.get(expected, frozenset()),
    )


def _error_code(result: dict[str, Any] | None) -> str | None:
    """The stable code a result blamed, or nothing.

    Codes are part of the frozen contract and are safe to keep: they are chosen
    from a fixed list, they do not vary with the environment, and they are the
    one part of a failure a person can act on months later. The message, the
    diagnostics and the command's stderr are none of those things and stay out
    of the trail.
    """

    error = (result or {}).get("error")
    if isinstance(error, dict) and isinstance(error.get("code"), str):
        return str(error["code"])
    return None


def _warning_codes(result: dict[str, Any] | None) -> list[str]:
    """The warnings' codes, kept for the reason `_error_code` keeps its one.

    A partial run carries its reason among them and no error (review 26-10-24,
    02-03), so a trail of error codes alone said nothing about why.
    """

    listed = (result or {}).get("warnings")
    codes = [
        entry["code"]
        for entry in (listed if isinstance(listed, list) else ())
        if isinstance(entry, dict) and isinstance(entry.get("code"), str)
    ]
    return list(dict.fromkeys(codes))


def _finish(
    connection: Any,
    job: db.ClaimedJob,
    *,
    state: str,
    outcome: str | None,
    exit_code: int | None,
    result: dict[str, Any] | None,
    stderr_excerpt: str | None,
    worker: str,
) -> bool:
    """Write how a job ended, and record it, in one transaction.

    The audit row goes in beside the result rather than after it. A trail that
    commits separately from the thing it describes is a trail that can disagree
    with the job table, and the disagreement would surface during an incident -
    which is the one time nobody can afford to work out which of two records is
    the true one.

    What it deliberately does not carry: the result document, the operation's
    stderr and the payload. The trail answers who ran what against which cluster
    and how it ended. Raw diagnostics are held on the job row, behind the roles
    that may read it, and the contract forbids showing them to a reader anyway.
    """

    if not db.finish_job(
        connection,
        job_id=job.id,
        claim_token=job.claim_token,
        state=state,
        exit_code=exit_code,
        outcome=outcome,
        result=diagnostics.redact_result(result),
        stderr_excerpt=stderr_excerpt,
    ):
        logger.error("job %s could not be finished; its lease was gone", job.id)
        connection.rollback()
        return False

    removed_profile: str | None = None
    if (
        state == "done"
        and job.operation in {"dns_profile_apply", "ndes_profile_apply"}
        and job.payload.get("remove") is True
    ):
        profile = job.payload.get("profile")
        revision = job.payload.get("revision")
        delete_row = (
            db.delete_dns_profile
            if job.operation == "dns_profile_apply"
            else db.delete_ndes_profile
        )
        if (
            not isinstance(profile, str)
            or type(revision) is not int
            or not delete_row(connection, profile, revision)
        ):
            logger.error("job %s removed profile files but its fenced database row changed", job.id)
            connection.rollback()
            return False
        removed_profile = profile

    #
    # A publish that renamed a pool keeps its history under the new name
    # (B253). Written here, beside the job's ending, because only a done
    # publish put the new name in a version; one refused or failed after it
    # was queued would otherwise have handed the old name's readings to
    # whatever is given the new name later. A publish that committed and then
    # failed to install leaves the card starting afresh, which is the loss of a
    # history and never a wrong one.
    #
    renames = job.payload.get("backend_renames")
    #
    # A publish followed by a deploy in the same job (B257) published even
    # when the deploy did not; its own answer is under `publish`.
    #
    embedded = (result or {}).get("publish")
    published = state == "done" or (
        isinstance(embedded, dict) and embedded.get("outcome") == "done"
    )
    if (
        published
        and job.operation == "changes_publish"
        and job.cluster is not None
        and isinstance(renames, dict)
    ):
        db.record_backend_renames(
            connection,
            cluster=job.cluster,
            renamed=dict(renames.get("renamed") or {}),
            introduced=list(renames.get("introduced") or ()),
        )

    db.record_audit_event(
        connection,
        actor=worker,
        action="job_finished",
        cluster=job.cluster,
        request_id=job.request_id,
        detail={
            "job": job.id,
            "operation": job.operation,
            "state": state,
            "outcome": outcome,
            "exit_code": exit_code,
            "error_code": _error_code(result),
            **({"warning_codes": codes} if (codes := _warning_codes(result)) else {}),
            **({"removed_profile": removed_profile} if removed_profile is not None else {}),
        },
    )
    connection.commit()
    logger.info("job %s ended as %s", job.id, state)
    return True


def _internal_error() -> dict[str, Any]:
    return {
        "error": {
            "code": "internal_error",
            "message": "the operation returned an invalid result document",
        }
    }


def _sudo_refused(argv: Sequence[str], refused: str) -> dict[str, Any]:
    return {
        "error": {
            "code": "dependency_unavailable",
            "message": (
                f"sudo does not let the worker run {argv[-1]}, so nothing ran: {refused}."
                " Platform step 07 installs the worker's rules"
            ),
        }
    }


def _no_result() -> dict[str, Any]:
    #
    # Nothing at all is a different answer from a wrong one: a helper behind a
    # socket that went quiet leaves no document on purpose, and may have acted.
    # Its sentence is in the stderr excerpt beside this.
    #
    return {
        "error": {
            "code": "internal_error",
            "message": "the operation ended without a result document and may have acted",
        }
    }


def _judged(
    envelope: dict[str, Any], completed: execution.Completed
) -> tuple[str, str, dict[str, Any]]:
    """State, outcome and result of a run whose envelope was accepted.

    `done` also needs the process to have exited 0. A helper that wrote a done
    envelope and then failed, or a wrapper that failed after it, is not a
    success the worker may record - and on Publish & deploy it would let the
    deploy follow (review 26-10-13, L2). Nothing says what did take effect, so
    the job is `unknown` with the envelope kept beside the code.
    """

    outcome = str(envelope.get("outcome", "unknown"))
    if outcome == "done" and completed.exit_code != 0:
        return (
            "unknown",
            "unknown",
            {
                "error": {
                    "code": "exit_mismatch",
                    "message": (
                        f"the operation answered done but exited {completed.exit_code}"
                        " and may not have finished"
                    ),
                },
                "answer": envelope,
            },
        )
    state = outcome if outcome in {"done", "partial", "failed", "blocked"} else "unknown"
    return state, outcome, envelope


def _judge_run(
    completed: execution.Completed, envelope: dict[str, Any] | None
) -> tuple[str, str, dict[str, Any] | None]:
    """State, outcome and result of a finished run: a job's own, and a run after it.

    One judgement for both. The two had drifted: a silent second step was
    called an invalid document, and an answer written before a timeout was
    thrown away (review 26-10-24, 02-04 and 02-05).

    - A document beyond the hard cap, or not UTF-8, is no contract document;
      the operation may still have taken effect, so `unknown`.
    - An accepted envelope is judged on what it says, also after a timeout: a
      helper that answered at its checkpoint and was then stopped said what it
      did. A `done` without exit 0 stays `unknown` (`_judged`).
    - A timeout with no answer may have finished its work first: `unknown`,
      never retried automatically.
    - Nothing at all is a different answer from a wrong one.
    """

    if completed.stdout_error is not None:
        return "unknown", "unknown", _internal_error()
    if envelope is not None:
        return _judged(envelope, completed)
    if completed.ending == "timeout":
        return "unknown", "unknown", None
    return "unknown", "unknown", _no_result() if not completed.stdout.strip() else _internal_error()


def _sealed_profile(
    connection: Any, profile_id: str, *, ndes: bool = False
) -> operations.SealedProfileRow | None:
    """The one row a profile job needs, read as the worker under its own grant."""

    row = (
        db.sealed_ndes_profile(connection, profile_id)
        if ndes
        else db.sealed_profile(connection, profile_id)
    )
    if row is None:
        return None
    return operations.SealedProfileRow(
        id=row.id,
        provider_id=row.provider_id,
        schema_version=row.schema_version,
        key_id=row.key_id,
        revision=row.revision,
        ciphertext=bytes(row.ciphertext),
    )


#
# How long before the lease runs out, by this worker's clock, a renewal that
# keeps failing stops the run: two ticks, so the stop is ours and not another
# worker's claim.
#
LEASE_MARGIN_SECONDS = 2 * int(execution.TICK_SECONDS)
FINISH_RETRY_SECONDS = 5


def _broken(connection: Any) -> bool:
    return (
        getattr(connection, "broken", False) is True or getattr(connection, "closed", False) is True
    )


def _renewed(connection: Any, job: db.ClaimedJob) -> bool:
    ours = db.renew_lease(
        connection,
        job_id=job.id,
        claim_token=job.claim_token,
        lease_seconds=LEASE_SECONDS,
    )
    if ours:
        #
        # A renewal hidden inside this transaction is invisible to every
        # other worker, and the role's ten-second idle-in-transaction limit
        # would then terminate the connection while the CLI is running.
        # Each tick is therefore its own completed database transaction.
        #
        connection.commit()
    else:
        connection.rollback()
    return ours


def _finish_on(
    connection: Any,
    connect: Callable[[], AbstractContextManager[Any]] | None,
    renewed_at: Callable[[], float],
    job: db.ClaimedJob,
    **fields: Any,
) -> None:
    """`_finish`, on a fresh connection when the job's was dropped, while the lease holds.

    Gives up while the lease is still this worker's, so that the job is left
    `running` for recovery to settle and never written by two workers.
    """

    while True:
        try:
            if connect is not None and _broken(connection):
                with connect() as fresh:
                    _finish(fresh, job, **fields)
            else:
                _finish(connection, job, **fields)
            return
        except psycopg.OperationalError as exc:
            left = renewed_at() + LEASE_SECONDS - LEASE_MARGIN_SECONDS - time.monotonic()
            if connect is None or left <= FINISH_RETRY_SECONDS:
                logger.error(
                    "job %s: its end could not be written (%s); recovery settles it", job.id, exc
                )
                raise
            logger.warning("job %s: its end could not be written yet (%s)", job.id, exc)
            time.sleep(FINISH_RETRY_SECONDS)


def run_one_job(
    connection: Any,
    job: db.ClaimedJob,
    *,
    worker: str,
    connect: Callable[[], AbstractContextManager[Any]] | None = None,
    stopping: Callable[[], bool] = lambda: False,
) -> None:
    """Run a claimed job and record how it ended.

    The lease is renewed from inside the run, and the renewal is also the check:
    the moment it fails, this worker no longer owns the job and the command is
    stopped. Nothing is written in that case - the row belongs to whoever claimed
    it next, and a write here would be the double write the fencing token exists
    to prevent.

    `connect` lends a fresh connection when the job's own was dropped - a
    PostgreSQL restart under a running deploy. Until then a renewal that fails
    is not a lease lost: the run goes on while the lease this worker last wrote
    still holds by its own clock, and the end is written on a fresh connection
    (review 2026-10-22, 1B-6).
    """

    if job.held_decision == "discard":
        #
        # Held since the manager started, and an admin said it should not run
        # (0082). Ended here, as every job is, and never started.
        #
        logger.info("job %s was held and discarded by %s", job.id, job.held_decided_by)
        _finish(
            connection,
            job,
            state="blocked",
            outcome="blocked",
            exit_code=None,
            result={
                "error": {
                    "code": "held_discarded",
                    "message": (
                        f"queued before the manager last started; {job.held_decided_by}"
                        " decided it should not run"
                    ),
                }
            },
            stderr_excerpt=None,
            worker=worker,
        )
        return

    waited = (datetime.now(UTC) - job.created_at).total_seconds()
    if job.attempts == 1 and job.held_decision is None and waited > MAX_PENDING_SECONDS:
        #
        # Taken for the first time and older than any real queue: asked for
        # before a restore, or while writes were off for hours. Nothing runs;
        # a job requeued by recovery has been judged on evidence and is not
        # held to this.
        #
        logger.error("job %s waited %d s and was not run", job.id, waited)
        _finish(
            connection,
            job,
            state="blocked",
            outcome="blocked",
            exit_code=None,
            result={
                "error": {
                    "code": "request_expired",
                    "message": (
                        f"the request waited {int(waited // 60)} minutes and was not run;"
                        " ask again if it still applies"
                    ),
                }
            },
            stderr_excerpt=None,
            worker=worker,
        )
        return

    try:
        prepared = operations.prepare(
            operation=job.operation,
            cluster=job.cluster,
            request_id=job.request_id,
            payload=job.payload,
            profile_lookup=lambda profile_id: _sealed_profile(
                connection, profile_id, ndes=job.operation == "ndes_profile_apply"
            ),
        )
    except (operations.UnknownOperation, operations.BadPayload) as refusal:
        #
        # Nothing ran, so this is `blocked` rather than `failed`: the cluster is
        # untouched and the job needs a person, not a retry.
        #
        logger.error("job %s refused before it ran: %s", job.id, refusal)
        _finish(
            connection,
            job,
            state="blocked",
            outcome="blocked",
            exit_code=None,
            result=None,
            stderr_excerpt=diagnostics.safe_excerpt(str(refusal)),
            worker=worker,
        )
        return

    renewed_at = time.monotonic()

    def lease_is_ours() -> bool:
        """Push the lease forward, and say whether this worker still holds it.

        Asked on every tick of the run. Renewing and checking are one operation
        on purpose: a worker that checked without renewing would lose the job to
        its own idleness, and one that renewed without checking would keep
        running after somebody else took it.
        """

        nonlocal renewed_at
        try:
            if connect is not None and _broken(connection):
                with connect() as fresh:
                    ours = _renewed(fresh, job)
            else:
                ours = _renewed(connection, job)
        except psycopg.Error as exc:
            left = renewed_at + LEASE_SECONDS - LEASE_MARGIN_SECONDS - time.monotonic()
            logger.warning(
                "job %s: the lease could not be renewed (%s); %d s of it is left",
                job.id,
                exc,
                max(0, int(left)),
            )
            with suppress(psycopg.Error):
                connection.rollback()
            return left > 0
        if ours:
            renewed_at = time.monotonic()
        return ours

    refused = execution.sudo_refusal(prepared.argv)
    if refused is not None:
        logger.error("job %s: sudo will not run %s: %s", job.id, prepared.argv[-1], refused)
        _finish(
            connection,
            job,
            state="blocked",
            outcome="blocked",
            exit_code=None,
            result=_sudo_refused(prepared.argv, refused),
            stderr_excerpt=diagnostics.safe_excerpt(refused),
            worker=worker,
        )
        return

    logger.info("job %s: %s on %s", job.id, job.operation, job.cluster)
    completed = execution.run(
        prepared.argv,
        request=prepared.request,
        timeout_seconds=prepared.timeout_seconds,
        still_ours=lease_is_ours,
        lifeline=prepared.lifeline,
    )

    if completed.ending == "lease_lost":
        logger.error("job %s was taken over while it ran; writing nothing", job.id)
        return

    envelope = _envelope(completed.stdout, job) if completed.stdout_error is None else None
    if _stopped_under_it(stopping, envelope, job, job.operation):
        return
    state, outcome, result = _judge_run(completed, envelope)

    exit_code = completed.exit_code
    stderr = completed.stderr
    if state == "done" and job.operation == "changes_publish" and job.payload.get("deploy") is True:
        deployed = _deploy_after(
            connection, job, cast(dict[str, Any], result), lease_is_ours, stopping
        )
        if deployed is None:
            return
        state, outcome, result, exit_code, stderr = deployed
    elif state == "done" and job.operation == "cluster_node":
        version = _node_change_deploys(job, result)
        if version is not None:
            followed = _node_deploy_after(
                job, cast(dict[str, Any], result), version, lease_is_ours, stopping
            )
            if followed is None:
                return
            state, outcome, result, exit_code, stderr = followed

    _finish_on(
        connection,
        connect,
        lambda: renewed_at,
        job,
        state=state,
        outcome=outcome,
        exit_code=exit_code,
        result=result,
        stderr_excerpt=diagnostics.safe_excerpt(stderr) or None,
        worker=worker,
    )


#
# The deploy that follows a publish asked for with Publish & deploy (B257) is
# its own request to the deploy helper, so it has its own ID - derived from the
# job's, so the retry of an interrupted job asks the same question again. The
# certificate deploy before an added node's deploy (B321) likewise.
#
DEPLOY_AFTER = UUID("4f6c1d2e-8b7a-4c3d-9e1f-2a5b6c7d8e9f")
CERT_DEPLOY_AFTER = UUID("8d2a7c41-3e5b-4f69-a0c8-1b7e9d2f4a63")

type Followed = tuple[str, str, dict[str, Any] | None, int | None, str]


def _run_after(
    job: db.ClaimedJob,
    operation: str,
    payload: dict[str, Any],
    salt: UUID,
    still_ours: Callable[[], bool],
    stopping: Callable[[], bool],
) -> Followed | None:
    """One more helper run inside a job that has already done its own (B257, B321).

    The state, outcome, answer, exit code and stderr of that run; None when the
    lease was lost, or the worker was stopped under it, and nothing may be written.
    """

    request_id = uuid5(salt, str(job.request_id))
    try:
        prepared = operations.prepare(
            operation=operation, cluster=job.cluster, request_id=request_id, payload=payload
        )
    except (operations.UnknownOperation, operations.BadPayload) as refusal:
        logger.error("job %s: the %s after it was refused: %s", job.id, operation, refusal)
        return "blocked", "blocked", _internal_error(), None, ""
    refused = execution.sudo_refusal(prepared.argv)
    if refused is not None:
        logger.error("job %s: sudo will not run %s: %s", job.id, prepared.argv[-1], refused)
        return "blocked", "blocked", _sudo_refused(prepared.argv, refused), None, refused
    logger.info("job %s: %s on %s", job.id, operation, job.cluster)
    completed = execution.run(
        prepared.argv,
        request=prepared.request,
        timeout_seconds=prepared.timeout_seconds,
        still_ours=still_ours,
        lifeline=prepared.lifeline,
    )
    if completed.ending == "lease_lost":
        logger.error("job %s was taken over during its %s; writing nothing", job.id, operation)
        return None
    envelope = (
        _envelope(completed.stdout, job, operation=operation, request_id=str(request_id))
        if completed.stdout_error is None
        else None
    )
    if _stopped_under_it(stopping, envelope, job, operation):
        return None
    state, outcome, judged = _judge_run(completed, envelope)
    return state, outcome, judged or {}, completed.exit_code, completed.stderr


def _stopped_under_it(
    stopping: Callable[[], bool],
    envelope: dict[str, Any] | None,
    job: db.ClaimedJob,
    operation: str,
) -> bool:
    """Whether the worker was stopped while the helper ran and left no answer.

    systemd stops the whole unit, so a stop or restart of the worker - by hand,
    by needrestart, by a reboot - ends the root helper under it as well. Its
    silence then says nothing about what it did, and `unknown` would be a worse
    end than a crash leaves: nothing is written, the job stays `running`, and
    recovery settles it after the restart as it settles a dead worker's (review
    26-10-24, 02-01). A helper that answered before it was stopped is judged on
    its answer.
    """

    if envelope is not None or not stopping():
        return False
    logger.warning(
        "job %s: the worker was stopped during its %s; recovery settles it", job.id, operation
    )
    return True


def _node_change_deploys(job: db.ClaimedJob, result: dict[str, Any] | None) -> int | None:
    """The version a node change published, when it is to be deployed in the same job (B321).

    Asked for by the page (`deploy`), and only when the helper read every node
    on the published version before the change: then the change is the only
    thing the deploy rolls out. Anything else - a version somebody published
    and did not deploy, a node that could not be read, a publication that
    failed - is left to a person, and the job says a deploy is owed.
    """

    if job.payload.get("deploy") is not True or job.payload.get("action") not in ("add", "remove"):
        return None
    body = (result or {}).get("result")
    if not isinstance(body, dict) or body.get("converged_before") is not True:
        return None
    publication = body.get("publication")
    version = publication.get("version") if isinstance(publication, dict) else None
    if "error" in (publication or {}) or not isinstance(version, int) or isinstance(version, bool):
        return None
    return version


def _node_deploy_after(
    job: db.ClaimedJob,
    changed: dict[str, Any],
    version: int,
    still_ours: Callable[[], bool],
    stopping: Callable[[], bool],
) -> Followed | None:
    """Deploy a node change in its own job (B321), as Publish & deploy does a publish (B257).

    An added node has no certificates, and a deploy refuses a node without
    them, so a certificate deploy goes first; one that does not finish ends
    the job there. The job ends as its last run ended, with the node change's
    own answer beside it under `node` and that run named under `step`: the
    change stands either way.
    """

    if job.payload.get("action") == "add":
        certificates = _run_after(
            job,
            "cert_deploy",
            {"allow_vip_unknown": False},
            CERT_DEPLOY_AFTER,
            still_ours,
            stopping,
        )
        if certificates is None:
            return None
        state, outcome, answer, exit_code, stderr = certificates
        if state != "done":
            ended = {**(answer or {}), "node": changed, "step": "cert_deploy"}
            return state, outcome, ended, exit_code, stderr
    deployed = _run_after(
        job,
        "deploy",
        {"allow_vip_unknown": False, "expected_version": version},
        DEPLOY_AFTER,
        still_ours,
        stopping,
    )
    if deployed is None:
        return None
    state, outcome, answer, exit_code, stderr = deployed
    return state, outcome, {**(answer or {}), "node": changed, "step": "deploy"}, exit_code, stderr


def _deploy_after(
    connection: Any,
    job: db.ClaimedJob,
    published: dict[str, Any],
    still_ours: Callable[[], bool],
    stopping: Callable[[], bool],
) -> Followed | None:
    """Deploy the version a publish of saved changes just recorded, in the same job (B257).

    Asked for with Publish & deploy. The worker may not queue a job of its own -
    only the web role inserts into the queue - and the cluster takes one job at
    a time, so the deploy is a second helper run inside this one. Both halves
    are safe to repeat: a publish retried finds its own version, and a deploy is
    a reconcile. So a job interrupted between them is requeued like any other.

    The job ends as the deploy ends, with the deploy's answer as its result and
    the publish's beside it under `publish` and the step under `step`: the
    version is recorded either way, and what a person needs from a failure is
    why the nodes did not take it.
    None when the lease was lost and nothing may be written.
    """

    body = published.get("result")
    version = body.get("version") if isinstance(body, dict) else None
    deployed = _run_after(
        job,
        "deploy",
        {"allow_vip_unknown": False, "expected_version": version},
        DEPLOY_AFTER,
        still_ours,
        stopping,
    )
    if deployed is None:
        return None
    state, outcome, answer, exit_code, stderr = deployed
    return (
        state,
        outcome,
        {**(answer or {}), "publish": published, "step": "deploy"},
        exit_code,
        stderr,
    )


def _wait_for_work(listener: Any, stopping: StopRequest, seconds: int) -> None:
    """Wait for a queued job, the interval, or a stop - whichever comes first.

    Replaces a flat sleep. A job queued a moment after a tick began used to wait
    out the whole interval before anything looked at it, which is most of a
    minute of an operator watching a page that says "queued" about a cluster
    nobody is touching.

    The wait itself lives in `service` because the poller needs the same one for
    the other direction - it is told when a job finishes. Two copies of a loop
    this small drift in exactly the way that makes one service stop promptly and
    the other not.
    """

    service.sleep_until_notified(stopping, listener, seconds)


def boot_time(stat: Path = Path("/proc/stat")) -> datetime | None:
    """When this machine last started, from the kernel's `btime`; None if it cannot be read."""

    try:
        for line in stat.read_text(encoding="ascii").splitlines():
            if line.startswith("btime "):
                return datetime.fromtimestamp(int(line.split()[1]), UTC)
    except (OSError, ValueError):
        pass
    return None


def hold_from_before_boot(connection: Any, *, worker: str, boot: datetime | None) -> list[int]:
    """Hold what was queued before this machine started (0082, review 2026-10-20 R1).

    A manager restored from an image or a backup boots holding the jobs that
    were waiting when the backup was taken, and those ran then. A marker on the
    manager cannot say it was restored - it is restored too - but the boot can.
    The cost is that a job queued just before an ordinary reboot waits for a
    click as well. A boot that cannot be read holds nothing: the two-hour rule
    is still there behind it.
    """

    if boot is None:
        logger.warning("the machine's start time could not be read; no job is held")
        return []
    held = db.hold_jobs_queued_before(connection, boot=boot)
    if held:
        db.record_audit_event(
            connection,
            actor=worker,
            action="jobs_held",
            cluster=None,
            request_id=None,
            detail={"jobs": held, "reason": "queued before the manager started"},
        )
        logger.warning(
            "%s queued before the manager started are held for an admin: %s",
            labels.counted(len(held), "job"),
            ", ".join(str(job) for job in held),
        )
    connection.commit()
    return held


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(format="%(levelname)s %(message)s", level=logging.INFO)
    path = Path(os.environ.get("HAPRION_UI_CONFIG", str(DEFAULT_CONFIG_PATH)))
    config = load_config(path)

    pool = db.pool(config.database, min_size=1, max_size=2)
    listener = db.listener(config.database)
    pool.open(wait=True, timeout=10)
    try:
        with pool.connection() as connection:
            identity, database = db.connected_identity(connection)
        #
        # Reported rather than assumed, on every start. Peer authentication
        # means the role is decided by the kernel, and a worker running as the
        # wrong role looks exactly like one running correctly until something is
        # denied - or, worse, allowed.
        #
        logger.info("worker running as %s on %s", identity, database)

        if not config.management_writes:
            #
            # Said once and then quiet. A line every thirty seconds saying
            # nothing happened is a log nobody reads, and this is a normal state
            # rather than a fault: turning management writes off is the
            # documented rollback for the write path, and it leaves a worker
            # that runs and provably claims nothing.
            #
            logger.info("management writes are disabled; no job will be claimed")

        stopping = StopRequest(what="worker")
        worker = worker_identity()
        with pool.connection() as connection:
            hold_from_before_boot(connection, worker=worker, boot=boot_time())
        while not stopping.requested():
            if not config.management_writes:
                stopping.sleep(IDLE_SECONDS)
                continue

            try:
                job = _one_turn(pool, worker, stopping.requested)
            except psycopg.OperationalError as exc:
                #
                # The database went away between jobs, or under one whose end
                # could not be written before its lease ran out: said, and the
                # loop goes on. Exiting handed systemd a worker to kill with a
                # root helper still at work under it (review 2026-10-22, 1B-6);
                # a job left `running` is recovery's to settle.
                #
                logger.error("the database did not answer: %s", exc)
                stopping.sleep(IDLE_SECONDS)
                continue
            if job is None:
                _wait_for_work(listener, stopping, IDLE_SECONDS)
    finally:
        listener.close()
        pool.close()
    return 0


def _one_turn(
    pool: Any, worker: str, stopping: Callable[[], bool] = lambda: False
) -> db.ClaimedJob | None:
    """Settle what dead workers left, claim one job and run it; the job, or None."""

    with pool.connection() as connection:
        #
        # Before claiming anything new. A job abandoned by a dead worker
        # is invisible to `claim_job` - it is still `running` - so
        # nothing would ever pick it up again, and settling it first
        # means the claim below can find it on this same tick rather
        # than on the next one.
        #
        # Below the management-writes check on purpose. With writes off
        # nothing moves at all, including a job somebody would rather
        # see moved: that is what makes the flag a rollback and not a
        # pause, and an abandoned job is still there to adjudicate when
        # writes come back.
        #
        recovery.adjudicate(connection, worker=worker)

        job = db.claim_job(connection, worker_id=worker, lease_seconds=LEASE_SECONDS)
        #
        # Committed before the command starts, and not at the end of the
        # block. The claim holds a row lock until it is committed, and a
        # deploy that runs inside that transaction would keep the lock -
        # and its own invisibility - for the whole operation. Every other
        # worker would see a job that is still pending and nobody
        # holding it.
        #
        connection.commit()
        if job is not None:
            run_one_job(connection, job, worker=worker, connect=pool.connection, stopping=stopping)
    return job


def _entry() -> None:  # pragma: no cover - console script shim
    sys.exit(main())


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
