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

import json
import logging
import os
import socket
import sys
from pathlib import Path
from typing import Any, cast

from haproxy_ui import db, diagnostics, execution, operations, recovery, service
from haproxy_ui.config import DEFAULT_CONFIG_PATH
from haproxy_ui.config import load as load_config
from haproxy_ui.service import StopRequest

logger = logging.getLogger("haproxy_ui.worker")

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


_REQUIRED_ENVELOPE_FIELDS = frozenset(
    {
        "schema_version",
        "ok",
        "outcome",
        "operation",
        "cluster",
        "request_id",
        "result",
        "warnings",
        "error",
    }
)
_OPERATION_OUTCOMES = {
    "backup_run": frozenset({"done", "partial", "failed"}),
    "backup_schedule": frozenset({"done", "failed"}),
    "deploy": frozenset({"done", "partial", "failed", "blocked"}),
    "cert_deploy": frozenset({"done", "partial", "failed", "blocked"}),
    "revert": frozenset({"done", "failed", "blocked"}),
    "network_publish": frozenset({"done", "failed", "blocked"}),
    "objects_publish": frozenset({"done", "failed", "blocked"}),
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
}


class _InvalidEnvelope(ValueError):
    """A helper answer is not one result the claimed job may accept."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise _InvalidEnvelope("duplicate field")
        value[key] = item
    return value


def _finite_number(_value: str) -> None:
    raise _InvalidEnvelope("non-finite number")


def _message(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and isinstance(value.get("code"), str)
        and bool(value["code"])
        and isinstance(value.get("message"), str)
        and bool(value["message"])
    )


def _envelope(stdout: str, job: db.ClaimedJob) -> dict[str, Any] | None:
    """Accept only the common v1 envelope bound to this exact claimed job.

    The operation helpers own their operation-specific result schemas. The
    worker still owns the boundary that says whose answer this is: accepting a
    valid deploy result carrying another request ID would turn request binding
    into decoration rather than fencing.
    """

    try:
        parsed = json.loads(
            stdout,
            object_pairs_hook=_unique_object,
            parse_constant=_finite_number,
        )
    except (json.JSONDecodeError, TypeError, _InvalidEnvelope):
        return None
    if not isinstance(parsed, dict):
        return None
    envelope = cast(dict[str, Any], parsed)
    if not _REQUIRED_ENVELOPE_FIELDS.issubset(envelope):
        return None
    if type(envelope["schema_version"]) is not int or envelope["schema_version"] != 1:
        return None
    if envelope["operation"] != job.operation:
        return None
    if envelope["cluster"] != job.cluster:
        return None
    if envelope["request_id"] != str(job.request_id):
        return None

    outcome = envelope["outcome"]
    allowed = _OPERATION_OUTCOMES.get(job.operation, frozenset())
    if not isinstance(outcome, str) or outcome not in allowed:
        return None
    if not isinstance(envelope["ok"], bool):
        return None
    warnings = envelope["warnings"]
    if not isinstance(warnings, list) or not all(_message(item) for item in warnings):
        return None

    error = envelope["error"]
    if outcome == "done":
        valid_cross_fields = envelope["ok"] and error is None
    elif outcome == "partial":
        valid_cross_fields = not envelope["ok"] and bool(warnings) and error is None
    else:
        valid_cross_fields = not envelope["ok"] and _message(error)
    if not valid_cross_fields:
        return None
    if outcome in {"done", "partial"} and not isinstance(envelope["result"], dict):
        return None
    return envelope


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
        result=result,
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


def run_one_job(connection: Any, job: db.ClaimedJob, *, worker: str) -> None:
    """Run a claimed job and record how it ended.

    The lease is renewed from inside the run, and the renewal is also the check:
    the moment it fails, this worker no longer owns the job and the command is
    stopped. Nothing is written in that case - the row belongs to whoever claimed
    it next, and a write here would be the double write the fencing token exists
    to prevent.
    """

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

    def lease_is_ours() -> bool:
        """Push the lease forward, and say whether this worker still holds it.

        Asked on every tick of the run. Renewing and checking are one operation
        on purpose: a worker that checked without renewing would lose the job to
        its own idleness, and one that renewed without checking would keep
        running after somebody else took it.
        """

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

    logger.info("job %s: %s on %s", job.id, job.operation, job.cluster)
    completed = execution.run(
        prepared.argv,
        request=prepared.request,
        timeout_seconds=operations.TIMEOUT_SECONDS,
        still_ours=lease_is_ours,
        lifeline=prepared.lifeline,
    )

    if completed.ending == "lease_lost":
        logger.error("job %s was taken over while it ran; writing nothing", job.id)
        return

    envelope = _envelope(completed.stdout, job) if completed.stdout_error is None else None
    if completed.stdout_error is not None:
        #
        # A document beyond the hard cap is rejected before JSON parsing, and
        # invalid UTF-8 cannot be a contract document. The operation itself may
        # still have taken effect, so the job remains `unknown`; the structured
        # code says why the worker could not accept the answer.
        #
        state = outcome = "unknown"
        result = _internal_error()
    elif completed.ending == "timeout":
        #
        # A command that was stopped may have finished its work first. `unknown`
        # is what the plan reserves for exactly this, and it is never retried
        # automatically.
        #
        state = outcome = "unknown"
        result = None
    elif envelope is None:
        state = outcome = "unknown"
        result = _internal_error()
    else:
        outcome = str(envelope.get("outcome", "unknown"))
        state = outcome if outcome in {"done", "partial", "failed", "blocked"} else "unknown"
        result = envelope

    _finish(
        connection,
        job,
        state=state,
        outcome=outcome,
        exit_code=completed.exit_code,
        result=result,
        stderr_excerpt=diagnostics.safe_excerpt(completed.stderr) or None,
        worker=worker,
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


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(format="%(levelname)s %(message)s", level=logging.INFO)
    path = Path(os.environ.get("HAPROXY_UI_CONFIG", str(DEFAULT_CONFIG_PATH)))
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
        while not stopping.requested():
            if not config.management_writes:
                stopping.sleep(IDLE_SECONDS)
                continue

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
                    run_one_job(connection, job, worker=worker)

            if job is None:
                _wait_for_work(listener, stopping, IDLE_SECONDS)
    finally:
        listener.close()
        pool.close()
    return 0


def _entry() -> None:  # pragma: no cover - console script shim
    sys.exit(main())


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
