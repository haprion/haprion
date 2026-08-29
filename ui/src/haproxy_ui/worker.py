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
from typing import Any

from haproxy_ui import db, execution, operations
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
LEASE_SECONDS = 60

#
# The contract's cap on stored diagnostics, applied before the write rather than
# discovered at the constraint.
#
STDERR_LIMIT = 65536


def worker_identity() -> str:
    """Who is holding a job, in a form that means something during an incident.

    Host and process, because "which worker" is a question somebody asks while
    looking at a row that has been running for too long, and the answer has to
    lead to a process on a machine.
    """

    return f"{socket.gethostname()}/{os.getpid()}"


def _envelope(stdout: str) -> dict[str, Any] | None:
    try:
        parsed = json.loads(stdout)
    except (json.JSONDecodeError, TypeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def run_one_job(connection: Any, job: db.ClaimedJob) -> None:
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
        )
    except (operations.UnknownOperation, operations.BadPayload) as refusal:
        #
        # Nothing ran, so this is `blocked` rather than `failed`: the cluster is
        # untouched and the job needs a person, not a retry.
        #
        logger.error("job %s refused before it ran: %s", job.id, refusal)
        db.finish_job(
            connection,
            job_id=job.id,
            claim_token=job.claim_token,
            state="blocked",
            exit_code=None,
            outcome="blocked",
            result=None,
            stderr_excerpt=str(refusal)[:STDERR_LIMIT],
        )
        connection.commit()
        return

    def lease_is_ours() -> bool:
        """Push the lease forward, and say whether this worker still holds it.

        Asked on every tick of the run. Renewing and checking are one operation
        on purpose: a worker that checked without renewing would lose the job to
        its own idleness, and one that renewed without checking would keep
        running after somebody else took it.
        """

        return db.renew_lease(
            connection,
            job_id=job.id,
            claim_token=job.claim_token,
            lease_seconds=LEASE_SECONDS,
        )

    logger.info("job %s: %s on %s", job.id, job.operation, job.cluster)
    completed = execution.run(
        prepared.argv,
        request=prepared.request,
        timeout_seconds=operations.TIMEOUT_SECONDS,
        still_ours=lease_is_ours,
    )

    if completed.ending == "lease_lost":
        logger.error("job %s was taken over while it ran; writing nothing", job.id)
        return

    envelope = _envelope(completed.stdout)
    if completed.ending == "timeout" or envelope is None:
        #
        # The honest answer in both cases is that reality is undetermined. A
        # command that was stopped may have finished its work first, and one that
        # answered with something unparseable did something this process cannot
        # describe. `unknown` is what the plan reserves for exactly this, and it
        # is never retried automatically.
        #
        state = outcome = "unknown"
        result = None
    else:
        outcome = str(envelope.get("outcome", "unknown"))
        state = outcome if outcome in {"done", "partial", "failed", "blocked"} else "unknown"
        result = envelope

    if not db.finish_job(
        connection,
        job_id=job.id,
        claim_token=job.claim_token,
        state=state,
        exit_code=completed.exit_code,
        outcome=outcome,
        result=result,
        stderr_excerpt=completed.stderr[:STDERR_LIMIT] or None,
    ):
        logger.error("job %s could not be finished; the lease was gone by then", job.id)
        return
    connection.commit()
    logger.info("job %s ended as %s", job.id, state)


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(format="%(levelname)s %(message)s", level=logging.INFO)
    path = Path(os.environ.get("HAPROXY_UI_CONFIG", str(DEFAULT_CONFIG_PATH)))
    config = load_config(path)

    pool = db.pool(config.database, min_size=1, max_size=2)
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
                    run_one_job(connection, job)

            if job is None:
                stopping.sleep(IDLE_SECONDS)
    finally:
        pool.close()
    return 0


def _entry() -> None:  # pragma: no cover - console script shim
    sys.exit(main())


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
