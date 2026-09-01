"""What to do with a job whose worker stopped answering.

An expired lease says one thing only: the process that held the job is no longer
renewing its authority. It does not say whether the operation ran, whether it
finished, or whether anything reached a node. Deciding that from the outside is
the whole problem, and getting it wrong in either direction is expensive - a
blind retry can publish twice, and a blind `unknown` leaves work undone that a
person now has to reconstruct by hand.

So nothing here guesses. Each operation is judged by what can be READ:

* `publish` and `revert` record a version, and since Phase 6 that version
  carries the request that asked for it. The cached listing therefore answers
  "did this request already record something?" exactly, and the published hash
  answers "did the release land?". A version that exists but was never published
  is not a failure to be retried blindly - the retry lands on the helper's
  unchanged path, which repairs the release from that same commit and records no
  second version.
* `deploy` and `cert_deploy` record nothing. They are reconcile loops: they read
  the cluster, act only on what is behind, and leave a converged cluster
  untouched. Repeating one is not a risk to be weighed, it is how they work.

Why the cluster lock is not consulted
-------------------------------------
The obvious worry about requeuing is an orphan process still running the
operation. The lock answers that by itself, and does it better than a check
here could: `flock` is held on an open file, so a dead process releases it in
the kernel with no cleanup, and a live one that still holds it makes the
requeued run exit `blocked` before it touches anything. Reading the lock would
also mean reading a root-owned path from the worker's account. The fencing that
already exists is stronger than the check that would have needed the privilege.

Why the evidence has to be newer than the lease
-----------------------------------------------
A listing observed while the operation may still have been running describes a
world that was still moving. It cannot prove a version was NOT recorded, because
the recording may have happened after the reading. Old evidence is therefore not
weak evidence to be used carefully; it is no evidence, and the job waits for the
poller rather than being judged on it.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Literal

from haproxy_ui import db

logger = logging.getLogger("haproxy_ui.recovery")

#
# How many times one job may be handed to a worker. The first claim is the
# operation; the second is the one retry an abandoned job gets. A job that has
# been taken twice and answered neither time is exactly what `unknown` is for -
# an operation that keeps killing its worker would otherwise be retried without
# end, and the history would fill with the same failure while nothing said the
# system had stopped trying.
#
MAX_ATTEMPTS = 2

#
# Operations that leave no record of their own and cannot be harmed by running
# again. Both are reconcile loops: they read the cluster, act only on what is
# behind, and a converged cluster is a no-op that says so.
#
REPEATABLE = frozenset({"deploy", "cert_deploy"})

#
# Operations that record a version bound to the request that asked for it.
#
RECORDED = frozenset({"publish", "revert", "network_publish"})

type Verdict = Literal["requeue", "abandon", "wait"]


@dataclass(frozen=True, slots=True)
class Judgement:
    verdict: Verdict
    #
    # Why, in a form worth reading months later. `code` is stable and `reason`
    # is for a person; both go to the audit trail, and `code` is what a stored
    # `unknown` result blames.
    #
    code: str
    reason: str


def _recorded_version(listing: dict[str, Any], request_id: str) -> dict[str, Any] | None:
    versions = listing.get("versions")
    if not isinstance(versions, list):
        return None
    for entry in versions:
        if isinstance(entry, dict) and entry.get("request_id") == request_id:
            return entry
    return None


def judge(job: db.AbandonedJob, history: db.ClusterHistory | None) -> Judgement:
    """Decide what may be done with one abandoned job, from evidence alone."""

    if job.attempts >= MAX_ATTEMPTS:
        return Judgement(
            "abandon",
            "attempts_exhausted",
            f"the job was handed to a worker {job.attempts} times and answered neither time",
        )

    if job.operation in REPEATABLE:
        #
        # No evidence is needed. The operation reads the cluster before it acts,
        # so running it again establishes the truth rather than assuming it, and
        # the cluster lock refuses a second run while a first is still going.
        #
        return Judgement(
            "requeue",
            "operation_repeatable",
            f"{job.operation} reconciles what it reads and is safe to run again",
        )

    if job.operation not in RECORDED:
        return Judgement(
            "abandon",
            "operation_unknown",
            f"there is no completion evidence defined for {job.operation}",
        )

    if history is None or history.poll_error is not None or history.outcome != "done":
        return Judgement(
            "wait",
            "evidence_unavailable",
            "the cached version listing could not be read for this cluster",
        )

    if history.observed_at <= job.lease_until:
        #
        # Not "probably fine". A reading taken before the lease ran out was
        # taken while the operation could still have been recording a version,
        # so its silence proves nothing at all.
        #
        return Judgement(
            "wait",
            "evidence_too_old",
            "the version listing was read before this job's lease expired",
        )

    listing = history.result
    recorded = _recorded_version(listing, str(job.request_id))
    if recorded is not None:
        #
        # The version exists. Whether its release landed decides nothing here:
        # the retry lands on the helper's unchanged path either way, which
        # repairs the release when it is missing and reports a no-op when it is
        # not. Both are the same safe re-run, and both end with the helper - not
        # this module - writing what happened.
        #
        published = recorded.get("hash") == listing.get("published_hash")
        return Judgement(
            "requeue",
            "version_recorded" if published else "release_incomplete",
            f"version {recorded.get('version')} was recorded for this request and "
            + ("is published" if published else "was never published"),
        )

    if listing.get("truncated"):
        #
        # The request is not among the versions shown, and the listing does not
        # show all of them. "Not found" and "not there" are different answers,
        # and only the second one licenses a retry.
        #
        return Judgement(
            "abandon",
            "evidence_truncated",
            "the version listing is truncated, so a recorded version cannot be ruled out",
        )

    return Judgement(
        "requeue",
        "nothing_recorded",
        "no version carries this request, so the operation did not record one",
    )


def adjudicate(connection: Any, *, worker: str) -> int:
    """Judge every abandoned job once, and act on the ones that can be settled.

    Returns how many jobs were moved, which is what a caller logs. Each job is
    its own transaction: one undecidable job must not hold up the next, and a
    requeue that succeeded must not be rolled back because a later judgement
    failed.
    """

    moved = 0
    for job in db.expired_leases(connection):
        history = db.cluster_history(connection, job.cluster) if job.operation in RECORDED else None
        judgement = judge(job, history)

        if judgement.verdict == "wait":
            logger.info("job %s is not yet decidable: %s", job.id, judgement.reason)
            connection.rollback()
            continue

        if judgement.verdict == "requeue":
            settled = db.requeue_expired(connection, job_id=job.id, attempts=job.attempts)
            action = "job_requeued"
        else:
            settled = db.abandon_expired(
                connection,
                job_id=job.id,
                attempts=job.attempts,
                code=judgement.code,
                message=judgement.reason,
            )
            action = "job_abandoned"

        if not settled:
            #
            # Another worker claimed the row between the reading and the write,
            # or another adjudicator got there first. Either way this decision
            # was made about a world that no longer exists.
            #
            logger.info("job %s moved while it was being judged; leaving it alone", job.id)
            connection.rollback()
            continue

        db.record_audit_event(
            connection,
            actor=worker,
            action=action,
            cluster=job.cluster,
            request_id=job.request_id,
            detail={
                "job": job.id,
                "operation": job.operation,
                "attempts": job.attempts,
                "code": judgement.code,
                "reason": judgement.reason,
            },
        )
        connection.commit()
        moved += 1
        logger.warning("job %s %s: %s", job.id, action, judgement.reason)

    return moved
