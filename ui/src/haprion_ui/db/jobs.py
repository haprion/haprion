"""The job queue: what the web asks for, what the worker claims, runs and finishes."""

from __future__ import annotations

from collections.abc import Collection, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

import psycopg
from psycopg import Connection
from psycopg.rows import class_row
from psycopg.types.json import Jsonb

from haprion_ui.db.core import CLUSTER_CHANNEL, savepoint


@dataclass(frozen=True, slots=True)
class Job:
    id: int
    request_id: UUID
    operation: str
    cluster: str | None
    payload: dict[str, Any]
    state: str
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    exit_code: int | None
    outcome: str | None
    result: dict[str, Any] | None
    stderr_excerpt: str | None
    idempotency_key: UUID | None
    attempts: int
    #
    # Held since the manager last started (0082): waiting for an admin's
    # `run` or `discard`. Read by the Jobs page; other readers leave them out.
    #
    held_since: datetime | None = None
    held_decision: str | None = None
    held_decided_by: str | None = None
    #
    # When the lease of a running job ran out, by the database's clock; None
    # while a worker holds it, and for a job not running. Read by
    # `recent_jobs` and `active_job` (review 26-10-29, Q01): a worker stopped
    # or hung leaves its job `running`, and only a living worker settles it.
    #
    lease_lapsed_since: datetime | None = None
    #
    # Whether some job runs under a living lease as this row is read: a worker
    # alive and busy, which settles a lease run out when its own job ends
    # (review 26-10-29, A2). The same for every row of one read.
    #
    worker_busy: bool = False

    @property
    def waits_for_decision(self) -> bool:
        """Held and not yet answered: waiting for an admin, not for the worker.

        A running one too (review 2026-10-28, F01): its helper may have kept an
        answer, and what follows it in the job waits for Run as a queued job does.
        """

        return (
            self.state in ("pending", "running")
            and self.held_since is not None
            and self.held_decision is None
        )


@dataclass(frozen=True, slots=True)
class AbandonedJob:
    """A running job whose holder stopped renewing its lease.

    Deliberately narrow. Adjudicating an abandoned job needs to know which
    operation on which cluster, how many times it has been picked up, and when
    its authority ran out. It does not need the payload, the result or the
    diagnostics, and a type that carried them would invite a decision to be made
    from a stored answer rather than from what can be read now.
    """

    id: int
    request_id: UUID
    operation: str
    cluster: str | None
    state: str
    attempts: int
    lease_until: datetime
    #
    # Held since the manager last started, and the admin's answer if any: an
    # adoption waits for it (review 2026-10-28, F01).
    #
    held_since: datetime | None = None
    held_decision: str | None = None


@dataclass(frozen=True, slots=True)
class ClaimedJob:
    """A job this worker holds, and the token that proves it.

    A separate type from `Job` rather than an optional field on it, because the
    difference is a grant and not a convenience: `app_web` holds no `select` on
    `claim_token`, so a web page reading this shape would be refused by the
    database. Keeping them apart makes that impossible to do by accident.
    """

    id: int
    request_id: UUID
    operation: str
    cluster: str | None
    payload: dict[str, Any]
    state: str
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    exit_code: int | None
    outcome: str | None
    result: dict[str, Any] | None
    stderr_excerpt: str | None
    idempotency_key: UUID | None
    attempts: int
    claim_token: UUID
    held_decision: str | None = None
    held_decided_by: str | None = None


class ClusterBusy(Exception):
    """A job for this cluster is already pending or running.

    Not an error in the caller's request - the request was fine, the cluster is
    not free. The two are told apart because the answer differs: this one is
    worth retrying when the running job finishes, and the one below never is.

    `active` is the job that holds the cluster, when it could be read: a held
    one, or one no worker holds, does not finish by itself, and the sentence
    says so (review 26-10-29, Q07/R05).
    """

    def __init__(self, cluster: str | None = None, *, active: Job | None = None) -> None:
        super().__init__(*(() if cluster is None else (cluster,)))
        self.active = active


class CertificateBusy(Exception):
    """A certificate job is already pending or running.

    The same kind of answer as `ClusterBusy` and told apart from it for the same
    reason: worth retrying shortly, and not a fault in what was asked. Separate
    because the sentence a person needs differs - no cluster is busy, and naming
    one would send them to look at a cluster that is fine.

    There is one of these at a time for every certificate rather than one per
    certificate, which is the queue agreeing with the publisher: it takes a
    single lock across all certificate material, so two certificate jobs admitted
    at once would meet inside it with one holding a lease while it waited.

    `active` as for `ClusterBusy`.
    """

    def __init__(self, *, active: Job | None = None) -> None:
        super().__init__()
        self.active = active


class RequestConflict(Exception):
    """The same idempotency key, asking for something else.

    A retry carries the key it used before. If what it now asks for differs, the
    two are not the same attempt, and treating it as a no-op would silently drop
    an operation somebody asked for. Refused rather than queued, and never
    treated as already done.
    """


#
# A running job's lease as the web reads it: when it ran out, and whether any
# job runs under a living one. The web holds `select` on `lease_until`, not on
# the claim's token; `jobs.no_worker` reads both.
#
_LEASE_COLUMNS = (
    "case when state = 'running' and lease_until < statement_timestamp() "
    "     then lease_until end as lease_lapsed_since, "
    "exists (select 1 from job living "
    "         where living.state = 'running' "
    "           and living.lease_until >= statement_timestamp()) as worker_busy"
)


def recent_jobs(
    connection: Connection[Any], *, cluster: str | None = None, limit: int = 20
) -> list[Job]:
    """The newest jobs, optionally for one cluster - and every job still pending or running.

    The cluster arrives as a bound parameter, never as text pasted into the
    statement. That is not only about injection: a bound parameter is also what
    lets PostgreSQL keep the plan, and it keeps the SQL below identical to what
    can be pasted into psql while debugging.

    A job still in flight is in the answer however old it is. Every page reads
    what a cluster is busy with out of this list, and one older than the newest
    `limit` was missing from it: the cluster looked idle while the queue
    refused the next job for it (review 2026-10-22, 1B-4). The queue holds one
    active job per cluster and one for the certificates, so they are few.
    """

    with connection.cursor(row_factory=class_row(Job)) as cursor:
        cursor.execute(
            "select id, request_id, operation, cluster, payload, state, created_at, "  # noqa: S608 - constant
            "       started_at, finished_at, exit_code, outcome, result, stderr_excerpt, "
            "       idempotency_key, attempts, held_since, held_decision, held_decided_by, "
            f"       {_LEASE_COLUMNS} "
            "  from job "
            " where (%(cluster)s::text is null or cluster = %(cluster)s) "
            "   and (state in ('pending', 'running') "
            "        or id in (select id from job "
            "                   where (%(cluster)s::text is null or cluster = %(cluster)s) "
            "                   order by created_at desc, id desc "
            "                   limit %(limit)s)) "
            " order by created_at desc, id desc",
            {"cluster": cluster, "limit": limit},
        )
        return cursor.fetchall()


@dataclass(frozen=True, slots=True)
class ClaimPause:
    """A release holding the worker's claims (`haprion-drain pause`) until `until`."""

    until: datetime
    by: str


def claim_pause(connection: Connection[Any]) -> ClaimPause | None:
    """The release's pause on the queue while it holds, by the database's clock.

    The clock the worker's claim reads it by. A pause carries its end, so one
    a killed release left behind lets the queue go by itself (review 26-10-29,
    Q06: jobs it held back were blamed on the worker).
    """

    with connection.cursor(row_factory=class_row(ClaimPause)) as cursor:
        cursor.execute(
            "select paused_until as until, coalesce(paused_by, 'release') as by "
            "  from job_claim_gate "
            " where paused_until > statement_timestamp()"
        )
        return cursor.fetchone()


def attention_evidence(connection: Connection[Any]) -> list[Job]:
    """The newest finished job of every cluster, step and subject, however old
    (0089, review 26-10-24, 05-01).

    Needs attention reads these beside the newest jobs. The newest 200 alone
    lost a failure nothing had settled once that many jobs came after it, and
    the pruning removed it a week on; the function is the set the pruning
    keeps, so the two cannot disagree about which job is still the answer.
    """

    with connection.cursor(row_factory=class_row(Job)) as cursor:
        cursor.execute(
            "select id, request_id, operation, cluster, payload, state, created_at, "
            "       started_at, finished_at, exit_code, outcome, result, stderr_excerpt, "
            "       idempotency_key, attempts, held_since, held_decision, held_decided_by "
            "  from job "
            " where id in (select job_attention_evidence()) "
            " order by created_at desc, id desc"
        )
        return cursor.fetchall()


def draft_publishes(
    connection: Connection[Any], *, cluster: str, draft_ids: Collection[str]
) -> list[Job]:
    """The finished publishes of these drafts, whichever revision they carried.

    Asked by the drafts' own ids rather than read out of the newest jobs. Until
    2026-10-06 the evidence was the newest twenty jobs of the cluster, so twenty
    later jobs of any kind made a published draft look unpublished again - and
    the editor opens a draft in preference to the stored object (review
    2026-10-04, CR-04). Retention keeps these rows while their draft exists.
    """

    if not draft_ids:
        return []
    with connection.cursor(row_factory=class_row(Job)) as cursor:
        cursor.execute(
            "select id, request_id, operation, cluster, payload, state, created_at, "
            "       started_at, finished_at, exit_code, outcome, result, stderr_excerpt, "
            "       idempotency_key, attempts "
            "  from job "
            " where (state = 'done' or result->'publish'->>'outcome' = 'done') "
            "   and cluster = %(cluster)s "
            "   and operation = 'changes_publish' "
            "   and exists (select 1 "
            "                 from jsonb_array_elements(payload->'drafts') as entry "
            "                where entry->>'id' = any(%(ids)s)) "
            " order by created_at desc, id desc",
            {"cluster": cluster, "ids": sorted(draft_ids)},
        )
        return cursor.fetchall()


def operation_jobs(connection: Connection[Any], operation: str, *, limit: int = 500) -> list[Job]:
    """Every job of one operation, newest first.

    A profile's state is read from its own apply jobs. Until 2026-09-18 the
    pages read it out of the newest twenty (the form) or hundred (the list)
    jobs of every kind, and a day of certificate work pushed the apply job
    out of the window: the list said "In effect" while the form offered no
    profile at all. The limit here is a sanity bound, not a window - a
    profile has a handful of apply jobs in its lifetime.
    """

    with connection.cursor(row_factory=class_row(Job)) as cursor:
        cursor.execute(
            "select id, request_id, operation, cluster, payload, state, created_at, "
            "       started_at, finished_at, exit_code, outcome, result, stderr_excerpt, "
            "       idempotency_key, attempts, held_since, held_decision, held_decided_by "
            "  from job "
            " where operation = %(operation)s "
            " order by created_at desc, id desc "
            " limit %(limit)s",
            {"operation": operation, "limit": limit},
        )
        return cursor.fetchall()


def profile_jobs(connection: Connection[Any], operation: str) -> list[Job]:
    """Each profile's own apply jobs, newest first, down to its newest apply.

    What `profile_status` reads and no more: it walks a profile's jobs newest
    first and stops at the first one that is not a refused removal, which at
    the latest is the newest job that applied a revision. Read per profile
    rather than as the newest N of the operation, so no number of jobs for
    other profiles can push a profile's evidence out of reach - the same rows
    the retention keeps (`haprion-retention`, `profile_evidence`).
    """

    with connection.cursor(row_factory=class_row(Job)) as cursor:
        cursor.execute(
            "select id, request_id, operation, cluster, payload, state, created_at, "
            "       started_at, finished_at, exit_code, outcome, result, stderr_excerpt, "
            "       idempotency_key, attempts "
            "  from job "
            " where operation = %(operation)s "
            "   and created_at >= coalesce(("
            "       select max(applied.created_at) from job applied "
            "        where applied.operation = job.operation "
            "          and applied.payload->>'profile' = job.payload->>'profile' "
            "          and coalesce(applied.payload->>'remove', 'false') <> 'true'"
            "   ), '-infinity') "
            " order by created_at desc, id desc",
            {"operation": operation},
        )
        return cursor.fetchall()


def restore_jobs(connection: Connection[Any], run: str) -> list[Job]:
    """The jobs of one node restore run, oldest first.

    A run is nothing but these rows: the five restore operations whose payload
    names it. Nothing else is stored, so the page cannot disagree with them.
    """

    with connection.cursor(row_factory=class_row(Job)) as cursor:
        cursor.execute(
            "select id, request_id, operation, cluster, payload, state, created_at, "
            "       started_at, finished_at, exit_code, outcome, result, stderr_excerpt, "
            "       idempotency_key, attempts, held_since, held_decision, held_decided_by "
            "  from job "
            " where operation in ('node_restore_prepare', 'node_restore_preview', "
            "                     'node_restore', 'node_restore_discard', "
            "                     'node_restore_status') "
            "   and payload->>'run' = %(run)s "
            " order by id",
            {"run": run},
        )
        return cursor.fetchall()


def job_state(connection: Connection[Any], job_id: int) -> str | None:
    """One job's state, or None when there is no such job."""

    with connection.cursor() as cursor:
        cursor.execute("select state from job where id = %(job_id)s", {"job_id": job_id})
        row = cursor.fetchone()
    return None if row is None else str(row[0])


def queue_job(
    connection: Connection[Any],
    *,
    operation: str,
    cluster: str | None,
    payload: Mapping[str, Any],
    idempotency_key: UUID,
) -> Job:
    """Ask for an operation. Say nothing about what happened.

    Four columns now, which is exactly what the web role holds `insert` on. The
    state, the request ID and the creation time are still not passed and could
    not be: they come from column defaults, so the row that comes back states
    what the database decided rather than what this process asked for.

    Three outcomes, and the difference between them is the point:

    - the insert succeeds and a job is queued
    - the key has been seen before, asking for exactly this, and the job already
      queued is returned unchanged. That is what makes a refresh or a
      double-click harmless: the second attempt is the first one, not a second
      operation
    - the request is refused, either because the cluster is busy or because the
      key was used for something else

    The comparison that decides between the last two is made in SQL against
    `payload_hash`, so "the same request" means the same bytes the database
    hashed - not the same Python object graph, and not a second hashing here
    that could disagree with the trigger.
    """

    parameters = {
        "operation": operation,
        "cluster": cluster,
        "payload": Jsonb(payload),
        "key": str(idempotency_key),
    }
    conflict: BaseException | None = None
    constraint = ""
    try:
        #
        # A savepoint, so a refused insert leaves the connection usable. Without
        # it the failed statement aborts the whole transaction and the read
        # below - the one that turns a conflict into a useful answer - cannot
        # run.
        #
        with savepoint(connection), connection.cursor(row_factory=class_row(Job)) as cursor:
            cursor.execute(
                "insert into job (operation, cluster, payload, idempotency_key) "
                "values (%(operation)s, %(cluster)s, %(payload)s, %(key)s) "
                "returning id, request_id, operation, cluster, payload, state, created_at, "
                "          started_at, finished_at, exit_code, outcome, result, "
                "          stderr_excerpt, idempotency_key, attempts",
                parameters,
            )
            row = cursor.fetchone()
            #
            # Inside the transaction on purpose. Postgres holds a notification
            # until commit and drops it on rollback, so this cannot tell a
            # worker about a job that does not exist - and the worker cannot be
            # woken before the row it is being woken for is visible.
            #
            # No payload. The channel says "something arrived", and the worker
            # then asks the database what it may claim; sending the id would
            # invite a worker to act on a row it has not claimed, which is the
            # one thing the claim exists to prevent.
            #
            cursor.execute("notify job_queued")
        if row is None:  # pragma: no cover - insert ... returning yields a row or raises
            raise psycopg.OperationalError("the insert returned no row")
        return row
    except psycopg.errors.UniqueViolation as violation:
        conflict = violation
        constraint = violation.diag.constraint_name or ""
        #
        # A retry of the same request conflicts with both unique indexes: its
        # key already exists and its cluster already has the pending row. The
        # executor is free to report either one first, so the cluster constraint
        # cannot mean "busy" until the key lookup below has ruled out the retry.
        #
        if constraint not in {
            "job_one_active_per_cluster",
            "job_one_active_certificate",
            "job_idempotency_key",
        }:
            # pragma: no cover - no other unique index
            raise
    #
    # The key has been used. Whether that is a retry or a collision is decided by
    # what the earlier row asked for, and the hash is compared the way the
    # trigger computed it.
    #
    with connection.cursor(row_factory=class_row(Job)) as cursor:
        cursor.execute(
            "select id, request_id, operation, cluster, payload, state, created_at, "
            "       started_at, finished_at, exit_code, outcome, result, stderr_excerpt, "
            "       idempotency_key, attempts "
            "  from job "
            " where idempotency_key = %(key)s "
            "   and operation = %(operation)s "
            #
            # `is not distinct from`, because a certificate job has no cluster
            # and `null = null` is null: a plain equality would never recognise
            # a certificate retry as the request it already queued, and the
            # refresh of a page would be reported as a key collision.
            #
            "   and cluster is not distinct from %(cluster)s "
            "   and payload_hash = sha256(convert_to(%(payload)s::jsonb::text, 'UTF8'))",
            parameters,
        )
        existing = cursor.fetchone()
    if existing is None:
        if constraint in {"job_one_active_per_cluster", "job_one_active_certificate"}:
            if conflict is None:  # pragma: no cover - the lookup only follows that violation
                raise psycopg.OperationalError(
                    "the cluster conflict was lost before classification"
                )
            active = active_job(connection, cluster)
            if constraint == "job_one_active_certificate":
                raise CertificateBusy(active=active) from conflict
            raise ClusterBusy(cluster, active=active) from conflict
        raise RequestConflict(str(idempotency_key))
    return existing


def active_job(connection: Connection[Any], cluster: str | None) -> Job | None:
    """The job that holds this cluster's place in the queue, or the certificates'.

    None when it ended between the refused insert and this read.
    """

    with connection.cursor(row_factory=class_row(Job)) as cursor:
        cursor.execute(
            "select id, request_id, operation, cluster, payload, state, created_at, "  # noqa: S608 - constant
            "       started_at, finished_at, exit_code, outcome, result, stderr_excerpt, "
            "       idempotency_key, attempts, held_since, held_decision, held_decided_by, "
            f"       {_LEASE_COLUMNS} "
            "  from job "
            " where cluster is not distinct from %(cluster)s "
            "   and state in ('pending', 'running')",
            {"cluster": cluster},
        )
        return cursor.fetchone()


def job_for_key(
    connection: Connection[Any], key: UUID, *, operation: str, cluster: str | None
) -> Job | None:
    """The job queued under this form's key for this operation and cluster, whatever it carried.

    For the forms whose payload is drawn afresh on every submission - a restore
    run's ID, a join key sealed again - and only after `queue_job` refused: a
    second click carries other bytes under the same key, which the queue reads
    as busy or as a collision although the first click queued the job (review
    26-10-24, 02-06). The key was drawn into one rendered form, so a job under
    it is the answer to that form.
    """

    with connection.cursor(row_factory=class_row(Job)) as cursor:
        cursor.execute(
            "select id, request_id, operation, cluster, payload, state, created_at, "
            "       started_at, finished_at, exit_code, outcome, result, stderr_excerpt, "
            "       idempotency_key, attempts "
            "  from job "
            " where idempotency_key = %(key)s "
            "   and operation = %(operation)s "
            "   and cluster is not distinct from %(cluster)s",
            {"key": str(key), "operation": operation, "cluster": cluster},
        )
        return cursor.fetchone()


def claim_job(
    connection: Connection[Any], *, worker_id: str, lease_seconds: int
) -> ClaimedJob | None:
    """Take the oldest waiting job, atomically, and hold it with a lease.

    One statement, never read-then-write. Two workers running the same select
    and then the same update would both believe they own the row; here the
    database decides, and the loser gets a different row or none.

    `for update skip locked` rather than a plain subselect: a worker must skip a
    row another worker is already taking rather than queue behind it, or one slow
    claim serialises every worker in the installation.

    The claim token is rotated on every claim, including a re-claim after an
    expired lease. That is what makes the fencing in `renew_lease` and
    `finish_job` work: the previous holder's token is no longer the row's token,
    so its writes are refused by the database rather than by its own good
    manners.

    Nothing is taken while a release has paused claims (`job_claim_gate`,
    CR-12). The release sets the pause holding a lock on this table that every
    claim also needs, so a claim either finished before the pause or reads it.

    `started_at` keeps its first value, because it records when the work first
    began and not when it was last picked up. `attempts` does the opposite: it
    counts the pickups, which is what the recovery path needs to know before it
    requeues anything a second time.
    """

    with connection.cursor(row_factory=class_row(ClaimedJob)) as cursor:
        cursor.execute(
            "update job "
            "   set state = 'running', "
            "       claim_token = gen_random_uuid(), "
            "       worker_id = %(worker_id)s, "
            "       lease_until = statement_timestamp() "
            "                     + %(lease_seconds)s * interval '1 second', "
            "       started_at = coalesce(started_at, statement_timestamp()), "
            "       attempts = attempts + 1 "
            " where id = ( "
            "         select id from job "
            "          where state = 'pending' "
            "            and (held_since is null or held_decision is not null) "
            "            and not exists ( "
            "                select 1 from job_claim_gate "
            "                 where paused_until > statement_timestamp()) "
            "          order by created_at, id "
            "            for update skip locked "
            "          limit 1) "
            "returning id, request_id, operation, cluster, payload, state, created_at, "
            "          started_at, finished_at, exit_code, outcome, result, "
            "          stderr_excerpt, idempotency_key, attempts, claim_token, "
            "          held_decision, held_decided_by",
            {"worker_id": worker_id, "lease_seconds": lease_seconds},
        )
        return cursor.fetchone()


def hold_jobs_queued_before(connection: Connection[Any], *, boot: datetime | None) -> list[int]:
    """Hold every waiting or running job queued before `boot` (0082, review 2026-10-20 R1).

    A manager restored from an image boots, and its database holds the jobs
    that were waiting at the backup's moment - which ran then. None of them is
    taken again until an admin says `run`. `boot` None holds every one: that is
    `haprion-backup after-restore`, for a dump restored without a boot.
    A running one stays running for recovery to settle; if recovery puts it
    back in the queue, the hold keeps it there.

    A job held at an earlier boot is held again and its answer cleared (0085,
    logic review 2026-10-22, L2): an answer holds for the machine's life it
    was given in. The function does it, since the worker may not write the
    answer itself.
    """

    with connection.cursor() as cursor:
        cursor.execute("select hold_jobs_queued_before(%(boot)s::timestamptz)", {"boot": boot})
        return sorted(row[0] for row in cursor.fetchall())


def decide_held_job(connection: Connection[Any], *, job_id: int, decision: str, actor: str) -> bool:
    """An admin's answer for a held job: `run` or `discard`. False when it is not held and waiting.

    Only the answer is written; the worker takes the job and runs or ends it,
    as it changes every job's state. A running one is answered too: recovery
    adopts it on its helper's kept answer only once it is (review 2026-10-28,
    F01), and `discard` then ends it on that answer without what follows.
    """

    with connection.cursor() as cursor:
        cursor.execute(
            "update job set held_decision = %(decision)s, held_decided_by = %(actor)s "
            " where id = %(id)s and state in ('pending', 'running') "
            "   and held_since is not null and held_decision is null",
            {"id": job_id, "decision": decision, "actor": actor},
        )
        if cursor.rowcount != 1:
            return False
        #
        # The worker sleeps until a job is queued; an answer is as good as one.
        #
        cursor.execute("notify job_queued")
        return True


def renew_lease(
    connection: Connection[Any], *, job_id: int, claim_token: UUID, lease_seconds: int
) -> bool:
    """Push the lease forward while the work is still running.

    False means the lease is gone - either its time elapsed or another worker
    holds the row. The caller must abort rather than finish: an expired lease is
    no longer authority to mutate even before recovery has assigned a new
    token, and two workers writing one result is the failure fencing prevents.
    """

    with connection.cursor() as cursor:
        cursor.execute(
            "update job "
            "   set lease_until = statement_timestamp() "
            "                     + %(lease_seconds)s * interval '1 second' "
            " where id = %(job_id)s "
            "   and claim_token = %(claim_token)s "
            "   and state = 'running' "
            "   and lease_until >= statement_timestamp() "
            "returning id",
            {"job_id": job_id, "claim_token": str(claim_token), "lease_seconds": lease_seconds},
        )
        return cursor.fetchone() is not None


def finish_job(
    connection: Connection[Any],
    *,
    job_id: int,
    claim_token: UUID,
    state: str,
    exit_code: int | None,
    outcome: str | None,
    result: Mapping[str, Any] | None,
    stderr_excerpt: str | None,
) -> bool:
    """Record how a job ended, if this process is still the one holding it.

    The claim token and an unexpired lease are in the WHERE clause for the same
    reason they are in `renew_lease`: a worker that woke after its authority
    elapsed must not be able to overwrite a result, whether or not recovery has
    assigned a new token yet. False is worth logging rather than retrying.

    The lease is cleared as part of finishing, so a reclaim query can never find
    a row that is already done.
    """

    with connection.cursor() as cursor:
        cursor.execute(
            "update job "
            "   set state = %(state)s, "
            "       finished_at = statement_timestamp(), "
            "       lease_until = null, "
            "       exit_code = %(exit_code)s, "
            "       outcome = %(outcome)s, "
            "       result = %(result)s, "
            "       stderr_excerpt = %(stderr_excerpt)s "
            " where id = %(job_id)s "
            "   and claim_token = %(claim_token)s "
            "   and state = 'running' "
            "   and lease_until >= statement_timestamp() "
            "returning id",
            {
                "job_id": job_id,
                "claim_token": str(claim_token),
                "state": state,
                "exit_code": exit_code,
                "outcome": outcome,
                "result": Jsonb(result) if result is not None else None,
                "stderr_excerpt": stderr_excerpt,
            },
        )
        finished = cursor.fetchone() is not None
        if finished:
            #
            # In the transaction, and only when the update actually landed. A
            # worker whose lease had elapsed changed nothing, and waking the
            # poller to re-read an unchanged world is a helper run against every
            # node for no reason.
            #
            # Every outcome notifies, not only the successful ones. A deploy
            # that failed partway still moved some nodes, and a poller told only
            # about the tidy endings would be most stale exactly when somebody
            # is looking hardest.
            #
            cursor.execute("notify cluster_changed")
        return finished


def wake_poller(connection: Connection[Any]) -> None:
    """Ask the poller to read the clusters now instead of at its next interval.

    A notification and nothing else. The poller owns every path to a node - the
    identity, both nodes, the timeouts - and a caller that wanted a fresher
    reading would otherwise need its own way to reach a machine. This one has
    no payload and grants nothing: the poller does what it always does, only
    sooner.
    """

    with connection.cursor() as cursor:
        cursor.execute(f"notify {CLUSTER_CHANNEL}")


def expired_leases(connection: Connection[Any]) -> list[AbandonedJob]:
    """Jobs whose holder stopped renewing, for the recovery path to adjudicate.

    Still a read: nothing here moves a job. A lease that ran out says the worker
    is gone; it does not say whether the operation ran, and only an operation
    proved not to have started, or proved safe to repeat, may be requeued. That
    judgement lives in `recovery`, which reads evidence this query does not have.

    `lease_until` is returned because the judgement depends on it: evidence
    gathered before the lease expired describes the world as it was while the
    operation may still have been running, and cannot settle anything.

    Its own row type rather than `Job`, because `lease_until` is not a column the
    web role may read. Widening `Job` would have put it in the shape a page
    renders, and the database would then refuse the page rather than the
    mistake.
    """

    with connection.cursor(row_factory=class_row(AbandonedJob)) as cursor:
        cursor.execute(
            "select id, request_id, operation, cluster, state, attempts, lease_until, "
            "       held_since, held_decision "
            "  from job "
            " where state = 'running' and lease_until < statement_timestamp() "
            " order by lease_until"
        )
        return cursor.fetchall()


def requeue_expired(connection: Connection[Any], *, job_id: int, attempts: int) -> bool:
    """Put one abandoned job back in the queue, atomically.

    The predicate is the whole safety of this. The row must still be running,
    its lease must still be in the past, and its attempt count must be the one
    the adjudication looked at - so a worker that claimed the job between the
    reading and this write finds its work untouched, and a second adjudicator
    running the same reasoning writes nothing. That is the same
    read-decide-write hazard `claim_job` avoids, on the way back out.

    The claim token is cleared rather than kept. The previous holder's token is
    then no longer the row's token, so a process that wakes up late is refused
    by the database even before another worker has claimed the row.

    False means the world moved and the caller must do nothing.
    """

    with connection.cursor() as cursor:
        cursor.execute(
            "update job "
            "   set state = 'pending', "
            "       claim_token = null, "
            "       worker_id = null, "
            "       lease_until = null "
            " where id = %(job_id)s "
            "   and state = 'running' "
            "   and lease_until < statement_timestamp() "
            "   and attempts = %(attempts)s "
            "returning id",
            {"job_id": job_id, "attempts": attempts},
        )
        return cursor.fetchone() is not None


def adopt_expired(
    connection: Connection[Any], *, job_id: int, attempts: int, worker_id: str, lease_seconds: int
) -> ClaimedJob | None:
    """Take one abandoned job over, to end it on the answer its helper kept (B367).

    Not a requeue: the operation is not run again. The helper behind a socket
    lived on when the worker that asked it stopped, and its kept answer is what
    the job ends on - with what follows it in the same job, a node change's
    deploy, run as the first worker would have. A fresh claim token and lease,
    so the adopting worker writes the end as any holder does, and one more
    attempt, so a job whose ending keeps stopping its worker is not adopted
    without end.

    Guarded as `requeue_expired` is; None means the world moved. And as a
    claim is (review 2026-10-28, F01, F03): nothing held and unanswered is
    adopted - what follows the kept answer is new work an admin has not
    allowed - and nothing while a release has paused claims. The pause holds
    the lock on this table every adoption needs, as `claim_job` says, so an
    adoption either finished before it, and is a running job the release
    waits for, or reads it.
    """

    with connection.cursor(row_factory=class_row(ClaimedJob)) as cursor:
        cursor.execute(
            "update job "
            "   set claim_token = gen_random_uuid(), "
            "       worker_id = %(worker_id)s, "
            "       lease_until = statement_timestamp() "
            "                     + %(lease_seconds)s * interval '1 second', "
            "       attempts = attempts + 1 "
            " where id = %(job_id)s "
            "   and state = 'running' "
            "   and lease_until < statement_timestamp() "
            "   and attempts = %(attempts)s "
            "   and (held_since is null or held_decision is not null) "
            "   and not exists ( "
            "       select 1 from job_claim_gate "
            "        where paused_until > statement_timestamp()) "
            "returning id, request_id, operation, cluster, payload, state, created_at, "
            "          started_at, finished_at, exit_code, outcome, result, "
            "          stderr_excerpt, idempotency_key, attempts, claim_token, "
            "          held_decision, held_decided_by",
            {
                "job_id": job_id,
                "attempts": attempts,
                "worker_id": worker_id,
                "lease_seconds": lease_seconds,
            },
        )
        return cursor.fetchone()


def abandon_expired(
    connection: Connection[Any],
    *,
    job_id: int,
    attempts: int,
    code: str,
    message: str,
    answer: dict[str, Any] | None = None,
) -> bool:
    """End one abandoned job as `unknown`, atomically.

    `unknown` is not a failure and must not read as one. It says the operation
    may or may not have taken effect, which is the honest answer when the worker
    that held it is gone and nothing readable settles the question. Nothing
    retries it; a person decides.

    Guarded exactly as `requeue_expired` is, and for the same reason: the
    adjudication read the row a moment ago, and only a row that has not moved
    since may be written. A helper's `answer` that was kept, when there is one,
    is stored beside the error, as the worker keeps an answer it could not
    record as done (`exit_mismatch`).
    """

    result: dict[str, Any] = {"error": {"code": code, "message": message}}
    if answer is not None:
        result["answer"] = answer

    with connection.cursor() as cursor:
        cursor.execute(
            "update job "
            "   set state = 'unknown', "
            "       outcome = 'unknown', "
            "       finished_at = statement_timestamp(), "
            "       claim_token = null, "
            "       worker_id = null, "
            "       lease_until = null, "
            "       result = %(result)s "
            " where id = %(job_id)s "
            "   and state = 'running' "
            "   and lease_until < statement_timestamp() "
            "   and attempts = %(attempts)s "
            "returning id",
            {
                "job_id": job_id,
                "attempts": attempts,
                "result": Jsonb(result),
            },
        )
        return cursor.fetchone() is not None
