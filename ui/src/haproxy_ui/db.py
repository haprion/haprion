"""Reaching the database, with the transaction boundary visible from the caller.

Every function here takes a connection. None of them opens one, commits one, or
decides how long one is held - because the two mistakes this layer exists to
prevent are both about scope rather than syntax:

* an audit record written in a different transaction from the change it
  describes, which leaves a history that can disagree with what happened
* a connection held while a subprocess runs. A rollout takes minutes and a pool
  has a handful of connections; a worker that keeps one for the duration is a
  worker that stops the interface from answering.

So the caller opens a transaction, does everything belonging to it, and closes
it. What is inside is visible at the call site instead of buried here.

Columns are listed one at a time in every statement, never `*`. A schema change
then shows up as a failure at the query that must change, and the row shapes
below stay a contract rather than whatever the table happens to hold.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import psycopg
from haproxy_mgmt import node_resources
from haproxy_mgmt.generate import METRICS_FRONTEND
from psycopg import Connection, sql
from psycopg.rows import class_row
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

from haproxy_ui import metrics, search_index
from haproxy_ui.config import Database


@dataclass(frozen=True, slots=True)
class Account:
    id: int
    username: str
    role: str
    disabled: bool
    #
    # None for an account the provider owns (0041): it has no password, and
    # the sign-in form treats it as it treats a disabled one.
    #
    password_hash: str | None
    source: str = "local"
    break_glass: bool = False
    oidc_issuer: str | None = None


@dataclass(frozen=True, slots=True)
class AccountRow:
    """One line of Settings -> Users: an account and what is true of it now."""

    id: int
    username: str
    role: str
    disabled: bool
    sessions: int
    last_sign_in: datetime | None
    locked: bool
    source: str = "local"
    break_glass: bool = False


@dataclass(frozen=True, slots=True)
class AuthenticatedSession:
    """A live session and the account it belongs to, read in one statement.

    Joined rather than fetched in two queries because every authenticated
    request needs both, and two round trips per request is a cost paid on the
    hot path for no benefit. The row is also the only place the two can be seen
    to agree: a session whose account has since been disabled is caught here,
    not later.
    """

    token_hash: bytes
    user_id: int
    username: str
    role: str
    disabled: bool
    created_at: datetime
    last_seen_at: datetime
    expires_at: datetime
    revoked_at: datetime | None
    #
    # `oidc` for an account the provider owns (0041): it has no password here,
    # so the account menu offers none to change.
    #
    source: str = "local"


@dataclass(frozen=True, slots=True)
class ClusterStatus:
    cluster: str
    observed_at: datetime
    outcome: str
    result: dict[str, Any]
    warnings: list[Any]
    error: dict[str, Any] | None
    poll_error: str | None


@dataclass(frozen=True, slots=True)
class ClusterInventory:
    """The last published configuration inventory the poller could read."""

    cluster: str
    observed_at: datetime
    outcome: str
    result: dict[str, Any]
    warnings: list[Any]
    error: dict[str, Any] | None
    poll_error: str | None


@dataclass(frozen=True, slots=True)
class ClusterBackups:
    """The last state backup listing the poller could read for one cluster."""

    cluster: str
    observed_at: datetime
    outcome: str
    result: dict[str, Any]
    warnings: list[Any]
    error: dict[str, Any] | None
    poll_error: str | None


@dataclass(frozen=True, slots=True)
class ClusterCertificates:
    """The last certificate metadata the poller could read for one cluster."""

    cluster: str
    observed_at: datetime
    outcome: str
    result: dict[str, Any]
    warnings: list[Any]
    error: dict[str, Any] | None
    poll_error: str | None


@dataclass(frozen=True, slots=True)
class ClusterSettingsRow:
    """The last settings reading - log targets and metrics - for one cluster (Fas 15)."""

    cluster: str
    observed_at: datetime
    outcome: str
    result: dict[str, Any]
    warnings: list[Any]
    error: dict[str, Any] | None
    poll_error: str | None


@dataclass(frozen=True, slots=True)
class ClusterNetwork:
    """The last network description the poller could read for one cluster."""

    cluster: str
    observed_at: datetime
    outcome: str
    result: dict[str, Any]
    warnings: list[Any]
    error: dict[str, Any] | None
    poll_error: str | None


@dataclass(frozen=True, slots=True)
class ClusterObjects:
    """The last reading of one cluster's proxy objects as they are written.

    Distinct from `ClusterInventory`, which holds published HAProxy
    configuration. That answers what a node is serving; this answers what an
    edit is made against, and the two are the same only until somebody edits.
    """

    cluster: str
    observed_at: datetime
    outcome: str
    result: dict[str, Any]
    warnings: list[Any]
    error: dict[str, Any] | None
    poll_error: str | None


@dataclass(frozen=True, slots=True)
class ClusterHistory:
    """The last version listing the poller could read for one cluster."""

    cluster: str
    observed_at: datetime
    outcome: str
    result: dict[str, Any]
    warnings: list[Any]
    error: dict[str, Any] | None
    poll_error: str | None


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


def pool(database: Database, *, min_size: int = 1, max_size: int = 4) -> ConnectionPool:
    """A small pool, opened explicitly by whoever owns its lifetime.

    Deliberately small. These services do a handful of short queries per
    request; a large pool would mostly serve to let a mistake hold many
    connections instead of one, and PostgreSQL charges for each of them.

    `open=False` so nothing connects as a side effect of importing or
    constructing. Failing to reach the database has to happen where it can be
    reported, not during module import.
    """

    return ConnectionPool(
        conninfo=database.connection_string,
        min_size=min_size,
        max_size=max_size,
        open=False,
    )


JOB_CHANNEL = "job_queued"

#
# The other direction. `job_queued` tells the worker that something is waiting;
# this one tells the poller that something has happened, so the cache it feeds
# every page from is re-read within seconds instead of at the next tick.
#
CLUSTER_CHANNEL = "cluster_changed"


def listener(database: Database, channel: str = JOB_CHANNEL) -> Connection[Any]:
    """A connection whose only job is to be told when something arrives.

    Its own connection rather than one from the pool. A listener is held for the
    process's whole life, and the pool exists for short queries - lending one out
    permanently would leave the pool a size smaller than it says it is, in a way
    that only shows up under load.

    `autocommit` because a LISTEN inside a transaction does not take effect until
    that transaction commits, so a listener in transaction mode would wait
    politely for notifications it had not actually subscribed to yet.

    The channel is passed as an identifier rather than interpolated. It is a
    constant today; a constant that is formatted by hand is how the next caller
    learns the wrong habit.
    """

    connection = psycopg.connect(database.connection_string, autocommit=True)
    connection.execute(sql.SQL("listen {}").format(sql.Identifier(channel)))
    return connection


def lock_session(database: Database) -> Connection[Any]:
    """A connection whose only job is to hold a singleton advisory lock.

    Its own connection rather than one from the pool, for the same reason the
    listener has one: it is held for the process's whole life, and the pool
    exists for short queries.

    `autocommit` is what makes the lock survive. A session-scoped advisory lock
    lives exactly as long as its session, and taking it in transaction mode
    leaves an open transaction that nothing ever commits. The roles here carry
    `idle_in_transaction_session_timeout = 10s`, so the server closes that
    session ten seconds in and takes the lock with it - while the process that
    believes it holds the lock keeps running. Autocommit means there is no
    transaction to sit idle, so the session stays and the lock stays with it.
    """

    return psycopg.connect(database.connection_string, autocommit=True)


def connected_identity(connection: Connection[Any]) -> tuple[str, str]:
    """Who the database thinks we are, and which database this is.

    Asked rather than assumed. Peer authentication means the answer is decided
    by the kernel and the role map, so this is the only honest way to state the
    identity a process is actually using - and the health endpoint reports it,
    because "running as the wrong role" otherwise looks exactly like working.
    """

    with connection.cursor() as cursor:
        cursor.execute("select current_user, current_database()")
        row = cursor.fetchone()
    if row is None:  # pragma: no cover - a select of two constants returns a row
        raise psycopg.OperationalError("the database did not answer current_user")
    return str(row[0]), str(row[1])


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


@dataclass(frozen=True, slots=True)
class ProxyDraft:
    """One object being edited, and what it was edited against.

    `base_hash` is the commit the draft was derived from; a publish compares
    its snapshot to it, so a draft made against a tree that has since moved is
    refused rather than applied to something else. `revision` is the database's
    own counter, raised by a trigger on every write, and it is what tells two
    tabs apart.

    `deleted` means the draft asks for the object to be *removed* when it is
    published. It is not a discarded draft - discarding one deletes the row,
    because an abandoned edit should leave nothing behind to be mistaken for a
    decision.
    """

    cluster: str
    object_id: str
    yaml: str
    base_version: int | None
    base_hash: str
    revision: int
    updated_by: str
    updated_at: datetime
    deleted: bool
    #
    # Set by the database and never by the caller. A draft is deleted once its
    # publish is done, so the next edit of the same object starts again at
    # revision 1 under the same key - and this is what tells the two apart. The
    # job that publishes a draft names it, and the row that appears afterwards
    # is visibly not the row that was published.
    #
    id: UUID | None = None


class DraftConflict(Exception):
    """Somebody else wrote this draft since it was read.

    The revision the caller carried is not the one in the table. Refused rather
    than merged: the two edits are both somebody's intention, and picking one
    silently is how the other disappears without anyone noticing.
    """


class ClusterBusy(Exception):
    """A job for this cluster is already pending or running.

    Not an error in the caller's request - the request was fine, the cluster is
    not free. The two are told apart because the answer differs: this one is
    worth retrying when the running job finishes, and the one below never is.
    """


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
    """


class RequestConflict(Exception):
    """The same idempotency key, asking for something else.

    A retry carries the key it used before. If what it now asks for differs, the
    two are not the same attempt, and treating it as a no-op would silently drop
    an operation somebody asked for. Refused rather than queued, and never
    treated as already done.
    """


def recent_jobs(
    connection: Connection[Any], *, cluster: str | None = None, limit: int = 20
) -> list[Job]:
    """The newest jobs, optionally for one cluster.

    The cluster arrives as a bound parameter, never as text pasted into the
    statement. That is not only about injection: a bound parameter is also what
    lets PostgreSQL keep the plan, and it keeps the SQL below identical to what
    can be pasted into psql while debugging.
    """

    with connection.cursor(row_factory=class_row(Job)) as cursor:
        cursor.execute(
            "select id, request_id, operation, cluster, payload, state, created_at, "
            "       started_at, finished_at, exit_code, outcome, result, stderr_excerpt, "
            "       idempotency_key, attempts "
            "  from job "
            " where (%(cluster)s::text is null or cluster = %(cluster)s) "
            " order by created_at desc, id desc "
            " limit %(limit)s",
            {"cluster": cluster, "limit": limit},
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
            "       idempotency_key, attempts "
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
    the retention keeps (`haproxy-ui-retention`, `profile_evidence`).
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
            "       idempotency_key, attempts "
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
        with connection.transaction(), connection.cursor(row_factory=class_row(Job)) as cursor:
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
            if constraint == "job_one_active_certificate":
                raise CertificateBusy() from conflict
            raise ClusterBusy(cluster) from conflict
        raise RequestConflict(str(idempotency_key))
    return existing


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
            "          order by created_at, id "
            "            for update skip locked "
            "          limit 1) "
            "returning id, request_id, operation, cluster, payload, state, created_at, "
            "          started_at, finished_at, exit_code, outcome, result, "
            "          stderr_excerpt, idempotency_key, attempts, claim_token",
            {"worker_id": worker_id, "lease_seconds": lease_seconds},
        )
        return cursor.fetchone()


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
            "select id, request_id, operation, cluster, state, attempts, lease_until "
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


def abandon_expired(
    connection: Connection[Any], *, job_id: int, attempts: int, code: str, message: str
) -> bool:
    """End one abandoned job as `unknown`, atomically.

    `unknown` is not a failure and must not read as one. It says the operation
    may or may not have taken effect, which is the honest answer when the worker
    that held it is gone and nothing readable settles the question. Nothing
    retries it; a person decides.

    Guarded exactly as `requeue_expired` is, and for the same reason: the
    adjudication read the row a moment ago, and only a row that has not moved
    since may be written.
    """

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
                "result": Jsonb({"error": {"code": code, "message": message}}),
            },
        )
        return cursor.fetchone() is not None


def account_by_username(connection: Connection[Any], username: str) -> Account | None:
    """Look an account up by the normalised name.

    The comparison uses the generated column rather than `lower(username)` in
    the predicate, so it reads the unique index and cannot disagree with the
    constraint that made the name unique in the first place.
    """

    with connection.cursor(row_factory=class_row(Account)) as cursor:
        cursor.execute(
            "select id, username, role, disabled, password_hash, source, break_glass, oidc_issuer "
            "  from app_user "
            " where username_normalised = lower(%(username)s)",
            {"username": username},
        )
        return cursor.fetchone()


def record_login_attempt(
    connection: Connection[Any], *, username: str, client_ip: str, succeeded: bool
) -> None:
    """Write down that someone tried. Always, whichever way it went.

    Successes are recorded too, and not for symmetry: the throttle counts
    failures *since the last success*, so without the success rows a person who
    mistypes a password four times and then logs in correctly would still be
    carrying those four failures for the rest of the window.
    """

    with connection.cursor() as cursor:
        cursor.execute(
            "insert into login_attempt (username_normalised, client_ip, succeeded) "
            "values (lower(%(username)s), %(client_ip)s, %(succeeded)s)",
            {"username": username, "client_ip": client_ip, "succeeded": succeeded},
        )


def failures_since_last_success(
    connection: Connection[Any], *, username: str, client_ip: str, window_minutes: int
) -> int:
    """How many failures this name and address have accumulated recently.

    Two bounds, and both are needed. The window keeps an old mistake from
    counting forever; "since the last success" keeps a person who has proved
    they know the password from being locked out by their own earlier typos.
    An unlock (0039) counts as that success for every address: the failures
    stay in the record, and stop counting.
    """

    with connection.cursor() as cursor:
        cursor.execute(
            "select count(*) "
            "  from login_attempt "
            " where username_normalised = lower(%(username)s) "
            "   and client_ip = %(client_ip)s "
            "   and succeeded = false "
            "   and at > statement_timestamp() - make_interval(mins => %(window)s) "
            "   and at > greatest( "
            "         coalesce((select max(at) from login_attempt "
            "                    where username_normalised = lower(%(username)s) "
            "                      and client_ip = %(client_ip)s "
            "                      and succeeded = true), '-infinity'::timestamptz), "
            "         coalesce((select max(at) from login_unlock "
            "                    where username_normalised = lower(%(username)s)), "
            "                  '-infinity'::timestamptz))",
            {"username": username, "client_ip": client_ip, "window": window_minutes},
        )
        row = cursor.fetchone()
    return int(row[0]) if row is not None else 0


def create_session(
    connection: Connection[Any],
    *,
    token_hash: bytes,
    user_id: int,
    expires_at: datetime,
    id_token: str | None = None,
) -> None:
    """Store the hash of a session token, never the token.

    Three columns, which is exactly what the web role holds `insert` on.
    `created_at` and `last_seen_at` come from column defaults, so a session
    cannot be recorded as older or fresher than it is.
    """

    with connection.cursor() as cursor:
        cursor.execute(
            "insert into app_session (token_hash, user_id, expires_at, id_token) "
            "values (%(token_hash)s, %(user_id)s, %(expires_at)s, %(id_token)s)",
            {
                "token_hash": token_hash,
                "user_id": user_id,
                "expires_at": expires_at,
                "id_token": id_token,
            },
        )


def session_by_hash(connection: Connection[Any], token_hash: bytes) -> AuthenticatedSession | None:
    """The session and its account, or nothing.

    Deliberately returns rows that are expired, revoked or disabled rather than
    filtering them out in SQL. Whether a session is still usable is a policy
    question with a timeout in it, and it belongs where the timeout is
    configured - not spread between here and there.
    """

    with connection.cursor(row_factory=class_row(AuthenticatedSession)) as cursor:
        cursor.execute(
            "select s.token_hash, s.user_id, u.username, u.role, u.disabled, "
            "       s.created_at, s.last_seen_at, s.expires_at, s.revoked_at, u.source "
            "  from app_session s "
            "  join app_user u on u.id = s.user_id "
            " where s.token_hash = %(token_hash)s",
            {"token_hash": token_hash},
        )
        return cursor.fetchone()


def touch_session(connection: Connection[Any], token_hash: bytes) -> None:
    """Move the inactivity clock forward, and nothing else.

    `last_seen_at` is set from `statement_timestamp()` rather than from a value
    this process supplies, and `expires_at` is not touched at all - the web role
    holds no `update` on it. A session can therefore be kept alive by use, and
    still never outlive the absolute limit it was issued with.
    """

    with connection.cursor() as cursor:
        cursor.execute(
            "update app_session set last_seen_at = statement_timestamp() "
            " where token_hash = %(token_hash)s and revoked_at is null",
            {"token_hash": token_hash},
        )


def revoke_session(connection: Connection[Any], token_hash: bytes) -> None:
    """End one session. Idempotent, and never un-revokes one already ended."""

    with connection.cursor() as cursor:
        cursor.execute(
            "update app_session set revoked_at = statement_timestamp() "
            " where token_hash = %(token_hash)s and revoked_at is null",
            {"token_hash": token_hash},
        )


def change_password(
    connection: Connection[Any], *, user_id: int, password_hash: str, keep: bytes
) -> int:
    """Set an account's own new password and end its other sessions.

    The one it was changed from stays signed in; every other cookie goes, as a
    reset on the command line does, because a password is usually changed when
    somebody else may have had it. `updated_at` is the database's to set.
    Returns how many sessions were ended.
    """

    with connection.cursor() as cursor:
        cursor.execute(
            "update app_user set password_hash = %(hash)s where id = %(user_id)s",
            {"hash": password_hash, "user_id": user_id},
        )
        cursor.execute(
            "update app_session set revoked_at = statement_timestamp() "
            " where user_id = %(user_id)s and token_hash <> %(keep)s and revoked_at is null",
            {"user_id": user_id, "keep": keep},
        )
        return cursor.rowcount


#
# *Locked* is the throttle's own question asked for every address at once: a
# name is locked when any one address has reached the limit of failures since
# the latest of its last success there and the name's last unlock. The same
# bounds as `failures_since_last_success`, which is what the sign-in reads.
#
_ACCOUNT_ROWS = """
    select u.id, u.username, u.role, u.disabled, u.source, u.break_glass,
           (select count(*) from app_session s
             where s.user_id = u.id and s.revoked_at is null
               and s.expires_at > statement_timestamp()) as sessions,
           (select max(a.at) from login_attempt a
             where a.username_normalised = u.username_normalised and a.succeeded) as last_sign_in,
           exists (
             select 1 from login_attempt a
              where a.username_normalised = u.username_normalised
                and not a.succeeded
                and a.at > statement_timestamp() - make_interval(mins => %(window)s)
                and a.at > greatest(
                      coalesce((select max(b.at) from login_attempt b
                                 where b.username_normalised = a.username_normalised
                                   and b.client_ip = a.client_ip and b.succeeded),
                               '-infinity'::timestamptz),
                      coalesce((select max(l.at) from login_unlock l
                                 where l.username_normalised = a.username_normalised),
                               '-infinity'::timestamptz))
              group by a.client_ip
             having count(*) >= %(limit)s) as locked
      from app_user u
"""


def account_rows(
    connection: Connection[Any], *, window_minutes: int, max_failures: int
) -> list[AccountRow]:
    """Every account, in the order a person reads names: alphabetical."""

    with connection.cursor(row_factory=class_row(AccountRow)) as cursor:
        cursor.execute(
            _ACCOUNT_ROWS + " order by u.username_normalised",
            {"window": window_minutes, "limit": max_failures},
        )
        return cursor.fetchall()


def account_row(
    connection: Connection[Any], username: str, *, window_minutes: int, max_failures: int
) -> AccountRow | None:
    with connection.cursor(row_factory=class_row(AccountRow)) as cursor:
        cursor.execute(
            _ACCOUNT_ROWS + " where u.username_normalised = lower(%(username)s)",
            {"window": window_minutes, "limit": max_failures, "username": username},
        )
        return cursor.fetchone()


@dataclass(frozen=True, slots=True)
class FeatureSwitch:
    """One of the capabilities an installation may turn off (0040, B193)."""

    name: str
    enabled: bool
    remembered: dict[str, Any]
    updated_at: datetime
    updated_by: str | None


def feature_switches(connection: Connection[Any]) -> dict[str, FeatureSwitch]:
    """Every switch by name. Before 0040 there are none, and everything is on."""

    with connection.cursor(row_factory=class_row(FeatureSwitch)) as cursor:
        cursor.execute(
            "select name, enabled, remembered, updated_at, updated_by from feature_switch"
        )
        return {row.name: row for row in cursor.fetchall()}


def set_feature_switch(
    connection: Connection[Any],
    *,
    name: str,
    enabled: bool,
    remembered: Mapping[str, Any],
    actor: str,
) -> bool:
    """Flip one switch, if it is not already where it is asked to go.

    The condition is in the statement, so two admins pressing the same button
    at once flip it once: the second finds it already flipped and is told so.
    """

    with connection.cursor() as cursor:
        cursor.execute(
            "update feature_switch "
            "   set enabled = %(enabled)s, remembered = %(remembered)s, updated_by = %(actor)s "
            " where name = %(name)s and enabled is distinct from %(enabled)s",
            {
                "name": name,
                "enabled": enabled,
                "remembered": Jsonb(dict(remembered)),
                "actor": actor,
            },
        )
        return cursor.rowcount == 1


class LastAdmin(Exception):
    """The database refused to leave no active admin (0039's trigger, widened by 0041)."""


class NoBreakGlass(LastAdmin):
    """The same trigger, refusing to leave no active break-glass admin while
    sign-in through the provider is on (0041)."""


def create_account(
    connection: Connection[Any],
    *,
    username: str,
    password_hash: str,
    role: str,
    break_glass: bool = False,
) -> bool:
    """A new local account, or False when the name is taken. The CLI's `add`."""

    with connection.cursor() as cursor:
        cursor.execute(
            "insert into app_user (username, password_hash, role, break_glass) "
            "values (%(username)s, %(hash)s, %(role)s, %(break_glass)s) "
            "on conflict do nothing returning id",
            {
                "username": username,
                "hash": password_hash,
                "role": role,
                "break_glass": break_glass,
            },
        )
        return cursor.fetchone() is not None


def _guarded_update(connection: Connection[Any], statement: str, values: dict[str, Any]) -> None:
    """An update the last-admin trigger may refuse, turned into `LastAdmin`.

    Run under a savepoint so the refusal leaves the caller's transaction usable
    for the audit row that says what was refused.
    """

    try:
        with connection.transaction(), connection.cursor() as cursor:
            cursor.execute(statement, values)
    except psycopg.errors.CheckViolation as error:
        #
        # The trigger raises without a constraint name; a named one is a
        # table constraint (a role outside the list) and stays what it is.
        # Its two refusals are told apart by what it says.
        #
        if error.diag.constraint_name is None:
            if "break-glass" in (error.diag.message_primary or ""):
                raise NoBreakGlass from error
            raise LastAdmin from error
        raise


def set_role(connection: Connection[Any], *, user_id: int, role: str) -> None:
    _guarded_update(
        connection,
        "update app_user set role = %(role)s where id = %(user_id)s",
        {"role": role, "user_id": user_id},
    )


def set_disabled(connection: Connection[Any], *, user_id: int, disabled: bool) -> int:
    """Disable or enable; a disable ends every session, as the CLI's does."""

    _guarded_update(
        connection,
        "update app_user set disabled = %(disabled)s where id = %(user_id)s",
        {"disabled": disabled, "user_id": user_id},
    )
    return revoke_sessions_for_user(connection, user_id) if disabled else 0


def set_break_glass(connection: Connection[Any], *, user_id: int, break_glass: bool) -> None:
    """Mark a local account as one that signs in with a password whatever else is on (B195)."""

    _guarded_update(
        connection,
        "update app_user set break_glass = %(break_glass)s where id = %(user_id)s",
        {"break_glass": break_glass, "user_id": user_id},
    )


def delete_account(connection: Connection[Any], *, user_id: int) -> bool:
    """Remove an account for good (B197). Its sessions go with it; jobs and the
    audit trail keep the name. False when it was already gone."""

    try:
        with connection.transaction(), connection.cursor() as cursor:
            cursor.execute("delete from app_user where id = %s", (user_id,))
            return cursor.rowcount == 1
    except psycopg.errors.CheckViolation as error:
        if "break-glass" in (error.diag.message_primary or ""):
            raise NoBreakGlass from error
        raise LastAdmin from error


def reset_password(connection: Connection[Any], *, user_id: int, password_hash: str) -> int:
    """Another account's new password, and every session it had. The CLI's `reset`."""

    with connection.cursor() as cursor:
        cursor.execute(
            "update app_user set password_hash = %(hash)s where id = %(user_id)s",
            {"hash": password_hash, "user_id": user_id},
        )
    return revoke_sessions_for_user(connection, user_id)


def unlock_account(connection: Connection[Any], *, username: str, actor: str) -> None:
    """The row the throttle counts from. The CLI's `unlock` writes the same one."""

    with connection.cursor() as cursor:
        cursor.execute(
            "insert into login_unlock (username_normalised, actor) values (lower(%s), %s)",
            (username, actor),
        )


def revoke_sessions_for_user(connection: Connection[Any], user_id: int) -> int:
    """End every live session an account has, and say how many that was.

    What "log this person out everywhere" means, and what a password reset or a
    disable has to do to be worth anything: an account that cannot log in again
    while its existing cookie keeps working has not really been disabled.
    """

    with connection.cursor() as cursor:
        cursor.execute(
            "update app_session set revoked_at = statement_timestamp() "
            " where user_id = %(user_id)s and revoked_at is null",
            {"user_id": user_id},
        )
        return cursor.rowcount


def record_audit_event(
    connection: Connection[Any],
    *,
    actor: str | None,
    action: str,
    cluster: str | None = None,
    request_id: UUID | None = None,
    detail: Mapping[str, Any] | None = None,
) -> None:
    """Append to the record.

    Written in the caller's transaction, which is the entire reason this module
    takes connections instead of opening them: an audit row that commits
    separately from the thing it describes is a history that can disagree with
    what happened.
    """

    with connection.cursor() as cursor:
        cursor.execute(
            "insert into audit_event (actor, action, cluster, request_id, detail) "
            "values (%(actor)s, %(action)s, %(cluster)s, %(request_id)s, %(detail)s)",
            {
                "actor": actor,
                "action": action,
                "cluster": cluster,
                "request_id": request_id,
                "detail": Jsonb(dict(detail or {})),
            },
        )


#
# Older than this, the previous reading is not used for a CPU share: an average
# over a poller that stood still for an hour describes that hour, not now.
#
CPU_READING_MAX_GAP = timedelta(minutes=5)


def _with_cpu_shares(result: Mapping[str, Any], previous: Any) -> Mapping[str, Any]:
    """Each node's CPU share since its previous reading, as `cpu_percent` beside its status.

    `null` without a previous reading of the same node, so the first answer
    after a gap shows a dash rather than a figure averaged over the gap.
    """

    nodes = result.get("nodes")
    if not isinstance(nodes, list):
        return result
    before: dict[str, Any] = {}
    if isinstance(previous, Mapping) and isinstance(previous.get("nodes"), list):
        for node in previous["nodes"]:
            if isinstance(node, Mapping) and isinstance(node.get("status"), Mapping):
                before[str(node.get("name"))] = node["status"].get("resources")
    shared: list[Any] = []
    for node in nodes:
        if not isinstance(node, Mapping):
            shared.append(node)
            continue
        status = node.get("status")
        current = status.get("resources") if isinstance(status, Mapping) else None
        shared.append(
            {
                **node,
                "cpu_percent": node_resources.cpu_percent(
                    before.get(str(node.get("name"))), current
                ),
            }
        )
    return {**result, "nodes": shared}


def record_cluster_status(
    connection: Connection[Any],
    *,
    cluster: str,
    outcome: str,
    result: Mapping[str, Any],
    warnings: Any = None,
    error: Mapping[str, Any] | None = None,
    poll_error: str | None = None,
) -> None:
    """Write what one cluster last said. Insert or replace, never accumulate.

    One row per cluster rather than a history: this is a cache of the newest
    answer, and what happened over time belongs in metrics, which is a later
    phase with different retention. Keeping every poll here would grow without
    bound to answer a question nothing asks.

    `observed_at` appears nowhere in this statement. The database sets it, on
    insert by default and on update by trigger, so the freshness a reader
    trusts is not something the writer supplies.
    """

    with connection.cursor() as cursor:
        #
        # The previous answer, read before it is replaced: CPU use is a rate,
        # and this row is the only place the previous reading is kept (B239).
        #
        cursor.execute(
            "select result, now() - observed_at <= %(fresh)s "
            "  from cluster_status where cluster = %(cluster)s",
            {"cluster": cluster, "fresh": CPU_READING_MAX_GAP},
        )
        previous = cursor.fetchone()
        result = _with_cpu_shares(result, previous[0] if previous and previous[1] else None)
        cursor.execute(
            "insert into cluster_status (cluster, outcome, result, warnings, error, poll_error) "
            "values (%(cluster)s, %(outcome)s, %(result)s, %(warnings)s, %(error)s, %(poll)s) "
            "on conflict (cluster) do update set "
            "    outcome = excluded.outcome, "
            "    result = excluded.result, "
            "    warnings = excluded.warnings, "
            "    error = excluded.error, "
            "    poll_error = excluded.poll_error",
            {
                "cluster": cluster,
                "outcome": outcome,
                "result": Jsonb(dict(result)),
                "warnings": Jsonb(list(warnings or [])),
                "error": None if error is None else Jsonb(dict(error)),
                "poll": poll_error,
            },
        )


def cluster_statuses(connection: Connection[Any]) -> list[ClusterStatus]:
    """Every cluster's newest reading, oldest observation first.

    Ordered by age rather than by name, so whatever has gone stale is what a
    reader sees at the top - which is the row that means something is wrong.
    """

    with connection.cursor(row_factory=class_row(ClusterStatus)) as cursor:
        cursor.execute(
            "select cluster, observed_at, outcome, result, warnings, error, poll_error "
            "  from cluster_status "
            " order by observed_at asc"
        )
        return cursor.fetchall()


def record_cluster_inventory(
    connection: Connection[Any],
    *,
    cluster: str,
    outcome: str,
    result: Mapping[str, Any],
    warnings: Any = None,
    error: Mapping[str, Any] | None = None,
    poll_error: str | None = None,
) -> None:
    """Replace one cluster's cached inventory with the newest helper answer."""

    with connection.cursor() as cursor:
        cursor.execute(
            "insert into cluster_inventory (cluster, outcome, result, warnings, error, poll_error) "
            "values (%(cluster)s, %(outcome)s, %(result)s, %(warnings)s, %(error)s, %(poll)s) "
            "on conflict (cluster) do update set "
            "    outcome = excluded.outcome, "
            "    result = excluded.result, "
            "    warnings = excluded.warnings, "
            "    error = excluded.error, "
            "    poll_error = excluded.poll_error",
            {
                "cluster": cluster,
                "outcome": outcome,
                "result": Jsonb(dict(result)),
                "warnings": Jsonb(list(warnings or [])),
                "error": None if error is None else Jsonb(dict(error)),
                "poll": poll_error,
            },
        )


def cluster_inventories(connection: Connection[Any]) -> list[ClusterInventory]:
    """Every cluster's newest inventory, with the stalest one first."""

    with connection.cursor(row_factory=class_row(ClusterInventory)) as cursor:
        cursor.execute(
            "select cluster, observed_at, outcome, result, warnings, error, poll_error "
            "  from cluster_inventory "
            " order by observed_at asc"
        )
        return cursor.fetchall()


COMMIT_SHAPE = re.compile(r"^[0-9a-f]{40,64}$")


def versions_without_diff(
    connection: Connection[Any], *, cluster: str, limit: int
) -> tuple[str, ...]:
    """The newest listed versions of a cluster whose diff is not kept yet.

    Read from the listing the previous pass stored: the first pass after a
    publish lists the new version, and the next one asks for its diff.
    """

    with connection.cursor() as cursor:
        cursor.execute(
            "select version ->> 'hash' from cluster_history history, "
            "     jsonb_array_elements(case jsonb_typeof(history.result -> 'versions') "
            "         when 'array' then history.result -> 'versions' else '[]'::jsonb end) "
            "     with ordinality as listed(version, position) "
            " where history.cluster = %(cluster)s "
            "   and not exists (select 1 from version_diff kept "
            "                    where kept.cluster = history.cluster "
            "                      and kept.commit = version ->> 'hash') "
            " order by position limit %(limit)s",
            {"cluster": cluster, "limit": limit},
        )
        return tuple(
            row[0]
            for row in cursor.fetchall()
            if isinstance(row[0], str) and COMMIT_SHAPE.fullmatch(row[0])
        )


def record_version_diffs(
    connection: Connection[Any], *, cluster: str, result: Mapping[str, Any]
) -> int:
    """Keep the diffs a listing carried, once each; answer how many were new."""

    diffs = result.get("diffs")
    if not isinstance(diffs, Mapping):
        return 0
    written = 0
    with connection.cursor() as cursor:
        for commit, diff in diffs.items():
            if not isinstance(commit, str) or not COMMIT_SHAPE.fullmatch(commit):
                continue
            if not isinstance(diff, Mapping):
                continue
            cursor.execute(
                "insert into version_diff (cluster, commit, diff) "
                "values (%(cluster)s, %(commit)s, %(diff)s) on conflict do nothing",
                {"cluster": cluster, "commit": commit, "diff": Jsonb(dict(diff))},
            )
            written += cursor.rowcount
    return written


def read_version_diff(
    connection: Connection[Any], *, cluster: str, commit: str
) -> Mapping[str, Any] | None:
    """One version's diff as kept, or None when it has not been fetched yet."""

    if not COMMIT_SHAPE.fullmatch(commit):
        return None
    with connection.cursor() as cursor:
        cursor.execute(
            "select diff from version_diff where cluster = %(cluster)s and commit = %(commit)s",
            {"cluster": cluster, "commit": commit},
        )
        row = cursor.fetchone()
    return None if row is None else row[0]


def record_cluster_history(
    connection: Connection[Any],
    *,
    cluster: str,
    outcome: str,
    result: Mapping[str, Any],
    warnings: Any = None,
    error: Mapping[str, Any] | None = None,
    poll_error: str | None = None,
) -> None:
    """Replace one cluster's cached version listing with the newest answer.

    Without `diffs`: those are kept per version in `version_diff`
    (`record_version_diffs`, the source's second write), and a listing carrying
    up to ten of them on every pass would only make this row large.
    """

    result = {key: value for key, value in result.items() if key != "diffs"}

    with connection.cursor() as cursor:
        cursor.execute(
            "insert into cluster_history (cluster, outcome, result, warnings, error, poll_error) "
            "values (%(cluster)s, %(outcome)s, %(result)s, %(warnings)s, %(error)s, %(poll)s) "
            "on conflict (cluster) do update set "
            "    outcome = excluded.outcome, "
            "    result = excluded.result, "
            "    warnings = excluded.warnings, "
            "    error = excluded.error, "
            "    poll_error = excluded.poll_error",
            {
                "cluster": cluster,
                "outcome": outcome,
                "result": Jsonb(dict(result)),
                "warnings": Jsonb(list(warnings or [])),
                "error": None if error is None else Jsonb(dict(error)),
                "poll": poll_error,
            },
        )


def cluster_history(connection: Connection[Any], cluster: str) -> ClusterHistory | None:
    """One cluster's cached version listing, or nothing when it has never been read.

    Separate from `cluster_histories` rather than filtered out of it: the
    recovery path asks about exactly one cluster and needs the answer's age, and
    fetching every cluster to discard all but one would make the query's cost
    grow with an installation that has nothing to do with the question.
    """

    with connection.cursor(row_factory=class_row(ClusterHistory)) as cursor:
        cursor.execute(
            "select cluster, observed_at, outcome, result, warnings, error, poll_error "
            "  from cluster_history "
            " where cluster = %(cluster)s",
            {"cluster": cluster},
        )
        return cursor.fetchone()


def cluster_histories(connection: Connection[Any]) -> list[ClusterHistory]:
    """Every cluster's newest version listing, with the stalest one first."""

    with connection.cursor(row_factory=class_row(ClusterHistory)) as cursor:
        cursor.execute(
            "select cluster, observed_at, outcome, result, warnings, error, poll_error "
            "  from cluster_history "
            " order by observed_at asc"
        )
        return cursor.fetchall()


def record_cluster_backups(
    connection: Connection[Any],
    *,
    cluster: str,
    outcome: str,
    result: Mapping[str, Any],
    warnings: Any = None,
    error: Mapping[str, Any] | None = None,
    poll_error: str | None = None,
) -> None:
    """Replace one cluster's cached state backup listing with the newest helper answer."""

    with connection.cursor() as cursor:
        cursor.execute(
            "insert into cluster_backups (cluster, outcome, result, warnings, error, poll_error) "
            "values (%(cluster)s, %(outcome)s, %(result)s, %(warnings)s, %(error)s, %(poll)s) "
            "on conflict (cluster) do update set "
            "    outcome = excluded.outcome, "
            "    result = excluded.result, "
            "    warnings = excluded.warnings, "
            "    error = excluded.error, "
            "    poll_error = excluded.poll_error",
            {
                "cluster": cluster,
                "outcome": outcome,
                "result": Jsonb(dict(result)),
                "warnings": Jsonb(list(warnings or [])),
                "error": None if error is None else Jsonb(dict(error)),
                "poll": poll_error,
            },
        )


def cluster_backups(connection: Connection[Any]) -> list[ClusterBackups]:
    """Every cluster's newest state backup listing, with the stalest one first."""

    with connection.cursor(row_factory=class_row(ClusterBackups)) as cursor:
        cursor.execute(
            "select cluster, observed_at, outcome, result, warnings, error, poll_error "
            "  from cluster_backups "
            " order by observed_at asc"
        )
        return cursor.fetchall()


def record_cluster_certificates(
    connection: Connection[Any],
    *,
    cluster: str,
    outcome: str,
    result: Mapping[str, Any],
    warnings: Any = None,
    error: Mapping[str, Any] | None = None,
    poll_error: str | None = None,
) -> None:
    """Replace one cluster's cached certificate metadata with the newest helper answer."""

    with connection.cursor() as cursor:
        cursor.execute(
            "insert into cluster_certificates (cluster, outcome, result, warnings, error, poll_error) "
            "values (%(cluster)s, %(outcome)s, %(result)s, %(warnings)s, %(error)s, %(poll)s) "
            "on conflict (cluster) do update set "
            "    outcome = excluded.outcome, "
            "    result = excluded.result, "
            "    warnings = excluded.warnings, "
            "    error = excluded.error, "
            "    poll_error = excluded.poll_error",
            {
                "cluster": cluster,
                "outcome": outcome,
                "result": Jsonb(dict(result)),
                "warnings": Jsonb(list(warnings or [])),
                "error": None if error is None else Jsonb(dict(error)),
                "poll": poll_error,
            },
        )


def cluster_certificates(connection: Connection[Any]) -> list[ClusterCertificates]:
    """Every cluster's newest certificate metadata, with the stalest one first."""

    with connection.cursor(row_factory=class_row(ClusterCertificates)) as cursor:
        cursor.execute(
            "select cluster, observed_at, outcome, result, warnings, error, poll_error "
            "  from cluster_certificates "
            " order by observed_at asc"
        )
        return cursor.fetchall()


def record_cluster_network(
    connection: Connection[Any],
    *,
    cluster: str,
    outcome: str,
    result: Mapping[str, Any],
    warnings: Any = None,
    error: Mapping[str, Any] | None = None,
    poll_error: str | None = None,
) -> None:
    """Replace one cluster's cached network description with the newest helper answer."""

    with connection.cursor() as cursor:
        cursor.execute(
            "insert into cluster_network (cluster, outcome, result, warnings, error, poll_error) "
            "values (%(cluster)s, %(outcome)s, %(result)s, %(warnings)s, %(error)s, %(poll)s) "
            "on conflict (cluster) do update set "
            "    outcome = excluded.outcome, "
            "    result = excluded.result, "
            "    warnings = excluded.warnings, "
            "    error = excluded.error, "
            "    poll_error = excluded.poll_error",
            {
                "cluster": cluster,
                "outcome": outcome,
                "result": Jsonb(dict(result)),
                "warnings": Jsonb(list(warnings or [])),
                "error": None if error is None else Jsonb(dict(error)),
                "poll": poll_error,
            },
        )


def cluster_networks(connection: Connection[Any]) -> list[ClusterNetwork]:
    """Every cluster's newest network description, with the stalest one first."""

    with connection.cursor(row_factory=class_row(ClusterNetwork)) as cursor:
        cursor.execute(
            "select cluster, observed_at, outcome, result, warnings, error, poll_error "
            "  from cluster_network "
            " order by observed_at asc"
        )
        return cursor.fetchall()


def record_cluster_settings(
    connection: Connection[Any],
    *,
    cluster: str,
    outcome: str,
    result: Mapping[str, Any],
    warnings: Any = None,
    error: Mapping[str, Any] | None = None,
    poll_error: str | None = None,
) -> None:
    """Replace one cluster's cached settings with the newest helper answer."""

    with connection.cursor() as cursor:
        cursor.execute(
            "insert into cluster_settings (cluster, outcome, result, warnings, error, poll_error) "
            "values (%(cluster)s, %(outcome)s, %(result)s, %(warnings)s, %(error)s, %(poll)s) "
            "on conflict (cluster) do update set "
            "    outcome = excluded.outcome, "
            "    result = excluded.result, "
            "    warnings = excluded.warnings, "
            "    error = excluded.error, "
            "    poll_error = excluded.poll_error",
            {
                "cluster": cluster,
                "outcome": outcome,
                "result": Jsonb(dict(result)),
                "warnings": Jsonb(list(warnings or [])),
                "error": None if error is None else Jsonb(dict(error)),
                "poll": poll_error,
            },
        )


def record_cluster_list(connection: Connection[Any], clusters: Sequence[str]) -> None:
    """Replace the list of clusters that exist with the poller's newest reading."""

    with connection.cursor() as cursor:
        cursor.execute(
            "insert into cluster_list (clusters) values (%(clusters)s) "
            "on conflict (id) do update set clusters = excluded.clusters",
            {"clusters": Jsonb(list(clusters))},
        )


def replace_search_entries(
    connection: Connection[Any],
    *,
    cluster: str,
    source: str,
    entries: Sequence[search_index.Entry],
) -> int:
    """Replace what one reading of one cluster contributes to the search (B222).

    In the caller's transaction, so the search never sees the cluster with its
    old rows gone and its new ones not yet written.
    """

    with connection.cursor() as cursor:
        cursor.execute(
            "delete from search_entry where cluster = %(cluster)s and source = %(source)s",
            {"cluster": cluster, "source": source},
        )
        cursor.executemany(
            "insert into search_entry "
            "(cluster, source, kind, title, label, value, href, admin_only) "
            "values (%(cluster)s, %(source)s, %(kind)s, %(title)s, %(label)s, %(value)s, "
            "%(href)s, %(admin_only)s)",
            [
                {
                    "cluster": entry.cluster,
                    "source": entry.source,
                    "kind": entry.kind,
                    "title": entry.title,
                    "label": entry.label,
                    "value": entry.value,
                    "href": entry.href,
                    "admin_only": entry.admin_only,
                }
                for entry in entries
            ],
        )
    return len(entries)


def prune_search_entries(connection: Connection[Any], clusters: Sequence[str]) -> int:
    """Remove what clusters that no longer exist left in the search."""

    with connection.cursor() as cursor:
        cursor.execute(
            "delete from search_entry where not (cluster = any(%(clusters)s))",
            {"clusters": list(clusters)},
        )
        return cursor.rowcount


def _like_pattern(query: str) -> str:
    """A substring pattern that matches the text and nothing it could mean to LIKE."""

    escaped = query.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def search(
    connection: Connection[Any],
    query: str,
    *,
    role: str,
    clusters: Sequence[str],
    page: int = 1,
) -> search_index.Results:
    """One page of the header's search, answered by the trigram index.

    Grouped per thing found, with every value of it that matched; a
    certificate is one thing however many clusters list it. The order and the
    page are the database's, so a page past the first costs what the first
    does.
    """

    query = search_index.normalise(query)
    if not query:
        return search_index.Results(query, (), 0, 1)
    page = max(1, page)
    kinds = list(search_index.KINDS)
    with connection.cursor() as cursor:
        cursor.execute(
            "select kind, shown_cluster, title, href, "
            "       string_agg(distinct case when label = '' then value "
            "                            else label || ' ' || value end, ', '), "
            "       count(*) over () "
            "  from (select kind, title, href, label, value, "
            "               case when kind = 'certificate' then '' else cluster end as shown_cluster "
            "          from search_entry "
            "         where lower(value) like %(pattern)s "
            "           and cluster = any(%(clusters)s) "
            "           and (%(admin)s or not admin_only)) hits "
            " group by kind, shown_cluster, title, href "
            " order by array_position(%(kinds)s::text[], kind), shown_cluster, lower(title) "
            " limit %(limit)s offset %(offset)s",
            {
                "pattern": _like_pattern(query),
                "clusters": list(clusters),
                "admin": role == "admin",
                "kinds": kinds,
                "limit": search_index.PAGE_SIZE,
                "offset": (page - 1) * search_index.PAGE_SIZE,
            },
        )
        rows = cursor.fetchall()
    total = int(rows[0][5]) if rows else 0
    hits = [
        search_index.Hit(
            kind=kind,
            cluster=cluster or None,
            title=title,
            matched=matched or "",
            href=search_index.reader_href(kind, href, role),
        )
        for kind, cluster, title, href, matched, _total in rows
    ]
    return search_index.Results(query, search_index.grouped(hits), total, page)


def cluster_list(connection: Connection[Any]) -> tuple[str, ...] | None:
    """The clusters the poller last read from the cluster file, in its order; None before it has."""

    with connection.cursor() as cursor:
        cursor.execute("select clusters from cluster_list where id = 1")
        row = cursor.fetchone()
    if row is None or not isinstance(row[0], list):
        return None
    return tuple(str(name) for name in row[0])


def cluster_settings(connection: Connection[Any]) -> list[ClusterSettingsRow]:
    """Every cluster's newest settings reading, with the stalest one first."""

    with connection.cursor(row_factory=class_row(ClusterSettingsRow)) as cursor:
        cursor.execute(
            "select cluster, observed_at, outcome, result, warnings, error, poll_error "
            "  from cluster_settings "
            " order by observed_at asc"
        )
        return cursor.fetchall()


def record_cluster_objects(
    connection: Connection[Any],
    *,
    cluster: str,
    outcome: str,
    result: Mapping[str, Any],
    warnings: Any = None,
    error: Mapping[str, Any] | None = None,
    poll_error: str | None = None,
) -> None:
    """Replace one cluster's cached objects with the newest helper answer.

    Or confirm them, when the helper said the listing the poller holds still
    stands (B222): an update that changes nothing, which the table's trigger
    turns into a fresh `observed_at`. Rewriting the same eight megabytes every
    pass to say the same thing was the cost this avoids.
    """

    if outcome == "done" and result.get("unchanged") is True:
        with connection.cursor() as cursor:
            cursor.execute(
                "update cluster_objects set outcome = outcome "
                " where cluster = %(cluster)s and outcome = 'done'",
                {"cluster": cluster},
            )
        return

    with connection.cursor() as cursor:
        cursor.execute(
            "insert into cluster_objects (cluster, outcome, result, warnings, error, poll_error) "
            "values (%(cluster)s, %(outcome)s, %(result)s, %(warnings)s, %(error)s, %(poll)s) "
            "on conflict (cluster) do update set "
            "    outcome = excluded.outcome, "
            "    result = excluded.result, "
            "    warnings = excluded.warnings, "
            "    error = excluded.error, "
            "    poll_error = excluded.poll_error",
            {
                "cluster": cluster,
                "outcome": outcome,
                "result": Jsonb(dict(result)),
                "warnings": Jsonb(list(warnings or [])),
                "error": None if error is None else Jsonb(dict(error)),
                "poll": poll_error,
            },
        )


def objects_fingerprint(connection: Connection[Any], cluster: str) -> str | None:
    """The fingerprint of the objects listing the poller holds, if it holds one."""

    with connection.cursor() as cursor:
        cursor.execute(
            "select result ->> 'fingerprint' from cluster_objects "
            " where cluster = %(cluster)s and outcome = 'done'",
            {"cluster": cluster},
        )
        row = cursor.fetchone()
    return row[0] if row is not None and isinstance(row[0], str) else None


def cluster_objects(connection: Connection[Any]) -> list[ClusterObjects]:
    """Every cluster's newest objects reading, with the stalest one first."""

    with connection.cursor(row_factory=class_row(ClusterObjects)) as cursor:
        cursor.execute(
            "select cluster, observed_at, outcome, result, warnings, error, poll_error "
            "  from cluster_objects "
            " order by observed_at asc"
        )
        return cursor.fetchall()


def try_singleton_lock(connection: Connection[Any], key: int) -> bool:
    """Take a session-scoped advisory lock, or report that somebody else has it.

    The lock lives in the database rather than in a file, because that is the
    one place every candidate can see and because it is released by the server
    when a connection dies - including when the process holding it is killed
    without running any cleanup, which is precisely when a lock file would be
    left behind to block the replacement.
    """

    with connection.cursor() as cursor:
        cursor.execute("select pg_try_advisory_lock(%s)", (key,))
        row = cursor.fetchone()
    return bool(row and row[0])


def cluster_drafts(connection: Connection[Any], cluster: str) -> list[ProxyDraft]:
    """Every draft for one cluster, in the order a listing shows objects."""

    with connection.cursor(row_factory=class_row(ProxyDraft)) as cursor:
        cursor.execute(
            "select id, cluster, object_id, yaml, base_version, base_hash, revision, "
            "       updated_by, updated_at, deleted "
            "  from proxy_draft "
            " where cluster = %(cluster)s "
            " order by object_id",
            {"cluster": cluster},
        )
        return cursor.fetchall()


def live_drafts(connection: Connection[Any]) -> list[ProxyDraft]:
    """Every draft in every cluster that still asks for an object to exist.

    A draft marked `deleted` asks for its object to go and names nothing a
    deletion has to respect, so it is left out here rather than filtered by
    every caller.
    """

    with connection.cursor(row_factory=class_row(ProxyDraft)) as cursor:
        cursor.execute(
            "select id, cluster, object_id, yaml, base_version, base_hash, revision, "
            "       updated_by, updated_at, deleted "
            "  from proxy_draft "
            " where not deleted "
            " order by cluster, object_id"
        )
        return cursor.fetchall()


def read_draft(connection: Connection[Any], cluster: str, object_id: str) -> ProxyDraft | None:
    """One draft, or None where the object has no unsaved edit."""

    with connection.cursor(row_factory=class_row(ProxyDraft)) as cursor:
        cursor.execute(
            "select id, cluster, object_id, yaml, base_version, base_hash, revision, "
            "       updated_by, updated_at, deleted "
            "  from proxy_draft "
            " where cluster = %(cluster)s and object_id = %(object_id)s",
            {"cluster": cluster, "object_id": object_id},
        )
        return cursor.fetchone()


def save_draft(
    connection: Connection[Any],
    *,
    cluster: str,
    object_id: str,
    yaml: str,
    base_version: int | None,
    base_hash: str,
    updated_by: str,
    deleted: bool = False,
    expected_revision: int | None,
) -> ProxyDraft:
    """Create or replace one draft, refusing a write the caller did not see.

    `expected_revision` is None for a draft that should not exist yet and the
    revision the caller read for one that should. Both are enforced by the
    statement rather than by a check-then-write: a read followed by a write is
    two moments, and the interesting case is precisely somebody writing between
    them.

    The insert therefore carries `on conflict do nothing` and the update
    carries the revision in its `where`, so a row that changed underneath
    matches nothing and comes back as a conflict instead of an overwrite.
    """

    values = {
        "cluster": cluster,
        "object_id": object_id,
        "yaml": yaml,
        "base_version": base_version,
        "base_hash": base_hash,
        "updated_by": updated_by,
        "deleted": deleted,
        "revision": expected_revision,
    }
    with connection.transaction(), connection.cursor(row_factory=class_row(ProxyDraft)) as cursor:
        if expected_revision is None:
            cursor.execute(
                "insert into proxy_draft "
                "       (cluster, object_id, yaml, base_version, base_hash, updated_by, deleted) "
                "values (%(cluster)s, %(object_id)s, %(yaml)s, %(base_version)s, "
                "        %(base_hash)s, %(updated_by)s, %(deleted)s) "
                "on conflict do nothing "
                "returning id, cluster, object_id, yaml, base_version, base_hash, revision, "
                "          updated_by, updated_at, deleted",
                values,
            )
        else:
            cursor.execute(
                "update proxy_draft "
                "   set yaml = %(yaml)s, base_version = %(base_version)s, "
                "       base_hash = %(base_hash)s, updated_by = %(updated_by)s, "
                "       deleted = %(deleted)s "
                " where cluster = %(cluster)s and object_id = %(object_id)s "
                "   and revision = %(revision)s "
                "returning id, cluster, object_id, yaml, base_version, base_hash, revision, "
                "          updated_by, updated_at, deleted",
                values,
            )
        row = cursor.fetchone()
        if row is None:
            raise DraftConflict(
                f"the draft for {object_id} changed since it was read; reload it and try again"
            )
        return row


def rename_draft(
    connection: Connection[Any],
    *,
    cluster: str,
    object_id: str,
    new_object_id: str,
    yaml: str,
    base_version: int | None,
    base_hash: str,
    updated_by: str,
    expected_revision: int,
) -> ProxyDraft:
    """Move one draft to another name, as a change of its key.

    A rename is not a new draft and a removal of the old one. Written that way
    it is two writes, and `save_draft` commits its own transaction - so a
    conflict on the second left the first standing and the person had two
    drafts where they had made one, which is precisely how this was found.

    One statement instead. `(cluster, object_id)` is the primary key, so the
    move either happens or does not, and a name already taken fails on the key
    rather than on a check that raced. The row keeps its `id`: it is the same
    piece of work, and the publish that eventually carries it should be able to
    say so.
    """

    values = {
        "cluster": cluster,
        "object_id": object_id,
        "new_object_id": new_object_id,
        "yaml": yaml,
        "base_version": base_version,
        "base_hash": base_hash,
        "updated_by": updated_by,
        "revision": expected_revision,
    }
    with connection.transaction(), connection.cursor(row_factory=class_row(ProxyDraft)) as cursor:
        try:
            cursor.execute(
                "update proxy_draft "
                "   set object_id = %(new_object_id)s, yaml = %(yaml)s, "
                "       base_version = %(base_version)s, base_hash = %(base_hash)s, "
                "       updated_by = %(updated_by)s "
                " where cluster = %(cluster)s and object_id = %(object_id)s "
                "   and revision = %(revision)s "
                "returning id, cluster, object_id, yaml, base_version, base_hash, revision, "
                "          updated_by, updated_at, deleted",
                values,
            )
        except psycopg.errors.UniqueViolation as clash:
            raise DraftConflict(
                f"{new_object_id} already has a draft in this cluster; "
                f"the rename would replace somebody's work"
            ) from clash
        row = cursor.fetchone()
        if row is None:
            raise DraftConflict(
                f"the draft for {object_id} changed since it was read; reload it and try again"
            )
        return row


def discard_draft(
    connection: Connection[Any], *, cluster: str, object_id: str, expected_revision: int
) -> None:
    """Throw one draft away, and only the revision the caller was looking at.

    A real delete rather than a flag. An abandoned edit that stayed in the table
    would be indistinguishable from a decision to remove the object, which is
    what `deleted` means and what this is not.
    """

    with connection.cursor() as cursor:
        cursor.execute(
            "delete from proxy_draft "
            " where cluster = %(cluster)s and object_id = %(object_id)s "
            "   and revision = %(revision)s",
            {"cluster": cluster, "object_id": object_id, "revision": expected_revision},
        )
        if cursor.rowcount == 0:
            raise DraftConflict(
                f"the draft for {object_id} changed since it was read; reload it and try again"
            )


def record_metric_samples(
    connection: Connection[Any],
    *,
    cluster: str,
    result: Mapping[str, Any],
) -> int:
    """Append one poll's samples. Returns how many rows were written.

    Append, never replace, which is what separates these tables from every
    cache above: a cache answers what is true now and a sample answers what was
    true then, and rewriting the second would destroy the only thing it is for.

    `observed_at` appears in neither statement. The database sets it from
    `transaction_timestamp()`, so every row of one poll carries the same
    instant and none of them can be written to look fresher than the read that
    produced it - the same reason the caches leave it out, for a different
    consequence.

    It is the *transaction's* timestamp and not the statement's, and that was a
    correction rather than a design: `executemany` sends one statement per row,
    so the first release to write samples spread one poll across microseconds.
    Migration 0019 has the measurement. This function's single commit is what
    makes the guarantee hold, so a caller that splits the write into two
    transactions breaks it.

    Nothing here is idempotent and nothing needs to be. Two polls a second
    apart are two measurements, not one measurement written twice; the primary
    key includes the timestamp precisely so both survive.
    """

    frontends, members = metrics.samples(result)
    if not frontends and not members:
        return 0

    with connection.cursor() as cursor:
        if frontends:
            cursor.executemany(
                _sample_insert("metric_frontend", ("node", "frontend", "owns_vip")),
                [
                    {
                        "cluster": cluster,
                        "node": sample.node,
                        "frontend": sample.frontend,
                        "owns_vip": sample.owns_vip,
                        "uptime_sec": sample.uptime_sec,
                        "status": sample.status,
                        **_counter_values(sample.counters),
                    }
                    for sample in frontends
                ],
            )
        if members:
            cursor.executemany(
                _sample_insert(
                    "metric_backend_member",
                    ("node", "backend", "member", "check_status", "check_code"),
                ),
                [
                    {
                        "cluster": cluster,
                        "node": sample.node,
                        "backend": sample.backend,
                        "member": sample.member,
                        "check_status": sample.check_status,
                        "check_code": sample.check_code,
                        "uptime_sec": sample.uptime_sec,
                        "status": sample.status,
                        **_counter_values(sample.counters),
                    }
                    for sample in members
                ],
            )

    return len(frontends) + len(members)


def _sample_insert(table: str, identifying: tuple[str, ...]) -> sql.Composed:
    """The insert for one sample table, composed rather than formatted.

    Every name here is a literal from this module - the table, the identifying
    columns and `metrics.METRIC_COUNTERS` - so there is nothing a caller could
    put in one. It is composed through `psycopg.sql` anyway, because the way to
    know that stays true is for the code to be unable to express the other
    thing rather than for a reader to check that it does not.

    Columns are named one at a time, including where that is every column. The
    grants are written column by column for the same reason: a statement that
    named the table alone would silently widen the next time one is added.
    """

    columns = ("cluster", *identifying, "uptime_sec", "status", *metrics.METRIC_COUNTERS)
    return sql.SQL("insert into {table} ({columns}) values ({values})").format(
        table=sql.Identifier(table),
        columns=sql.SQL(", ").join(sql.Identifier(name) for name in columns),
        values=sql.SQL(", ").join(sql.Placeholder(name) for name in columns),
    )


def _counter_values(counters: Mapping[str, int]) -> dict[str, int | None]:
    """Every counter column, with the ones this row did not report as None.

    `executemany` needs every placeholder present in every row, and the missing
    ones must arrive as null rather than be left out or defaulted to zero.
    """

    return {name: counters.get(name) for name in metrics.METRIC_COUNTERS}


def _bucketed_raw(width: timedelta) -> sql.Composed:
    """The raw table, reduced to one reading per bucket.

    The last reading in each bucket is the one kept, because the counters are
    cumulative: a difference between two bucket-ends is exactly the traffic
    between them, and the middle of a bucket cannot improve on it.

    `floor_uptime_sec` is why this is not merely sampling. Dropping rows would
    hide a restart that happened and was climbed past between two kept
    readings, and that interval would then be reported as a quiet stretch - so
    the lowest uptime anywhere inside the bucket travels with the reading.

    **Every bucket is per node.** Backend members are recorded only from the node
    holding the VIP, so a failover leaves one series written by two machines,
    and a bucket that kept whichever row happened to be last would hand the
    reader two processes' cumulative counters as one. The node is in the
    table's primary key; taking it into the bucket, the restart window and the
    result is what carries that fact as far as the difference is taken.
    """

    columns = sql.SQL(", ").join(sql.Identifier(name) for name in metrics.METRIC_COUNTERS)
    return sql.SQL(
        "select distinct on (node, bucket) bucket as at, observed_at, uptime_sec, "
        "       floor_uptime_sec, node, {columns} "
        "  from ( "
        "       select date_bin(%(width)s, observed_at, timestamptz '2000-01-01') as bucket, "
        "              observed_at, uptime_sec, node, {columns}, "
        "              min(uptime_sec) over ( "
        "                  partition by node, "
        "                               date_bin(%(width)s, observed_at, timestamptz '2000-01-01') "
        "              ) as floor_uptime_sec "
        "         from metric_backend_member "
        "        where cluster = %(cluster)s and backend = %(backend)s "
        "          and member = %(member)s and observed_at >= %(since)s "
        "          and observed_at >= %(raw_from)s "
        "          and observed_at <= %(until)s "
        "       ) as bucketed "
        " order by node, bucket, observed_at desc"
    ).format(columns=columns)


def _rolled_up() -> sql.Composed:
    """The hourly rollup, in the same shape the bucketed raw query returns.

    Same columns and same meaning, so nothing downstream knows which table
    answered. That is the whole reason a rollup row stores the hour's last
    cumulative value rather than the hour's delta: a second shape would need a
    second reader with its own idea of what a restart is.
    """

    columns = sql.SQL(", ").join(sql.Identifier(name) for name in metrics.METRIC_COUNTERS)
    return sql.SQL(
        "select bucket_at as at, observed_at, uptime_sec, floor_uptime_sec, node, {columns} "
        "  from metric_backend_hour "
        " where cluster = %(cluster)s and backend = %(backend)s "
        "   and member = %(member)s and bucket_at >= date_trunc('hour', %(since)s) "
        "   and bucket_at < %(raw_from)s and observed_at >= %(since)s "
        "   and observed_at < %(raw_from)s and observed_at <= %(until)s "
        " order by bucket_at, node"
    ).format(columns=columns)


def _backend_history_boundary(
    connection: Connection[Any], *, since: datetime, now: datetime | None
) -> datetime:
    """Where a backend history changes from completed rollup to retained raw rows.

    Seven days remains the normal boundary and keeps recent views at raw
    resolution. If maintenance has fallen behind, its continuous completion
    marker moves the boundary further into the past instead. No marker is the
    conservative answer: use whatever raw data remains and claim no rollup
    coverage for this window.

    **Counted from now, not from the end of what is asked.** The raw rows are
    pruned a week back from today, whatever range a reader marks. Counting from
    the range's end put a range marked two weeks ago on the raw side of the
    line, where its rows no longer are, and kept it off the rollup that holds
    them: the figures beside the drawing read 0 under a visible peak (seen
    2026-10-01, 15-18 Sep on the 30-day window). The drawing always ends now,
    which is why it was right.
    """

    retained_from = (now or datetime.now(UTC)) - metrics.RAW_RETENTION
    if since >= retained_from:
        return retained_from
    with connection.cursor() as cursor:
        cursor.execute(
            "select complete_before from metric_rollup_state where rollup_name = 'backend_hour'"
        )
        row = cursor.fetchone()
    if row is None or not isinstance(row[0], datetime):
        return since
    return max(since, min(retained_from, row[0]))


def read_backend_samples(
    connection: Connection[Any],
    *,
    cluster: str,
    backend: str,
    since: datetime,
    until: datetime,
    width: timedelta,
    member: str = "BACKEND",
    now: datetime | None = None,
) -> list[metrics.Sample]:
    """One backend's readings since a moment, one per bucket, oldest first.

    `BACKEND` by default, which is HAProxy's own aggregate row for the backend -
    the sum across its servers, counted by the thing doing the balancing rather
    than added up here. A caller that wants one server names it.

    **Two sources, one shape.** The raw samples are normally kept for a week;
    anything older is answered from the hourly rollup. Its continuous
    completion marker may move that boundary further back after missed runs,
    and the raw prune follows the same marker. The two halves still meet at one
    instant, so they cannot overlap and count an hour twice.

    A window inside the retention never reads the rollup at all, so the common
    case costs one query and the long one costs two.
    """

    raw_from = _backend_history_boundary(connection, since=since, now=now)
    arguments = {
        "cluster": cluster,
        "backend": backend,
        "member": member,
        "since": since,
        "width": width,
        "raw_from": raw_from,
        "until": until,
    }

    rows: list[Any] = []
    with connection.cursor() as cursor:
        if since < raw_from:
            cursor.execute(_rolled_up(), arguments)
            rows.extend(cursor.fetchall())
        cursor.execute(_bucketed_raw(width), arguments)
        rows.extend(cursor.fetchall())

    found = [
        metrics.Sample(
            observed_at=row[1],
            member=member,
            uptime_sec=row[2],
            floor_uptime_sec=row[3],
            node=row[4],
            counters=dict(zip(metrics.METRIC_COUNTERS, row[5:], strict=True)),
        )
        for row in rows
    ]
    #
    # Sorted here rather than trusted from the two queries. They are ordered
    # individually and the rollup's half is older, so a concatenation happens to
    # be right - and a `happens to be` in the one place a difference is taken
    # is how a negative interval appears months later.
    #
    found.sort(key=lambda sample: (sample.observed_at, sample.node or ""))
    return found


def _bucketed_frontend(width: timedelta) -> sql.Composed:
    """One frontend's raw readings on one node, reduced to one per bucket.

    The same reduction the backend query makes, against `metric_frontend` and
    without a rollup half: frontends have no rollup, and their raw rows are
    kept for a fixed seven days. A window reaching further back is answered by
    the part of it that still exists, which the card's own coverage states.

    **The VIP is what listens, so the series is the VIP's.** Every node
    reports its own frontends, but only the node holding the address receives
    anything on it - its peer binds the same ports and sits flat. Drawing both
    put an implementation detail on the page and answered a question nobody
    asks: what a standby did not serve.

    So the readings are those of whichever node held the address, which is the
    same rule backend members are already recorded under (B94) and makes the two
    halves of the page one model. Both nodes' rows are kept per bucket, and
    `intervals` differences each node against itself - the standby's flat
    series adds nothing, and a failover is the active series ending where the
    incoming one begins. Pairing them as neighbours in time instead made every
    interval on an address a refused difference, which is why these cards
    carried a star and a coverage of 0 % while nothing was wrong with them
    (B97, measured 2026-09-07).

    **Every bucket is per node**, exactly as the backend query's is, and that is
    load-bearing rather than symmetry for its own sake. Collapsing to one row
    per bucket looked safe while only the owner is read - and is not. An
    address that moves away and back inside one bucket leaves the *other*
    machine's low uptime as the bucket's floor while the kept row is the
    original node, so the reader sees a restart with no change of author and
    reports the node's cumulative counter as this bucket's traffic. Measured
    2026-09-07: 5 000 400 requests where 400 had passed. Keeping both nodes'
    rows makes it what it is - two handovers, refused.
    """

    columns = sql.SQL(", ").join(sql.Identifier(name) for name in metrics.METRIC_COUNTERS)
    return sql.SQL(
        "select distinct on (node, bucket) bucket as at, observed_at, uptime_sec, "
        "       floor_uptime_sec, node, {columns} "
        "  from ( "
        "       select date_bin(%(width)s, observed_at, timestamptz '2000-01-01') as bucket, "
        "              observed_at, uptime_sec, node, {columns}, "
        "              min(uptime_sec) over ( "
        "                  partition by node, "
        "                               date_bin("
        "                                   %(width)s, observed_at, timestamptz '2000-01-01')"
        "              ) as floor_uptime_sec "
        "         from metric_frontend "
        "        where cluster = %(cluster)s and frontend = %(frontend)s "
        "          and owns_vip and observed_at >= %(since)s "
        "          and observed_at <= %(until)s "
        "       ) as bucketed "
        " order by node, bucket, observed_at desc"
    ).format(columns=columns)


def read_frontend_samples(
    connection: Connection[Any],
    *,
    cluster: str,
    frontend: str,
    since: datetime,
    until: datetime,
    width: timedelta,
) -> list[metrics.Sample]:
    """One VIP frontend's readings, one per bucket, oldest first."""

    with connection.cursor() as cursor:
        cursor.execute(
            _bucketed_frontend(width),
            {
                "cluster": cluster,
                "frontend": frontend,
                "since": since,
                "width": width,
                "until": until,
            },
        )
        rows = cursor.fetchall()

    return [
        metrics.Sample(
            observed_at=row[1],
            member=frontend,
            uptime_sec=row[2],
            floor_uptime_sec=row[3],
            node=row[4],
            counters=dict(zip(metrics.METRIC_COUNTERS, row[5:], strict=True)),
        )
        for row in rows
    ]


def read_cluster_frontends(
    connection: Connection[Any], *, cluster: str, since: datetime, until: datetime
) -> list[tuple[str, bool]]:
    """Which VIP frontends this cluster saw, and whether any node held each.

    Asked of the samples rather than of the configuration, because the card is
    history: a frontend removed yesterday still has a window worth reading, and
    one added this morning has nothing to show whatever the document says.

    **Existing and being held are two questions, and asking them as one hid
    rows the table had.** `owns_vip` is `boolean` and nullable: false is "this
    node did not hold the address", and null is "this node could not say" - an
    older status script, or a `vip` block that would not read. `where
    owns_vip` is false for null, so filtering the list by it removed the whole
    address from the page while its rows sat in the table, and the page then
    said it had no samples. It also went blank during a total outage, when
    nothing holds the address at all - which is the one moment this page is
    opened.

    So the address is listed whenever anything was recorded for it, and
    ownership travels beside it as its own answer. The card is still drawn from
    the owner's readings; what changed is that an address with none of them
    says so instead of vanishing.

    This is also what reads the non-owning node's rows. They are written every
    poll, and until now nothing looked at them.
    """

    with connection.cursor() as cursor:
        cursor.execute(
            "select frontend, coalesce(bool_or(owns_vip), false) from metric_frontend "
            " where cluster = %(cluster)s "
            "   and observed_at >= %(since)s and observed_at <= %(until)s "
            " group by frontend order by frontend",
            {"cluster": cluster, "since": since, "until": until},
        )
        return [(row[0], bool(row[1])) for row in cursor.fetchall()]


def read_cluster_backends(
    connection: Connection[Any], *, cluster: str, since: datetime, until: datetime
) -> list[str]:
    """Which backends this cluster has readings for, by the runtime's own names.

    `BACKEND` only - HAProxy's aggregate row for each backend, which is what the
    comparison is between. A per-server breakdown is a different question and
    belongs on the backend it is asked about, not on a page comparing backends.
    """

    with connection.cursor() as cursor:
        cursor.execute(
            "select distinct backend from metric_backend_member "
            " where cluster = %(cluster)s and member = 'BACKEND' "
            "   and observed_at >= %(since)s and observed_at <= %(until)s "
            " order by backend",
            {"cluster": cluster, "since": since, "until": until},
        )
        return [row[0] for row in cursor.fetchall()]


#
# The counters migration 0048 stores a difference for. A figure is only ever
# summed from these; a test holds the card's and the dashboard's lists to it.
#
STORED_DELTAS = (
    "req_tot",
    "hrsp_2xx",
    "hrsp_3xx",
    "hrsp_4xx",
    "hrsp_5xx",
    "econ",
    "wretr",
    "bin",
    "bout",
)


def _interval_aggregates(names: Sequence[str]) -> sql.Composed:
    """The one aggregate both readers end in, over rows shaped as intervals.

    Each row is one interval: `started_at`, `ended_at`, `restarted`,
    `handed_over`, `span_sec` and `delta_<counter>`. The columns come out in the
    order `_measurement` reads them.
    """

    per_counter = sql.SQL(", ").join(
        sql.SQL(
            "coalesce(sum({delta}), 0)::bigint, "
            "coalesce(sum(span_sec) filter ("
            "    where {delta} is not null and not restarted and not handed_over"
            "), 0)"
        ).format(delta=sql.Identifier(f"delta_{name}"))
        for name in names
    )
    return sql.SQL(
        "select count(*)::bigint, min(started_at), max(ended_at), "
        "       coalesce(bool_or(restarted), false), "
        "       coalesce(bool_or(handed_over), false), "
        "       coalesce(sum(span_sec) filter (where not restarted and not handed_over), 0), "
        "       coalesce(sum(span_sec), 0), {per_counter} "
    ).format(per_counter=per_counter)


def _stored_intervals(names: Sequence[str]) -> sql.Composed:
    """The interval columns of a raw row, read from what migration 0048 stored."""

    return sql.SQL(
        "previous_at as started_at, observed_at as ended_at, restarted, "
        "false as handed_over, extract(epoch from observed_at - previous_at) as span_sec, {deltas}"
    ).format(deltas=sql.SQL(", ").join(sql.Identifier(f"delta_{name}") for name in names))


def _backend_totals() -> sql.Composed:
    """One backend's figures, summed from the differences stored per sample.

    Each raw sample carries what every counter did since the series' previous
    sample on that node, decided when it was written (migration 0048) by the
    rules this query used to apply on read. An interval belongs to the range
    when it starts inside it, so the first sample in the range - which has
    nothing in the range to pair with - adds nothing, as before.

    The completed older half still comes from the hourly rollup, one reading
    per hour, and is paired here as it always was: a few hundred rows. The
    first raw sample after the boundary pairs with the last hour before it,
    as it did when the two halves were one ordered list, so that one interval
    is paired here too rather than read from storage.
    """

    names = metrics.CARD_COUNTERS
    columns = sql.SQL(", ").join(sql.Identifier(name) for name, _label in names)
    counters = [name for name, _label in names]
    previous = sql.SQL(", ").join(
        sql.SQL("lag({name}) over ordered as {before}").format(
            name=sql.Identifier(name), before=sql.Identifier(f"before_{name}")
        )
        for name in counters
    )
    deltas = sql.SQL(", ").join(
        sql.SQL(
            "case when handed_over or {before} is null or {after} is null then null "
            "     when restarted then {after} "
            "     when {after} < {before} then null "
            "     else {after} - {before} end as {delta}"
        ).format(
            before=sql.Identifier(f"before_{name}"),
            after=sql.Identifier(name),
            delta=sql.Identifier(f"delta_{name}"),
        )
        for name in counters
    )
    series = sql.SQL("cluster = %(cluster)s and backend = %(backend)s and member = %(member)s ")
    return sql.SQL(
        "with readings as ("
        "    select observed_at, uptime_sec, floor_uptime_sec, node, {columns} "
        "      from metric_backend_hour "
        "     where {series} "
        "       and bucket_at >= date_trunc('hour', %(since)s) "
        "       and bucket_at < %(raw_from)s and observed_at >= %(since)s "
        "       and observed_at < %(raw_from)s and observed_at <= %(until)s"
        "    union all "
        #
        # The raw samples whose stored partner lies before the boundary: the
        # first of each node after it, which pairs with the last hour instead.
        #
        "    select observed_at, uptime_sec, uptime_sec, node, {columns} "
        "      from metric_backend_member "
        "     where {series} "
        "       and observed_at >= %(since)s and observed_at >= %(raw_from)s "
        "       and observed_at <= %(until)s "
        "       and (previous_at is null or previous_at < %(raw_from)s)"
        "), paired as ("
        "    select observed_at as ended_at, "
        "           lag(observed_at) over ordered as started_at, "
        "           uptime_sec, floor_uptime_sec, node, {columns}, "
        "           lag(uptime_sec) over ordered as previous_uptime_sec, "
        "           lag(node) over ordered as previous_node, {previous} "
        "      from readings "
        "    window ordered as (partition by node order by observed_at)"
        "), marked as ("
        "    select *, "
        "           coalesce(floor_uptime_sec < previous_uptime_sec, false) as restarted, "
        "           (previous_node is not null and node is not null "
        "            and previous_node <> node) as handed_over, "
        "           extract(epoch from ended_at - started_at) as span_sec "
        "      from paired where started_at is not null"
        "), intervals as ("
        "    select started_at, ended_at, restarted, handed_over, span_sec, {deltas} from marked"
        "    union all "
        "    select {stored} "
        "      from metric_backend_member "
        "     where {series} "
        "       and observed_at >= %(since)s and observed_at >= %(raw_from)s "
        "       and observed_at <= %(until)s "
        "       and previous_at >= %(since)s and previous_at >= %(raw_from)s"
        ") "
        "{aggregates} from intervals"
    ).format(
        columns=columns,
        series=series,
        previous=previous,
        deltas=deltas,
        stored=_stored_intervals(counters),
        aggregates=_interval_aggregates(counters),
    )


def _frontend_totals(
    counters: tuple[tuple[str, str], ...] = metrics.CARD_COUNTERS, *, every_frontend: bool = False
) -> sql.Composed:
    """One frontend's figures, summed from the differences stored per sample.

    Only the samples on which a node held the address count, and each of them
    stored its difference from that node's previous such sample (migration
    0048) - which is how the readings were paired here before. There is no
    frontend rollup, so there is no boundary.

    `every_frontend` sums every VIP frontend of the clusters in `%(clusters)s`
    instead of one: the dashboard's traffic, counted the way each card on the
    metrics page is.
    """

    names = [name for name, _label in counters]
    return sql.SQL(
        "with intervals as ("
        "    select {stored} "
        "      from metric_frontend "
        "     where {scope} "
        "       and owns_vip and observed_at >= %(since)s and observed_at <= %(until)s "
        "       and previous_at >= %(since)s"
        ") "
        "{aggregates} from intervals"
    ).format(
        stored=_stored_intervals(names),
        aggregates=_interval_aggregates(names),
        #
        # Every frontend but the metrics exporter's, whose requests are the
        # monitoring system's scrapes and not traffic to anything served.
        #
        scope=(
            sql.SQL("cluster = any(%(clusters)s) and frontend <> {exporter}").format(
                exporter=sql.Literal(METRICS_FRONTEND)
            )
            if every_frontend
            else sql.SQL("cluster = %(cluster)s and frontend = %(frontend)s")
        ),
    )


def _measurement(
    row: Any, counters: tuple[tuple[str, str], ...] = metrics.CARD_COUNTERS
) -> metrics.BackendMeasurement:
    """One aggregate row, in the shape both totals readers return.

    Written once because the two queries deliberately produce the same columns
    in the same order. A second copy of this unpacking is how a column added to
    one of them would come back as a figure silently read from the wrong place.
    """

    span = float(row[6])
    counted = float(row[5])
    totals = tuple(
        metrics.Total(
            label=label,
            value=int(row[7 + index * 2]),
            counted_sec=float(row[8 + index * 2]),
            span_sec=span,
        )
        for index, (_name, label) in enumerate(counters)
    )
    return metrics.BackendMeasurement(
        intervals=int(row[0]),
        started_at=row[1],
        ended_at=row[2],
        restarted=bool(row[3]),
        handed_over=bool(row[4]),
        coverage=100 if span <= 0 else int(counted / span * 100),
        totals=totals,
    )


def read_frontend_totals(
    connection: Connection[Any],
    *,
    cluster: str,
    frontend: str,
    since: datetime,
    until: datetime,
) -> metrics.BackendMeasurement:
    """One VIP frontend's figures at stored resolution, apart from its graph."""

    with connection.cursor() as cursor:
        cursor.execute(
            _frontend_totals(),
            {
                "cluster": cluster,
                "frontend": frontend,
                "since": since,
                "until": until,
            },
        )
        row = cursor.fetchone()

    if row is None:
        raise RuntimeError("the frontend totals aggregate returned no row")
    return _measurement(row)


def read_traffic_summary(
    connection: Connection[Any],
    *,
    clusters: Sequence[str],
    since: datetime,
    until: datetime,
) -> metrics.BackendMeasurement:
    """Every VIP frontend of these clusters summed: requests, bytes in, bytes out."""

    with connection.cursor() as cursor:
        cursor.execute(
            _frontend_totals(metrics.SUMMARY_COUNTERS, every_frontend=True),
            {"clusters": list(clusters), "since": since, "until": until},
        )
        row = cursor.fetchone()

    if row is None:
        raise RuntimeError("the traffic summary aggregate returned no row")
    return _measurement(row, metrics.SUMMARY_COUNTERS)


def read_response_times(
    connection: Connection[Any],
    *,
    clusters: Sequence[str],
    since: datetime,
    until: datetime,
) -> tuple[int, int | None, int | None]:
    """How many answered requests the traffic log holds, and their median and 95th percentile.

    `response_time` is HAProxy's `%Tr`: from the request being sent to the
    server until its response headers came back, in milliseconds. -1 means no
    server answered - an abort, or a redirect HAProxy gave itself - and those
    are left out rather than counted as instant.
    """

    with connection.cursor() as cursor:
        cursor.execute(
            "select count(*), "
            "       percentile_disc(0.5) within group (order by response_time), "
            "       percentile_disc(0.95) within group (order by response_time) "
            "  from traffic_log "
            " where cluster = any(%(clusters)s) and response_time >= 0 "
            "   and occurred_at >= %(since)s and occurred_at <= %(until)s",
            {"clusters": list(clusters), "since": since, "until": until},
        )
        row = cursor.fetchone()
    if row is None or not row[0]:
        return 0, None, None
    return int(row[0]), int(row[1]), int(row[2])


def read_backend_totals(
    connection: Connection[Any],
    *,
    cluster: str,
    backend: str,
    since: datetime,
    until: datetime,
    member: str = "BACKEND",
    now: datetime | None = None,
) -> metrics.BackendMeasurement:
    """One backend's figures at stored resolution, independent of its graph."""

    arguments = {
        "cluster": cluster,
        "backend": backend,
        "member": member,
        "since": since,
        "raw_from": _backend_history_boundary(connection, since=since, now=now),
        "until": until,
    }
    with connection.cursor() as cursor:
        cursor.execute(_backend_totals(), arguments)
        row = cursor.fetchone()

    if row is None:
        raise RuntimeError("the backend totals aggregate returned no row")
    return _measurement(row)


# - DNS provider profiles --------------------------------------------------
#
# A profile row is a sealed box and its binding (migration 0025). The web
# reads everything but the box; the worker reads the box and the binding and
# nothing about who made it. Neither can open it - that is the point.
#


@dataclass(frozen=True, slots=True)
class DnsProfile:
    """One profile as the web sees it: metadata, never the box."""

    id: str
    name: str
    provider_id: str
    schema_version: int
    key_id: str
    revision: int
    created_at: datetime
    created_by: str
    updated_at: datetime
    updated_by: str
    endpoint: str = ""
    """NDES rows only: the plain copy of the sealed endpoint, for listing."""


@dataclass(frozen=True, slots=True)
class SealedProfile:
    """One profile as the worker hands it to the helper."""

    id: str
    provider_id: str
    schema_version: int
    key_id: str
    revision: int
    ciphertext: bytes


class ProfileExists(Exception):
    """A profile with this ID is already there; creating it again is refused."""


class ProfileMissing(Exception):
    """No profile has this ID."""


def dns_profiles(connection: Connection[Any]) -> list[DnsProfile]:
    with connection.cursor(row_factory=class_row(DnsProfile)) as cursor:
        cursor.execute(
            "select id, name, provider_id, schema_version, key_id, revision, "
            "       created_at, created_by, updated_at, updated_by "
            "  from dns_provider_profile order by id"
        )
        return cursor.fetchall()


def dns_profile(connection: Connection[Any], profile_id: str) -> DnsProfile | None:
    with connection.cursor(row_factory=class_row(DnsProfile)) as cursor:
        cursor.execute(
            "select id, name, provider_id, schema_version, key_id, revision, "
            "       created_at, created_by, updated_at, updated_by "
            "  from dns_provider_profile where id = %(id)s",
            {"id": profile_id},
        )
        return cursor.fetchone()


def create_dns_profile(
    connection: Connection[Any],
    *,
    profile_id: str,
    name: str,
    provider_id: str,
    key_id: str,
    ciphertext: bytes,
    actor: str,
) -> DnsProfile:
    """Insert revision 1 of a new profile, or say that the ID is taken."""

    try:
        with (
            connection.transaction(),
            connection.cursor(row_factory=class_row(DnsProfile)) as cursor,
        ):
            cursor.execute(
                "insert into dns_provider_profile "
                "  (id, name, provider_id, schema_version, key_id, revision, ciphertext, "
                "   created_by, updated_by) "
                "values (%(id)s, %(name)s, %(provider)s, 1, %(key_id)s, 1, %(box)s, "
                "        %(actor)s, %(actor)s) "
                "returning id, name, provider_id, schema_version, key_id, revision, "
                "          created_at, created_by, updated_at, updated_by",
                {
                    "id": profile_id,
                    "name": name,
                    "provider": provider_id,
                    "key_id": key_id,
                    "box": ciphertext,
                    "actor": actor,
                },
            )
            row = cursor.fetchone()
    except psycopg.errors.UniqueViolation as exc:
        raise ProfileExists(profile_id) from exc
    if row is None:
        raise RuntimeError("the profile insert returned no row")
    return row


def replace_dns_profile(
    connection: Connection[Any],
    *,
    profile_id: str,
    revision: int,
    key_id: str,
    ciphertext: bytes,
    actor: str,
    name: str | None = None,
) -> DnsProfile:
    """Store a new box as the next revision. The provider never changes.

    `revision` is the one the caller sealed into the box, so the row and the
    box agree; the update is fenced on the previous revision so two
    replacements racing each other cannot both claim the same number.
    """

    with connection.cursor(row_factory=class_row(DnsProfile)) as cursor:
        cursor.execute(
            "update dns_provider_profile "
            "   set revision = %(revision)s, key_id = %(key_id)s, ciphertext = %(box)s, "
            "       name = coalesce(%(name)s, name), "
            "       updated_at = statement_timestamp(), updated_by = %(actor)s "
            " where id = %(id)s and revision = %(revision)s - 1 "
            "returning id, name, provider_id, schema_version, key_id, revision, "
            "          created_at, created_by, updated_at, updated_by",
            {
                "id": profile_id,
                "revision": revision,
                "key_id": key_id,
                "box": ciphertext,
                "name": name,
                "actor": actor,
            },
        )
        row = cursor.fetchone()
    if row is None:
        raise ProfileMissing(profile_id)
    return row


def sealed_profile(connection: Connection[Any], profile_id: str) -> SealedProfile | None:
    """The worker's read: the box and its binding, for the helper."""

    with connection.cursor(row_factory=class_row(SealedProfile)) as cursor:
        cursor.execute(
            "select id, provider_id, schema_version, key_id, revision, ciphertext "
            "  from dns_provider_profile where id = %(id)s",
            {"id": profile_id},
        )
        return cursor.fetchone()


def delete_dns_profile(connection: Connection[Any], profile_id: str, revision: int) -> bool:
    """Delete exactly the row whose materialization the helper removed."""

    with connection.cursor() as cursor:
        cursor.execute(
            "delete from dns_provider_profile where id = %(id)s and revision = %(revision)s",
            {"id": profile_id, "revision": revision},
        )
        return cursor.rowcount == 1


# NDES has an independent table and grant surface; it never enters the DNS catalogue.
def ndes_profiles(connection: Connection[Any]) -> list[DnsProfile]:
    with connection.cursor(row_factory=class_row(DnsProfile)) as cursor:
        cursor.execute(
            "select id, name, provider_id, schema_version, key_id, revision, "
            "       created_at, created_by, updated_at, updated_by, endpoint "
            "  from ndes_provider_profile order by id"
        )
        return cursor.fetchall()


def ndes_profile(connection: Connection[Any], profile_id: str) -> DnsProfile | None:
    with connection.cursor(row_factory=class_row(DnsProfile)) as cursor:
        cursor.execute(
            "select id, name, provider_id, schema_version, key_id, revision, "
            "       created_at, created_by, updated_at, updated_by, endpoint "
            "  from ndes_provider_profile where id = %(id)s",
            {"id": profile_id},
        )
        return cursor.fetchone()


def create_ndes_profile(
    connection: Connection[Any],
    *,
    profile_id: str,
    name: str,
    provider_id: str,
    key_id: str,
    ciphertext: bytes,
    actor: str,
    endpoint: str,
) -> DnsProfile:
    """Insert revision 1 of a new profile, or say that the ID is taken."""

    try:
        with (
            connection.transaction(),
            connection.cursor(row_factory=class_row(DnsProfile)) as cursor,
        ):
            cursor.execute(
                "insert into ndes_provider_profile "
                "  (id, name, provider_id, schema_version, key_id, revision, ciphertext, "
                "   created_by, updated_by, endpoint) "
                "values (%(id)s, %(name)s, %(provider)s, 1, %(key_id)s, 1, %(box)s, "
                "        %(actor)s, %(actor)s, %(endpoint)s) "
                "returning id, name, provider_id, schema_version, key_id, revision, "
                "          created_at, created_by, updated_at, updated_by, endpoint",
                {
                    "id": profile_id,
                    "name": name,
                    "provider": provider_id,
                    "key_id": key_id,
                    "box": ciphertext,
                    "actor": actor,
                    "endpoint": endpoint,
                },
            )
            row = cursor.fetchone()
    except psycopg.errors.UniqueViolation as exc:
        raise ProfileExists(profile_id) from exc
    if row is None:
        raise RuntimeError("the profile insert returned no row")
    return row


def replace_ndes_profile(
    connection: Connection[Any],
    *,
    profile_id: str,
    revision: int,
    key_id: str,
    ciphertext: bytes,
    actor: str,
    endpoint: str,
    name: str | None = None,
) -> DnsProfile:
    """Store a new box as the next revision. The provider never changes.

    `revision` is the one the caller sealed into the box, so the row and the
    box agree; the update is fenced on the previous revision so two
    replacements racing each other cannot both claim the same number.
    """

    with connection.cursor(row_factory=class_row(DnsProfile)) as cursor:
        cursor.execute(
            "update ndes_provider_profile "
            "   set revision = %(revision)s, key_id = %(key_id)s, ciphertext = %(box)s, "
            "       name = coalesce(%(name)s, name), endpoint = %(endpoint)s, "
            "       updated_at = statement_timestamp(), updated_by = %(actor)s "
            " where id = %(id)s and revision = %(revision)s - 1 "
            "returning id, name, provider_id, schema_version, key_id, revision, "
            "          created_at, created_by, updated_at, updated_by, endpoint",
            {
                "id": profile_id,
                "revision": revision,
                "key_id": key_id,
                "box": ciphertext,
                "name": name,
                "actor": actor,
                "endpoint": endpoint,
            },
        )
        row = cursor.fetchone()
    if row is None:
        raise ProfileMissing(profile_id)
    return row


def delete_ndes_profile(connection: Connection[Any], profile_id: str, revision: int) -> bool:
    """Delete exactly the row whose root record the helper removed."""

    with connection.cursor() as cursor:
        cursor.execute(
            "delete from ndes_provider_profile where id = %(id)s and revision = %(revision)s",
            {"id": profile_id, "revision": revision},
        )
        return cursor.rowcount == 1


def sealed_ndes_profile(connection: Connection[Any], profile_id: str) -> SealedProfile | None:
    """The worker's read: the box and its binding, for the helper."""

    with connection.cursor(row_factory=class_row(SealedProfile)) as cursor:
        cursor.execute(
            "select id, provider_id, schema_version, key_id, revision, ciphertext "
            "  from ndes_provider_profile where id = %(id)s",
            {"id": profile_id},
        )
        return cursor.fetchone()


@dataclass(frozen=True, slots=True)
class OidcProvider:
    """The one OpenID Connect provider row (0041, B197-B199)."""

    enabled: bool
    issuer: str | None
    client_id: str | None
    client_secret_sealed: bytes | None
    key_id: str | None
    auth_method: str
    scopes: str
    username_claim: str
    groups_claim: str
    admin_group: str | None
    reader_group: str | None
    auto_create: bool
    button_text: str
    prompt_login: bool
    logout_mode: str
    local_login: str
    ca_pem: str | None
    revision: int
    verified_revision: int | None
    updated_at: datetime
    updated_by: str | None

    @property
    def verified(self) -> bool:
        return self.verified_revision == self.revision


_OIDC_COLUMNS = (
    "enabled, issuer, client_id, client_secret_sealed, key_id, auth_method, scopes, "
    "username_claim, groups_claim, admin_group, reader_group, auto_create, button_text, "
    "prompt_login, logout_mode, local_login, ca_pem, revision, verified_revision, "
    "updated_at, updated_by"
)
#
# What the settings page writes. `enabled`, `verified_revision` and the
# bookkeeping are written by their own functions; `revision` by the trigger.
#
OIDC_SETTINGS = (
    "issuer",
    "client_id",
    "client_secret_sealed",
    "key_id",
    "auth_method",
    "scopes",
    "username_claim",
    "groups_claim",
    "admin_group",
    "reader_group",
    "auto_create",
    "button_text",
    "prompt_login",
    "logout_mode",
    "local_login",
    "ca_pem",
)


def oidc_provider(connection: Connection[Any]) -> OidcProvider | None:
    """The provider row, or None before 0041."""

    with connection.cursor(row_factory=class_row(OidcProvider)) as cursor:
        cursor.execute(f"select {_OIDC_COLUMNS} from oidc_provider")  # noqa: S608 - constant
        return cursor.fetchone()


class ProviderRefused(Exception):
    """The database refused a change to the provider, as a sentence."""


def save_oidc_provider(
    connection: Connection[Any],
    *,
    settings: Mapping[str, Any],
    actor: str,
    verified: bool = False,
) -> None:
    """Write the settings. `verified` records, in the same statement, that the
    new settings passed Verify - which is how settings are changed while
    sign-in through the provider is on, since it may only be on at a verified
    revision. The trigger raises the revision, so `revision + 1` is the one
    this statement makes."""

    unknown = set(settings) - set(OIDC_SETTINGS)
    if unknown:
        raise ValueError(f"not provider settings: {sorted(unknown)}")
    assignments = ", ".join(f"{name} = %({name})s" for name in settings)
    verification = ", verified_revision = revision + 1" if verified else ""
    try:
        with connection.transaction(), connection.cursor() as cursor:
            cursor.execute(
                f"update oidc_provider set {assignments}{verification}, "  # noqa: S608 - names from OIDC_SETTINGS
                "updated_by = %(actor)s",
                {**settings, "actor": actor},
            )
    except psycopg.errors.CheckViolation as error:
        raise ProviderRefused(
            "Sign-in through the provider is on; these settings did not pass Verify."
        ) from error


def record_oidc_verified(connection: Connection[Any], *, revision: int) -> bool:
    """Record that Verify passed at `revision`, if the settings are still that one."""

    with connection.cursor() as cursor:
        cursor.execute(
            "update oidc_provider set verified_revision = %(revision)s "
            " where revision = %(revision)s",
            {"revision": revision},
        )
        return cursor.rowcount == 1


def set_oidc_enabled(connection: Connection[Any], *, enabled: bool, actor: str) -> None:
    """Turn sign-in through the provider on or off. The database refuses on
    unless the settings are complete and verified and a break-glass admin is
    active; each refusal comes back as its sentence."""

    try:
        with connection.transaction(), connection.cursor() as cursor:
            cursor.execute(
                "update oidc_provider set enabled = %(enabled)s, updated_by = %(actor)s",
                {"enabled": enabled, "actor": actor},
            )
    except psycopg.errors.CheckViolation as error:
        if "break-glass" in (error.diag.message_primary or ""):
            raise ProviderRefused(
                "Mark an active admin as break-glass first: sign-in through the provider "
                "needs one that signs in with a password."
            ) from error
        raise ProviderRefused(
            "Verify the settings first: sign-in through the provider turns on only with "
            "settings that passed Verify."
        ) from error


# - signing in through the provider (O5) --------------------------------------


def account_by_oidc(connection: Connection[Any], *, issuer: str, subject: str) -> Account | None:
    """The account bound to this provider identity (B199: bound to `sub`, not the name)."""

    with connection.cursor(row_factory=class_row(Account)) as cursor:
        cursor.execute(
            "select id, username, role, disabled, password_hash, source, break_glass, oidc_issuer "
            "  from app_user where oidc_issuer = %(issuer)s and oidc_subject = %(subject)s",
            {"issuer": issuer, "subject": subject},
        )
        return cursor.fetchone()


def create_oidc_account(
    connection: Connection[Any],
    *,
    username: str,
    role: str,
    issuer: str | None,
    subject: str | None,
) -> bool:
    """A provider's account: no password; bound now, or later at its first sign-in
    when an admin prepares it. False when the name or the identity is taken."""

    try:
        with connection.transaction(), connection.cursor() as cursor:
            cursor.execute(
                "insert into app_user (username, role, source, oidc_issuer, oidc_subject) "
                "values (%(username)s, %(role)s, 'oidc', %(issuer)s, %(subject)s) "
                "on conflict do nothing returning id",
                {"username": username, "role": role, "issuer": issuer, "subject": subject},
            )
            return cursor.fetchone() is not None
    except psycopg.errors.UniqueViolation:
        return False


def bind_oidc_account(
    connection: Connection[Any], *, user_id: int, issuer: str, subject: str
) -> bool:
    """Bind a prepared provider account to the identity that first signs in as it."""

    with connection.cursor() as cursor:
        cursor.execute(
            "update app_user set oidc_issuer = %(issuer)s, oidc_subject = %(subject)s "
            " where id = %(user_id)s and source = 'oidc' and oidc_issuer is null",
            {"issuer": issuer, "subject": subject, "user_id": user_id},
        )
        return cursor.rowcount == 1


@dataclass(frozen=True, slots=True)
class OidcLogin:
    nonce: str
    verifier: str
    mode: str
    pre_session_hash: bytes


def start_oidc_login(
    connection: Connection[Any],
    *,
    state: str,
    nonce: str,
    verifier: str,
    mode: str,
    pre_session_hash: bytes,
) -> None:
    with connection.cursor() as cursor:
        cursor.execute(
            "insert into oidc_login (state, nonce, verifier, mode, pre_session_hash) "
            "values (%(state)s, %(nonce)s, %(verifier)s, %(mode)s, %(pre)s)",
            {
                "state": state,
                "nonce": nonce,
                "verifier": verifier,
                "mode": mode,
                "pre": pre_session_hash,
            },
        )


def use_oidc_login(
    connection: Connection[Any], *, state: str, max_age_minutes: int = 10
) -> OidcLogin | None:
    """The sign-in `state` names, once: used here, so a second answer finds nothing."""

    with connection.cursor(row_factory=class_row(OidcLogin)) as cursor:
        cursor.execute(
            "update oidc_login set used_at = statement_timestamp() "
            " where state = %(state)s and used_at is null "
            "   and created_at > statement_timestamp() - make_interval(mins => %(age)s) "
            "returning nonce, verifier, mode, pre_session_hash",
            {"state": state, "age": max_age_minutes},
        )
        return cursor.fetchone()


def session_id_token(connection: Connection[Any], token_hash: bytes) -> str | None:
    """The provider's id_token a session kept for signing out there, if any."""

    with connection.cursor() as cursor:
        cursor.execute("select id_token from app_session where token_hash = %s", (token_hash,))
        row = cursor.fetchone()
    return None if row is None else row[0]


@dataclass(frozen=True, slots=True)
class WafFinding:
    """One rule's matches on one object and part of the request (Fas 21, B234)."""

    cluster: str
    object: str
    rule_id: int
    field: str
    requests: int
    clients: int
    last_seen: datetime
    matched: str
    paths: list[str]
    path_count: int


#
# The paths a finding lists, and the findings a page shows. Bounded so a scan
# that touched ten thousand paths with one rule is one row with its first
# twenty paths, not a page nobody can read; the count says there were more.
#
WAF_FINDING_PATHS = 20
WAF_FINDING_LIMIT = 500


def waf_findings(
    connection: Connection[Any], *, clusters: Sequence[str], since: datetime
) -> list[WafFinding]:
    """What the engine matched since then, per cluster, object, rule and field (0052)."""

    with connection.cursor(row_factory=class_row(WafFinding)) as cursor:
        cursor.execute(
            "select cluster, object, rule_id, field, "
            "       count(distinct request_id)::int as requests, "
            "       count(distinct nullif(client, ''))::int as clients, "
            "       max(occurred_at) as last_seen, "
            "       (array_agg(matched order by occurred_at desc))[1] as matched, "
            "       (array_agg(distinct path order by path))[1:%(paths)s] as paths, "
            "       count(distinct path)::int as path_count "
            "  from waf_match "
            " where cluster = any(%(clusters)s) and occurred_at >= %(since)s "
            " group by cluster, object, rule_id, field "
            " order by cluster, object, max(occurred_at) desc "
            " limit %(limit)s",
            {
                "clusters": list(clusters),
                "since": since,
                "paths": WAF_FINDING_PATHS,
                "limit": WAF_FINDING_LIMIT,
            },
        )
        return cursor.fetchall()


def waf_verdicts(
    connection: Connection[Any], *, clusters: Sequence[str], since: datetime
) -> dict[tuple[str, str], tuple[int, int]]:
    """Per cluster and object: requests the engine judged an attack, and their clients.

    Read from the traffic record (`crs:log` or `crs:deny`, 0051) and the
    engine's transaction ID that names the object (`<object>.<uuid>`, 0052).
    """

    with connection.cursor() as cursor:
        cursor.execute(
            "select cluster, split_part(waf_id, '.', 1), count(*)::int, "
            "       count(distinct client)::int "
            "  from traffic_log "
            " where cluster = any(%(clusters)s) and occurred_at >= %(since)s "
            "   and rule in ('crs:log', 'crs:deny') and waf_id <> '' "
            " group by 1, 2",
            {"clusters": list(clusters), "since": since},
        )
        return {(row[0], row[1]): (row[2], row[3]) for row in cursor.fetchall()}


def waf_request_count(
    connection: Connection[Any], *, clusters: Sequence[str], since: datetime
) -> int:
    """Requests a rule met (an access rule or the engine), the WAF page's Requests tab.

    The same rows the tab lists (`rule <> ''`), counted over the page's days;
    each partition's partial index on `occurred_at` (0050) answers it.
    """

    with connection.cursor() as cursor:
        cursor.execute(
            "select count(*)::int from traffic_log "
            " where cluster = any(%(clusters)s) and occurred_at >= %(since)s and rule <> ''",
            {"clusters": list(clusters), "since": since},
        )
        row = cursor.fetchone()
        return int(row[0]) if row is not None else 0
