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

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

import psycopg
from psycopg import Connection, sql
from psycopg.rows import class_row
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

from haproxy_ui.config import Database


@dataclass(frozen=True, slots=True)
class Account:
    id: int
    username: str
    role: str
    disabled: bool
    password_hash: str


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
    cluster: str
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
    cluster: str
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
    cluster: str
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


def queue_job(
    connection: Connection[Any],
    *,
    operation: str,
    cluster: str,
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
        if constraint not in {"job_one_active_per_cluster", "job_idempotency_key"}:
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
            "   and cluster = %(cluster)s "
            "   and payload_hash = sha256(convert_to(%(payload)s::jsonb::text, 'UTF8'))",
            parameters,
        )
        existing = cursor.fetchone()
    if existing is None:
        if constraint == "job_one_active_per_cluster":
            if conflict is None:  # pragma: no cover - the lookup only follows that violation
                raise psycopg.OperationalError(
                    "the cluster conflict was lost before classification"
                )
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
            "select id, username, role, disabled, password_hash "
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
    """

    with connection.cursor() as cursor:
        cursor.execute(
            "select count(*) "
            "  from login_attempt "
            " where username_normalised = lower(%(username)s) "
            "   and client_ip = %(client_ip)s "
            "   and succeeded = false "
            "   and at > statement_timestamp() - make_interval(mins => %(window)s) "
            "   and at > coalesce( "
            "         (select max(at) from login_attempt "
            "           where username_normalised = lower(%(username)s) "
            "             and client_ip = %(client_ip)s "
            "             and succeeded = true), "
            "         '-infinity'::timestamptz)",
            {"username": username, "client_ip": client_ip, "window": window_minutes},
        )
        row = cursor.fetchone()
    return int(row[0]) if row is not None else 0


def create_session(
    connection: Connection[Any], *, token_hash: bytes, user_id: int, expires_at: datetime
) -> None:
    """Store the hash of a session token, never the token.

    Three columns, which is exactly what the web role holds `insert` on.
    `created_at` and `last_seen_at` come from column defaults, so a session
    cannot be recorded as older or fresher than it is.
    """

    with connection.cursor() as cursor:
        cursor.execute(
            "insert into app_session (token_hash, user_id, expires_at) "
            "values (%(token_hash)s, %(user_id)s, %(expires_at)s)",
            {"token_hash": token_hash, "user_id": user_id, "expires_at": expires_at},
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
            "       s.created_at, s.last_seen_at, s.expires_at, s.revoked_at "
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
    """Replace one cluster's cached version listing with the newest answer."""

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
    """Replace one cluster's cached objects with the newest helper answer."""

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
            "select cluster, object_id, yaml, base_version, base_hash, revision, "
            "       updated_by, updated_at, deleted "
            "  from proxy_draft "
            " where cluster = %(cluster)s "
            " order by object_id",
            {"cluster": cluster},
        )
        return cursor.fetchall()


def read_draft(connection: Connection[Any], cluster: str, object_id: str) -> ProxyDraft | None:
    """One draft, or None where the object has no unsaved edit."""

    with connection.cursor(row_factory=class_row(ProxyDraft)) as cursor:
        cursor.execute(
            "select cluster, object_id, yaml, base_version, base_hash, revision, "
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
                "returning cluster, object_id, yaml, base_version, base_hash, revision, "
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
                "returning cluster, object_id, yaml, base_version, base_hash, revision, "
                "          updated_by, updated_at, deleted",
                values,
            )
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
