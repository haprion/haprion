"""Reaching the database, with the transaction boundary visible from the caller.

Every function here takes a connection. None of them opens one, commits one, or
decides how long one is held - because the two mistakes this layer exists to
prevent are both about scope rather than syntax:

* an audit record written in a different transaction from the change it
  describes, which leaves a history that can disagree with what happened
* a transaction held open while a subprocess runs. A rollout takes minutes; an
  open transaction across it keeps its row locks for that long, and the roles'
  `idle_in_transaction_session_timeout` ends it ten seconds in. The worker may
  keep a connection from its own small pool through a job - the web's pool is
  another process's - but it commits before the command starts.

So the caller opens a transaction, does everything belonging to it, and closes
it. What is inside is visible at the call site instead of buried here.

Columns are listed one at a time in every statement, never `*`. A schema change
then shows up as a failure at the query that must change, and the row shapes
below stay a contract rather than whatever the table happens to hold.
"""

from __future__ import annotations

import re
from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from typing import Any
from uuid import UUID

import psycopg
from haprion import crs, node_resources
from haprion.generate import METRICS_FRONTEND
from psycopg import Connection, sql
from psycopg.rows import class_row
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

from haprion_ui import metrics, node_events, search_index, timing
from haprion_ui.config import Database


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
class ManagerCertificates:
    """The last reading of what the manager holds - the registry and what the
    interface is served with - asked for with no cluster (B304)."""

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

    The cursor adds each statement's time to the web request it serves, and
    does nothing more anywhere else (see `timing`).
    """

    return ConnectionPool(
        conninfo=database.connection_string,
        min_size=min_size,
        max_size=max_size,
        kwargs={"cursor_factory": timing.TimedCursor},
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


@dataclass(frozen=True, slots=True)
class Health:
    """What /healthz judges (B332): who we are, where, and on which schema.

    `web` is whether the role holds the web's grants (`app_web`); `revision`
    is the schema's Alembic revision, None when the database has none - an
    empty database, or one no migration has run against.
    """

    identity: str
    database: str
    web: bool
    revision: str | None


def health(connection: Connection[Any]) -> Health:
    """The facts /healthz judges, read in one transaction."""

    with connection.cursor() as cursor:
        cursor.execute(
            "select current_user, current_database(), "
            "pg_has_role(current_user, 'app_web', 'member'), "
            "to_regclass('alembic_version') is not null"
        )
        row = cursor.fetchone()
        if row is None:  # pragma: no cover - a select of constants returns a row
            raise psycopg.OperationalError("the database did not answer current_user")
        revision = None
        if row[3]:
            cursor.execute("select version_num from alembic_version")
            found = cursor.fetchone()
            revision = None if found is None else str(found[0])
    return Health(identity=str(row[0]), database=str(row[1]), web=bool(row[2]), revision=revision)


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
    #
    # B257: a *draft* is unfinished and never published; a *saved* change goes
    # out with the next publish. One of each may exist for an object - a draft
    # on top of a saved change - and the stage is part of the key.
    #
    stage: str = "draft"
    #
    # The published name this object takes the place of, for a rename. Kept on
    # the row so the publish that carries it removes the old name as well,
    # whenever that publish happens.
    #
    replaces: str | None = None
    #
    # The object as it was published when this row was written (0080): its
    # document, or empty where nothing of that name was published. What tells
    # a draft whose object moved from one the cluster merely moved past. None
    # on rows from before, which only `base_hash` can judge.
    #
    base_document: str | None = None


DRAFT = "draft"
SAVED = "saved"


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
            "   and ((operation = 'objects_publish' "
            "         and payload->'draft'->>'id' = any(%(ids)s)) "
            "        or (operation = 'changes_publish' "
            "            and exists (select 1 "
            "                          from jsonb_array_elements(payload->'drafts') as entry "
            "                         where entry->>'id' = any(%(ids)s)))) "
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
            "            and not exists ( "
            "                select 1 from job_claim_gate "
            "                 where paused_until > statement_timestamp()) "
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

    #
    # An IPv6 source is its /64: one host given a prefix has as many addresses
    # as it likes, and each was a budget of its own (security review S02).
    #
    with connection.cursor() as cursor:
        cursor.execute(
            "select count(*) "
            "  from login_attempt "
            " where username_normalised = lower(%(username)s) "
            "   and client_ip <<= set_masklen(%(client_ip)s::inet, "
            "         case when family(%(client_ip)s::inet) = 6 then 64 else 32 end) "
            "   and succeeded = false "
            "   and at > statement_timestamp() - make_interval(mins => %(window)s) "
            "   and at > greatest( "
            "         coalesce((select max(at) from login_attempt "
            "                    where username_normalised = lower(%(username)s) "
            "                      and client_ip <<= set_masklen(%(client_ip)s::inet, "
            "                    case when family(%(client_ip)s::inet) = 6 then 64 else 32 end) "
            "                      and succeeded = true), '-infinity'::timestamptz), "
            "         coalesce((select max(at) from login_unlock "
            "                    where username_normalised = lower(%(username)s)), "
            "                  '-infinity'::timestamptz))",
            {"username": username, "client_ip": client_ip, "window": window_minutes},
        )
        row = cursor.fetchone()
    return int(row[0]) if row is not None else 0


def account_failures_since_last_success(
    connection: Connection[Any], *, username: str, window_minutes: int
) -> int:
    """How many failures this name has accumulated recently, from anywhere (B305).

    The per-source count stops one address; this stops many guessing at one
    account. Bounded by the same window and reset the same way, by a success
    or an unlock, so it slows an attack rather than locking an account for good.
    """

    with connection.cursor() as cursor:
        cursor.execute(
            "select count(*) "
            "  from login_attempt "
            " where username_normalised = lower(%(username)s) "
            "   and succeeded = false "
            "   and at > statement_timestamp() - make_interval(mins => %(window)s) "
            "   and at > greatest( "
            "         coalesce((select max(at) from login_attempt "
            "                    where username_normalised = lower(%(username)s) "
            "                      and succeeded = true), '-infinity'::timestamptz), "
            "         coalesce((select max(at) from login_unlock "
            "                    where username_normalised = lower(%(username)s)), "
            "                  '-infinity'::timestamptz))",
            {"username": username, "window": window_minutes},
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


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """One row of the record, as *Audit* and the Servers card read it (B275)."""

    id: int
    at: datetime
    actor: str | None
    action: str
    cluster: str | None
    request_id: UUID | None
    detail: dict[str, Any]


#
# What the worker writes about jobs it ran; their outcome is the Jobs view's,
# so *Audit* leaves them out (B275).
#
JOB_EVENTS = ("job_finished", "job_requeued", "job_abandoned")
#
# How far back a free-text search reaches: `detail::text` cannot use an
# index, and a search that read the whole record would slow every page that
# shares the database (B275).
#
AUDIT_SEARCH_WINDOW_DAYS = 90


_AUDIT_WHERE = (
    " where not action = any(%(excluded)s) "
    "   and (%(actor)s = '' or actor = %(actor)s) "
    "   and (%(cluster)s = '' or cluster = %(cluster)s) "
    "   and (%(since)s::timestamptz is null or at >= %(since)s) "
    "   and (%(until)s::timestamptz is null or at <= %(until)s) "
    "   and (%(search)s = '' or ("
    "        at > statement_timestamp() - make_interval(days => %(window)s) "
    "        and (actor ilike %(like)s or action ilike %(like)s "
    "             or detail::text ilike %(like)s))) "
)


def _audit_filter(
    *,
    actor: str,
    cluster: str,
    search: str,
    since: datetime | None,
    until: datetime | None,
    excluded: Sequence[str],
) -> dict[str, Any]:
    return {
        "excluded": list(excluded),
        "actor": actor,
        "cluster": cluster,
        "since": since,
        "until": until,
        "search": search,
        "like": _like_pattern(search),
        "window": AUDIT_SEARCH_WINDOW_DAYS,
    }


#
# What each sortable Audit heading orders by (26-10-11). The sentence under
# *What* is built from the action, so it groups by kind of event; a tie keeps
# the newest first. Names only - the direction is the caller's bool.
#
AUDIT_ORDER_COLUMNS: Mapping[str, str] = {
    "time": "id",
    "who": "actor",
    "what": "action",
    "where": "cluster",
}


def audit_events(
    connection: Connection[Any],
    *,
    order: str = "time",
    descending: bool = True,
    offset: int = 0,
    limit: int = 50,
    actor: str = "",
    cluster: str = "",
    search: str = "",
    since: datetime | None = None,
    until: datetime | None = None,
    excluded: Sequence[str] = JOB_EVENTS,
) -> list[AuditEvent]:
    """One page of the record, newest first (B275; pages as the traffic log's, 26-10-11)."""

    with connection.cursor(row_factory=class_row(AuditEvent)) as cursor:
        cursor.execute(
            "select id, at, actor, action, cluster, request_id, detail "  # noqa: S608 - constant
            "  from audit_event "
            + _AUDIT_WHERE
            + f" order by {AUDIT_ORDER_COLUMNS.get(order, 'id')} {'desc' if descending else 'asc'}"
            " nulls last, id desc limit %(limit)s offset %(offset)s",
            {
                **_audit_filter(
                    actor=actor,
                    cluster=cluster,
                    search=search,
                    since=since,
                    until=until,
                    excluded=excluded,
                ),
                "limit": max(1, min(limit, 500)),
                "offset": max(0, offset),
            },
        )
        return cursor.fetchall()


def audit_count(
    connection: Connection[Any],
    *,
    actor: str = "",
    cluster: str = "",
    search: str = "",
    since: datetime | None = None,
    until: datetime | None = None,
    excluded: Sequence[str] = JOB_EVENTS,
) -> int:
    """How many rows the same filter matches: the "of N" under the page."""

    with connection.cursor() as cursor:
        cursor.execute(
            "select count(*) from audit_event " + _AUDIT_WHERE,  # noqa: S608 - constant
            _audit_filter(
                actor=actor,
                cluster=cluster,
                search=search,
                since=since,
                until=until,
                excluded=excluded,
            ),
        )
        row = cursor.fetchone()
        return int(row[0]) if row else 0


@dataclass(frozen=True, slots=True)
class NodeEventsWritten:
    events: int
    joining: frozenset[str]


def record_node_events(
    connection: Connection[Any], *, cluster: str, result: Mapping[str, Any]
) -> NodeEventsWritten:
    """Compare one status reading with the state kept, and write what changed (*Events → Nodes*).

    One transaction with the state it replaces, so two passes can never both
    see the old state and both write the change. Returns how many events, and
    which nodes have not answered yet (B329).
    """

    with connection.cursor() as cursor:
        cursor.execute(
            "select kind, subject, value from node_event_state where cluster = %(cluster)s "
            "   for update",
            {"cluster": cluster},
        )
        previous = {(row[0], row[1]): row[2] for row in cursor.fetchall()}
        changes, state, gone = node_events.compare(previous, node_events.observe(result))
        if changes:
            cursor.executemany(
                "insert into node_event (at, cluster, node, event, subject, detail) "
                "values (transaction_timestamp() - make_interval(secs => %(ago)s), "
                "        %(cluster)s, %(node)s, %(event)s, %(subject)s, %(detail)s)",
                [
                    {
                        "ago": change.seconds_ago or 0,
                        "cluster": cluster,
                        "node": change.node,
                        "event": change.event,
                        "subject": change.subject,
                        "detail": Jsonb(dict(change.detail)),
                    }
                    for change in changes
                ],
            )
        changed = [(key, value) for key, value in state.items() if previous.get(key) != value]
        if changed:
            cursor.executemany(
                "insert into node_event_state (cluster, kind, subject, value) "
                "values (%(cluster)s, %(kind)s, %(subject)s, %(value)s) "
                "on conflict (cluster, kind, subject) do update set value = excluded.value",
                [
                    {"cluster": cluster, "kind": key[0], "subject": key[1], "value": value}
                    for key, value in changed
                ],
            )
        if gone:
            cursor.execute(
                "delete from node_event_state "
                " where cluster = %(cluster)s and kind = 'server' and subject = any(%(gone)s)",
                {"cluster": cluster, "gone": [key[1] for key in gone]},
            )
    return NodeEventsWritten(len(changes), node_events.joining(state))


@dataclass(frozen=True, slots=True)
class NodeEvent:
    id: int
    at: datetime
    cluster: str
    node: str
    event: str
    subject: str
    detail: dict[str, Any]


_NODE_EVENT_WHERE = (
    " where (%(cluster)s = '' or cluster = %(cluster)s) "
    "   and (%(since)s::timestamptz is null or at >= %(since)s) "
    "   and (%(until)s::timestamptz is null or at <= %(until)s) "
    "   and (%(search)s = '' or node ilike %(like)s or subject ilike %(like)s) "
)

NODE_EVENT_ORDER_COLUMNS: Mapping[str, str] = {
    "time": "at",
    "node": "node",
    "what": "event",
    "where": "cluster",
}


def _node_event_filter(
    *, cluster: str, search: str, since: datetime | None, until: datetime | None
) -> dict[str, Any]:
    return {
        "cluster": cluster,
        "since": since,
        "until": until,
        "search": search,
        "like": _like_pattern(search),
    }


def node_event_page(
    connection: Connection[Any],
    *,
    order: str = "time",
    descending: bool = True,
    offset: int = 0,
    limit: int = 50,
    cluster: str = "",
    search: str = "",
    since: datetime | None = None,
    until: datetime | None = None,
) -> list[NodeEvent]:
    """One page of *Events → Nodes*, newest first, as *Audit* pages."""

    with connection.cursor(row_factory=class_row(NodeEvent)) as cursor:
        cursor.execute(
            "select id, at, cluster, node, event, subject, detail "  # noqa: S608 - constant
            "  from node_event "
            + _NODE_EVENT_WHERE
            + f" order by {NODE_EVENT_ORDER_COLUMNS.get(order, 'at')} "
            f"{'desc' if descending else 'asc'}, id desc limit %(limit)s offset %(offset)s",
            {
                **_node_event_filter(cluster=cluster, search=search, since=since, until=until),
                "limit": max(1, min(limit, 500)),
                "offset": max(0, offset),
            },
        )
        return cursor.fetchall()


def node_event_count(
    connection: Connection[Any],
    *,
    cluster: str = "",
    search: str = "",
    since: datetime | None = None,
    until: datetime | None = None,
) -> int:
    with connection.cursor() as cursor:
        cursor.execute(
            "select count(*) from node_event " + _NODE_EVENT_WHERE,  # noqa: S608 - constant
            _node_event_filter(cluster=cluster, search=search, since=since, until=until),
        )
        row = cursor.fetchone()
        return int(row[0]) if row else 0


def requested_by(connection: Connection[Any], request_ids: Collection[UUID]) -> dict[UUID, str]:
    """Who queued each of these jobs, from the `queue_job` row beside it (B275)."""

    if not request_ids:
        return {}
    with connection.cursor() as cursor:
        cursor.execute(
            "select distinct on (request_id) request_id, actor "
            "  from audit_event "
            " where action = 'queue_job' and request_id = any(%(ids)s) and actor is not null "
            " order by request_id, id",
            {"ids": list(request_ids)},
        )
        return {row[0]: row[1] for row in cursor.fetchall()}


def account_names(connection: Connection[Any]) -> frozenset[str]:
    """Every account's name, lowercased: what tells a known name from a typed one (B275)."""

    with connection.cursor() as cursor:
        cursor.execute("select username_normalised from app_user")
        return frozenset(str(row[0]) for row in cursor.fetchall())


@dataclass(frozen=True, slots=True)
class TakenOut:
    """The newest download or export of an external certificate (26-10-18)."""

    actor: str
    at: datetime
    fingerprint: str


def certificate_takeouts(connection: Connection[Any]) -> dict[str, TakenOut]:
    """Each external certificate's newest download or export, by certificate ID (0077)."""

    with connection.cursor() as cursor:
        cursor.execute(
            "select distinct on (detail->>'certificate') "
            "       detail->>'certificate', actor, at, detail->>'fingerprint_sha256' "
            "  from audit_event "
            " where action in ('certificate_export', 'certificate_download') "
            "   and detail->>'certificate' is not null "
            " order by detail->>'certificate', id desc"
        )
        return {
            str(certificate): TakenOut(str(actor), at, str(fingerprint or ""))
            for certificate, actor, at, fingerprint in cursor.fetchall()
        }


def server_state_events(
    connection: Connection[Any], *, cluster: str, object_name: str, limit: int = 200
) -> list[AuditEvent]:
    """The newest drains, maintenances and readies queued for one object's servers (B275)."""

    with connection.cursor(row_factory=class_row(AuditEvent)) as cursor:
        cursor.execute(
            "select id, at, actor, action, cluster, request_id, detail "
            "  from audit_event "
            " where cluster = %(cluster)s and action = 'queue_job' "
            "   and detail->>'operation' = 'server_state' "
            "   and detail->>'object' = %(object)s "
            " order by id desc "
            " limit %(limit)s",
            {"cluster": cluster, "object": object_name, "limit": limit},
        )
        return cursor.fetchall()


@dataclass(frozen=True, slots=True)
class StatusAccess:
    """One network allowed to ask `/status/` what needs doing (B274)."""

    network: str
    added_by: str
    added_at: datetime


#
# A row of *Needs attention* by kind, cluster ('' for none) and subject (B299).
#
type AttentionKey = tuple[str, str, str]


def attention_acks(connection: Connection[Any]) -> set[AttentionKey]:
    """The rows an admin has acknowledged (0073)."""

    with connection.cursor() as cursor:
        cursor.execute("select kind, cluster, subject from attention_ack")
        return {(str(kind), str(cluster), str(subject)) for kind, cluster, subject in cursor}


def acknowledge_attention(connection: Connection[Any], key: AttentionKey, *, actor: str) -> bool:
    """Acknowledge one row; False when it already was."""

    with connection.cursor() as cursor:
        cursor.execute(
            "insert into attention_ack (kind, cluster, subject, acknowledged_by) "
            "values (%s, %s, %s, %s) on conflict do nothing",
            (*key, actor),
        )
        return cursor.rowcount == 1


def forget_attention_acks(connection: Connection[Any], gone: set[AttentionKey]) -> None:
    """Remove acknowledgements whose row has gone, so the row is new if it comes back."""

    with connection.cursor() as cursor:
        for kind, cluster, subject in sorted(gone):
            cursor.execute(
                "delete from attention_ack where kind = %s and cluster = %s and subject = %s",
                (kind, cluster, subject),
            )


def getting_started_hidden_at(connection: Connection[Any]) -> datetime | None:
    """When an admin hid the getting started list (0075); None while it shows."""

    with connection.cursor() as cursor:
        cursor.execute("select hidden_at from getting_started")
        row = cursor.fetchone()
        if row is None:
            return None
        hidden_at: datetime = row[0]
        return hidden_at


def hide_getting_started(connection: Connection[Any], *, actor: str) -> bool:
    """Hide the list for the whole installation; False when it already was."""

    with connection.cursor() as cursor:
        cursor.execute(
            "insert into getting_started (hidden_by) values (%s) on conflict do nothing", (actor,)
        )
        return cursor.rowcount == 1


def show_getting_started(connection: Connection[Any]) -> bool:
    """Show the list again (0076); False when it was not hidden."""

    with connection.cursor() as cursor:
        cursor.execute("delete from getting_started")
        return cursor.rowcount == 1


def status_access(connection: Connection[Any]) -> list[StatusAccess]:
    with connection.cursor(row_factory=class_row(StatusAccess)) as cursor:
        cursor.execute(
            "select network::text as network, added_by, added_at "
            "  from status_access order by network"
        )
        return cursor.fetchall()


def set_status_access(connection: Connection[Any], *, networks: Sequence[str], actor: str) -> None:
    """The list as given, in the caller's transaction (B274).

    Only what changed is written: an address that stays keeps who added it and
    when. Replacing the whole list gave every address the last saver's name
    and time (26-10-12), which the edit page shows beside each one.
    """

    wanted = list(networks)
    with connection.cursor() as cursor:
        cursor.execute(
            "delete from status_access where network <> all(%(wanted)s::cidr[])",
            {"wanted": wanted},
        )
        for network in wanted:
            cursor.execute(
                "insert into status_access (network, added_by) "
                "select %(network)s::cidr, %(actor)s "
                " where not exists (select 1 from status_access where network = %(network)s::cidr)",
                {"network": network, "actor": actor},
            )


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


def _forward_receivers(node: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    status = node.get("status")
    forwarding = status.get("log_forwarding") if isinstance(status, Mapping) else None
    receivers = forwarding.get("receivers") if isinstance(forwarding, Mapping) else None
    if not isinstance(receivers, list):
        return []
    return [receiver for receiver in receivers if isinstance(receiver, Mapping)]


def _with_forward_waiting(
    result: Mapping[str, Any], previous: Any, now: datetime
) -> Mapping[str, Any]:
    """Per node, since when each log receiver's queue has not been empty (26-10-12).

    A receiver that keeps up empties its queue within seconds; one whose queue
    is still not empty minutes later is not being reached - on a quiet cluster
    long before the queue is long enough to say so by its size. Carried from
    reading to reading as `forward_waiting_since`, beside the node's status,
    as the CPU share is; a receiver whose queue is empty, or a node without a
    recent previous reading, starts again from now.

    So does a queue shorter than at the previous reading: lines left it, so the
    receiver is reached. One far away always has a few lines on their way, and
    a clock that waited for an empty queue would call it unreached (review
    26-10-12 F3). One out of reach keeps or grows its queue.
    """

    nodes = result.get("nodes")
    if not isinstance(nodes, list):
        return result
    before: dict[str, Mapping[str, Any]] = {}
    queued_before: dict[str, dict[str, Any]] = {}
    if isinstance(previous, Mapping) and isinstance(previous.get("nodes"), list):
        for node in previous["nodes"]:
            if not isinstance(node, Mapping):
                continue
            if isinstance(node.get("forward_waiting_since"), Mapping):
                before[str(node.get("name"))] = node["forward_waiting_since"]
            queued_before[str(node.get("name"))] = {
                str(receiver.get("name")): receiver.get("queued")
                for receiver in _forward_receivers(node)
            }
    carried: list[Any] = []
    for node in nodes:
        if not isinstance(node, Mapping):
            carried.append(node)
            continue
        earlier = before.get(str(node.get("name")), {})
        sizes = queued_before.get(str(node.get("name")), {})
        waiting: dict[str, str] = {}
        for receiver in _forward_receivers(node):
            queued = receiver.get("queued")
            if isinstance(queued, int) and not isinstance(queued, bool) and queued > 0:
                name = str(receiver.get("name"))
                kept = earlier.get(name)
                size = sizes.get(name)
                shrank = isinstance(size, int) and not isinstance(size, bool) and queued < size
                waiting[name] = kept if isinstance(kept, str) and not shrank else now.isoformat()
        carried.append({**node, "forward_waiting_since": waiting})
    return {**result, "nodes": carried}


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
        recent = previous[0] if previous and previous[1] else None
        result = _with_cpu_shares(result, recent)
        result = _with_forward_waiting(result, recent, datetime.now(UTC))
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


def cluster_histories(
    connection: Connection[Any], *, cluster: str | None = None
) -> list[ClusterHistory]:
    """Every cluster's newest version listing, with the stalest one first."""

    with connection.cursor(row_factory=class_row(ClusterHistory)) as cursor:
        cursor.execute(
            sql.SQL(
                "select cluster, observed_at, outcome, result, warnings, error, poll_error "
                "from cluster_history {scope} order by observed_at asc"
            ).format(scope=sql.SQL("where cluster = %(cluster)s" if cluster is not None else "")),
            {"cluster": cluster},
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


def cluster_certificates(
    connection: Connection[Any], *, cluster: str | None = None
) -> list[ClusterCertificates]:
    """Every cluster's newest certificate metadata, with the stalest one first."""

    with connection.cursor(row_factory=class_row(ClusterCertificates)) as cursor:
        cursor.execute(
            sql.SQL(
                "select cluster, observed_at, outcome, result, warnings, error, poll_error "
                "from cluster_certificates {scope} order by observed_at asc"
            ).format(scope=sql.SQL("where cluster = %(cluster)s" if cluster is not None else "")),
            {"cluster": cluster},
        )
        return cursor.fetchall()


def record_manager_certificates(
    connection: Connection[Any],
    *,
    outcome: str,
    result: Mapping[str, Any],
    warnings: Any = None,
    error: Mapping[str, Any] | None = None,
    poll_error: str | None = None,
) -> None:
    """Replace the manager's certificate reading with the newest helper answer (B304)."""

    with connection.cursor() as cursor:
        cursor.execute(
            "insert into manager_certificates (outcome, result, warnings, error, poll_error) "
            "values (%(outcome)s, %(result)s, %(warnings)s, %(error)s, %(poll)s) "
            "on conflict (id) do update set "
            "    outcome = excluded.outcome, "
            "    result = excluded.result, "
            "    warnings = excluded.warnings, "
            "    error = excluded.error, "
            "    poll_error = excluded.poll_error",
            {
                "outcome": outcome,
                "result": Jsonb(dict(result)),
                "warnings": Jsonb(list(warnings or [])),
                "error": None if error is None else Jsonb(dict(error)),
                "poll": poll_error,
            },
        )


def manager_certificates(connection: Connection[Any]) -> ManagerCertificates | None:
    """The manager's newest certificate reading; None before the poller has made one."""

    with connection.cursor(row_factory=class_row(ManagerCertificates)) as cursor:
        cursor.execute(
            "select observed_at, outcome, result, warnings, error, poll_error "
            "from manager_certificates where id = 1"
        )
        return cursor.fetchone()


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


def cluster_networks(
    connection: Connection[Any], *, cluster: str | None = None
) -> list[ClusterNetwork]:
    """Every cluster's newest network description, with the stalest one first."""

    with connection.cursor(row_factory=class_row(ClusterNetwork)) as cursor:
        cursor.execute(
            sql.SQL(
                "select cluster, observed_at, outcome, result, warnings, error, poll_error "
                "from cluster_network {scope} order by observed_at asc"
            ).format(scope=sql.SQL("where cluster = %(cluster)s" if cluster is not None else "")),
            {"cluster": cluster},
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
    cluster: str | None,
    source: str,
    entries: Sequence[search_index.Entry],
) -> int:
    """Replace what one reading of one cluster contributes to the search (B222).

    In the caller's transaction, so the search never sees the cluster with its
    old rows gone and its new ones not yet written.

    Rows that already say exactly this are left alone (review 2026-10-03, D5):
    most readings change nothing, and rewriting them every poll cost a delete
    and an insert in two indexes, one of them trigram, for each. Compared in
    the same transaction against what is stored, so a write that failed before
    is not mistaken for one that happened.
    """

    #
    # The manager's own rows have no cluster (B304), and `= null` matches none.
    #
    scope = sql.SQL(
        "where cluster is null and source = %(source)s"
        if cluster is None
        else "where cluster = %(cluster)s and source = %(source)s"
    )
    wanted = sorted(
        (entry.kind, entry.title, entry.label, entry.value, entry.href, entry.admin_only)
        for entry in entries
    )
    with connection.cursor() as cursor:
        cursor.execute(
            sql.SQL(
                "select kind, title, label, value, href, admin_only from search_entry {scope}"
            ).format(scope=scope),
            {"cluster": cluster, "source": source},
        )
        if sorted(tuple(row) for row in cursor.fetchall()) == wanted:
            return len(entries)
        cursor.execute(
            sql.SQL("delete from search_entry {scope}").format(scope=scope),
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
            "delete from search_entry "
            "where cluster is not null and not (cluster = any(%(clusters)s))",
            {"clusters": list(clusters)},
        )
        return cursor.rowcount


def _like_pattern(query: str) -> str:
    """A substring pattern that matches the text and nothing it could mean to LIKE."""

    escaped = query.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def backend_rows(
    connection: Connection[Any], *, cluster: str, addresses: Sequence[str]
) -> list[tuple[str, str, str]]:
    """(server, object, link) for the objects in `cluster` that name any of `addresses`."""

    if not addresses:
        return []
    with connection.cursor() as cursor:
        cursor.execute(
            "select value, title, href from search_entry "
            " where cluster = %(cluster)s and source = 'objects' and kind = 'proxy' "
            "   and label = %(label)s and value = any(%(addresses)s)",
            {
                "cluster": cluster,
                "label": search_index.BACKEND_LABEL,
                "addresses": list(addresses),
            },
        )
        return [(str(value), str(title), str(href)) for value, title, href in cursor.fetchall()]


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
            "           and (cluster is null or cluster = any(%(clusters)s)) "
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


def cluster_list_observed(connection: Connection[Any]) -> datetime | None:
    """When the poller last wrote the cluster list - it does on every pass; None before the first."""

    with connection.cursor() as cursor:
        cursor.execute("select observed_at from cluster_list where id = 1")
        row = cursor.fetchone()
    return None if row is None else row[0]


def partition_horizons(
    connection: Connection[Any], tables: Iterable[str]
) -> dict[str, date | None]:
    """The last day each partitioned table has a partition for, from the catalog.

    Partitions are named `<table>_YYYYMMDD` by the functions that make them;
    a default partition has no date and is not counted. None for a table with
    no dated partition, or that does not exist.
    """

    names = list(tables)
    with connection.cursor() as cursor:
        cursor.execute(
            "select parent.relname, max(substring(child.relname from '_([0-9]{8})$')) "
            "  from pg_inherits "
            "  join pg_class parent on parent.oid = pg_inherits.inhparent "
            "  join pg_class child on child.oid = pg_inherits.inhrelid "
            " where parent.relname = any(%(names)s) "
            " group by parent.relname",
            {"names": names},
        )
        found = {str(name): last for name, last in cursor.fetchall()}
    return {
        name: datetime.strptime(found[name], "%Y%m%d").date() if found.get(name) else None
        for name in names
    }


def begin_cluster_pass(connection: Connection[Any], cluster: str) -> None:
    """Mark the start of a pass over one cluster (0068). The moment is the database's."""

    with connection.cursor() as cursor:
        cursor.execute(
            "insert into cluster_pass (cluster) values (%(cluster)s) "
            "on conflict (cluster) do update set began_at = statement_timestamp()",
            {"cluster": cluster},
        )


def settle_cluster_pass(connection: Connection[Any], cluster: str) -> None:
    """Every reading of the pass begun last is recorded: it is what the cluster is read through."""

    with connection.cursor() as cursor:
        cursor.execute(
            "update cluster_pass set settled_from = began_at where cluster = %(cluster)s",
            {"cluster": cluster},
        )


def clusters_catching_up(
    connection: Connection[Any], clusters: Sequence[str], *, within: timedelta
) -> list[str]:
    """The clusters whose last finished job no whole pass has read since (0068).

    A job that ended more than `within` ago is caught up whatever the poller
    did: a poller that is down must not leave a page waiting on it for good,
    and the pages say for themselves how old their readings are. Only a
    cluster's two newest jobs are looked at - one runs at a time, so the newest
    finished one is among them - which the job's own index answers.
    """

    with connection.cursor() as cursor:
        cursor.execute(
            "select c.cluster"
            "  from unnest(%(clusters)s::text[]) as c (cluster)"
            "  cross join lateral ("
            "      select max(recent.finished_at) as finished"
            "        from (select finished_at from job"
            "               where job.cluster = c.cluster"
            "               order by created_at desc limit 2) recent"
            "  ) last"
            "  left join cluster_pass p on p.cluster = c.cluster"
            " where last.finished > statement_timestamp() - %(within)s"
            "   and (p.settled_from is null or p.settled_from <= last.finished)"
            " order by c.cluster",
            {"clusters": list(clusters), "within": within},
        )
        return [str(cluster) for (cluster,) in cursor.fetchall()]


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


def cluster_objects(
    connection: Connection[Any], *, cluster: str | None = None
) -> list[ClusterObjects]:
    """Every cluster's newest objects reading, with the stalest one first."""

    with connection.cursor(row_factory=class_row(ClusterObjects)) as cursor:
        cursor.execute(
            sql.SQL(
                "select cluster, observed_at, outcome, result, warnings, error, poll_error "
                "from cluster_objects {scope} order by observed_at asc"
            ).format(scope=sql.SQL("where cluster = %(cluster)s" if cluster is not None else "")),
            {"cluster": cluster},
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


def holds_singleton_lock(connection: Connection[Any], key: int) -> bool:
    """Whether this session still holds the lock `try_singleton_lock` took.

    False as well when the session itself is gone. A terminated lock session
    releases the lock on the server while the pool's connections keep working,
    so a process that never asked again would go on as if it were the only one
    (review 2026-10-18, A1). A bigint key is held as the high and low halves in
    `classid` and `objid`, with `objsubid` 1.
    """

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "select exists (select 1 from pg_locks "
                " where locktype = 'advisory' and pid = pg_backend_pid() and granted "
                "   and objsubid = 1 and classid = %s::oid and objid = %s::oid)",
                ((key >> 32) & 0xFFFFFFFF, key & 0xFFFFFFFF),
            )
            row = cursor.fetchone()
    except psycopg.Error:
        return False
    return bool(row and row[0])


def cluster_drafts(connection: Connection[Any], cluster: str) -> list[ProxyDraft]:
    """Every draft and saved change for one cluster, in the order a listing shows objects."""

    with connection.cursor(row_factory=class_row(ProxyDraft)) as cursor:
        cursor.execute(
            "select id, cluster, object_id, yaml, base_version, base_hash, revision, "
            "       updated_by, updated_at, deleted, stage, replaces, base_document "
            "  from proxy_draft "
            " where cluster = %(cluster)s "
            " order by object_id, stage",
            {"cluster": cluster},
        )
        return cursor.fetchall()


def live_drafts(connection: Connection[Any]) -> list[ProxyDraft]:
    """Every draft and saved change in every cluster that still asks for an object to exist.

    A row marked `deleted` asks for its object to go and names nothing a
    deletion has to respect, so it is left out here rather than filtered by
    every caller.
    """

    with connection.cursor(row_factory=class_row(ProxyDraft)) as cursor:
        cursor.execute(
            "select id, cluster, object_id, yaml, base_version, base_hash, revision, "
            "       updated_by, updated_at, deleted, stage, replaces, base_document "
            "  from proxy_draft "
            " where not deleted "
            " order by cluster, object_id, stage"
        )
        return cursor.fetchall()


def read_draft(
    connection: Connection[Any], cluster: str, object_id: str, stage: str = DRAFT
) -> ProxyDraft | None:
    """One draft or saved change, or None where the object has none of that stage."""

    with connection.cursor(row_factory=class_row(ProxyDraft)) as cursor:
        cursor.execute(
            "select id, cluster, object_id, yaml, base_version, base_hash, revision, "
            "       updated_by, updated_at, deleted, stage, replaces, base_document "
            "  from proxy_draft "
            " where cluster = %(cluster)s and object_id = %(object_id)s "
            "   and stage = %(stage)s",
            {"cluster": cluster, "object_id": object_id, "stage": stage},
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
    base_document: str | None,
    deleted: bool = False,
    replaces: str | None = None,
    expected_revision: int | None,
) -> ProxyDraft:
    """Create or replace one draft, refusing a write the caller did not see.

    A draft only: a saved change is written by `save_change`, which also
    takes the draft it was finished from out of the way.

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
        "replaces": replaces,
        "base_document": base_document,
        "revision": expected_revision,
    }
    with connection.transaction(), connection.cursor(row_factory=class_row(ProxyDraft)) as cursor:
        if expected_revision is None:
            cursor.execute(
                "insert into proxy_draft "
                "       (cluster, object_id, yaml, base_version, base_hash, updated_by, deleted, "
                "        replaces, base_document, stage) "
                "values (%(cluster)s, %(object_id)s, %(yaml)s, %(base_version)s, "
                "        %(base_hash)s, %(updated_by)s, %(deleted)s, %(replaces)s, "
                "        %(base_document)s, 'draft') "
                "on conflict do nothing "
                "returning id, cluster, object_id, yaml, base_version, base_hash, revision, "
                "          updated_by, updated_at, deleted, stage, replaces, base_document",
                values,
            )
        else:
            cursor.execute(
                "update proxy_draft "
                "   set yaml = %(yaml)s, base_version = %(base_version)s, "
                "       base_hash = %(base_hash)s, updated_by = %(updated_by)s, "
                "       deleted = %(deleted)s, replaces = %(replaces)s, "
                "       base_document = %(base_document)s "
                " where cluster = %(cluster)s and object_id = %(object_id)s "
                "   and stage = 'draft' and revision = %(revision)s "
                "returning id, cluster, object_id, yaml, base_version, base_hash, revision, "
                "          updated_by, updated_at, deleted, stage, replaces, base_document",
                values,
            )
        row = cursor.fetchone()
        if row is None:
            raise DraftConflict(
                f"the draft for {object_id} changed since it was read; reload it and try again"
            )
        return row


def save_change(
    connection: Connection[Any],
    *,
    cluster: str,
    object_id: str,
    new_object_id: str | None = None,
    yaml: str,
    base_version: int | None,
    base_hash: str,
    updated_by: str,
    base_document: str | None,
    deleted: bool = False,
    replaces: str | None = None,
    saved_revision: int | None,
    draft_revision: int | None,
) -> ProxyDraft:
    """Write one object's saved change, and drop the draft it was finished from (B257).

    One transaction, so a conflict on any part leaves all of it as it was:
    the draft the person was looking at is removed (`draft_revision`, None
    when there is none), and the saved change is written - inserted when
    `saved_revision` is None, updated at that revision otherwise. A rename
    moves the saved row's key to `new_object_id`; a name already taken fails
    on the key rather than on a check that raced.

    Each part is held to the revision the caller read, as `save_draft` holds
    its one row, and for the same reason.
    """

    target = new_object_id or object_id
    values = {
        "cluster": cluster,
        "object_id": object_id,
        "target": target,
        "yaml": yaml,
        "base_version": base_version,
        "base_hash": base_hash,
        "updated_by": updated_by,
        "deleted": deleted,
        "replaces": replaces,
        "base_document": base_document,
        "saved_revision": saved_revision,
        "draft_revision": draft_revision,
    }
    stale = f"the changes to {object_id} changed since they were read; reload and try again"
    with connection.transaction(), connection.cursor(row_factory=class_row(ProxyDraft)) as cursor:
        if draft_revision is not None:
            cursor.execute(
                "delete from proxy_draft "
                " where cluster = %(cluster)s and object_id = %(object_id)s "
                "   and stage = 'draft' and revision = %(draft_revision)s",
                values,
            )
            if cursor.rowcount == 0:
                raise DraftConflict(stale)
        try:
            if saved_revision is None:
                cursor.execute(
                    "insert into proxy_draft "
                    "       (cluster, object_id, yaml, base_version, base_hash, updated_by, "
                    "        deleted, replaces, base_document, stage) "
                    "values (%(cluster)s, %(target)s, %(yaml)s, %(base_version)s, "
                    "        %(base_hash)s, %(updated_by)s, %(deleted)s, %(replaces)s, "
                    "        %(base_document)s, 'saved') "
                    "on conflict do nothing "
                    "returning id, cluster, object_id, yaml, base_version, base_hash, revision, "
                    "          updated_by, updated_at, deleted, stage, replaces, base_document",
                    values,
                )
            else:
                cursor.execute(
                    "update proxy_draft "
                    "   set object_id = %(target)s, yaml = %(yaml)s, "
                    "       base_version = %(base_version)s, base_hash = %(base_hash)s, "
                    "       updated_by = %(updated_by)s, deleted = %(deleted)s, "
                    "       replaces = %(replaces)s, base_document = %(base_document)s "
                    " where cluster = %(cluster)s and object_id = %(object_id)s "
                    "   and stage = 'saved' and revision = %(saved_revision)s "
                    "returning id, cluster, object_id, yaml, base_version, base_hash, revision, "
                    "          updated_by, updated_at, deleted, stage, replaces, base_document",
                    values,
                )
        except psycopg.errors.UniqueViolation as clash:
            raise DraftConflict(
                f"{target} already has saved changes in this cluster; "
                f"the rename would replace somebody's work"
            ) from clash
        row = cursor.fetchone()
        if row is None:
            raise DraftConflict(
                f"{target} already has saved changes in this cluster"
                if saved_revision is None and target != object_id
                else stale
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
    base_document: str | None,
    replaces: str | None = None,
    expected_revision: int,
) -> ProxyDraft:
    """Move one draft to another name, as a change of its key.

    A rename is not a new draft and a removal of the old one. Written that way
    it is two writes, and `save_draft` commits its own transaction - so a
    conflict on the second left the first standing and the person had two
    drafts where they had made one, which is precisely how this was found.

    One statement instead. The stage is part of the key, so the move either
    happens or does not, and a name already taken fails on the key rather
    than on a check that raced. The row keeps its `id`: it is the same piece
    of work, and the publish that eventually carries it should be able to
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
        "replaces": replaces,
        "base_document": base_document,
        "revision": expected_revision,
    }
    with connection.transaction(), connection.cursor(row_factory=class_row(ProxyDraft)) as cursor:
        try:
            cursor.execute(
                "update proxy_draft "
                "   set object_id = %(new_object_id)s, yaml = %(yaml)s, "
                "       base_version = %(base_version)s, base_hash = %(base_hash)s, "
                "       updated_by = %(updated_by)s, replaces = %(replaces)s, "
                "       base_document = %(base_document)s "
                " where cluster = %(cluster)s and object_id = %(object_id)s "
                "   and stage = 'draft' and revision = %(revision)s "
                "returning id, cluster, object_id, yaml, base_version, base_hash, revision, "
                "          updated_by, updated_at, deleted, stage, replaces, base_document",
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
    connection: Connection[Any],
    *,
    cluster: str,
    object_id: str,
    expected_revision: int,
    stage: str = DRAFT,
) -> None:
    """Throw one draft or saved change away, and only the revision the caller was looking at.

    A real delete rather than a flag. An abandoned edit that stayed in the table
    would be indistinguishable from a decision to remove the object, which is
    what `deleted` means and what this is not.
    """

    with connection.cursor() as cursor:
        cursor.execute(
            "delete from proxy_draft "
            " where cluster = %(cluster)s and object_id = %(object_id)s "
            "   and stage = %(stage)s and revision = %(revision)s",
            {
                "cluster": cluster,
                "object_id": object_id,
                "stage": stage,
                "revision": expected_revision,
            },
        )
        if cursor.rowcount == 0:
            raise DraftConflict(
                f"the saved changes to {object_id} changed since they were read; "
                "reload them and try again"
                if stage == SAVED
                else f"the draft for {object_id} changed since it was read; reload it and try again"
            )


@dataclass(frozen=True, slots=True)
class ClusterChange:
    """A cluster's saved network description or settings, before a publish (B257).

    The whole document, saved the way a proxy object's change is: written
    here, published with the next publish, and cleared once that publish can
    be read.
    """

    cluster: str
    kind: str
    document: str
    base_hash: str
    revision: int
    updated_by: str
    updated_at: datetime
    id: UUID


CHANGE_KINDS = ("network", "settings")


def cluster_changes(connection: Connection[Any], cluster: str) -> dict[str, ClusterChange]:
    """This cluster's saved network description and settings, by kind."""

    with connection.cursor(row_factory=class_row(ClusterChange)) as cursor:
        cursor.execute(
            "select cluster, kind, document, base_hash, revision, updated_by, updated_at, id "
            "  from cluster_change "
            " where cluster = %(cluster)s",
            {"cluster": cluster},
        )
        return {row.kind: row for row in cursor.fetchall()}


def save_cluster_change(
    connection: Connection[Any],
    *,
    cluster: str,
    kind: str,
    document: str,
    base_hash: str,
    updated_by: str,
    expected_revision: int | None,
) -> ClusterChange:
    """Create or replace one saved document, refusing a write the caller did not see.

    The same rule as `save_draft`: None for a document that should not exist
    yet, the revision read for one that should, both enforced by the statement.
    """

    values = {
        "cluster": cluster,
        "kind": kind,
        "document": document,
        "base_hash": base_hash,
        "updated_by": updated_by,
        "revision": expected_revision,
    }
    with (
        connection.transaction(),
        connection.cursor(row_factory=class_row(ClusterChange)) as cursor,
    ):
        if expected_revision is None:
            cursor.execute(
                "insert into cluster_change (cluster, kind, document, base_hash, updated_by) "
                "values (%(cluster)s, %(kind)s, %(document)s, %(base_hash)s, %(updated_by)s) "
                "on conflict do nothing "
                "returning cluster, kind, document, base_hash, revision, updated_by, "
                "          updated_at, id",
                values,
            )
        else:
            cursor.execute(
                "update cluster_change "
                "   set document = %(document)s, base_hash = %(base_hash)s, "
                "       updated_by = %(updated_by)s "
                " where cluster = %(cluster)s and kind = %(kind)s "
                "   and revision = %(revision)s "
                "returning cluster, kind, document, base_hash, revision, updated_by, "
                "          updated_at, id",
                values,
            )
        row = cursor.fetchone()
        if row is None:
            raise DraftConflict(
                f"the saved {kind} of {cluster} changed since it was read; reload and try again"
            )
        return row


def discard_cluster_change(
    connection: Connection[Any], *, cluster: str, kind: str, expected_revision: int
) -> None:
    """Throw one saved document away, and only the revision the caller was looking at."""

    with connection.cursor() as cursor:
        cursor.execute(
            "delete from cluster_change "
            " where cluster = %(cluster)s and kind = %(kind)s and revision = %(revision)s",
            {"cluster": cluster, "kind": kind, "revision": expected_revision},
        )
        if cursor.rowcount == 0:
            raise DraftConflict(
                f"the saved {kind} of {cluster} changed since it was read; reload and try again"
            )


def change_publishes(
    connection: Connection[Any], *, cluster: str, change_ids: Collection[str]
) -> list[Job]:
    """The finished publishes of these saved documents, asked by their ids.

    The same evidence `draft_publishes` reads for a proxy object, under the
    payload's `change` - or in the `changes` of a publish of saved changes.
    Retention keeps these rows while their change exists.
    """

    if not change_ids:
        return []
    with connection.cursor(row_factory=class_row(Job)) as cursor:
        cursor.execute(
            "select id, request_id, operation, cluster, payload, state, created_at, "
            "       started_at, finished_at, exit_code, outcome, result, stderr_excerpt, "
            "       idempotency_key, attempts "
            "  from job "
            " where (state = 'done' or result->'publish'->>'outcome' = 'done') "
            "   and cluster = %(cluster)s "
            "   and ((operation in ('network_publish', 'cluster_settings_publish') "
            "         and payload->'change'->>'id' = any(%(ids)s)) "
            "        or (operation = 'changes_publish' "
            "            and exists (select 1 "
            "                          from jsonb_array_elements(payload->'changes') as entry "
            "                         where entry->>'id' = any(%(ids)s)))) "
            " order by created_at desc, id desc",
            {"cluster": cluster, "ids": sorted(change_ids)},
        )
        return cursor.fetchall()


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
    member_columns = (*metrics.METRIC_COUNTERS, *metrics.DNS_COUNTERS, *metrics.SYSLOG_COUNTERS)
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
                        "counters_kept": sample.counters_kept,
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
                    member_columns,
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
                        "counters_kept": sample.counters_kept,
                        "status": sample.status,
                        **_counter_values(sample.counters, member_columns),
                    }
                    for sample in members
                ],
            )

    return len(frontends) + len(members)


def _sample_insert(
    table: str,
    identifying: tuple[str, ...],
    counters: tuple[str, ...] = metrics.METRIC_COUNTERS,
) -> sql.Composed:
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

    columns = ("cluster", *identifying, "uptime_sec", "counters_kept", "status", *counters)
    return sql.SQL("insert into {table} ({columns}) values ({values})").format(
        table=sql.Identifier(table),
        columns=sql.SQL(", ").join(sql.Identifier(name) for name in columns),
        values=sql.SQL(", ").join(sql.Placeholder(name) for name in columns),
    )


def _counter_values(
    counters: Mapping[str, int], names: tuple[str, ...] = metrics.METRIC_COUNTERS
) -> dict[str, int | None]:
    """Every counter column, with the ones this row did not report as None.

    `executemany` needs every placeholder present in every row, and the missing
    ones must arrive as null rather than be left out or defaulted to zero.
    """

    return {name: counters.get(name) for name in names}


#
# The fixed grid every drawing is measured from, stated in UTC. A bare
# `timestamptz '2000-01-01'` is read in the session's time zone, and the
# installation's server runs in local time: the six-hour buckets then began at
# 23, 05, 11 and 17 UTC while the drawing's grid (`metrics.BUCKET_EPOCH`) began
# at 00, 06, 12 and 18 - measured 2026-10-04, with a day's load test drawn
# into the wrong bucket.
#
BUCKET_EPOCH_SQL = sql.SQL("timestamptz '2000-01-01 00:00:00+00'")


def _bucketed_changes(table: str, scope: sql.Composable) -> sql.Composed:
    """A series' stored changes (0048), summed per node and bucket, as intervals.

    **The graph sums what the figures sum.** It used to keep one cumulative
    reading per bucket and difference neighbouring buckets, and a restart is
    where that goes wrong: the reading kept is the newest process's, so a
    reload late in a bucket erased everything counted before it in the same
    bucket. Measured 2026-10-04: a load test of 28 998 requests at 17:44 UTC,
    reloads at 17:05 and 19:05, and the 30-day graph drew nothing where the
    figures beside it counted every request. Summing the per-sample changes
    loses at most the one sample a restart cuts, whatever the bucket's width.

    A sample whose pair lies in an earlier bucket is kept as its own interval,
    so the drawing shares it out over the time it covers - a poll that was late
    by an hour is an hour of traffic, not a spike in one bucket. The rest of the
    bucket's samples lie inside it and are one interval.

    An interval belongs to the range when it starts inside it - the totals'
    rule, so the first sample, which has nothing in the range to pair with,
    adds nothing to either.
    """

    bucket = sql.SQL("date_bin(%(width)s, observed_at, {epoch})").format(epoch=BUCKET_EPOCH_SQL)
    sums = sql.SQL(", ").join(
        sql.SQL("sum({delta})::bigint").format(delta=sql.Identifier(f"delta_{name}"))
        for name in _deltas(table)
    )
    return sql.SQL(
        "select min(previous_at), max(observed_at), coalesce(bool_or(restarted), false), {sums} "
        "  from {table} "
        " where {scope} and observed_at <= %(until)s "
        "   and previous_at >= %(after)s and observed_at > %(after)s "
        " group by node, {bucket}, previous_at < {bucket} "
        " order by {bucket}, node"
    ).format(sums=sums, table=sql.Identifier(table), scope=scope, bucket=bucket)


def _changed_intervals(rows: Sequence[Any], names: tuple[str, ...]) -> list[metrics.Interval]:
    """Rows of `_bucketed_changes` or `_hour_series`; `names` is that table's `_deltas`."""

    return [
        metrics.Interval(
            started_at=row[0],
            ended_at=row[1],
            counters={
                name: None if value is None else int(value)
                for name, value in zip(names, row[3:], strict=True)
            },
            restarted=bool(row[2]),
        )
        for row in rows
    ]


@dataclass(frozen=True, slots=True)
class EarlierName:
    """A name a backend had before, and until when its readings are the backend's.

    `until` is null while nobody has given the name to another backend.
    """

    name: str
    until: datetime | None = None


def _history(backend: str, earlier: Sequence[EarlierName]) -> dict[str, list[Any]]:
    """`%(backends)s` and `%(cutoffs)s` for the history scopes: the current name first."""

    names = [backend, *(item.name for item in earlier if item.name != backend)]
    cutoffs = [None, *(item.until for item in earlier if item.name != backend)]
    return {"backends": names, "cutoffs": cutoffs}


def read_backend_aliases(
    connection: Connection[Any], *, cluster: str
) -> dict[str, list[EarlierName]]:
    """Every backend's earlier names in one cluster, followed through each rename.

    `a` renamed `b` and then `c` gives `c` both. A chain that came back on
    itself would never end; a name is visited once.
    """

    with connection.cursor() as cursor:
        cursor.execute(
            "select old_name, new_name, reused_at from metric_backend_alias "
            " where cluster = %(cluster)s",
            {"cluster": cluster},
        )
        rows = cursor.fetchall()
    into: dict[str, list[tuple[str, datetime | None]]] = {}
    for old, new, reused in rows:
        into.setdefault(new, []).append((old, reused))
    found: dict[str, list[EarlierName]] = {}
    for current in into:
        seen = {current}
        pending: list[tuple[str, datetime | None]] = [(current, None)]
        names: list[EarlierName] = []
        while pending:
            name, cutoff = pending.pop()
            for old, reused in into.get(name, ()):
                if old in seen:
                    continue
                seen.add(old)
                bound = min((at for at in (cutoff, reused) if at is not None), default=None)
                names.append(EarlierName(old, bound))
                pending.append((old, bound))
        found[current] = names
    return found


def record_backend_renames(
    connection: Connection[Any],
    *,
    cluster: str,
    renamed: Mapping[str, str],
    introduced: Iterable[str],
) -> None:
    """Write down a publish's renames, and close the earlier names it gives out again.

    `renamed` maps an old backend name to its new one; `introduced` is every
    name the publish brings into use. A name that was renamed away and is now
    given to a backend again stops counting for the renamed card from now on.
    """

    with connection.cursor() as cursor:
        cursor.execute(
            "update metric_backend_alias set reused_at = statement_timestamp() "
            " where cluster = %(cluster)s and old_name = any(%(introduced)s) "
            "   and reused_at is null",
            {"cluster": cluster, "introduced": list(introduced)},
        )
        for old, new in renamed.items():
            cursor.execute(
                "insert into metric_backend_alias (cluster, old_name, new_name) "
                "values (%(cluster)s, %(old)s, %(new)s) "
                "on conflict (cluster, old_name) do update "
                "   set new_name = excluded.new_name, renamed_at = statement_timestamp(), "
                "       reused_at = null",
                {"cluster": cluster, "old": old, "new": new},
            )


def read_backend_series(
    connection: Connection[Any],
    *,
    cluster: str,
    backend: str,
    since: datetime,
    until: datetime,
    width: timedelta,
    member: str = "BACKEND",
    earlier: Sequence[EarlierName] = (),
) -> list[metrics.Interval]:
    """What one backend did, as intervals for its card's drawing, oldest first.

    `BACKEND` by default, which is HAProxy's own aggregate row for the backend -
    the sum across its servers, counted by the thing doing the balancing rather
    than added up here. A caller that wants one server names it.

    A window longer than a day, drawn in whole hours, is read from the hourly
    sums (migration 0055) with the hours at its edges read raw; anything
    shorter reads the raw samples. Both hold the same stored differences, so
    the drawing is the same either way.
    """

    arguments: dict[str, Any] = {
        "cluster": cluster,
        "member": member,
        "width": width,
        "until": until,
        "after": since,
        **_history(backend, earlier),
    }
    with connection.cursor() as cursor:
        if _reads_hours(since, until, width):
            cursor.execute(
                _hour_series(
                    "metric_backend_hour_delta",
                    "metric_backend_member",
                    BACKEND_HOUR_SCOPE,
                    BACKEND_SCOPE,
                ),
                arguments,
            )
        else:
            cursor.execute(_bucketed_changes("metric_backend_member", BACKEND_SCOPE), arguments)
        return _changed_intervals(cursor.fetchall(), BACKEND_DELTAS)


def read_frontend_series(
    connection: Connection[Any],
    *,
    cluster: str,
    frontend: str,
    since: datetime,
    until: datetime,
    width: timedelta,
) -> list[metrics.Interval]:
    """What one VIP frontend did, as intervals for its card's drawing, oldest first.

    **The VIP is what listens, so the series is the VIP's.** Every node reports
    its own frontends, but only the node holding the address receives anything
    on it; its peer binds the same ports and sits flat. Only the samples on
    which a node held the address count, and each stored its change from that
    node's previous such sample (0048) - which is also what keeps a failover
    from being read as one node's lifetime total. Long windows read the hourly
    sums of the same changes (0055), which keep 31 days.
    """

    arguments = {
        "cluster": cluster,
        "frontend": frontend,
        "width": width,
        "until": until,
        "after": since,
    }
    with connection.cursor() as cursor:
        if _reads_hours(since, until, width):
            cursor.execute(
                _hour_series(
                    "metric_frontend_hour_delta", "metric_frontend", FRONTEND_SCOPE, FRONTEND_HELD
                ),
                arguments,
            )
        else:
            cursor.execute(_bucketed_changes("metric_frontend", FRONTEND_HELD), arguments)
        return _changed_intervals(cursor.fetchall(), STORED_DELTAS)


#
# What counts as the cluster's newest poll: every row within this of the
# newest one. A poll writes all of a cluster's rows within a few seconds
# (measured at 2-3 s for a whole pass), so a minute holds one poll and never the
# one before it at the shortest interval the poller allows (10 s plus the pass).
#
NEWEST_POLL = timedelta(minutes=1)


def _active(table: str) -> sql.Composed:
    """The rows of the cluster's newest poll inside the window (2026-10-06).

    The page shows what HAProxy runs now, as the exporter does: a backend a
    rename or a removal took away is not listed, whatever history it has. Its
    readings are the newest poll's rather than the last minute's by the clock,
    so a poller that has stopped leaves the page as it last was instead of
    empty - an outage is the moment this page is opened.
    """

    #
    # The last ten minutes first, which is where the newest poll is whenever
    # the poller runs, and a few hundred rows; the whole window only when that
    # finds nothing. `coalesce` evaluates its second argument only then.
    #
    return sql.SQL(
        "{table}.observed_at >= coalesce("
        "    (select max(recent.observed_at) from {table} as recent "
        "      where recent.cluster = %(cluster)s "
        "        and recent.observed_at >= greatest(%(since)s, %(until)s - interval '10 minutes') "
        "        and recent.observed_at <= %(until)s), "
        "    (select max(newest.observed_at) from {table} as newest "
        "      where newest.cluster = %(cluster)s "
        "        and newest.observed_at >= %(since)s and newest.observed_at <= %(until)s)"
        ") - %(newest_poll)s"
    ).format(table=sql.Identifier(table))


def read_cluster_frontends(
    connection: Connection[Any], *, cluster: str, since: datetime, until: datetime
) -> list[tuple[str, bool]]:
    """Which VIP frontends this cluster serves now, and whether any node held each.

    Asked of the samples rather than of the configuration, and of the newest
    poll's (`_active`): a frontend that is gone is not listed, and one added this
    morning appears with its first reading whatever the document says.

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
            sql.SQL(
                "select frontend, coalesce(bool_or(owns_vip), false) from metric_frontend "
                " where cluster = %(cluster)s "
                "   and observed_at >= %(since)s and observed_at <= %(until)s and {active} "
                " group by frontend order by frontend"
            ).format(active=_active("metric_frontend")),
            {"cluster": cluster, "since": since, "until": until, "newest_poll": NEWEST_POLL},
        )
        return [(row[0], bool(row[1])) for row in cursor.fetchall()]


def read_cluster_backends(
    connection: Connection[Any],
    *,
    cluster: str,
    since: datetime,
    until: datetime,
    kind: str = "haproxy",
) -> list[str]:
    """Which backends this cluster serves now, by the runtime's own names.

    The newest poll's (`_active`): a pool renamed or removed is not listed,
    though its history is kept until retention takes it.

    `BACKEND` only - HAProxy's aggregate row for each backend, which is what the
    comparison is between. A per-server breakdown is a different question and
    belongs on the backend it is asked about, not on a page comparing backends.

    `kind` is `haproxy` for HAProxy's backends, `dns` for dnsdist's pools or
    `syslog` for IPVS's: told apart by the counters on the pool's own row
    (0057, 0061), since each counts something different.
    """

    which = POOL_KINDS[kind]

    with connection.cursor() as cursor:
        cursor.execute(
            sql.SQL(
                "select distinct backend from metric_backend_member "
                " where cluster = %(cluster)s and member = 'BACKEND' "
                "   and {which} "
                "   and observed_at >= %(since)s and observed_at <= %(until)s and {active} "
                " order by backend"
            ).format(active=_active("metric_backend_member"), which=which),
            {"cluster": cluster, "since": since, "until": until, "newest_poll": NEWEST_POLL},
        )
        return [row[0] for row in cursor.fetchall()]


#
# Which pools a kind is, by the counter only its pool's own row carries.
#
POOL_KINDS = {
    "haproxy": sql.SQL("dns_queries is null and syslog_messages is null"),
    "dns": sql.SQL("dns_queries is not null"),
    "syslog": sql.SQL("syslog_messages is not null"),
}

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
#
# A backend row's differences add dnsdist's (migration 0057) and IPVS's (0061);
# a frontend's do not.
#
BACKEND_DELTAS = (*STORED_DELTAS, *metrics.DNS_COUNTERS, *metrics.SYSLOG_COUNTERS)


def _deltas(table: str) -> tuple[str, ...]:
    """The differences a metrics table stores: a backend's include dnsdist's and IPVS's."""

    return BACKEND_DELTAS if table.startswith("metric_backend") else STORED_DELTAS


def _interval_aggregates(names: Sequence[str], *, by_cluster: bool = False) -> sql.Composed:
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
        "select {cluster}count(*)::bigint, min(started_at), max(ended_at), "
        "       coalesce(bool_or(restarted), false), "
        "       coalesce(bool_or(handed_over), false), "
        "       coalesce(sum(span_sec) filter (where not restarted and not handed_over), 0), "
        "       coalesce(sum(span_sec), 0), {per_counter} "
    ).format(per_counter=per_counter, cluster=sql.SQL("cluster, " if by_cluster else ""))


def _stored_intervals(names: Sequence[str]) -> sql.Composed:
    """The interval columns of a raw row, read from what migration 0048 stored."""

    return sql.SQL(
        "previous_at as started_at, observed_at as ended_at, restarted, "
        "false as handed_over, extract(epoch from observed_at - previous_at) as span_sec, {deltas}"
    ).format(deltas=sql.SQL(", ").join(sql.Identifier(f"delta_{name}") for name in names))


def _backend_totals(
    counters: tuple[tuple[str, str], ...] = metrics.CARD_COUNTERS,
) -> sql.Composed:
    """One backend's figures over raw samples, summed from the stored differences.

    Each raw sample carries what every counter did since the series' previous
    sample on that node, decided when it was written (migration 0048). An
    interval belongs to the range when it starts inside it, so the first
    sample in the range - which has nothing in the range to pair with - adds
    nothing. Windows longer than a day are read from the hourly sums instead
    (`_hour_totals`), which hold the same differences.
    """

    names = [name for name, _label in counters]
    return sql.SQL(
        "with intervals as ("
        "    select {stored} "
        "      from metric_backend_member "
        "     where {scope} "
        "       and observed_at >= %(since)s and observed_at <= %(until)s "
        "       and previous_at >= %(since)s"
        ") "
        "{aggregates} from intervals"
    ).format(
        stored=_stored_intervals(names),
        aggregates=_interval_aggregates(names),
        scope=BACKEND_SCOPE,
    )


#
# Windows longer than this are read from the hourly sums (migration 0055) when
# their buckets are whole hours. A day and shorter keep reading the raw rows:
# their buckets are minutes, and the rows are few.
#
HOURLY_FROM = timedelta(days=1)
HOUR = timedelta(hours=1)


def _reads_hours(since: datetime, until: datetime, width: timedelta | None = None) -> bool:
    if until - since <= HOURLY_FROM:
        return False
    return width is None or (width >= HOUR and width % HOUR == timedelta(0))


def _hour_pieces(
    hours: str, raw: str, scope: sql.Composable, raw_scope: sql.Composable
) -> sql.Composed:
    """A range's samples as hour rows where whole, and as raw rows where not.

    An hour row (migration 0055) counts whole when every sample in it lies in
    the range: its earliest pair at or after the start and its latest sample at
    or before the end. A crossing row is one sample, so that test is exact for
    it either way. An ordinary row that is not whole - the hour the range
    starts or ends in - is read from the raw rows of that hour and node instead,
    with the raw readers' own filters, which is at most two hours a node.

    Every piece has the hour table's columns, so the series and the figures
    aggregate pieces exactly as they would aggregate samples.

    An edge row is read back from the raw rows of its own series. A card that
    reads a renamed backend's earlier names too (`metric_backend_alias`) has
    several series in one hour on one node, and an edge matched by node alone
    would read each of their raw rows once per series.
    """

    key = sql.Identifier("backend" if hours == "metric_backend_hour_delta" else "frontend")
    names = _deltas(hours)

    deltas = sql.SQL(", ").join(
        sql.SQL("{delta}, {span}").format(
            delta=sql.Identifier(f"delta_{name}"), span=sql.Identifier(f"span_{name}_sec")
        )
        for name in names
    )
    return sql.SQL(
        "with hours as ("
        "    select node, hour as at, crossing, first_previous_at, last_observed_at, restarted, "
        "           samples, span_sec, span_clean_sec, {deltas}, {key} as series "
        "      from {hours} "
        "     where {scope} and hour >= date_trunc('hour', %(after)s::timestamptz, 'UTC') "
        "       and hour <= %(until)s"
        "), pieces as ("
        "    select * from hours "
        "     where first_previous_at >= %(after)s and last_observed_at <= %(until)s"
        "    union all "
        "    select edge.node, part.observed_at, false, part.previous_at, part.observed_at, "
        "           part.restarted, 1, extract(epoch from part.observed_at - part.previous_at), "
        "           case when part.restarted then 0 "
        "                else extract(epoch from part.observed_at - part.previous_at) end, "
        "           {raw_deltas_part}, edge.series "
        "      from hours as edge "
        "      cross join lateral ("
        "          select observed_at, previous_at, restarted, {raw_deltas} "
        "            from {raw} "
        "           where {raw_scope} and node = edge.node and {key} = edge.series "
        "             and observed_at >= edge.at and observed_at < edge.at + interval '1 hour' "
        "             and previous_at >= edge.at and previous_at >= %(after)s "
        "             and observed_at > %(after)s and observed_at <= %(until)s"
        "      ) as part "
        "     where not edge.crossing "
        "       and not (edge.first_previous_at >= %(after)s and edge.last_observed_at <= %(until)s)"
        ") "
    ).format(
        deltas=deltas,
        key=key,
        hours=sql.Identifier(hours),
        raw=sql.Identifier(raw),
        scope=scope,
        raw_scope=raw_scope,
        raw_deltas=sql.SQL(", ").join(
            sql.SQL("{delta}, {raw_span} as {span}").format(
                delta=sql.Identifier(f"delta_{name}"),
                raw_span=sql.SQL(
                    "case when {delta} is not null and not restarted "
                    "then extract(epoch from observed_at - previous_at) else 0 end"
                ).format(delta=sql.Identifier(f"delta_{name}")),
                span=sql.Identifier(f"span_{name}_sec"),
            )
            for name in names
        ),
        raw_deltas_part=sql.SQL(", ").join(
            sql.SQL("part.{delta}, part.{span}").format(
                delta=sql.Identifier(f"delta_{name}"), span=sql.Identifier(f"span_{name}_sec")
            )
            for name in names
        ),
    )


def _hour_series(
    hours: str, raw: str, scope: sql.Composable, raw_scope: sql.Composable
) -> sql.Composed:
    """`_bucketed_changes` over hour pieces: the same groups, the same columns.

    A raw sample is grouped by node, bucket and whether its pair lies in an
    earlier bucket. Every bucket here is whole hours, so a piece's hour is in
    the bucket its samples are in, and only a crossing piece - one sample - can
    have its pair before the bucket.
    """

    bucket = sql.SQL("date_bin(%(width)s, at, {epoch})").format(epoch=BUCKET_EPOCH_SQL)
    sums = sql.SQL(", ").join(
        sql.SQL("sum({delta})::bigint").format(delta=sql.Identifier(f"delta_{name}"))
        for name in _deltas(hours)
    )
    return sql.SQL(
        "{pieces}"
        "select min(first_previous_at), max(last_observed_at), "
        "       coalesce(bool_or(restarted), false), {sums} "
        "  from pieces "
        " group by node, {bucket}, crossing and first_previous_at < {bucket} "
        " order by {bucket}, node"
    ).format(pieces=_hour_pieces(hours, raw, scope, raw_scope), sums=sums, bucket=bucket)


def _hour_totals(
    hours: str,
    raw: str,
    scope: sql.Composable,
    raw_scope: sql.Composable,
    counters: tuple[tuple[str, str], ...] = metrics.CARD_COUNTERS,
) -> sql.Composed:
    """`_interval_aggregates` over hour pieces: the columns `_measurement` reads."""

    per_counter = sql.SQL(", ").join(
        sql.SQL("coalesce(sum({delta}), 0)::bigint, coalesce(sum({span}), 0)").format(
            delta=sql.Identifier(f"delta_{name}"), span=sql.Identifier(f"span_{name}_sec")
        )
        for name, _label in counters
    )
    return sql.SQL(
        "{pieces}"
        "select coalesce(sum(samples), 0)::bigint, min(first_previous_at), max(last_observed_at), "
        "       coalesce(bool_or(restarted), false), false, "
        "       coalesce(sum(span_clean_sec), 0), coalesce(sum(span_sec), 0), {per_counter} "
        "  from pieces"
    ).format(pieces=_hour_pieces(hours, raw, scope, raw_scope), per_counter=per_counter)


FRONTEND_SCOPE = sql.SQL("cluster = %(cluster)s and frontend = %(frontend)s")
# A frontend's raw rows count only where the node held the address (0048).
FRONTEND_HELD = sql.SQL("cluster = %(cluster)s and frontend = %(frontend)s and owns_vip")
#
# A backend and its earlier names (`metric_backend_alias`): each name in
# `%(backends)s` counts only before its own cutoff in `%(cutoffs)s` - null for
# the current name and for one nobody has taken again. An hour row counts only
# when the whole hour lies before the cutoff, so a name taken again within the
# hour is never drawn into the card that renamed it.
#
_HISTORY = (
    "cluster = %(cluster)s and member = %(member)s and exists ("
    "    select 1 from unnest(%(backends)s::text[], %(cutoffs)s::timestamptz[]) as h(name, cutoff)"
    "     where h.name = backend and {before} coalesce(h.cutoff, 'infinity'))"
)
BACKEND_SCOPE = sql.SQL(_HISTORY.format(before="observed_at <"))
BACKEND_HOUR_SCOPE = sql.SQL(_HISTORY.format(before="hour + interval '1 hour' <="))


def _frontend_totals(
    counters: tuple[tuple[str, str], ...] = metrics.CARD_COUNTERS,
    *,
    every_frontend: bool = False,
    by_cluster: bool = False,
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
        "    select {cluster}{stored} "
        "      from metric_frontend "
        "     where {scope} "
        "       and owns_vip and observed_at >= %(since)s and observed_at <= %(until)s "
        "       and previous_at >= %(since)s"
        ") "
        "{aggregates} from intervals{grouping}"
    ).format(
        stored=_stored_intervals(names),
        aggregates=_interval_aggregates(names, by_cluster=by_cluster),
        cluster=sql.SQL("cluster, " if by_cluster else ""),
        grouping=sql.SQL(" group by cluster" if by_cluster else ""),
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
    """One VIP frontend's figures at stored resolution, apart from its graph.

    A range longer than a day is summed from the hourly sums (0055), with the
    hours at its edges read raw; the figures are the raw rows' to the digit.
    """

    arguments = {"cluster": cluster, "frontend": frontend, "since": since, "until": until}
    with connection.cursor() as cursor:
        if _reads_hours(since, until):
            cursor.execute(
                _hour_totals(
                    "metric_frontend_hour_delta", "metric_frontend", FRONTEND_SCOPE, FRONTEND_HELD
                ),
                {**arguments, "after": since},
            )
        else:
            cursor.execute(_frontend_totals(), arguments)
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


def read_traffic_summaries(
    connection: Connection[Any],
    *,
    clusters: Sequence[str],
    since: datetime,
    until: datetime,
) -> dict[str, metrics.BackendMeasurement]:
    """One aggregate per selected cluster, including clusters without readings."""

    empty = _measurement(
        (
            0,
            None,
            None,
            False,
            False,
            0,
            0,
            *(0 for _ in metrics.SUMMARY_COUNTERS for _ in range(2)),
        ),
        metrics.SUMMARY_COUNTERS,
    )
    result = dict.fromkeys(clusters, empty)
    if not clusters:
        return result
    with connection.cursor() as cursor:
        cursor.execute(
            _frontend_totals(metrics.SUMMARY_COUNTERS, every_frontend=True, by_cluster=True),
            {"clusters": list(clusters), "since": since, "until": until},
        )
        for row in cursor.fetchall():
            result[row[0]] = _measurement(row[1:], metrics.SUMMARY_COUNTERS)
    return result


def read_response_times_by_cluster(
    connection: Connection[Any],
    *,
    clusters: Sequence[str],
    since: datetime,
    until: datetime,
) -> dict[str, tuple[int, int | None, int | None]]:
    """Exact percentiles per cluster; unanswered requests remain excluded."""

    result: dict[str, tuple[int, int | None, int | None]] = dict.fromkeys(clusters, (0, None, None))
    if not clusters:
        return result
    with connection.cursor() as cursor:
        cursor.execute(
            "select cluster, count(*), "
            "       percentile_disc(0.5) within group (order by response_time), "
            "       percentile_disc(0.95) within group (order by response_time) "
            "  from traffic_log "
            " where cluster = any(%(clusters)s) and response_time >= 0 "
            "   and occurred_at >= %(since)s and occurred_at <= %(until)s "
            " group by cluster",
            {"clusters": list(clusters), "since": since, "until": until},
        )
        for row in cursor.fetchall():
            result[row[0]] = int(row[1]), int(row[2]), int(row[3])
    return result


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
    earlier: Sequence[EarlierName] = (),
    counters: tuple[tuple[str, str], ...] = metrics.CARD_COUNTERS,
) -> metrics.BackendMeasurement:
    """One backend's figures at stored resolution, independent of its graph.

    Read like the frontend's: the hourly sums for a range longer than a day,
    the raw rows otherwise. `counters` names the figures: HAProxy's card's by
    default, a dns pool's (`metrics.DNS_SUMMED`) for one.
    """

    arguments = {
        "cluster": cluster,
        "member": member,
        "since": since,
        "until": until,
        "after": since,
        **_history(backend, earlier),
    }
    with connection.cursor() as cursor:
        if _reads_hours(since, until):
            cursor.execute(
                _hour_totals(
                    "metric_backend_hour_delta",
                    "metric_backend_member",
                    BACKEND_HOUR_SCOPE,
                    BACKEND_SCOPE,
                    counters,
                ),
                arguments,
            )
        else:
            cursor.execute(_backend_totals(counters), arguments)
        row = cursor.fetchone()

    if row is None:
        raise RuntimeError("the backend totals aggregate returned no row")
    return _measurement(row, counters)


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
    "username_claim, groups_claim, admin_group, reader_group, button_text, "
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
    issuer: str,
    subject: str,
) -> bool:
    """A provider's account, made at its first sign-in: no password, bound to the
    identity that signed in (B297). False when the name or the identity is taken."""

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
    """What the engine matched since then, per cluster, object, rule and field.

    Read from the counts kept as the matches arrive (0054), not from the
    matches themselves: an attack's hundred thousand rows are a few rows here.
    The window starts on the hour `since` falls in, which is how they are kept.
    """

    with connection.cursor(row_factory=class_row(WafFinding)) as cursor:
        cursor.execute(
            "with paths as ("
            "  select cluster, object, rule_id, field, "
            "         sum(requests)::int as requests, "
            "         max(last_seen) as last_seen, "
            "         (array_agg(matched order by last_seen desc))[1] as matched, "
            "         (array_agg(distinct path order by path))[1:%(paths)s] as paths, "
            "         count(distinct path)::int as path_count "
            "    from waf_finding_path "
            "   where cluster = any(%(clusters)s) and hour >= date_trunc('hour', %(since)s, 'UTC') "
            "     and (rule_id >= %(first)s or rule_id / 1000 = %(engine)s) "
            "   group by cluster, object, rule_id, field"
            "), clients as ("
            "  select cluster, object, rule_id, field, "
            "         count(distinct nullif(client, ''))::int as clients "
            "    from waf_finding_client "
            "   where cluster = any(%(clusters)s) and hour >= date_trunc('hour', %(since)s, 'UTC') "
            "     and (rule_id >= %(first)s or rule_id / 1000 = %(engine)s) "
            "   group by cluster, object, rule_id, field"
            ") "
            "select paths.cluster, paths.object, paths.rule_id, paths.field, paths.requests, "
            "       coalesce(clients.clients, 0) as clients, paths.last_seen, paths.matched, "
            "       paths.paths, paths.path_count "
            "  from paths left join clients using (cluster, object, rule_id, field) "
            " order by paths.cluster, paths.object, paths.last_seen desc "
            " limit %(limit)s",
            {
                "clusters": list(clusters),
                "since": since,
                "paths": WAF_FINDING_PATHS,
                "limit": WAF_FINDING_LIMIT,
                "first": WAF_RULE_FIRST,
                "engine": crs.ENGINE_RULE_FILE,
            },
        )
        return cursor.fetchall()


#
# The rule set's IDs start here; below are the exceptions' counters (B273),
# which count what was let through and are no finding, and the installation's
# own rules (crs.ENGINE_RULES, 1900xx), which are.
#
WAF_RULE_FIRST = 900000


@dataclass(frozen=True, slots=True)
class CounterScope:
    """What one exception covers, as its counter is read (review 26-10-11).

    Its counter's number is its place among the object's exceptions on the
    same rule, so a number can pass to another exception when one is removed;
    reading only within what this one covers - its field where it names one,
    its paths where it names any - keeps another's matches off its row.
    """

    cluster: str
    object: str
    counter: int
    field: str
    paths: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class WafCounted:
    """What one exception's counter counted within what it covers (B273)."""

    requests: int
    clients: int
    last_seen: datetime | None


def _counted_paths(paths: Sequence[str]) -> list[str]:
    """The paths as the collector stores them: the root also as `//`, which the counter counts."""

    return sorted({*paths, *(("//",) if "/" in paths else ())})


def waf_counted(
    connection: Connection[Any], *, scopes: Sequence[CounterScope], since: datetime
) -> dict[CounterScope, WafCounted]:
    """What each exception's counter counted since then, within what the exception covers.

    A path is compared as the collector stored it, the request's own path; one
    the engine reached through normalising (`/a/./b`, an encoded letter) is
    counted by the counter and left out here.
    """

    if not scopes:
        return {}
    listed = [
        {
            "id": index,
            "cluster": scope.cluster,
            "object": scope.object,
            "counter": scope.counter,
            "field": scope.field,
            "paths": _counted_paths(scope.paths),
        }
        for index, scope in enumerate(scopes)
    ]
    with connection.cursor() as cursor:
        cursor.execute(
            "with scope as ("
            "  select * from jsonb_to_recordset(%(scopes)s) "
            "    as s (id int, cluster text, object text, counter int, field text, paths text[])"
            ") "
            "select scope.id, "
            "  (select coalesce(sum(p.requests), 0)::int from waf_finding_path p "
            "    where p.cluster = scope.cluster and p.object = scope.object "
            "      and p.rule_id = scope.counter and p.hour >= date_trunc('hour', %(since)s, 'UTC') "
            "      and (scope.field = '' or p.field = scope.field) "
            "      and (cardinality(scope.paths) = 0 or p.path = any(scope.paths))), "
            "  (select count(distinct nullif(c.client, ''))::int from waf_finding_client c "
            "    where c.cluster = scope.cluster and c.object = scope.object "
            "      and c.rule_id = scope.counter and c.hour >= date_trunc('hour', %(since)s, 'UTC') "
            "      and (scope.field = '' or c.field = scope.field) "
            "      and (cardinality(scope.paths) = 0 or c.path = any(scope.paths))), "
            "  (select max(p.last_seen) from waf_finding_path p "
            "    where p.cluster = scope.cluster and p.object = scope.object "
            "      and p.rule_id = scope.counter and p.hour >= date_trunc('hour', %(since)s, 'UTC') "
            "      and (scope.field = '' or p.field = scope.field) "
            "      and (cardinality(scope.paths) = 0 or p.path = any(scope.paths))) "
            "  from scope",
            {"scopes": Jsonb(listed), "since": since},
        )
        rows = cursor.fetchall()
    return {
        scopes[index]: WafCounted(requests=requests, clients=clients, last_seen=last_seen)
        for index, requests, clients, last_seen in rows
    }


def deploys_carrying(
    connection: Connection[Any], *, cluster: str, moments: Sequence[datetime]
) -> dict[datetime, datetime]:
    """For each moment something was saved, when a deploy carrying it finished.

    The moment is when an exception was saved, which is not when it was
    published: a deploy in between rolls out the version before it (review
    26-10-11). So first the publish that took it - the first `changes_publish`
    created after the moment, which publishes everything saved for the cluster
    - and then the first deploy created after that publish finished, or that
    publish itself where it deployed (*Publish & deploy*, B257). A publish is
    one whose job was done or whose publish half was, as in `change_publishes`
    (review 26-10-13, D1). A deploy is `done` only,
    which is a deploy whose every node took the release and reloaded the WAF
    engine. A moment no such deploy has followed yet is left out, as is one
    published outside the job queue: unknown is not *Not working*.
    """

    if not moments:
        return {}
    with connection.cursor() as cursor:
        cursor.execute(
            "select moment, ("
            "  select min(deployed.finished_at) from job deployed "
            "   where deployed.cluster = %(cluster)s and deployed.state = 'done' "
            "     and ((deployed.operation = 'deploy' and deployed.created_at >= published.at) "
            "          or (deployed.operation = 'changes_publish' "
            "              and deployed.payload->>'deploy' = 'true' "
            "              and deployed.created_at >= moment "
            "              and deployed.finished_at >= published.at))"
            ") from unnest(%(moments)s::timestamptz[]) as asked(moment) "
            "cross join lateral ("
            "  select min(finished_at) as at from job "
            "   where cluster = %(cluster)s "
            "     and (state = 'done' or result->'publish'->>'outcome' = 'done') "
            "     and operation = 'changes_publish' and created_at >= moment"
            ") published",
            {"cluster": cluster, "moments": list(moments)},
        )
        return {moment: done for moment, done in cursor.fetchall() if done is not None}


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
