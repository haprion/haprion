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
from psycopg import Connection
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
            "       started_at, finished_at, exit_code, outcome, result, stderr_excerpt "
            "  from job "
            " where (%(cluster)s::text is null or cluster = %(cluster)s) "
            " order by created_at desc, id desc "
            " limit %(limit)s",
            {"cluster": cluster, "limit": limit},
        )
        return cursor.fetchall()


def queue_job(
    connection: Connection[Any], *, operation: str, cluster: str, payload: Mapping[str, Any]
) -> Job:
    """Ask for an operation. Say nothing about what happened.

    Three columns, which is exactly what the web role holds `insert` on. The
    state, the request ID and the creation time are not passed and could not be:
    they come from column defaults, so the row that comes back states what the
    database decided rather than what this process asked for.
    """

    with connection.cursor(row_factory=class_row(Job)) as cursor:
        cursor.execute(
            "insert into job (operation, cluster, payload) "
            "values (%(operation)s, %(cluster)s, %(payload)s) "
            "returning id, request_id, operation, cluster, payload, state, created_at, "
            "          started_at, finished_at, exit_code, outcome, result, stderr_excerpt",
            {
                "operation": operation,
                "cluster": cluster,
                "payload": Jsonb(payload),
            },
        )
        row = cursor.fetchone()
    if row is None:  # pragma: no cover - insert ... returning yields a row or raises
        raise psycopg.OperationalError("the insert returned no row")
    return row


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


def cluster_histories(connection: Connection[Any]) -> list[ClusterHistory]:
    """Every cluster's newest version listing, with the stalest one first."""

    with connection.cursor(row_factory=class_row(ClusterHistory)) as cursor:
        cursor.execute(
            "select cluster, observed_at, outcome, result, warnings, error, poll_error "
            "  from cluster_history "
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
