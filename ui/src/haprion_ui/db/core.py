"""The connection pool, the notifications between processes, and the locks."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import psycopg
from psycopg import Connection, sql
from psycopg_pool import ConnectionPool

from haprion_ui import timing
from haprion_ui.config import Database


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
