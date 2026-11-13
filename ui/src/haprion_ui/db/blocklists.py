"""The blocklists Settings defines, and what the refresh timer last did with them (0119, B500)."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from psycopg import Connection
from psycopg.rows import class_row


class BlocklistChanged(Exception):
    """The row is not at the revision the caller saw: another save came first."""


@dataclass(frozen=True)
class Blocklist:
    """A list as the web reads it; the box is not among the columns it may read."""

    name: str
    description: str
    url: str
    auth: str
    username: str
    every_hours: int
    excepts: list[str]
    key_id: str | None
    revision: int
    created_at: datetime
    updated_at: datetime
    updated_by: str


@dataclass(frozen=True)
class SealedBlocklist:
    """The worker's read: everything the apply helper is sent, the box with it."""

    name: str
    description: str
    url: str
    auth: str
    username: str
    every_hours: int
    excepts: list[str]
    key_id: str | None
    ciphertext: bytes | None
    revision: int
    secret_revision: int
    """The revision the box was last sealed at; `revision` is ahead of it when a save kept the box."""


@dataclass(frozen=True)
class BlocklistState:
    """What the refresh timer's last pass did with one list, as the poller read it."""

    name: str
    fetched_at: datetime | None
    attempted_at: datetime | None
    failed_at: datetime | None
    error: str
    entries: int
    skipped: int
    seen_at: datetime


def blocklists(connection: Connection[Any]) -> list[Blocklist]:
    with connection.cursor(row_factory=class_row(Blocklist)) as cursor:
        cursor.execute(
            "select name, description, url, auth, username, every_hours, excepts, key_id, revision, created_at, updated_at, updated_by from blocklist order by name"
        )
        return cursor.fetchall()


def blocklist(connection: Connection[Any], name: str) -> Blocklist | None:
    with connection.cursor(row_factory=class_row(Blocklist)) as cursor:
        cursor.execute(
            "select name, description, url, auth, username, every_hours, excepts, key_id, revision, created_at, updated_at, updated_by "
            "  from blocklist where name = %(name)s",
            {"name": name},
        )
        return cursor.fetchone()


def save_blocklist(
    connection: Connection[Any],
    *,
    name: str,
    previous: int | None,
    description: str,
    url: str,
    auth: str,
    username: str,
    every_hours: int,
    excepts: Sequence[str],
    key_id: str | None,
    ciphertext: bytes | None,
    keep_secret: bool,
    actor: str,
) -> Blocklist:
    """Insert a new list (`previous` None) or the next revision of one, fenced on `previous`.

    `keep_secret` leaves the stored box, and its `secret_revision`, as they
    are - a save that changed neither the source (the URL, the authorization
    and the username) nor the secret - and is refused when the source changed,
    which the form says before it gets here. A save that seals writes
    `secret_revision` with the revision it makes.
    """

    values = {
        "name": name,
        "description": description,
        "url": url,
        "auth": auth,
        "username": username,
        "every_hours": every_hours,
        "excepts": list(excepts),
        "key_id": key_id,
        "box": ciphertext,
        "actor": actor,
        "previous": previous,
    }
    with connection.cursor(row_factory=class_row(Blocklist)) as cursor:
        if previous is None:
            cursor.execute(
                "insert into blocklist (name, description, url, auth, username, every_hours, "
                "       excepts, key_id, ciphertext, revision, secret_revision, updated_by) "
                "values (%(name)s, %(description)s, %(url)s, %(auth)s, %(username)s, "
                "        %(every_hours)s, %(excepts)s, %(key_id)s, %(box)s, 1, 1, %(actor)s) "
                "on conflict (name) do nothing "
                "returning name, description, url, auth, username, every_hours, excepts, key_id, revision, created_at, updated_at, updated_by",
                values,
            )
        elif keep_secret:
            cursor.execute(
                "update blocklist "
                "   set description = %(description)s, url = %(url)s, auth = %(auth)s, "
                "       username = %(username)s, every_hours = %(every_hours)s, "
                "       excepts = %(excepts)s, revision = revision + 1, "
                "       updated_at = statement_timestamp(), updated_by = %(actor)s "
                " where name = %(name)s and revision = %(previous)s and auth = %(auth)s "
                "   and url = %(url)s and username = %(username)s "
                "returning name, description, url, auth, username, every_hours, excepts, key_id, revision, created_at, updated_at, updated_by",
                values,
            )
        else:
            cursor.execute(
                "update blocklist "
                "   set description = %(description)s, url = %(url)s, auth = %(auth)s, "
                "       username = %(username)s, every_hours = %(every_hours)s, "
                "       excepts = %(excepts)s, key_id = %(key_id)s, ciphertext = %(box)s, "
                "       revision = revision + 1, secret_revision = revision + 1, "
                "       updated_at = statement_timestamp(), updated_by = %(actor)s "
                " where name = %(name)s and revision = %(previous)s "
                "returning name, description, url, auth, username, every_hours, excepts, key_id, revision, created_at, updated_at, updated_by",
                values,
            )
        row = cursor.fetchone()
    if row is None:
        raise BlocklistChanged(name)
    return row


def sealed_blocklist(connection: Connection[Any], name: str) -> SealedBlocklist | None:
    """The worker's read, under its own grant."""

    with connection.cursor(row_factory=class_row(SealedBlocklist)) as cursor:
        cursor.execute(
            "select name, description, url, auth, username, every_hours, excepts, key_id, "
            "       ciphertext, revision, secret_revision from blocklist where name = %(name)s",
            {"name": name},
        )
        return cursor.fetchone()


def delete_blocklist(connection: Connection[Any], name: str, revision: int) -> bool:
    """Delete exactly the row whose definition the helper removed."""

    with connection.cursor() as cursor:
        cursor.execute(
            "delete from blocklist where name = %(name)s and revision = %(revision)s",
            {"name": name, "revision": revision},
        )
        return cursor.rowcount == 1


def blocklist_states(connection: Connection[Any]) -> list[BlocklistState]:
    with connection.cursor(row_factory=class_row(BlocklistState)) as cursor:
        cursor.execute(
            "select name, fetched_at, attempted_at, failed_at, error, entries, skipped, seen_at "
            "  from blocklist_state order by name"
        )
        return cursor.fetchall()


def record_blocklist_states(connection: Connection[Any], states: Iterable[BlocklistState]) -> None:
    """The poller's write: the state file's lists, whole; a list no longer in it is removed."""

    rows = list(states)
    with connection.cursor() as cursor:
        cursor.execute(
            "delete from blocklist_state where not (name = any(%(names)s))",
            {"names": [row.name for row in rows]},
        )
        for row in rows:
            cursor.execute(
                "insert into blocklist_state (name, fetched_at, attempted_at, failed_at, error, "
                "       entries, skipped, seen_at) "
                "values (%(name)s, %(fetched_at)s, %(attempted_at)s, %(failed_at)s, %(error)s, "
                "        %(entries)s, %(skipped)s, %(seen_at)s) "
                "on conflict (name) do update set fetched_at = excluded.fetched_at, "
                "       attempted_at = excluded.attempted_at, failed_at = excluded.failed_at, "
                "       error = excluded.error, entries = excluded.entries, "
                "       skipped = excluded.skipped, seen_at = excluded.seen_at",
                {
                    "name": row.name,
                    "fetched_at": row.fetched_at,
                    "attempted_at": row.attempted_at,
                    "failed_at": row.failed_at,
                    "error": row.error[:500],
                    "entries": row.entries,
                    "skipped": row.skipped,
                    "seen_at": row.seen_at,
                },
            )
