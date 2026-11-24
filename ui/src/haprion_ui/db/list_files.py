"""What the poller last read of the files root keeps for the lists (0125, B534, PW02)."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from psycopg import Connection
from psycopg.rows import class_row


@dataclass(frozen=True)
class ListFile:
    """One file as the reading gave it: its revision and a digest of what it says.

    Revision 0 with no digest is a file that cannot be read. A path list file
    the database had no row for also carries its description and paths.
    """

    kind: str
    name: str
    revision: int
    digest: str
    description: str | None
    paths: list[str] | None
    seen_at: datetime


def list_files(connection: Connection[Any], kind: str) -> list[ListFile]:
    with connection.cursor(row_factory=class_row(ListFile)) as cursor:
        cursor.execute(
            "select kind, name, revision, digest, description, paths, seen_at "
            "  from list_file where kind = %(kind)s order by name",
            {"kind": kind},
        )
        return cursor.fetchall()


def list_files_read_at(connection: Connection[Any]) -> datetime | None:
    """When the poller last read the files, or None before it has (review 26-11-24, PW02)."""

    with connection.cursor() as cursor:
        cursor.execute("select read_at from list_file_read")
        row = cursor.fetchone()
    return None if row is None else row[0]


def record_list_files(
    connection: Connection[Any], files: Iterable[ListFile], *, read_at: datetime
) -> None:
    """The poller's write: the reading's files, whole; a file no longer there is removed.

    The time of the reading is written with them, so an empty reading is known
    to have been made (review 26-11-24, PW02).
    """

    rows = list(files)
    with connection.cursor() as cursor:
        cursor.execute(
            "insert into list_file_read (only_row, read_at) values (true, %(at)s) "
            "on conflict (only_row) do update set read_at = excluded.read_at",
            {"at": read_at},
        )
        cursor.execute(
            "delete from list_file where not (kind || '/' || name = any(%(keys)s))",
            {"keys": [f"{row.kind}/{row.name}" for row in rows]},
        )
        for row in rows:
            cursor.execute(
                "insert into list_file (kind, name, revision, digest, description, paths, seen_at) "
                "values (%(kind)s, %(name)s, %(revision)s, %(digest)s, %(description)s, "
                "        %(paths)s, %(seen_at)s) "
                "on conflict (kind, name) do update set revision = excluded.revision, "
                "       digest = excluded.digest, description = excluded.description, "
                "       paths = excluded.paths, seen_at = excluded.seen_at",
                {
                    "kind": row.kind,
                    "name": row.name,
                    "revision": row.revision,
                    "digest": row.digest,
                    "description": row.description,
                    "paths": row.paths,
                    "seen_at": row.seen_at,
                },
            )
