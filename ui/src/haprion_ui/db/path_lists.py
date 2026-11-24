"""The path lists Settings keeps for *Denied paths* (0125, B527, B532)."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from psycopg import Connection
from psycopg.rows import class_row


class PathListChanged(Exception):
    """The row is not at the revision the caller saw: another save came first."""


@dataclass(frozen=True)
class PathList:
    name: str
    description: str
    paths: list[str]
    revision: int
    created_at: datetime
    updated_at: datetime
    updated_by: str


@dataclass(frozen=True)
class AppliedPathList:
    """The worker's read: what the apply helper is sent."""

    name: str
    description: str
    paths: list[str]
    revision: int


def path_lists(connection: Connection[Any]) -> list[PathList]:
    with connection.cursor(row_factory=class_row(PathList)) as cursor:
        cursor.execute(
            "select name, description, paths, revision, created_at, updated_at, updated_by "
            "  from path_list order by name"
        )
        return cursor.fetchall()


def path_list(connection: Connection[Any], name: str) -> PathList | None:
    with connection.cursor(row_factory=class_row(PathList)) as cursor:
        cursor.execute(
            "select name, description, paths, revision, created_at, updated_at, updated_by "
            "  from path_list where name = %(name)s",
            {"name": name},
        )
        return cursor.fetchone()


def save_path_list(
    connection: Connection[Any],
    *,
    name: str,
    previous: int | None,
    description: str,
    paths: Sequence[str],
    actor: str,
) -> PathList:
    """Insert a new list (`previous` None) or the next revision of one, fenced on `previous`."""

    values = {
        "name": name,
        "description": description,
        "paths": list(paths),
        "actor": actor,
        "previous": previous,
    }
    with connection.cursor(row_factory=class_row(PathList)) as cursor:
        if previous is None:
            cursor.execute(
                "insert into path_list (name, description, paths, revision, updated_by) "
                "values (%(name)s, %(description)s, %(paths)s, 1, %(actor)s) "
                "on conflict (name) do nothing "
                "returning name, description, paths, revision, created_at, updated_at, updated_by",
                values,
            )
        else:
            cursor.execute(
                "update path_list set description = %(description)s, paths = %(paths)s, "
                "       revision = revision + 1, updated_at = statement_timestamp(), "
                "       updated_by = %(actor)s "
                " where name = %(name)s and revision = %(previous)s "
                "returning name, description, paths, revision, created_at, updated_at, updated_by",
                values,
            )
        row = cursor.fetchone()
    if row is None:
        raise PathListChanged(name)
    return row


def take_in_path_list(
    connection: Connection[Any],
    *,
    name: str,
    description: str,
    paths: Sequence[str],
    revision: int,
    actor: str,
) -> PathList:
    """Insert the row a file on the manager has no row for, at the file's own revision."""

    with connection.cursor(row_factory=class_row(PathList)) as cursor:
        cursor.execute(
            "insert into path_list (name, description, paths, revision, updated_by) "
            "values (%(name)s, %(description)s, %(paths)s, %(revision)s, %(actor)s) "
            "on conflict (name) do nothing "
            "returning name, description, paths, revision, created_at, updated_at, updated_by",
            {
                "name": name,
                "description": description,
                "paths": list(paths),
                "revision": revision,
                "actor": actor,
            },
        )
        row = cursor.fetchone()
    if row is None:
        raise PathListChanged(name)
    return row


def applied_path_list(connection: Connection[Any], name: str) -> AppliedPathList | None:
    """The worker's read, under its own grant."""

    with connection.cursor(row_factory=class_row(AppliedPathList)) as cursor:
        cursor.execute(
            "select name, description, paths, revision from path_list where name = %(name)s",
            {"name": name},
        )
        return cursor.fetchone()


def delete_path_list(connection: Connection[Any], name: str, revision: int) -> bool:
    """Delete exactly the row whose list the helper removed."""

    with connection.cursor() as cursor:
        cursor.execute(
            "delete from path_list where name = %(name)s and revision = %(revision)s",
            {"name": name, "revision": revision},
        )
        return cursor.rowcount == 1
