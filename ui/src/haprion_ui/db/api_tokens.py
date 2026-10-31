"""API tokens (0107, 0108, B416): made, listed, used, extended, revoked and removed."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import psycopg
from psycopg import Connection
from psycopg.rows import class_row


@dataclass(frozen=True, slots=True)
class ApiToken:
    """One token as the table keeps it; the secret is not here, only its hash."""

    id: int
    name: str
    level: str
    clusters: list[str]
    objects: list[str]
    sources: list[str]
    prefix: str
    created_at: datetime
    created_by: str
    valid_from: datetime
    expires_at: datetime
    revoked_at: datetime | None
    revoked_by: str | None
    last_used_at: datetime | None
    last_used_from: str | None


class TokenNameTaken(ValueError):
    """Another token has this name."""


class TokenRevoked(ValueError):
    """The token is revoked, and a revoked token is not extended."""


class TokenInUse(ValueError):
    """The token is neither revoked nor expired, so it is not removed."""


#
# `sources` and `last_used_from` as text: the reader compares them with
# `ipaddress`, and a psycopg network type there would be a second shape of
# the same value.
#
_API_COLUMNS = (
    " id, name, level, clusters, objects, sources::text[] as sources, prefix, created_at, "
    " created_by, valid_from, expires_at, revoked_at, revoked_by, last_used_at, "
    " host(last_used_from) as last_used_from "
)
_API_SELECT = "select" + _API_COLUMNS + "from api_token"


def api_token_by_hash(connection: Connection[Any], token_hash: bytes) -> ApiToken | None:
    """The token with this hash, revoked and expired ones included: the caller judges."""

    with connection.cursor(row_factory=class_row(ApiToken)) as cursor:
        cursor.execute(
            _API_SELECT + " where token_hash = %(token_hash)s",
            {"token_hash": token_hash},
        )
        return cursor.fetchone()


def api_tokens(connection: Connection[Any]) -> list[ApiToken]:
    """Every token, by name."""

    with connection.cursor(row_factory=class_row(ApiToken)) as cursor:
        cursor.execute(_API_SELECT + " order by name")
        return cursor.fetchall()


def create_api_token(
    connection: Connection[Any],
    *,
    name: str,
    level: str,
    clusters: Sequence[str],
    objects: Sequence[str],
    sources: Sequence[str],
    token_hash: bytes,
    prefix: str,
    created_by: str,
    days: int,
) -> ApiToken:
    """Store a new token, valid for `days` from the database's own clock.

    The expiry is computed in the statement, from the same moment the row's
    `created_at` takes, so the table's two-year limit is met to the second.
    """

    try:
        with connection.cursor(row_factory=class_row(ApiToken)) as cursor:
            cursor.execute(
                "insert into api_token (name, level, clusters, objects, sources, token_hash, "
                "                       prefix, created_by, expires_at) "
                "values (%(name)s, %(level)s, %(clusters)s, %(objects)s, %(sources)s::cidr[], "
                "        %(token_hash)s, %(prefix)s, %(created_by)s, "
                "        statement_timestamp() + make_interval(days => %(days)s)) "
                "returning" + _API_COLUMNS,
                {
                    "name": name,
                    "level": level,
                    "clusters": list(clusters),
                    "objects": list(objects),
                    "sources": list(sources),
                    "token_hash": token_hash,
                    "prefix": prefix,
                    "created_by": created_by,
                    "days": days,
                },
            )
            row = cursor.fetchone()
    except psycopg.errors.UniqueViolation as exc:
        if exc.diag.constraint_name == "api_token_name_unique":
            raise TokenNameTaken(name) from exc
        raise
    if row is None:
        raise RuntimeError("the insert returned no row")
    return row


def touch_api_token(connection: Connection[Any], token_id: int, source: str) -> None:
    """Note a use, at most once a minute, so a busy caller is not a write per call."""

    with connection.cursor() as cursor:
        cursor.execute(
            "update api_token set last_used_at = statement_timestamp(), "
            "                     last_used_from = %(source)s::inet "
            " where id = %(id)s "
            "   and (last_used_at is null "
            "        or last_used_at < statement_timestamp() - interval '1 minute')",
            {"id": token_id, "source": source},
        )


def revoke_api_token(connection: Connection[Any], name: str, *, by: str) -> bool:
    """Revoke a token. False when there is none by that name or it is already revoked."""

    with connection.cursor() as cursor:
        cursor.execute(
            "update api_token set revoked_at = statement_timestamp(), revoked_by = %(by)s "
            " where name = %(name)s and revoked_at is null",
            {"name": name, "by": by},
        )
        return cursor.rowcount == 1


def extend_api_token(connection: Connection[Any], name: str, *, days: int) -> ApiToken | None:
    """Give a token a new end date, `days` from the database's own clock.

    The secret is the same. The table moves `valid_from` to this moment, so
    the two-year limit counts from the extension; a revoked token is refused
    by the table itself (`TokenRevoked`). None when there is no such token.
    """

    try:
        with connection.cursor(row_factory=class_row(ApiToken)) as cursor:
            cursor.execute(
                "update api_token "  # noqa: S608 - constant
                "   set expires_at = statement_timestamp() + make_interval(days => %(days)s) "
                " where name = %(name)s "
                "returning" + _API_COLUMNS,
                {"name": name, "days": days},
            )
            return cursor.fetchone()
    except psycopg.errors.CheckViolation as exc:
        if "revoked" in (exc.diag.message_primary or ""):
            raise TokenRevoked(name) from exc
        raise


def delete_api_token(connection: Connection[Any], name: str) -> bool:
    """Remove a revoked or expired token. False when there is none by that name.

    One still in use is refused by the table itself (`TokenInUse`).
    """

    try:
        with connection.cursor() as cursor:
            cursor.execute("delete from api_token where name = %(name)s", {"name": name})
            return cursor.rowcount == 1
    except psycopg.errors.CheckViolation as exc:
        raise TokenInUse(name) from exc
