"""The DNS and NDES profiles, sealed."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

import psycopg
from psycopg import Connection
from psycopg.rows import class_row

from haprion_ui.db.core import savepoint


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
            savepoint(connection),
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
            savepoint(connection),
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
