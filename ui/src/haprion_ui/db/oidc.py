"""The OIDC provider and signing in through it."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import psycopg
from psycopg import Connection
from psycopg.rows import class_row

from haprion_ui.db.accounts import Account


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
