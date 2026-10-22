"""Accounts, sign-in attempts and sessions."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

import psycopg
from psycopg import Connection
from psycopg.rows import class_row


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
