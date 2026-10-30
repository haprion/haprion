"""Accounts, sign-in attempts and sessions."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

import psycopg
from psycopg import Connection
from psycopg.rows import class_row

from haprion_ui.db.core import savepoint


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


#
# The first of the two keys a sign-in's lock is taken with (review 26-10-29,
# A4). A name's `hashtext` is an int4, and taken alone it went into the
# one-key space the worker's and the poller's singleton locks hold: a name
# whose hash is one of their keys - chosen by whoever sends the form, before
# any check - waited out the web's statement timeout. PostgreSQL keeps the
# two-key locks apart from the one-key ones, so this space meets neither.
#
SIGN_IN_LOCKS = 1


def lock_sign_in(connection: Connection[Any], *, username: str) -> None:
    """Hold one name's sign-ins to one at a time until the caller's transaction ends (3-3).

    The count of failures and the row that adds to it are read and written
    under it, so attempts sent at once are counted one after another.
    """

    with connection.cursor() as cursor:
        cursor.execute(
            "select pg_advisory_xact_lock(%(space)s::integer,"
            " hashtext('haprion-sign-in:' || lower(%(username)s)))",
            {"space": SIGN_IN_LOCKS, "username": username},
        )


#
# The one rule for "locked", as a SQL expression over a name. The sign-in asks
# it for one source address; Settings -> Users asks it for no source at all,
# meaning any. Two budgets, and both are needed. A name and a source (an IPv6
# address is its /64: one host given a prefix has as many addresses as it
# likes, security review S02) reach `max_failures`; or the name from anywhere
# reaches `max_failures * factor` (B305). The window keeps an old mistake from
# counting forever; "since the last success" keeps a person who has proved they
# know the password from being locked out by their own earlier typos. An unlock
# (0039) counts as that success for every address: the failures stay in the
# record, and stop counting.
#
ACCOUNT_FAILURE_FACTOR = 10
_SOURCE_PREFIX = "case when family({ip}) = 6 then 64 else 32 end"


def _locked_sql(name: str) -> str:
    """The expression that is true while `name` (a SQL expression holding a
    normalised username) may not be tried; `%(source)s` is an address or NULL for any."""

    own = _SOURCE_PREFIX.format(ip="a.client_ip")
    asked = _SOURCE_PREFIX.format(ip="%(source)s::inet")
    return (
        "(exists ("  # noqa: S608 - `name` is a column expression in this file, never input
        "select 1 from login_attempt a "
        f" where a.username_normalised = {name} "
        "   and not a.succeeded "
        "   and a.at > statement_timestamp() - make_interval(mins => %(window)s) "
        f"   and (%(source)s::inet is null or a.client_ip <<= set_masklen(%(source)s::inet, {asked})) "
        "   and a.at > greatest( "
        "         coalesce((select max(b.at) from login_attempt b "
        f"                    where b.username_normalised = {name} and b.succeeded "
        f"                      and b.client_ip <<= set_masklen(a.client_ip, {own})), "
        "                  '-infinity'::timestamptz), "
        "         coalesce((select max(l.at) from login_unlock l "
        f"                    where l.username_normalised = {name}), "
        "                  '-infinity'::timestamptz)) "
        f" group by network(set_masklen(a.client_ip, {own})) "
        " having count(*) >= %(limit)s) "
        " or (select count(*) from login_attempt a "
        f"      where a.username_normalised = {name} and not a.succeeded "
        "         and a.at > statement_timestamp() - make_interval(mins => %(window)s) "
        "         and a.at > greatest( "
        "               coalesce((select max(b.at) from login_attempt b "
        f"                          where b.username_normalised = {name} and b.succeeded), "
        "                        '-infinity'::timestamptz), "
        "               coalesce((select max(l.at) from login_unlock l "
        f"                          where l.username_normalised = {name}), "
        "                        '-infinity'::timestamptz))) "
        "    >= %(limit)s * %(factor)s)"
    )


def login_locked(
    connection: Connection[Any],
    *,
    username: str,
    client_ip: str,
    window_minutes: int,
    max_failures: int,
) -> bool:
    """Whether `username` may not be tried from `client_ip` now: the sign-in's question."""

    with connection.cursor() as cursor:
        cursor.execute(
            "select " + _locked_sql("lower(%(username)s)"),
            {
                "username": username,
                "source": client_ip,
                "window": window_minutes,
                "limit": max_failures,
                "factor": ACCOUNT_FAILURE_FACTOR,
            },
        )
        row = cursor.fetchone()
    return bool(row[0]) if row is not None else False


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
# *Locked* is the sign-in's own rule (`_locked_sql`), asked with no source address.
#
_ACCOUNT_ROWS = (
    """
    select u.id, u.username, u.role, u.disabled, u.source, u.break_glass,
           (select count(*) from app_session s
             where s.user_id = u.id and s.revoked_at is null
               and s.expires_at > statement_timestamp()) as sessions,
           (select max(a.at) from login_attempt a
             where a.username_normalised = u.username_normalised and a.succeeded) as last_sign_in,
           """  # noqa: S608 - joins a constant expression
    + _locked_sql("u.username_normalised")
    + """ as locked
      from app_user u
"""
)


def account_rows(
    connection: Connection[Any], *, window_minutes: int, max_failures: int
) -> list[AccountRow]:
    """Every account, in the order a person reads names: alphabetical."""

    with connection.cursor(row_factory=class_row(AccountRow)) as cursor:
        cursor.execute(
            _ACCOUNT_ROWS + " order by u.username_normalised",
            {
                "window": window_minutes,
                "limit": max_failures,
                "factor": ACCOUNT_FAILURE_FACTOR,
                "source": None,
            },
        )
        return cursor.fetchall()


def account_row(
    connection: Connection[Any], username: str, *, window_minutes: int, max_failures: int
) -> AccountRow | None:
    with connection.cursor(row_factory=class_row(AccountRow)) as cursor:
        cursor.execute(
            _ACCOUNT_ROWS + " where u.username_normalised = lower(%(username)s)",
            {
                "window": window_minutes,
                "limit": max_failures,
                "factor": ACCOUNT_FAILURE_FACTOR,
                "source": None,
                "username": username,
            },
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
        with savepoint(connection), connection.cursor() as cursor:
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


def set_break_glass(
    connection: Connection[Any], *, user_id: int, break_glass: bool, keep: bytes = b""
) -> int:
    """Mark a local account as one that signs in with a password whatever else is on (B195).

    Taking the mark away while sign-in goes through the provider with
    break-glass accounts only leaves the account unable to sign in, so its
    live sessions end in the same transaction, as they do when the provider is
    turned off; how many is the answer. `keep` is the session of the admin who
    asked.
    """

    _guarded_update(
        connection,
        "update app_user set break_glass = %(break_glass)s where id = %(user_id)s",
        {"break_glass": break_glass, "user_id": user_id},
    )
    if break_glass:
        return 0
    return end_locked_out_sessions(connection, user_id=user_id, keep=keep)


def end_sessions_where(cursor: Any, condition: str, *, keep: bytes = b"", **params: Any) -> int:
    """End the live sessions of the accounts `condition` (over `u`, app_user) picks.

    The one statement behind "this change leaves these accounts unable to sign
    in": the provider turned off ends the provider's, and the provider turned
    on with break-glass accounts only ends the local ones that are not. `keep`
    is the token hash of the session the acting admin is using, which stays.
    """

    cursor.execute(
        "update app_session s set revoked_at = statement_timestamp() "  # noqa: S608 - condition is code
        "  from app_user u "
        " where s.user_id = u.id and s.revoked_at is null "
        "   and s.expires_at > statement_timestamp() and s.token_hash <> %(keep)s "
        "   and (" + condition + ")",
        {"keep": keep, **params},
    )
    return int(cursor.rowcount)


def end_locked_out_sessions(
    connection: Connection[Any], *, user_id: int | None = None, keep: bytes = b""
) -> int:
    """End the sessions of local accounts the sign-in rule now turns away.

    While sign-in goes through the provider with break-glass accounts only, a
    password signs in a break-glass account and no other (B195). Run after a
    change that starts that rule - the provider turned on, the rule chosen, a
    break-glass mark removed - it ends what the rule would refuse on a new
    sign-in, so a session does not outlive it by up to the absolute lifetime.
    Nothing when the rule is not in force. `user_id` limits it to one account.
    """

    with connection.cursor() as cursor:
        return end_sessions_where(
            cursor,
            "u.source = 'local' and not u.break_glass "
            "and (select enabled and local_login = 'break_glass_only' from oidc_provider) "
            "and (%(user_id)s::bigint is null or u.id = %(user_id)s::bigint)",
            keep=keep,
            user_id=user_id,
        )


def delete_account(connection: Connection[Any], *, user_id: int) -> bool:
    """Remove an account for good (B197). Its sessions go with it; jobs and the
    audit trail keep the name. False when it was already gone."""

    try:
        with savepoint(connection), connection.cursor() as cursor:
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
