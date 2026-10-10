"""haprion-user - accounts, from a root shell and nowhere else.

The first admin has to come from somewhere, and every alternative is worse. A
default password shipped with the installation is a password that survives in
the field; a first-run setup page is an unauthenticated endpoint that creates an
administrator, which is a hole that exists for the entire life of the
installation to be useful for the first thirty seconds of it.

So account creation is a local root action. It is also the break-glass path:
when the only administrator is locked out, forgotten, or gone, this is what
brings the interface back without touching the database by hand. An account
made here is a break-glass account unless told otherwise (B196): it signs in
with its password even while sign-in goes through an OIDC provider.

The installation makes the first one itself, `admin`, with `init-admin`: the
person installing types its password at the terminal, and it is never printed.
That is neither a default password nor a setup
page - nothing about it is the same on two installations, and nothing answers
on the network before it exists.

Root connects as the migration role - the one that owns the schema. Since 0039
the web role may write accounts too, behind an admin session and the admin's own
password (Fas 13, B187); this tool is what still works when no admin can sign in.
The database refuses to leave no active admin from either path.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import psycopg

from haprion_ui import auth, users

ADMIN_CONFIG_DIRECTORY = Path("/etc/haprion")
ROLES = ("admin", "reader")

# The floor is shared with the web's own password change; see auth.
MINIMUM_PASSWORD_LENGTH = auth.MINIMUM_PASSWORD_LENGTH


class AdminError(Exception):
    """Something the operator needs to fix. Printed without a traceback."""


@dataclass(frozen=True, slots=True)
class Environment:
    database: str
    role: str


def load_environment() -> Environment:
    """Which database this installation is, read from a root-owned file.

    Deliberately not derived from the application's own configuration, so the
    tool cannot be pointed at another database by an environment variable or a
    working directory.
    """

    path = ADMIN_CONFIG_DIRECTORY / "ui-admin.conf"
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise AdminError(
            f"cannot read {path}: {exc}\n  It is written by install/platform/02-platform-database."
        ) from exc

    values: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip().strip('"')

    missing = sorted({"DB_NAME", "DB_ROLE"} - set(values))
    if missing:
        raise AdminError(f"{path} is missing: {', '.join(missing)}")
    return Environment(database=values["DB_NAME"], role=values["DB_ROLE"])


def connect(environment: Environment) -> psycopg.Connection[tuple[Any, ...]]:
    """Connect over the local socket, naming the role but holding no password.

    The role is named because libpq would otherwise ask for one called `root`,
    which does not exist and must not. Whether root may *be* this role is
    decided by peer authentication and the ident map - by the kernel and the
    server's configuration, not by anything this process knows.
    """

    return psycopg.connect(
        f"dbname={environment.database} user={environment.role} host=/var/run/postgresql"
    )


def read_new_password() -> str:
    """Ask twice, echo neither, and never accept one from the command line.

    A password given as an argument is in the shell history, in the process
    list, and in whatever collects either. There is deliberately no flag for it.
    """

    if not sys.stdin.isatty():
        raise AdminError("a password must be typed at a terminal, not piped in")
    first = getpass.getpass("New password: ")
    if len(first) < MINIMUM_PASSWORD_LENGTH:
        raise AdminError(f"password must be at least {MINIMUM_PASSWORD_LENGTH} characters")
    if len(first.encode("utf-8")) > auth.MAX_PASSWORD_BYTES:
        raise AdminError(f"password must be under {auth.MAX_PASSWORD_BYTES} bytes")
    if getpass.getpass("Repeat password: ") != first:
        raise AdminError("the two passwords do not match")
    return first


def _actor() -> str:
    """Who to record. The invoking login, not `root`.

    `sudo` keeps the original name in the environment, and that is the useful
    fact: an audit trail in which every administrative action was taken by
    "root" records that something happened and not who did it.
    """

    return os.environ.get("SUDO_USER") or getpass.getuser()


def _audit(
    connection: psycopg.Connection[tuple[Any, ...]], action: str, subject: str, **detail: object
) -> None:
    with connection.cursor() as cursor:
        cursor.execute(
            "insert into audit_event (actor, action, detail) "
            "values (%(actor)s, %(action)s, %(detail)s)",
            {
                "actor": _actor(),
                "action": action,
                "detail": psycopg.types.json.Jsonb({"account": subject, **detail}),
            },
        )


def _user_id(connection: psycopg.Connection[tuple[Any, ...]], username: str) -> int:
    with connection.cursor() as cursor:
        cursor.execute("select id from app_user where username_normalised = lower(%s)", (username,))
        row = cursor.fetchone()
    if row is None:
        raise AdminError(f"no such account: {username}")
    return int(row[0])


def _revoke_sessions(connection: psycopg.Connection[tuple[Any, ...]], user_id: int) -> int:
    with connection.cursor() as cursor:
        cursor.execute(
            "update app_session set revoked_at = statement_timestamp() "
            " where user_id = %s and revoked_at is null",
            (user_id,),
        )
        return cursor.rowcount


def _insert_local(
    connection: psycopg.Connection[tuple[Any, ...]],
    username: str,
    password: str,
    role: str,
    *,
    break_glass: bool,
) -> bool:
    with connection.cursor() as cursor:
        cursor.execute(
            "insert into app_user (username, password_hash, role, break_glass) "
            "values (%(username)s, %(hash)s, %(role)s, %(break_glass)s) "
            "on conflict do nothing returning id",
            {
                "username": username,
                "hash": auth.hash_password(password),
                "role": role,
                "break_glass": break_glass,
            },
        )
        return cursor.fetchone() is not None


def command_add(environment: Environment, args: argparse.Namespace) -> int:
    problem = users.name_problem(args.username)
    if problem is not None:
        raise AdminError(problem)
    password = read_new_password()
    break_glass = not args.no_break_glass
    with connect(environment) as connection:
        if not _insert_local(
            connection, args.username, password, args.role, break_glass=break_glass
        ):
            raise AdminError(f"an account named {args.username} already exists")
        _audit(
            connection, "account_created", args.username, role=args.role, break_glass=break_glass
        )
        connection.commit()
    kind = "break-glass " if break_glass else ""
    print(f"created {kind}{args.username} with role {args.role}")
    return 0


FIRST_ADMIN = "admin"


def _any_account(connection: psycopg.Connection[tuple[Any, ...]]) -> bool:
    with connection.cursor() as cursor:
        cursor.execute("select exists (select 1 from app_user)")
        row = cursor.fetchone()
    return row is not None and bool(row[0])


def command_init_admin(environment: Environment, _: argparse.Namespace) -> int:
    """The installation's first account, when there is none (B196).

    Does nothing on an installation that has any account at all, so the
    release that calls it every time is harmless after the first. The password
    is typed by the person installing, as `add` takes it; nothing is drawn,
    printed or kept anywhere else.
    """

    with connect(environment) as connection:
        if _any_account(connection):
            print("accounts exist; no first account created")
            return 0
    #
    # Asked outside any transaction, so no lock waits on a person typing.
    #
    print(f"The first account is {FIRST_ADMIN}, a break-glass admin. Choose its password.")
    password = read_new_password()
    with connect(environment) as connection:
        with connection.cursor() as cursor:
            #
            # Under the same lock as the last-admin guard, so two installers
            # running at once cannot both see an empty table.
            #
            cursor.execute("select pg_advisory_xact_lock(hashtext('app_user_keep_an_admin'))")
        if _any_account(connection):
            print("accounts exist; no first account created")
            return 0
        _insert_local(connection, FIRST_ADMIN, password, "admin", break_glass=True)
        _audit(connection, "account_created", FIRST_ADMIN, role="admin", break_glass=True)
        connection.commit()
    print(f"created break-glass {FIRST_ADMIN} with role admin")
    return 0


def command_delete(environment: Environment, args: argparse.Namespace) -> int:
    """Remove an account for good (B197). Asks for `--yes` rather than a prompt,
    so a script cannot delete by forgetting to answer."""

    with connect(environment) as connection:
        user_id = _user_id(connection, args.username)
        if not args.yes:
            print(f"would delete {args.username} and its sessions; repeat with --yes to do it")
            return 64
        with connection.cursor() as cursor:
            cursor.execute("delete from app_user where id = %s", (user_id,))
        _audit(connection, "account_deleted", args.username)
        connection.commit()
    print(f"deleted {args.username}")
    return 0


def command_break_glass(environment: Environment, args: argparse.Namespace) -> int:
    break_glass = not args.off
    with connect(environment) as connection:
        user_id = _user_id(connection, args.username)
        with connection.cursor() as cursor:
            cursor.execute("select source from app_user where id = %s", (user_id,))
            row = cursor.fetchone()
            if row is not None and row[0] != "local":
                raise AdminError(
                    f"{args.username} signs in through the provider; only local "
                    "accounts can be break-glass"
                )
            cursor.execute(
                "update app_user set break_glass = %s where id = %s", (break_glass, user_id)
            )
        _audit(connection, "break_glass_changed", args.username, break_glass=break_glass)
        connection.commit()
    print(f"{args.username} is {'now' if break_glass else 'no longer'} a break-glass account")
    return 0


def command_reset(environment: Environment, args: argparse.Namespace) -> int:
    with connect(environment) as connection:
        user_id = _user_id(connection, args.username)
        with connection.cursor() as cursor:
            cursor.execute("select source from app_user where id = %s", (user_id,))
            row = cursor.fetchone()
        if row is not None and row[0] != "local":
            raise AdminError(f"{args.username} signs in through the provider and has no password")
        password = read_new_password()
        with connection.cursor() as cursor:
            cursor.execute(
                "update app_user set password_hash = %(hash)s, "
                "       updated_at = statement_timestamp() where id = %(id)s",
                {"hash": auth.hash_password(password), "id": user_id},
            )
        #
        # Sessions go with the password. A reset that leaves existing cookies
        # working has not taken the account back from whoever had it - which is
        # the situation a reset is usually a response to.
        #
        ended = _revoke_sessions(connection, user_id)
        _audit(connection, "password_reset", args.username, sessions_revoked=ended)
        connection.commit()
    print(f"password reset for {args.username}; {ended} session(s) revoked")
    return 0


def command_disable(environment: Environment, args: argparse.Namespace) -> int:
    with connect(environment) as connection:
        user_id = _user_id(connection, args.username)
        with connection.cursor() as cursor:
            cursor.execute(
                "update app_user set disabled = true, updated_at = statement_timestamp() "
                " where id = %s",
                (user_id,),
            )
        ended = _revoke_sessions(connection, user_id)
        _audit(connection, "account_disabled", args.username, sessions_revoked=ended)
        connection.commit()
    print(f"disabled {args.username}; {ended} session(s) revoked")
    return 0


def command_enable(environment: Environment, args: argparse.Namespace) -> int:
    with connect(environment) as connection:
        user_id = _user_id(connection, args.username)
        with connection.cursor() as cursor:
            cursor.execute(
                "update app_user set disabled = false, updated_at = statement_timestamp() "
                " where id = %s",
                (user_id,),
            )
        _audit(connection, "account_enabled", args.username)
        connection.commit()
    print(f"enabled {args.username}")
    return 0


def command_unlock(environment: Environment, args: argparse.Namespace) -> int:
    """Clear the throttle for an account.

    Adds an unlock row (0039) rather than deleting the failed attempts or
    writing a successful one: the throttle counts failures since the latest of
    the two, so the account is let in again and the record of what was tried
    stays. A recorded login that did not happen would be a lie that later reads
    as evidence somebody signed in. The web page's *Unlock* writes the same row.
    """

    with connect(environment) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "insert into login_unlock (username_normalised, actor) values (lower(%s), %s)",
                (args.username, _actor()),
            )
        _audit(connection, "throttle_cleared", args.username)
        connection.commit()
    print(f"unlocked {args.username}")
    return 0


def command_revoke(environment: Environment, args: argparse.Namespace) -> int:
    with connect(environment) as connection:
        user_id = _user_id(connection, args.username)
        ended = _revoke_sessions(connection, user_id)
        _audit(connection, "sessions_revoked", args.username, sessions_revoked=ended)
        connection.commit()
    print(f"revoked {ended} session(s) for {args.username}")
    return 0


def command_list(environment: Environment, _: argparse.Namespace) -> int:
    with connect(environment) as connection, connection.cursor() as cursor:
        cursor.execute(
            "select u.username, u.role, u.disabled, u.source, u.break_glass, u.created_at::date, "
            "       (select count(*) from app_session s "
            "         where s.user_id = u.id and s.revoked_at is null "
            "           and s.expires_at > statement_timestamp()) "
            "  from app_user u order by u.username_normalised"
        )
        rows = cursor.fetchall()
    if not rows:
        print("no accounts. Create the first one with:")
        print("  sudo haprion-user add <username> --role admin")
        return 0
    print(f"{'USERNAME':<24} {'ROLE':<8} {'KIND':<12} {'STATE':<9} {'CREATED':<12} SESSIONS")
    for username, role, disabled, source, break_glass, created, sessions in rows:
        state = "disabled" if disabled else "active"
        kind = "sso" if source == "oidc" else "break-glass" if break_glass else "local"
        print(f"{username:<24} {role:<8} {kind:<12} {state:<9} {str(created):<12} {sessions}")
    return 0


COMMANDS = {
    "add": command_add,
    "init-admin": command_init_admin,
    "delete": command_delete,
    "break-glass": command_break_glass,
    "reset": command_reset,
    "disable": command_disable,
    "enable": command_enable,
    "unlock": command_unlock,
    "revoke": command_revoke,
    "list": command_list,
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="haprion-user",
        description="Manage interface accounts. Root only; passwords are never arguments.",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    add = subcommands.add_parser("add", help="create an account")
    add.add_argument("username")
    add.add_argument("--role", choices=ROLES, required=True)
    add.add_argument(
        "--no-break-glass",
        action="store_true",
        help="an ordinary account, which cannot sign in with a password while SSO is on",
    )

    subcommands.add_parser(
        "init-admin", help="create the break-glass admin 'admin' if there is no account at all"
    )

    delete = subcommands.add_parser("delete", help="remove an account and its sessions for good")
    delete.add_argument("username")
    delete.add_argument("--yes", action="store_true", help="do it; without it, only say what")

    glass = subcommands.add_parser(
        "break-glass", help="mark a local account as break-glass (or --off to unmark)"
    )
    glass.add_argument("username")
    glass.add_argument("--off", action="store_true")

    for name, help_text in (
        ("reset", "set a new password and end every session"),
        ("disable", "block sign-in and end every session"),
        ("enable", "allow sign-in again"),
        ("unlock", "clear the sign-in throttle"),
        ("revoke", "end every session without changing the password"),
    ):
        sub = subcommands.add_parser(name, help=help_text)
        sub.add_argument("username")

    subcommands.add_parser("list", help="show accounts and live sessions")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if os.geteuid() != 0:
        #
        # Refused here as well as by the database. Peer authentication would
        # reject a non-root caller anyway, but as a connection error naming a
        # role - which reads as a broken installation rather than as the answer
        # to "may I do this".
        #
        print("ERROR: run this with sudo", file=sys.stderr)
        return 77
    try:
        environment = load_environment()
        return COMMANDS[args.command](environment, args)
    except AdminError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 64
    except psycopg.Error as exc:
        print(f"ERROR: database: {exc}", file=sys.stderr)
        return 74


def _entry() -> None:  # pragma: no cover - console script shim
    sys.exit(main())


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
