"""haproxy-ui-user - accounts, from a root shell and nowhere else.

The first admin has to come from somewhere, and every alternative is worse. A
default password shipped with the installation is a password that survives in
the field; a first-run setup page is an unauthenticated endpoint that creates an
administrator, which is a hole that exists for the entire life of the
installation to be useful for the first thirty seconds of it.

So account creation is a local root action. It is also the break-glass path:
when the only administrator is locked out, forgotten, or gone, this is what
brings the interface back without touching the database by hand.

Root connects as the migration role - the one that owns the schema - because no
application role holds `insert` or `update` on `app_user`. That is the same
boundary the running services live behind, not an exception carved for tooling:
the web process cannot create an administrator no matter what it is asked to do.
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

from haproxy_ui import auth

ADMIN_CONFIG_DIRECTORY = Path("/etc/haproxy-manager")
ROLES = ("admin", "reader")

#
# Long rather than complex. Length is what actually costs an attacker something
# against a memory-hard hash, while composition rules mostly produce one
# predictable substitution per class and a password nobody can remember.
#
MINIMUM_PASSWORD_LENGTH = 12


class AdminError(Exception):
    """Something the operator needs to fix. Printed without a traceback."""


@dataclass(frozen=True, slots=True)
class Environment:
    name: str
    database: str
    role: str


def load_environment(name: str) -> Environment:
    """Which database this environment is, read from a root-owned file.

    Deliberately not derived from the application's own configuration. Prod and
    dev each have their own file, so `-e prod` cannot be made to mean the dev
    database - or the reverse, which is the direction that matters - by an
    environment variable or a working directory.
    """

    if not name.isalnum():
        raise AdminError(f"environment names are alphanumeric: {name!r}")
    path = ADMIN_CONFIG_DIRECTORY / f"ui-admin-{name}.conf"
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise AdminError(
            f"cannot read {path}: {exc}\n"
            f"  Environments are created by install/platform/02-platform-database."
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
    return Environment(name=name, database=values["DB_NAME"], role=values["DB_ROLE"])


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


def command_add(environment: Environment, args: argparse.Namespace) -> int:
    password = read_new_password()
    with connect(environment) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "insert into app_user (username, password_hash, role) "
                "values (%(username)s, %(hash)s, %(role)s) "
                "on conflict do nothing returning id",
                {
                    "username": args.username,
                    "hash": auth.hash_password(password),
                    "role": args.role,
                },
            )
            if cursor.fetchone() is None:
                raise AdminError(f"an account named {args.username} already exists")
        _audit(connection, "account_created", args.username, role=args.role)
        connection.commit()
    print(f"created {args.username} with role {args.role}")
    return 0


def command_reset(environment: Environment, args: argparse.Namespace) -> int:
    password = read_new_password()
    with connect(environment) as connection:
        user_id = _user_id(connection, args.username)
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

    Deletes the failed attempts rather than writing a successful one. Recording
    a login that did not happen would unlock the account too, and would put a
    lie in the record that later reads as evidence somebody signed in.

    The web role cannot do this - it holds no delete on the table - which is the
    property that makes the lockout meaningful in the first place.
    """

    with connect(environment) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "delete from login_attempt "
                " where username_normalised = lower(%s) and succeeded = false",
                (args.username,),
            )
            cleared = cursor.rowcount
        _audit(connection, "throttle_cleared", args.username, attempts_cleared=cleared)
        connection.commit()
    print(f"cleared {cleared} failed attempt(s) for {args.username}")
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
            "select u.username, u.role, u.disabled, u.created_at::date, "
            "       (select count(*) from app_session s "
            "         where s.user_id = u.id and s.revoked_at is null "
            "           and s.expires_at > statement_timestamp()) "
            "  from app_user u order by u.username_normalised"
        )
        rows = cursor.fetchall()
    if not rows:
        print("no accounts. Create the first one with:")
        print(f"  sudo haproxy-ui-user -e {environment.name} add <username> --role admin")
        return 0
    print(f"{'USERNAME':<24} {'ROLE':<8} {'STATE':<9} {'CREATED':<12} SESSIONS")
    for username, role, disabled, created, sessions in rows:
        state = "disabled" if disabled else "active"
        print(f"{username:<24} {role:<8} {state:<9} {str(created):<12} {sessions}")
    return 0


COMMANDS = {
    "add": command_add,
    "reset": command_reset,
    "disable": command_disable,
    "enable": command_enable,
    "unlock": command_unlock,
    "revoke": command_revoke,
    "list": command_list,
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="haproxy-ui-user",
        description="Manage interface accounts. Root only; passwords are never arguments.",
    )
    parser.add_argument(
        "-e",
        "--environment",
        default="prod",
        help="which installation to act on (default: prod)",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    add = subcommands.add_parser("add", help="create an account")
    add.add_argument("username")
    add.add_argument("--role", choices=ROLES, required=True)

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
        environment = load_environment(args.environment)
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
