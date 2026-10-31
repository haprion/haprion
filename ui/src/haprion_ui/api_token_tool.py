"""haprion-api-token - API tokens, from a root shell (B416).

The same table and the same rules as Settings -> API tokens (`api_token_apply`):
`add` makes a token and prints its secret once, `list` shows them, `extend`
gives one a new end date and keeps its secret, `revoke` ends one for good, `remove` deletes one that is revoked or has expired. Root
connects as the migration role, as `haprion-user` does, and the actor recorded
is the login that ran sudo.

`add` writes the secret alone on standard output, so a script can keep it, and
everything else on standard error. With `--json` the secret is in the answer
and nowhere else.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import psycopg
from haprion import exit_codes
from haprion.cli import arguments

from haprion_ui import (
    api_token_apply,
    api_tokens,
    config,
    db,
    external_blocking,
    moments,
    tool_answer,
)
from haprion_ui.admin import AdminError, actor_name, connect, load_environment
from haprion_ui.settings_tool import known_clusters

OPERATION = api_token_apply.OPERATION
EXITS = {"not_found": exit_codes.NOT_FOUND}


def _refusal(error: api_token_apply.Refused) -> AdminError:
    return AdminError(
        str(error), code=error.code, exit_code=EXITS.get(error.code, exit_codes.REFUSED)
    )


def _choices(connection: Any) -> tuple[tuple[str, ...], dict[str, tuple[str, ...]]]:
    """The clusters, and in each the objects with dynamic blocking, as the page offers them."""

    clusters, polled = known_clusters(connection, config.load())
    readings = [
        row
        for row in db.cluster_objects(connection)
        if not polled or getattr(row, "cluster", None) in clusters
    ]
    return clusters, {name: external_blocking.blocking_objects(readings, name) for name in clusters}


def command_add(args: argparse.Namespace) -> int:
    new = api_token_apply.NewToken(
        name=args.name,
        level=args.level,
        clusters=tuple(dict.fromkeys(args.cluster)),
        objects=tuple(dict.fromkeys(args.object)),
        sources=tuple(args.source),
        days=args.days,
    )
    with connect(load_environment()) as connection:
        clusters, blocking = _choices(connection)
        if text := api_token_apply.problem(new, clusters=clusters, blocking=blocking):
            raise AdminError(text, exit_code=exit_codes.REFUSED)
        try:
            made, secret = api_token_apply.issue(connection, new, actor=actor_name(), via="cli")
        except api_token_apply.Refused as error:
            raise _refusal(error) from error
        connection.commit()
    if args.json:
        result = api_token_apply.document(made, datetime.now(UTC))
        return tool_answer.done(
            OPERATION,
            {
                "action": "add",
                "token": {key: result[key] for key in TOKEN_FIELDS},
                "secret": secret,
            },
        )
    print(
        f"created {made.name} ({made.level}), valid until {moments.day(made.expires_at)}",
        file=sys.stderr,
    )
    print(secret)
    return 0


TOKEN_FIELDS = ("name", "level", "clusters", "objects", "sources", "prefix", "expires_at")


def command_list(args: argparse.Namespace) -> int:
    with connect(load_environment()) as connection:
        tokens = db.api_tokens(connection)
    now = datetime.now(UTC)
    if args.json:
        return tool_answer.done(
            OPERATION,
            {
                "action": "list",
                "tokens": [api_token_apply.document(token, now) for token in tokens],
            },
        )
    if not tokens:
        print("no API tokens. Make one with:")
        print("  sudo haprion-api-token add <name> --level read")
        return 0
    print(
        f"{'NAME':<24} {'PREFIX':<12} {'LEVEL':<6} {'STATE':<8} {'VALID UNTIL':<12} "
        f"{'LAST USED':<30} SCOPE"
    )
    for token in tokens:
        print(
            f"{token.name:<24} {token.prefix:<12} {token.level:<6} "
            f"{api_token_apply.state(token, now):<8} "
            f"{moments.day(token.expires_at)}     "
            f"{api_token_apply.last_used(token):<30} {api_token_apply.scope(token)}"
        )
    return 0


def _change(
    args: argparse.Namespace,
    action: str,
    do: Callable[..., db.ApiToken],
    said: str,
) -> int:
    with connect(load_environment()) as connection:
        try:
            do(connection, args.name, actor=actor_name(), via="cli")
        except api_token_apply.Refused as error:
            connection.rollback()
            raise _refusal(error) from error
        connection.commit()
    if args.json:
        return tool_answer.done(OPERATION, {"action": action, "name": args.name})
    print(f"{said} {args.name}")
    return 0


def command_extend(args: argparse.Namespace) -> int:
    with connect(load_environment()) as connection:
        try:
            extended = api_token_apply.extend(
                connection, args.name, days=args.days, actor=actor_name(), via="cli"
            )
        except api_token_apply.Refused as error:
            connection.rollback()
            raise _refusal(error) from error
        connection.commit()
    if args.json:
        return tool_answer.done(
            OPERATION,
            {
                "action": "extend",
                "name": extended.name,
                "expires_at": extended.expires_at.isoformat(),
            },
        )
    print(f"extended {extended.name}, valid until {moments.day(extended.expires_at)}")
    return 0


def command_revoke(args: argparse.Namespace) -> int:
    return _change(args, "revoke", api_token_apply.revoke, "revoked")


def command_remove(args: argparse.Namespace) -> int:
    return _change(args, "remove", api_token_apply.remove, "removed")


COMMANDS = {
    "add": command_add,
    "list": command_list,
    "extend": command_extend,
    "revoke": command_revoke,
    "remove": command_remove,
}


def build_parser() -> argparse.ArgumentParser:
    parser = arguments.ArgumentParser(
        prog="haprion-api-token",
        description="Manage API tokens. Root only; a secret is shown once, when it is made.",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    add = subcommands.add_parser("add", help="make a token and print its secret once")
    add.add_argument("name")
    add.add_argument("--level", choices=api_tokens.LEVELS, required=True)
    add.add_argument("--cluster", action="append", default=[], help="limit to a cluster; repeat")
    add.add_argument("--object", action="append", default=[], help="a block token's proxy; repeat")
    add.add_argument(
        "--source", action="append", default=[], help="an address or network it may be used from"
    )
    add.add_argument(
        "--days",
        type=int,
        default=api_tokens.DEFAULT_DAYS,
        help=f"valid for this many days (at most {api_tokens.LONGEST_DAYS})",
    )
    add.add_argument("--json", action="store_true")

    listing = subcommands.add_parser("list", help="show the tokens, never their secrets")
    listing.add_argument("--json", action="store_true")

    extend = subcommands.add_parser(
        "extend", help="give a token a new end date, from today; its secret stays"
    )
    extend.add_argument("name")
    extend.add_argument(
        "--days",
        type=int,
        default=api_tokens.DEFAULT_DAYS,
        help=f"valid for this many days from today (at most {api_tokens.LONGEST_DAYS})",
    )
    extend.add_argument("--json", action="store_true")

    for name, help_text in (
        ("revoke", "end a token for good"),
        ("remove", "delete a token that is revoked or has expired"),
    ):
        sub = subcommands.add_parser(name, help=help_text)
        sub.add_argument("name")
        sub.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if os.geteuid() != 0:
        return tool_answer.refusal(
            args, OPERATION, "not_root", "run this with sudo", exit_codes.NOT_ROOT
        )
    try:
        return COMMANDS[args.command](args)
    except AdminError as exc:
        return tool_answer.refusal(args, OPERATION, exc.code, str(exc), exc.exit_code)
    except config.ConfigError as exc:
        return tool_answer.refusal(
            args, OPERATION, "dependency_unavailable", str(exc), exc.exit_code
        )
    except psycopg.Error as exc:
        return tool_answer.database_refusal(args, OPERATION, exc)


def _entry() -> None:  # pragma: no cover - console script shim
    sys.exit(main())


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
