"""`haprion-cert-receiver` - the command that makes a receiver exist, or stop existing.

Runs as root, on the manager, and does the whole of it: the account, the
directory, the lock for the transport, and the registry entry. Until C7 this
was three manual steps in INSTALLATION 1.4.1, and three steps can be done
two-thirds of the way.

The private key of the receiver is never named here, because it never exists
here: the pair is made on the receiver, and `--public-key` takes the half
that may travel (B157).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, TextIO

from haprion.cert_lock import DEFAULT_LOCK_PATH
from haprion.cert_receiver import (
    Locations,
    ReceiverError,
    Result,
    Tools,
    add,
    listing,
    new_secret,
    remove,
    secret_hash,
    set_secret,
)
from haprion.cli.cert_publish import EXIT_NOT_ROOT
from haprion.config import DEFAULT_POLICY_PATH, ConfigError, load_policy, load_runtime_config
from haprion.envelope import envelope, failure, new_request_id

OPERATION = "cert_receiver"
EXIT_USAGE = 64

USAGE = (
    "Usage:\n"
    "  haprion-cert-receiver add <id> --transport rsync|sftp --public-key <file>\n"
    "                        [--owner <name>] [--path <dir>] [--json]\n"
    "  haprion-cert-receiver add <id> --transport https --allow <cidr>... [--path <dir>]\n"
    "                        [--json]\n"
    "  haprion-cert-receiver secret <id> [--json]\n"
    "  haprion-cert-receiver list [--json]\n"
    "  haprion-cert-receiver remove <id> [--json]\n"
    "\n"
    "A receiver is a machine outside this installation that fetches certificates.\n"
    "Registering one makes an account, a directory only that account may read, a\n"
    "lock binding its key to that directory, and the registry entry. Runs as root.\n"
    "\n"
    "  <id>                  The fetching host's DNS name or IP address. It is what\n"
    '                        from="..." and the nginx whitelist bind to, so the\n'
    "                        PTR record has to agree (B141).\n"
    "  --transport rsync     Fetches with rsync over ssh, forced to rrsync -ro.\n"
    "  --transport sftp      Fetches with sftp, read-only, chrooted into its own\n"
    "                        directory.\n"
    "  --transport https     Fetches over https from the addresses in --allow,\n"
    "                        with a password of its own, printed once here. A\n"
    "                        certificate a cluster carries is never published\n"
    "                        this way, and neither is a wildcard.\n"
    "  secret <id>           A new password for an https receiver, printed once;\n"
    "                        the old one stops working at once.\n"
    "  --public-key <file>   The .pub file the receiver's own ssh-keygen wrote.\n"
    "  --allow <cidr>        An address or network that may fetch over https.\n"
    "                        May be repeated. Required for https, refused otherwise.\n"
    "  --owner <name>        The account. Defaults to crx- and the ID.\n"
    "  --path <dir>          The directory. Defaults to receiver_root/<id>.\n"
    "  --json                Print the result envelope on stdout.\n"
)


class Arguments:
    def __init__(self) -> None:
        self.action = ""
        self.receiver_id = ""
        self.transport = "rsync"
        self.public_key: Path | None = None
        self.owner: str | None = None
        self.path: Path | None = None
        self.allow: list[str] = []
        self.json_mode = False


def _parse(argv: list[str], writer: TextIO) -> Arguments:
    parsed = Arguments()
    if not argv or argv[0] not in {"add", "list", "remove", "secret"}:
        writer.write(USAGE)
        raise SystemExit(EXIT_USAGE)
    parsed.action = argv[0]
    index = 1
    if parsed.action != "list":
        if len(argv) < 2 or argv[1].startswith("-"):
            writer.write(USAGE)
            raise SystemExit(EXIT_USAGE)
        parsed.receiver_id = argv[1]
        index = 2

    def value() -> str:
        if index + 1 >= len(argv) or argv[index + 1].startswith("-"):
            writer.write(USAGE)
            raise SystemExit(EXIT_USAGE)
        return argv[index + 1]

    while index < len(argv):
        argument = argv[index]
        if argument == "--transport":
            parsed.transport = value()
            index += 2
        elif argument == "--public-key":
            parsed.public_key = Path(value())
            index += 2
        elif argument == "--owner":
            parsed.owner = value()
            index += 2
        elif argument == "--path":
            parsed.path = Path(value())
            index += 2
        elif argument == "--allow":
            parsed.allow.append(value())
            index += 2
        elif argument == "--json":
            parsed.json_mode = True
            index += 1
        else:
            writer.write(USAGE)
            raise SystemExit(EXIT_USAGE)
    return parsed


def _print_result(result: Result, writer: TextIO, password: str | None = None) -> None:
    writer.write(f"{result.action} {result.receiver_id}\n")
    for layer in result.layers:
        detail = f"  ({layer.detail})" if layer.detail else ""
        writer.write(f"  {layer.state:<8} {layer.name}{detail}\n")
    if password is not None:
        writer.write(
            f"\npassword: {password}\n"
            "  shown this once; the manager keeps only its hash. Give it to the receiver.\n"
        )
    if result.instructions:
        writer.write("\nWhat the receiver needs:\n")
        for line in result.instructions:
            writer.write(f"  {line}\n")


def _print_listing(rows: list[dict[str, Any]], writer: TextIO) -> None:
    if not rows:
        writer.write("no receivers are registered\n")
        return
    writer.write(f"{'ID':<28} {'TRANSPORT':<9} HOLDS\n")
    for row in rows:
        holds = ", ".join(row["certificates"]) or "-"
        writer.write(f"{row['id']:<28} {row['transport']:<9} {holds}\n")


def main(
    argv: list[str] | None = None,
    *,
    policy_path: Path = DEFAULT_POLICY_PATH,
    output_stream: TextIO | None = None,
    error_stream: TextIO | None = None,
    require_secure: bool = True,
    require_root: bool = True,
    tools: Tools | None = None,
    locations: Locations | None = None,
    lock_path: Path = DEFAULT_LOCK_PATH,
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    writer: TextIO = output_stream or sys.stdout
    errors: TextIO = error_stream or sys.stderr
    request_id = new_request_id()

    try:
        arguments = _parse(argv, writer)
    except SystemExit as exc:
        return int(exc.code or 0)

    def refuse(code: str, message: str, exit_code: int) -> int:
        errors.write(f"ERROR: [{code}] {message}\n")
        if arguments.json_mode:
            document = failure(
                operation=OPERATION,
                cluster=None,
                request_id=request_id,
                code=code,
                message=message,
                exit_code=exit_code,
            )
            writer.write(json.dumps(document, separators=(",", ":"), sort_keys=True) + "\n")
        return exit_code

    if require_root and os.geteuid() != 0:
        return refuse("not_root", "haprion-cert-receiver must run as root", EXIT_NOT_ROOT)

    try:
        policy = load_policy(policy_path, require_secure=require_secure)
        runtime = load_runtime_config(policy, require_secure=require_secure)
    except ConfigError as exc:
        return refuse(
            "bad_input" if exc.exit_code == 64 else "dependency_unavailable",
            str(exc),
            exc.exit_code,
        )

    try:
        if arguments.action == "list":
            rows = listing(policy, runtime)
            if arguments.json_mode:
                writer.write(
                    json.dumps(
                        envelope(
                            operation=OPERATION,
                            outcome="done",
                            cluster=None,
                            result={"receivers": rows},
                            request_id=request_id,
                        ),
                        separators=(",", ":"),
                        sort_keys=True,
                    )
                    + "\n"
                )
            else:
                _print_listing(rows, writer)
            return 0

        #
        # The password is made here and shown here, once (B306); what goes on
        # is its hash, which is all nginx needs and all that is kept.
        #
        password = (
            new_secret()
            if arguments.action == "secret"
            or (arguments.action == "add" and arguments.transport == "https")
            else None
        )
        hashed = secret_hash(password) if password is not None else None
        if arguments.action == "secret":
            assert hashed is not None  # noqa: S101 - made just above
            result = set_secret(
                runtime,
                receiver_id=arguments.receiver_id,
                hashed_secret=hashed,
                tools=tools,
                locations=locations,
            )
        elif arguments.action == "add":
            result = add(
                policy,
                runtime,
                receiver_id=arguments.receiver_id,
                transport=arguments.transport,
                public_key=arguments.public_key,
                owner=arguments.owner,
                path=arguments.path,
                allow=arguments.allow,
                hashed_secret=hashed,
                tools=tools,
                locations=locations,
                require_secure=require_secure,
                lock_path=lock_path,
            )
        else:
            result = remove(
                policy,
                runtime,
                receiver_id=arguments.receiver_id,
                tools=tools,
                locations=locations,
                require_secure=require_secure,
                lock_path=lock_path,
            )
    except ReceiverError as exc:
        return refuse(exc.code, str(exc), exc.exit_code)

    if arguments.json_mode:
        writer.write(
            json.dumps(
                envelope(
                    operation=OPERATION,
                    outcome="done",
                    cluster=None,
                    result=result.as_dict()
                    | ({"password": password} if password is not None else {}),
                    request_id=request_id,
                ),
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        )
    else:
        _print_result(result, writer, password)
    return 0
