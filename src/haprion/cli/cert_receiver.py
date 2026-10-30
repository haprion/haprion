"""`haprion-cert-receiver` - the command that makes a receiver exist, or stop existing.

Runs as root, on the manager, and does the whole of it: the account, the
directory, the lock for the transport, and the registry entry. Until C7 this
was three manual steps, and three steps can be done
two-thirds of the way.

The private key of the receiver is never named here, because it never exists
here: the pair is made on the receiver, and `--public-key` takes the half
that may travel (B157).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, TextIO

from haprion import exit_codes
from haprion.cert_lock import DEFAULT_LOCK_PATH
from haprion.cert_receiver import (
    Locations,
    ReceiverError,
    Result,
    Tools,
    add,
    answer,
    listing,
    new_secret,
    remove,
    secret_hash,
    set_key,
    set_secret,
)
from haprion.config import DEFAULT_POLICY_PATH, ConfigError, load_policy, load_runtime_config
from haprion.envelope import envelope, failure, new_request_id
from haprion.helper_protocol import config_error_code, write_document

OPERATION = "cert_receiver"

USAGE = (
    "Usage:\n"
    "  haprion-cert-receiver add <id> --transport rsync|sftp --public-key <file>\n"
    "                        [--owner <name>] [--path <dir>] [--json]\n"
    "  haprion-cert-receiver add <id> --transport https --allow <cidr>... [--path <dir>]\n"
    "                        --show-password [--json]\n"
    "  haprion-cert-receiver secret <id> --show-password [--json]\n"
    "  haprion-cert-receiver key <id> --public-key <file> [--json]\n"
    "  haprion-cert-receiver list [--json]\n"
    "  haprion-cert-receiver remove <id> [--json]\n"
    "\n"
    "A receiver is a machine outside this installation that fetches certificates.\n"
    "Registering one makes an account, a directory only that account may read, a\n"
    "lock binding its key to that directory, and the registry entry. Runs as root.\n"
    "\n"
    "  <id>                  The fetching host's DNS name or IP address. An rsync or\n"
    '                        sftp key is bound to it with from="..."; a name has\n'
    "                        to resolve.\n"
    "  --transport rsync     Fetches with rsync over ssh, forced to rrsync -ro.\n"
    "  --transport sftp      Fetches with sftp, read-only, chrooted into its own\n"
    "                        directory.\n"
    "  --transport https     Fetches over https from the addresses in --allow,\n"
    "                        with a password of its own, printed once here.\n"
    "  secret <id>           A new password for an https receiver, printed once;\n"
    "                        the old one stops working at once.\n"
    "  key <id>              A new public key for an rsync or sftp receiver, its\n"
    "                        directory, lock and certificates kept; the old key\n"
    "                        stops working at once.\n"
    "  --show-password       Required wherever a password is made: it is printed\n"
    "                        on stdout. The interface shows it on the page instead.\n"
    "  --public-key <file>   The .pub file the receiver's own ssh-keygen wrote.\n"
    "  --allow <cidr>        An address or network that may fetch over https.\n"
    "                        May be repeated. Required for https, refused otherwise.\n"
    "  --owner <name>        The new account. Defaults to crx- and the ID.\n"
    "                        A name already in use is refused.\n"
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
        self.show_password = False


def _parse(argv: list[str], writer: TextIO) -> Arguments:
    parsed = Arguments()
    if not argv or argv[0] not in {"add", "list", "remove", "secret", "key"}:
        writer.write(USAGE)
        raise SystemExit(exit_codes.USAGE)
    parsed.action = argv[0]
    index = 1
    if parsed.action != "list":
        if len(argv) < 2 or argv[1].startswith("-"):
            writer.write(USAGE)
            raise SystemExit(exit_codes.USAGE)
        parsed.receiver_id = argv[1]
        index = 2

    def value() -> str:
        if index + 1 >= len(argv) or argv[index + 1].startswith("-"):
            writer.write(USAGE)
            raise SystemExit(exit_codes.USAGE)
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
        elif argument == "--show-password":
            parsed.show_password = True
            index += 1
        else:
            writer.write(USAGE)
            raise SystemExit(exit_codes.USAGE)
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

    def refuse(
        code: str, message: str, exit_code: int, details: dict[str, Any] | None = None
    ) -> int:
        errors.write(f"ERROR: [{code}] {message}\n")
        if arguments.json_mode:
            document = failure(
                operation=OPERATION,
                cluster=None,
                request_id=request_id,
                code=code,
                message=message,
                exit_code=exit_code,
                details=details,
            )
            write_document(writer, document, exit_code)
        return exit_code

    #
    # A password made here is printed here, so the command makes one only when
    # asked to print it - refused before anything is changed, so the receiver's
    # old password is never replaced by one nobody saw.
    #
    new_credential = arguments.action == "secret" or (
        arguments.action == "add" and arguments.transport == "https"
    )
    if new_credential and not arguments.show_password:
        return refuse(
            "bad_input",
            "this makes a password and prints it once: pass --show-password, "
            "or use the interface, which shows it on the page",
            exit_codes.USAGE,
        )

    if require_root and os.geteuid() != 0:
        return refuse("not_root", "haprion-cert-receiver must run as root", exit_codes.NOT_ROOT)

    try:
        policy = load_policy(policy_path, require_secure=require_secure)
        runtime = load_runtime_config(policy, require_secure=require_secure)
    except ConfigError as exc:
        return refuse(
            config_error_code(exc.exit_code),
            str(exc),
            exc.exit_code,
        )

    try:
        if arguments.action == "list":
            rows = listing(policy, runtime)
            if arguments.json_mode:
                return write_document(
                    writer,
                    envelope(
                        operation=OPERATION,
                        outcome="done",
                        cluster=None,
                        result={"receivers": rows},
                        request_id=request_id,
                    ),
                    exit_codes.OK,
                )
            _print_listing(rows, writer)
            return 0

        #
        # The password is made here and shown here, once (B306); what goes on
        # is its hash, which is all nginx needs and all that is kept.
        #
        password = new_secret() if new_credential else None
        hashed = secret_hash(password) if password is not None else None
        if arguments.action == "key":
            if arguments.public_key is None:
                return refuse("bad_input", "a new key needs --public-key <file>", exit_codes.USAGE)
            result = set_key(
                runtime,
                receiver_id=arguments.receiver_id,
                public_key=arguments.public_key,
                tools=tools,
            )
        elif arguments.action == "secret":
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
        return refuse(exc.code, str(exc), exc.exit_code, exc.details)

    document, code = answer(
        result,
        request_id=request_id,
        extra={"password": password} if password is not None else None,
    )
    if arguments.json_mode:
        return write_document(writer, document, code)
    _print_result(result, writer, password)
    return code
