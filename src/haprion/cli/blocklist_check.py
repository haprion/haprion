"""`haprion-blocklist-check` - which blocklists hold an address, or what a saved list holds now.

    sudo haprion-blocklist-check <address> [--json]
    sudo haprion-blocklist-check --list <name> [--json]

What *Check address* and *Test* on the interface's Settings -> Blocklists do,
through the same code as their helper. An address is looked up in the lists
the timer keeps, the last good fetch of each, without fetching: which lists
hold it, when each was fetched, and in which clusters an exception keeps it
off the nodes. `--list` fetches a saved list once with its saved password or
token and says what it holds, keeping nothing: the timer's next pass is what
changes the nodes; a list that could not be fetched exits 69 (partial).
Root, because the saved secrets and the kept lists are root's. `--json`
answers with the helper's document, which says it in `answer`.
"""

from __future__ import annotations

import argparse
import os
import sys
import uuid
from pathlib import Path
from typing import TextIO

from haprion import blocklist_check, blocklist_store, blocklists, exit_codes
from haprion.cli.arguments import ArgumentParser
from haprion.cli.blocklist_check_helper import OPERATION, perform
from haprion.config import DEFAULT_POLICY_PATH, ConfigError
from haprion.envelope import envelope, failure
from haprion.helper_protocol import HelperProtocolError, write_document


def _parser() -> argparse.ArgumentParser:
    parser = ArgumentParser(
        prog="haprion-blocklist-check",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    asked = parser.add_mutually_exclusive_group(required=True)
    asked.add_argument("address", nargs="?", help="the IPv4 or IPv6 address to look up")
    asked.add_argument(
        "--list", metavar="NAME", help="fetch this saved list once and say what it holds"
    )
    parser.add_argument("--json", action="store_true", help="answer with the JSON document")
    return parser


def _saved(name: str, definitions: Path) -> dict[str, object]:
    """A saved list as the helper's `list` parameter, with its saved secret."""

    for stored in blocklist_store.read_all(directory=definitions):
        item = stored.definition
        if item.name == name:
            return {
                "name": item.name,
                "url": item.url,
                "every_hours": item.every_hours,
                "authorization": item.authorization,
                "username": item.username,
                "excepts": list(item.excepts),
                "keep_secret": item.authorization != "none",
            }
    raise blocklist_check.CheckError("not_found", f"no blocklist is called {name}")


def main(
    argv: list[str] | None = None,
    *,
    stream_out: TextIO | None = None,
    stream_err: TextIO | None = None,
    policy_path: os.PathLike[str] | None = None,
    definitions: Path = blocklist_store.DEFINITIONS,
    state: Path = blocklist_store.STATE,
    fetch: blocklist_check.Fetch = blocklists.fetch,
    require_root: bool = True,
    require_secure: bool = True,
) -> int:
    out: TextIO = stream_out or sys.stdout
    err: TextIO = stream_err or sys.stderr
    arguments = _parser().parse_args(sys.argv[1:] if argv is None else argv)
    path = DEFAULT_POLICY_PATH if policy_path is None else Path(policy_path)
    request_id = str(uuid.uuid4())
    code, message, exit_code = "", "", exit_codes.OK
    result: dict[str, object] = {}
    if require_root and os.geteuid() != 0:
        code, message = "not_root", "the saved lists and their secrets are root's: run it with sudo"
        exit_code = exit_codes.NOT_ROOT
    else:
        try:
            parameters: dict[str, object] = (
                {"list": _saved(arguments.list, definitions)}
                if arguments.list is not None
                else {"address": arguments.address}
            )
            result = perform(
                parameters,
                policy_path=path,
                definitions=definitions,
                state=state,
                fetch=fetch,
                require_secure=require_secure,
            )
        except blocklist_check.CheckError as exc:
            code, message, exit_code = exc.code, str(exc), exc.exit_code
        except HelperProtocolError as exc:
            code, message, exit_code = "bad_input", str(exc), exc.exit_code
        except blocklist_store.StoreError as exc:
            code, message, exit_code = "bad_state", str(exc), exit_codes.CONFIG
        except ConfigError as exc:
            code, message, exit_code = "bad_policy", str(exc), exc.exit_code
    if code:
        if arguments.json:
            return write_document(
                out,
                failure(
                    operation=OPERATION,
                    cluster=None,
                    request_id=request_id,
                    code=code,
                    message=message,
                    exit_code=exit_code,
                ),
                exit_code,
            )
        err.write(f"ERROR: {message}\n")
        return exit_code
    if arguments.json:
        return write_document(
            out,
            envelope(
                operation=OPERATION,
                outcome="done",
                cluster=None,
                request_id=request_id,
                result=result,
            ),
            exit_codes.OK,
        )
    out.write(_sentence(result) + "\n")
    #
    # A test that could not fetch answered the question it was asked, so the
    # document is `done` and says `failed` in its answer; in words, where only
    # the exit is left for a script, it is a partial answer.
    #
    return exit_codes.PARTIAL if result.get("answer") == "failed" else exit_codes.OK


def _sentence(result: dict[str, object]) -> str:
    if result["kind"] == "list":
        return blocklist_check.Tested.from_dict(result).sentence()
    return blocklist_check.AddressCheck.from_dict(result).sentence()


if __name__ == "__main__":
    raise SystemExit(main())
