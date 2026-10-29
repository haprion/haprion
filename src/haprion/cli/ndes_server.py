"""`haprion-ndes-server` - the NDES servers this manager enrolls with.

    haprion-ndes-server list [--json]
    haprion-ndes-server add <address> [--json]                    the CA it gives; nothing changes
    sudo haprion-ndes-server add <address> --sha256 <x> ... [--json]  confirm, write it in the policy
    sudo haprion-ndes-server remove <address> [--json]

What the interface's NDES profile page does, through the same code as its
helper: the CA certificates a server gives with `GetCACert`, each with its
SHA-256 and the SHA-1 Windows shows as its thumbprint. Compare them with the
CA's own, then confirm them: one `--sha256` for each certificate shown, since
every one is saved. A server is removed only
when no NDES profile on this manager uses it. `--json` answers with the
helper's document.
"""

from __future__ import annotations

import argparse
import os
import sys
import uuid
from pathlib import Path
from typing import Any, TextIO

from haprion import exit_codes, ndes_servers
from haprion.cli.arguments import ArgumentParser
from haprion.cli.ndes_server_helper import OPERATION, perform
from haprion.config import DEFAULT_POLICY_PATH, ConfigError
from haprion.envelope import envelope, failure
from haprion.helper_protocol import HelperProtocolError, write_document


def _parser() -> argparse.ArgumentParser:
    parser = ArgumentParser(
        prog="haprion-ndes-server",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    actions = parser.add_subparsers(dest="action", required=True)
    listed = actions.add_parser("list", help="the servers in the runtime policy")
    add = actions.add_parser("add", help="show a server's CA, or confirm it with --sha256")
    add.add_argument("address")
    add.add_argument(
        "--sha256",
        action="append",
        help="the SHA-256 of a CA certificate you compared; once for each one shown",
    )
    remove = actions.add_parser("remove", help="take a server no profile uses out of the policy")
    remove.add_argument("address")
    for each in (listed, add, remove):
        each.add_argument("--json", action="store_true", help="answer with the JSON document")
    return parser


def _text(action: str, result: dict[str, Any], out: TextIO) -> None:
    if action == "list":
        for server in result["servers"]:
            out.write(f"{server['endpoint']}  CA {server['issuing_ca']}\n")
        if not result["servers"]:
            out.write("No NDES server is confirmed on this manager.\n")
    elif action == "fetch":
        for authority in result["authorities"]:
            role = "issues for NDES" if authority["issues_ra"] else "CA"
            out.write(
                f"{authority['subject']} ({role})\n"
                f"  SHA-256  {authority['sha256']}\n"
                f"  SHA-1    {authority['sha1']}  (the thumbprint Windows shows)\n"
            )
        if result["state"] == "confirmed":
            out.write("This server is confirmed already.\n")
        else:
            if result["state"] == "changed":
                out.write("This server is confirmed with other CA certificates.\n")
            confirm = " ".join(f"--sha256 {a['sha256']}" for a in result["authorities"])
            out.write(
                "Nothing was changed. Compare with the CA, then confirm every certificate shown:\n"
                f"  sudo haprion-ndes-server add {result['endpoint']} {confirm}\n"
            )
    elif action == "add":
        out.write(
            f"Confirmed {result['endpoint']}; its CA certificates are in {result['issuing_ca']}.\n"
        )
    else:
        out.write(f"Removed {result['endpoint']}.\n")


def main(
    argv: list[str] | None = None,
    *,
    stream_out: TextIO | None = None,
    stream_err: TextIO | None = None,
    fetch: ndes_servers.Fetch = ndes_servers.get_ca_cert,
    policy_path: os.PathLike[str] | None = None,
) -> int:
    out: TextIO = stream_out or sys.stdout
    err: TextIO = stream_err or sys.stderr
    arguments = _parser().parse_args(sys.argv[1:] if argv is None else argv)
    path = DEFAULT_POLICY_PATH if policy_path is None else Path(policy_path)
    action = arguments.action
    parameters: dict[str, Any] = {"action": action}
    if action != "list":
        parameters["endpoint"] = arguments.address
    if action == "add":
        if arguments.sha256 is None:
            parameters["action"] = action = "fetch"
        else:
            parameters["sha256"] = [each.lower() for each in arguments.sha256]
    request_id = str(uuid.uuid4())
    code, message, exit_code = "", "", exit_codes.OK
    result: dict[str, Any] = {}
    if action in ("add", "remove") and os.geteuid() != 0:
        code, message = "not_root", "this changes the runtime policy: run it with sudo"
        exit_code = exit_codes.NOT_ROOT
    else:
        try:
            result = perform(parameters, policy_path=path, fetch=fetch)
        except ndes_servers.NdesServerError as exc:
            code, message, exit_code = exc.code, str(exc), exc.exit_code
        except HelperProtocolError as exc:
            # The helper's own bounds, the same for both (review 2026-10-29).
            code, message, exit_code = "bad_input", str(exc), exc.exit_code
        except ConfigError as exc:
            code, message, exit_code = "bad_policy", str(exc), exit_codes.CONFIG
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
    _text(action, result, out)
    return exit_codes.OK


if __name__ == "__main__":
    raise SystemExit(main())
