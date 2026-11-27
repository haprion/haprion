"""`haprion-cert-bmc` - the BMC an external certificate is installed on.

    sudo haprion-cert-bmc check <id> --address <bmc> --user <user> [--port N] [--json]
    sudo haprion-cert-bmc save <id> --address <bmc> --user <user> --sha256 <x> [--port N] [--json]
    sudo haprion-cert-bmc install <id> [--json]
    sudo haprion-cert-bmc remove <id> [--json]

What the certificate's BMC page does, through the same code as its helpers.
The password is read from standard input, never from the command line: typed
at a prompt, or piped. `check` signs in and says what the BMC serves; compare
its SHA-256 with the BMC's own web page, then `save` with it. `save` writes
the target, keeps the account and installs the certificate at once, as the
page's *Save and install* does: the BMC restarts and is away for about two
minutes. `install` installs it again now. `remove` takes the target and its
account away; the BMC keeps the certificate it serves. `--json` answers with
the helper's document; `save`'s carries the install under `install`.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import os
import sys
import uuid
from pathlib import Path
from typing import Any, TextIO

from haprion import exit_codes
from haprion.bmc_redfish import BmcError
from haprion.bmc_targets import Root, TargetError, seal_account
from haprion.cert_registry import RegistryError
from haprion.cli import bmc_helper
from haprion.cli.arguments import ArgumentParser
from haprion.config import CERTIFICATE_ID, DEFAULT_POLICY_PATH, ConfigError, bmc_target
from haprion.dns_profile_keys import DnsProfilePublicKey, key_id_of
from haprion.envelope import envelope, failure
from haprion.helper_protocol import HelperProtocolError, config_error_code, write_document


def _parser() -> argparse.ArgumentParser:
    parser = ArgumentParser(
        prog="haprion-cert-bmc",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    actions = parser.add_subparsers(dest="action", required=True)
    check = actions.add_parser("check", help="sign in and say what the BMC serves; nothing changes")
    save = actions.add_parser("save", help="write the BMC you checked, with the SHA-256 it serves")
    install = actions.add_parser("install", help="install the certificate on its BMC now")
    remove = actions.add_parser("remove", help="take the BMC and its account away")
    for each in (check, save, install, remove):
        each.add_argument("id", help="the certificate's ID")
        each.add_argument("--json", action="store_true", help="answer with the JSON document")
    for each in (check, save):
        each.add_argument("--address", required=True, help="the BMC's name or address")
        each.add_argument("--port", type=int, default=443, help="its HTTPS port (443)")
        each.add_argument("--user", required=True, help="the Redfish account's user")
    save.add_argument(
        "--sha256", required=True, help="the SHA-256 check showed, as its web page shows it"
    )
    return parser


def _fingerprint(value: str) -> str:
    """A SHA-256 as `check` prints it or as a BMC's page shows it: colons and case dropped."""

    return value.replace(":", "").lower()


def _password(user: str, address: str, stream_in: TextIO, err: TextIO) -> str:
    if stream_in.isatty():
        return getpass.getpass(f"Password for {user} on {address}: ", stream=err)
    return stream_in.readline().rstrip("\r\n")


def _sealing_key(root: Root) -> DnsProfilePublicKey:
    """The key the account is sealed against: the last the runtime policy lists.

    A key replacement adds the new pair after the old one (`ROTATE=1`), so the
    last is the one that stays.
    """

    private = root.private_keys[-1]
    return DnsProfilePublicKey(key_id=key_id_of(private.key.public_key), key=private.key.public_key)


def _text(action: str, result: dict[str, Any], out: TextIO, user: str) -> None:
    if action == "check":
        served = ":".join(
            result["served_sha256"][index : index + 2] for index in range(0, 64, 2)
        ).upper()
        account = {
            True: "signed in, may upload certificates",
            False: "signed in, but may not upload certificates: it needs the Administrator role",
            None: "signed in; whether it may upload certificates was not said",
        }[result["may_upload"]]
        out.write(
            f"{result['address']} answers with\n"
            f"  Firmware  {result['model']} {result['firmware']}\n"
            f"  Serves    {result['subject'] or 'no name'} · {result['issuer'] or 'unknown issuer'}"
            f" · expires {result['not_after'] or 'unknown'}\n"
            f"  SHA-256   {served}\n"
            f"  Account   {account}\n"
            "Nothing was changed. Compare the SHA-256 with the BMC's own web page, then:\n"
            f"  sudo haprion-cert-bmc save {result['id']} --address {result['address']}"
            f"{'' if result['port'] == 443 else ' --port ' + str(result['port'])}"
            f" --user {user} --sha256 {result['served_sha256']}\n"
        )
    elif action == "save":
        out.write(
            f"Saved {result['address']} for {result['id']} and installed the certificate: "
            f"{result['install'].get('message') or 'done'}\n"
        )
    elif action == "install":
        out.write(f"Installed {result['id']} on its BMC: {result.get('message') or 'done'}\n")
    else:
        out.write(f"Removed the BMC of {result['id']}; the BMC keeps what it serves.\n")


def main(
    argv: list[str] | None = None,
    *,
    stream_out: TextIO | None = None,
    stream_err: TextIO | None = None,
    stream_in: TextIO | None = None,
    policy_path: os.PathLike[str] | None = None,
    root: Root | None = None,
) -> int:
    out: TextIO = stream_out or sys.stdout
    err: TextIO = stream_err or sys.stderr
    arguments = _parser().parse_args(sys.argv[1:] if argv is None else argv)
    action: str = arguments.action
    operation = bmc_helper.INSTALL_OPERATION if action == "install" else bmc_helper.OPERATION
    request_id = str(uuid.uuid4())

    def refuse(
        code: str, message: str, exit_code: int, details: dict[str, Any] | None = None
    ) -> int:
        if arguments.json:
            return write_document(
                out,
                failure(
                    operation=operation,
                    cluster=None,
                    request_id=request_id,
                    code=code,
                    message=message,
                    exit_code=exit_code,
                    details=details,
                ),
                exit_code,
            )
        err.write(f"ERROR: {message}\n")
        return exit_code

    #
    # The call is judged before anything is read: an ID, an address, a port
    # and a fingerprint each have the registry's own form.
    #
    if not CERTIFICATE_ID.fullmatch(arguments.id):
        return refuse("bad_input", f"{arguments.id} is not a certificate ID", exit_codes.USAGE)
    parameters: dict[str, Any] = {"id": arguments.id}
    if action in ("check", "save"):
        confirmed = _fingerprint(arguments.sha256) if action == "save" else "0" * 64
        try:
            bmc_target(
                {
                    "address": arguments.address,
                    "port": arguments.port,
                    "fingerprint_sha256": confirmed,
                    "username": "-",
                },
                "the BMC",
            )
        except ConfigError as exc:
            return refuse("bad_input", str(exc), exit_codes.USAGE)
        parameters.update(address=arguments.address, port=arguments.port)
        if action == "save":
            parameters["fingerprint_sha256"] = confirmed
    if os.geteuid() != 0:
        return refuse(
            "not_root",
            "this opens the BMC accounts and writes the registry: run it with sudo",
            exit_codes.NOT_ROOT,
        )
    path = DEFAULT_POLICY_PATH if policy_path is None else Path(policy_path)
    try:
        side = root or bmc_helper.root_side(path)
        if action == "install":
            result = bmc_helper.perform_install({"id": arguments.id, "by": "install_now"}, side)
        else:
            parameters["action"] = action
            if action in ("check", "save"):
                password = _password(arguments.user, arguments.address, stream_in or sys.stdin, err)
                key = _sealing_key(side)
                box = seal_account(
                    key,
                    certificate_id=arguments.id,
                    address=arguments.address,
                    username=arguments.user,
                    password=password,
                )
                parameters.update(key_id=key.key_id, ciphertext=box)
            result = _perform(parameters, side)
    except HelperProtocolError as exc:
        return refuse("bad_input", str(exc), exc.exit_code)
    except TargetError as exc:
        return refuse(exc.code, str(exc), exc.exit_code)
    except RegistryError as exc:
        return refuse(exc.code, str(exc), exc.exit_code)
    except BmcError as exc:
        return refuse(f"bmc_{exc.code}", str(exc), exit_codes.REFUSED)
    except ConfigError as exc:
        return refuse(config_error_code(exc.exit_code), str(exc), exc.exit_code)
    if action == "save":
        #
        # Installed at once, as the page's save starts its job: the target is
        # saved whatever the install says, and a failed install says so.
        #
        try:
            attempt = bmc_helper.perform_install({"id": arguments.id, "by": "save"}, side)
        except (TargetError, BmcError) as exc:
            code = exc.code if isinstance(exc, TargetError) else f"bmc_{exc.code}"
            exit_code = exc.exit_code if isinstance(exc, TargetError) else exit_codes.REFUSED
            return refuse(
                code,
                f"saved {arguments.address} for {arguments.id}, but the install failed: {exc}",
                exit_code,
                {"saved": result},
            )
        result = {**result, "install": attempt}
    if arguments.json:
        return write_document(
            out,
            envelope(
                operation=operation,
                outcome="done",
                cluster=None,
                request_id=request_id,
                result=result,
            ),
            exit_codes.OK,
        )
    _text(action, result, out, getattr(arguments, "user", ""))
    return exit_codes.OK


def _perform(parameters: dict[str, Any], side: Root) -> dict[str, Any]:
    """The web helper's own work, with the box handed over as it travels on the socket."""

    box = parameters.pop("ciphertext", None)
    if box is not None:
        parameters["ciphertext_base64"] = base64.b64encode(box).decode("ascii")
    return bmc_helper.perform(parameters, side)


if __name__ == "__main__":
    raise SystemExit(main())
