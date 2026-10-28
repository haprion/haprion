"""`haprion-ndes-server` - the NDES servers this manager enrolls with.

    haprion-ndes-server list
    haprion-ndes-server add <address>                    the CA it gives; nothing is changed
    sudo haprion-ndes-server add <address> --sha256 <x>  confirm it and write it into the policy
    sudo haprion-ndes-server remove <address>

What the interface's NDES profile page does when an address is new: the CA
certificates the server gives with `GetCACert`, each with its SHA-256 and
the SHA-1 Windows shows as its thumbprint. Compare one of them with the CA's
own, then confirm it by its SHA-256. A server is removed only when no NDES
profile on this manager uses it.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import TextIO

from haprion import exit_codes, ndes_servers
from haprion.cli.ndes_server_helper import EXIT_CODES
from haprion.config import DEFAULT_POLICY_PATH, ConfigError, load_policy


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="haprion-ndes-server",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    actions = parser.add_subparsers(dest="action", required=True)
    actions.add_parser("list", help="the servers in the runtime policy")
    add = actions.add_parser("add", help="show a server's CA, or confirm it with --sha256")
    add.add_argument("address")
    add.add_argument("--sha256", help="the SHA-256 of the CA certificate you compared")
    remove = actions.add_parser("remove", help="take a server no profile uses out of the policy")
    remove.add_argument("address")
    return parser


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
    writes = arguments.action == "remove" or (
        arguments.action == "add" and arguments.sha256 is not None
    )
    if writes and os.geteuid() != 0:
        err.write("ERROR: this changes the runtime policy: run it with sudo\n")
        return exit_codes.NOT_ROOT
    try:
        if arguments.action == "list":
            ndes = load_policy(path).ndes
            for server in ndes.servers if ndes is not None else ():
                out.write(f"{server.endpoint}  CA {server.issuing_ca}\n")
            if ndes is None:
                out.write("No NDES server is confirmed on this manager.\n")
            return exit_codes.OK
        if arguments.action == "add" and arguments.sha256 is None:
            for authority in ndes_servers.authorities(arguments.address, fetch=fetch):
                role = "issues the RA certificate" if authority.issues_ra else "CA"
                out.write(
                    f"{authority.subject} ({role})\n"
                    f"  SHA-256  {authority.sha256}\n"
                    f"  SHA-1    {authority.sha1}  (the thumbprint Windows shows)\n"
                )
            out.write(
                "Nothing was changed. Compare with the CA, then confirm:\n"
                f"  sudo haprion-ndes-server add {arguments.address} --sha256 <SHA-256>\n"
            )
            return exit_codes.OK
        if arguments.action == "add":
            added = ndes_servers.add(
                arguments.address, arguments.sha256.lower(), policy_path=path, fetch=fetch
            )
            out.write(f"Confirmed {added['endpoint']}; its CA is in {added['issuing_ca']}.\n")
            return exit_codes.OK
        ndes = load_policy(path).ndes
        used_by = (
            ndes_servers.profiles_using(ndes.profiles.directory, arguments.address)
            if ndes is not None
            else ()
        )
        ndes_servers.remove(arguments.address, used_by=used_by, policy_path=path)
        out.write(f"Removed {arguments.address}.\n")
        return exit_codes.OK
    except ndes_servers.NdesServerError as exc:
        err.write(f"ERROR: {exc}\n")
        return EXIT_CODES[exc.code]
    except ConfigError as exc:
        err.write(f"ERROR: {exc}\n")
        return exit_codes.CONFIG


if __name__ == "__main__":
    raise SystemExit(main())
