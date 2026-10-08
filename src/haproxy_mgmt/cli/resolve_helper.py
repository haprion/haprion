"""`haproxy-resolve-helper` - look a dns server's names up for the web (B253, 2026-10-06).

A dns object's server may be written as a name, and dnsdist takes addresses
only, so each name is looked up (`dnsdist_config.lookup`, B252) - since B261
when the object is saved, and the address stored beside it, so the publish
looks nothing up. Saving happens in the web service, which is built to reach
nothing but localhost (`IPAddressDeny=any`): there a lookup worked only because
the manager's resolver happened to be systemd-resolved's stub on 127.0.0.53,
and on a host whose `resolv.conf` names a server elsewhere it would have
refused names that resolve. So the web asks here, over
`/run/haproxy-mgmt/resolve.sock`, and this answers with the manager's own
resolver - the one the status uses to say a name has moved.

Not root, and nothing to hold: a dynamic account, no files, and the network
only because looking a name up is the point. The names are held to the model's
host name pattern before anything is asked.
"""

from __future__ import annotations

import sys
from typing import Any, BinaryIO, TextIO

from haproxy_mgmt import dnsdist_config
from haproxy_mgmt.cli import cert_job
from haproxy_mgmt.envelope import envelope
from haproxy_mgmt.helper_protocol import HelperProtocolError, write_document
from haproxy_mgmt.proxy_model import HOSTNAME

OPERATION = "resolve"
PARAMETERS = frozenset({"names"})
#
# One object's pool, as the probe bounds it: a request with hundreds of names
# would be a resolver for anybody who can reach the socket.
#
MAX_NAMES = 20


def _names(parameters: Any) -> list[str]:
    names = parameters.get("names") if isinstance(parameters, dict) else None
    if not isinstance(names, list) or not names:
        raise HelperProtocolError("parameters.names must be a non-empty list", exit_code=65)
    if len(names) > MAX_NAMES:
        raise HelperProtocolError(f"at most {MAX_NAMES} names at once", exit_code=65)
    for name in names:
        if not isinstance(name, str) or dnsdist_config.is_address(name) or not HOSTNAME.match(name):
            raise HelperProtocolError("every name must be a host name", exit_code=65)
    return list(dict.fromkeys(names))


def answer(name: str, lookup: dnsdist_config.Lookup) -> dict[str, str | None]:
    """One name's address, or the sentence the generator would refuse it with."""

    try:
        return {"name": name, "address": lookup(name), "problem": None}
    except dnsdist_config.Unresolved as exc:
        return {"name": name, "address": None, "problem": str(exc)}


def main(
    argv: list[str] | None = None,
    *,
    input_stream: BinaryIO | None = None,
    output_stream: TextIO | None = None,
    error_stream: TextIO | None = None,
    lookup: dnsdist_config.Lookup = dnsdist_config.lookup,
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    writer: TextIO = output_stream or sys.stdout
    errors: TextIO = error_stream or sys.stderr

    try:
        request = cert_job.read_request(
            OPERATION,
            parameters=PARAMETERS,
            input_stream=input_stream,
            argv=argv,
            require_root=False,
            helper_name="haproxy-resolve-helper",
        )
    except HelperProtocolError as exc:
        errors.write(f"ERROR: {exc}\n")
        return exc.exit_code

    refuse = cert_job.Refuse(OPERATION, request, writer, errors)
    try:
        names = _names(request.parameters)
    except HelperProtocolError as exc:
        return refuse("bad_input", str(exc), exc.exit_code)

    #
    # `done` whatever the names gave: a name that does not resolve is the
    # answer to the question, said per name, as the generator would say it.
    #
    write_document(
        writer,
        envelope(
            operation=OPERATION,
            outcome="done",
            cluster=None,
            request_id=request.request_id,
            result={"names": [answer(name, lookup) for name in names]},
        ),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
