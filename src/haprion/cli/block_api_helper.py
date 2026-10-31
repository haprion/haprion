"""`haprion-block-api-helper` - place a block for the web's API, in the same call (B416).

The API's `block` level answers an address at once, without the job queue: a
publish that holds the cluster's one place in the queue must not make a
fail2ban ban wait, and a burst of bans must not be a burst of jobs. The web
asks over `/run/haprion/block.sock`; this runs as root, because the key that
reaches the nodes and the cluster's repository are root's.

The web has judged the token and its scope, so there is no client to check;
everything else is `haprion-block-helper`'s, shared as `block_helper.prepare`:
the object exists in the cluster's newest version and blocks at all. An
address the object exempts is not refused for the whole request, as the ssh
path does, but left out and said, so one exempt address in a fail2ban's list
does not stop the others - the answer is `partial` and names it.

Like that helper it can do nothing else: it does not lift a block, set a
server's state or read anything back but the nodes' answers. What was blocked,
on which object and for whom goes to the journal; the web writes the same into
the audit trail.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import BinaryIO, TextIO

from haprion import exit_codes
from haprion.cli.block_helper import Refused, place, prepare
from haprion.cli.server_state_helper import write_unblocked
from haprion.config import DEFAULT_POLICY_PATH
from haprion.helper_protocol import (
    HelperProtocolError,
    read_helper_request,
    require_no_arguments,
    write_failure,
)
from haprion.server_state import (
    BLOCK_OPERATION,
    ServerStateError,
    UnblockCall,
    addresses,
    ask_unblock,
    exempted,
    object_name,
)
from haprion.version_history import UnfitName, trailer_name

PARAMETERS = frozenset({"object", "addresses", "actor"})


def main(
    argv: list[str] | None = None,
    *,
    policy_path: Path = DEFAULT_POLICY_PATH,
    input_stream: BinaryIO | None = None,
    output_stream: TextIO | None = None,
    error_stream: TextIO | None = None,
    require_secure: bool = True,
    require_root: bool = True,
    ask: UnblockCall = ask_unblock,
) -> int:
    writer = output_stream or sys.stdout
    errors = error_stream or sys.stderr
    stream = input_stream or sys.stdin.buffer
    arguments = sys.argv[1:] if argv is None else argv

    try:
        require_no_arguments(arguments)
        if require_root and os.geteuid() != 0:
            raise HelperProtocolError(
                "block api helper must run as root", exit_code=exit_codes.NOT_ROOT
            )
        request = read_helper_request(
            stream, expected_operation=BLOCK_OPERATION, allowed_parameter_keys=PARAMETERS
        )
    except HelperProtocolError as exc:
        errors.write(f"ERROR: {exc}\n")
        return exc.exit_code

    def refuse(
        code: str, message: str, exit_code: int, details: dict[str, object] | None = None
    ) -> int:
        errors.write(f"ERROR: [{code}] {message}\n")
        return write_failure(
            writer,
            operation=BLOCK_OPERATION,
            cluster=request.cluster,
            request_id=request.request_id,
            code=code,
            message=message,
            exit_code=exit_code,
            details=details,
        )

    parameters = request.parameters
    try:
        wanted = addresses(parameters.get("addresses"))
        name = object_name(parameters.get("object"))
        #
        # Held to the rule the version history uses for a name, so what the
        # journal line below says cannot be broken by it.
        #
        actor = trailer_name(parameters.get("actor"))
        placement = prepare(
            request.cluster, name, policy_path=policy_path, require_secure=require_secure
        )
    except UnfitName as exc:
        return refuse("bad_input", f"parameters.actor {exc}", exit_codes.REFUSED)
    except (ServerStateError, Refused) as exc:
        return refuse(exc.code, str(exc), exc.exit_code)

    spared = exempted(placement.proxy, wanted, placement.networks)
    placed = tuple(address for address in wanted if address not in spared)
    if not placed:
        return refuse(
            "bad_input",
            f"{name} never blocks {', '.join(spared)}: the object exempts it",
            exit_codes.REFUSED,
            {"addresses": list(spared)},
        )
    errors.write(f"block {name} in {request.cluster}: {' '.join(placed)} for {actor}\n")
    return write_unblocked(
        writer,
        request.cluster,
        request.request_id,
        placement.proxy.name,
        place(placement, placed, ask=ask),
        operation=BLOCK_OPERATION,
        spared=spared,
    )


if __name__ == "__main__":
    raise SystemExit(main())
