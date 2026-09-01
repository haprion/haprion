"""The privileged, read-only half of ``haproxy-network``.

The cluster repository is group-readable by the engine's own group and by
nobody else, and the interface's identities are deliberately not in it. This
helper reads one cluster's network description inside that boundary and returns
three tables of addresses.

The caller names a cluster and nothing else. Where that cluster's repository
is, and whether it carries a `managed/network.yaml` at all, are resolved from
configuration on this side of the boundary.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import BinaryIO, TextIO

from haproxy_mgmt.config import DEFAULT_POLICY_PATH, ConfigError, load_policy, load_runtime_config
from haproxy_mgmt.envelope import envelope
from haproxy_mgmt.helper_protocol import (
    HelperProtocolError,
    config_error_code,
    read_helper_request,
    require_no_arguments,
    write_document,
    write_failure,
)
from haproxy_mgmt.network_inventory import network_result

OPERATION = "network"
PARAMETERS: frozenset[str] = frozenset()
EXIT_NOT_ROOT = 77


def main(
    argv: list[str] | None = None,
    *,
    policy_path: Path = DEFAULT_POLICY_PATH,
    input_stream: BinaryIO | None = None,
    output_stream: TextIO | None = None,
    error_stream: TextIO | None = None,
    require_secure: bool = True,
    require_root: bool = True,
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    writer: TextIO = output_stream or sys.stdout
    errors: TextIO = error_stream or sys.stderr

    try:
        require_no_arguments(argv)
        if require_root and os.geteuid() != 0:
            raise HelperProtocolError(
                "haproxy-network-helper must run as root", exit_code=EXIT_NOT_ROOT
            )
        request = read_helper_request(
            input_stream or sys.stdin.buffer,
            expected_operation=OPERATION,
            allowed_parameter_keys=PARAMETERS,
        )
    except HelperProtocolError as exc:
        #
        # Deliberately stderr only, for the same reason every other helper does
        # it: the cluster and request ID an envelope must be bound to are
        # fields of the request that just failed to parse.
        #
        errors.write(f"ERROR: {exc}\n")
        return exc.exit_code

    try:
        policy = load_policy(policy_path, require_secure=require_secure)
        cluster = load_runtime_config(policy, require_secure=require_secure).cluster(
            request.cluster
        )
        result = network_result(cluster)
    except ConfigError as exc:
        #
        # A malformed `managed/network.yaml` arrives here as a ConfigError and
        # is reported as one. Falling back to the engine's own tables when the
        # repository's description does not parse would answer with a different
        # network than the one somebody wrote, which is worse than refusing.
        #
        errors.write(f"ERROR: {exc}\n")
        return write_failure(
            writer,
            operation=OPERATION,
            cluster=request.cluster,
            request_id=request.request_id,
            code=config_error_code(exc.exit_code),
            message=str(exc),
            exit_code=exc.exit_code,
        )

    write_document(
        writer,
        envelope(
            operation=OPERATION,
            outcome="done",
            cluster=request.cluster,
            request_id=request.request_id,
            result=result,
        ),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
