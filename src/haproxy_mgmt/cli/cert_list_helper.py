"""The privileged, read-only half of ``haproxy-cert-list``.

The certificate distribution root is root-owned because the files in it are
private key plus chain. This helper reports metadata about them and never lets
key material out: what reaches the X.509 parser is the leaf block alone, and
what reaches the caller is nine fields per certificate.

The caller names a cluster and nothing else. Which certificates that cluster
references, and which root they are distributed from, are resolved inside the
privilege boundary from configuration.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import BinaryIO, TextIO

from haproxy_mgmt import ui_interface
from haproxy_mgmt.cert_inventory import CertInventoryError, cert_list_result
from haproxy_mgmt.cert_receiver import manager_name
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

OPERATION = "cert_list"
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
                "haproxy-cert-list-helper must run as root", exit_code=EXIT_NOT_ROOT
            )
        request = read_helper_request(
            input_stream or sys.stdin.buffer,
            expected_operation=OPERATION,
            allowed_parameter_keys=PARAMETERS,
        )
    except HelperProtocolError as exc:
        #
        # Deliberately stderr only. The cluster and the request ID an envelope
        # must be bound to are fields of the request that just failed to parse;
        # an envelope invented here could not be bound to the caller's request
        # and would rightly be rejected as somebody else's answer.
        #
        errors.write(f"ERROR: {exc}\n")
        return exc.exit_code

    try:
        policy = load_policy(policy_path, require_secure=require_secure)
        runtime = load_runtime_config(policy, require_secure=require_secure)
        cluster = runtime.cluster(request.cluster)
    except ConfigError as exc:
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

    if policy.certificate_root is None:
        return write_failure(
            writer,
            operation=OPERATION,
            cluster=request.cluster,
            request_id=request.request_id,
            code="certificate_metadata_unavailable",
            message="the runtime policy declares no certificate_root",
            exit_code=65,
        )

    # The pending-request field is read from the NDES state root when the
    # policy names one. A policy without the block lists as before.
    ndes_policy = getattr(policy, "ndes", None)
    try:
        result = cert_list_result(
            policy.certificate_root,
            cluster,
            registry=runtime.registry,
            request_root=ndes_policy.state_root if ndes_policy is not None else None,
            manager=manager_name(),
            interface_served=ui_interface.served_description(),
        )
    except CertInventoryError as exc:
        return write_failure(
            writer,
            operation=OPERATION,
            cluster=request.cluster,
            request_id=request.request_id,
            code="certificate_metadata_unavailable",
            message=str(exc),
            exit_code=65,
        )

    #
    # A certificate that could not be read is reported inside the result, not as
    # a failure. The contract allows only done or failed here, and failing the
    # whole listing for one damaged file would hide the other certificates -
    # including the ones a rollout could still use.
    #
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
