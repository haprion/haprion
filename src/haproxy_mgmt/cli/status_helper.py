"""The privileged half of `haproxy-status` - reach the nodes, read the release.

Takes no arguments; the cluster arrives as a structured request on stdin, the
same form and for the same reason as the other helpers: PRIVILEGE.md forbids
wildcards in sudoers argument matching, so a rule naming a cluster is not
available and one no-argument rule covers every cluster.

Why this needs root at all, for a command that changes nothing
--------------------------------------------------------------
Two things are out of an unprivileged caller's reach. The status identity's
private key is root-owned, because no application identity may hold a key that
reaches a node. And the published release tree is readable only by root and the
pull identity, so the target the nodes are compared against cannot be read by
the caller either.

Both are reads. Nothing here writes, and nothing here takes the cluster lock:
a status must stay answerable while a deploy is running, and a reading that
queued behind a rollout would describe a cluster that has since moved.

What it does not trust
----------------------
The cluster name is validated here. The target is read here, from the published
tree, rather than accepted from the caller - the same rule the deploy helper
follows, and for a sharper reason than it looks: the target is what decides
whether a node is reported as current, so a caller-supplied one would let an
unprivileged process choose what the operator is told is in sync.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import BinaryIO, TextIO

from haproxy_mgmt.candidate_validation import validator_version
from haproxy_mgmt.config import (
    DEFAULT_POLICY_PATH,
    ConfigError,
    Node,
    load_policy,
    load_runtime_config,
)
from haproxy_mgmt.helper_protocol import (
    HelperProtocolError,
    config_error_code,
    read_helper_request,
    require_no_arguments,
    write_document,
    write_failure,
)
from haproxy_mgmt.status_collect import NodeResponse, ReadNode, ask_node, collect, read_target

OPERATION = "status"
PARAMETERS: frozenset[str] = frozenset()

EXIT_NOT_ROOT = 77
EXIT_NO_IDENTITY = 78


def main(
    argv: list[str] | None = None,
    *,
    policy_path: Path = DEFAULT_POLICY_PATH,
    input_stream: BinaryIO | None = None,
    output_stream: TextIO | None = None,
    error_stream: TextIO | None = None,
    require_secure: bool = True,
    require_root: bool = True,
    node_reader: ReadNode | None = None,
    version_reader: Callable[[], str | None] | None = None,
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    writer: TextIO = output_stream or sys.stdout
    errors: TextIO = error_stream or sys.stderr

    try:
        require_no_arguments(argv)
        if require_root and os.geteuid() != 0:
            raise HelperProtocolError(
                "haproxy-status-helper must run as root", exit_code=EXIT_NOT_ROOT
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
        cluster = load_runtime_config(policy, require_secure=require_secure).cluster(
            request.cluster
        )
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

    identity = policy.status_identity
    if identity is None and node_reader is None:
        #
        # Named rather than guessed, exactly as the deploy identity is. A
        # compiled-in default would put a real account name in a repository
        # meant to be public, and a wrong guess would reach a node as the wrong
        # identity.
        #
        message = (
            "no status identity is configured. Add status_identity with "
            "'user' and 'key' to the runtime policy."
        )
        #
        # The code beside the message, not instead of it. The terminal, the jobs
        # page and the audit trail then name the same string for the same
        # failure, so "what my window said" and "what the page says" can be put
        # side by side without guessing. Added 2026-08-31 as F1b.
        #
        errors.write(f"ERROR: [status_unavailable] {message}\n")
        return write_failure(
            writer,
            operation=OPERATION,
            cluster=request.cluster,
            request_id=request.request_id,
            code="status_unavailable",
            message=message,
            exit_code=EXIT_NO_IDENTITY,
        )

    def default_reader(node: Node) -> NodeResponse:
        assert identity is not None  # noqa: S101 - guarded above, stated for the reader
        return ask_node(node, identity)

    report = collect(
        cluster.nodes,
        node_reader or default_reader,
        target=read_target(Path(cluster.publish_path), cluster.node_path),
        publish_path=Path(cluster.publish_path),
    )

    #
    # The version this host validates candidates with, beside the versions the
    # nodes run, so a validator newer than a node is visible where the nodes are.
    #
    report.result["summary"]["validator_version"] = (version_reader or validator_version)()
    write_document(writer, report.as_envelope(request.cluster, request_id=request.request_id))
    return report.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
