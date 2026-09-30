"""Add a node to a cluster, or take one away, at the interface's request (B211).

One request names one cluster and one of two actions: `add`, with the node's
enrollment block and the host name the manager is to reach it at, or
`remove`, with the node's name. What each means - the six files, the proof
that the node answers as itself, the refusal to remove the node holding the
VIP - is `node_enrollment`'s, exactly as when the operator types
`haproxy-node`; this helper only carries the request across the privilege
boundary.

Not run through sudo, for the reason the receiver helper gives (B163): it
writes root's `known_hosts` and the pull accounts' `authorized_keys`, outside
anything the worker's sandbox leaves writable. It answers on
`/run/haproxy-mgmt/cluster-node.sock` from a unit of its own, and the worker
sends the request there with `haproxy-node-ask`. The terminal command runs it
directly, as root.
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import BinaryIO, TextIO

from haproxy_mgmt import node_enrollment
from haproxy_mgmt.cluster_lock import DEFAULT_LOCK_ROOT, LockBusy, hold
from haproxy_mgmt.config import (
    DEFAULT_POLICY_PATH,
    NAME,
    ConfigError,
    Node,
    load_policy,
    load_runtime_config,
)
from haproxy_mgmt.envelope import envelope, failure
from haproxy_mgmt.helper_protocol import (
    HelperProtocolError,
    HelperRequest,
    JsonValue,
    config_error_code,
    read_helper_request,
    require_no_arguments,
    write_document,
)
from haproxy_mgmt.node_enrollment import AskNode, EnrollmentError, Locations
from haproxy_mgmt.status_collect import NodeResponse, ask_node

OPERATION = "cluster_node"
HELPER = "/opt/haproxy-mgmt/current/bin/haproxy-node-helper"
PARAMETERS = frozenset({"action", "block", "host", "node"})
ACTIONS = frozenset({"add", "remove"})

__all__ = ["HELPER", "OPERATION", "build_request", "main"]


def build_request(
    cluster: str,
    request_id: str,
    *,
    action: str,
    block: str | None = None,
    host: str | None = None,
    node: str | None = None,
) -> str:
    """The exact bounded request the worker and the terminal command send."""

    parameters: dict[str, JsonValue] = {"action": action}
    if block is not None:
        parameters["block"] = block
    if host is not None:
        parameters["host"] = host
    if node is not None:
        parameters["node"] = node
    return json.dumps(
        {
            "schema_version": 1,
            "operation": OPERATION,
            "cluster": cluster,
            "request_id": request_id,
            "parameters": parameters,
        },
        separators=(",", ":"),
    )


def _refuse(
    request: HelperRequest, output: TextIO, errors: TextIO, code: str, message: str, exit_code: int
) -> int:
    errors.write(f"ERROR: [{code}] {message}\n")
    write_document(
        output,
        failure(
            operation=OPERATION,
            cluster=request.cluster,
            request_id=request.request_id,
            code=code,
            message=message,
            exit_code=exit_code,
        ),
    )
    return exit_code


def _text(parameters: Mapping[str, JsonValue], key: str) -> str:
    value = parameters.get(key)
    if not isinstance(value, str) or not value:
        raise HelperProtocolError(f"parameters.{key} must be a non-empty string", exit_code=65)
    return value


def main(
    argv: list[str] | None = None,
    *,
    policy_path: Path = DEFAULT_POLICY_PATH,
    input_stream: BinaryIO | None = None,
    output_stream: TextIO | None = None,
    error_stream: TextIO | None = None,
    require_secure: bool = True,
    require_root: bool = True,
    lock_root: Path = DEFAULT_LOCK_ROOT,
    locations: Locations | None = None,
    ask: AskNode | None = None,
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    output: TextIO = output_stream or sys.stdout
    errors: TextIO = error_stream or sys.stderr
    try:
        require_no_arguments(argv)
        if require_root and os.geteuid() != 0:
            raise HelperProtocolError("haproxy-node-helper must run as root", exit_code=77)
        request = read_helper_request(
            input_stream or sys.stdin.buffer,
            expected_operation=OPERATION,
            allowed_parameter_keys=PARAMETERS,
        )
    except HelperProtocolError as exc:
        errors.write(f"ERROR: {exc}\n")
        return exc.exit_code

    parameters = request.parameters
    try:
        action = _text(parameters, "action")
        if action not in ACTIONS:
            raise HelperProtocolError("parameters.action must be add or remove", exit_code=65)
        if action == "add":
            if "node" in parameters:
                raise HelperProtocolError("an addition names its node in the block", exit_code=65)
            block = _text(parameters, "block")
            host = node_enrollment.host_name(_text(parameters, "host"))
            enrollment = node_enrollment.parse(block)
        else:
            extra = sorted(set(parameters) - {"action", "node"})
            if extra:
                raise HelperProtocolError(f"a removal takes no {', '.join(extra)}", exit_code=65)
            name = _text(parameters, "node")
            if not NAME.fullmatch(name):
                raise HelperProtocolError("parameters.node is not a node name", exit_code=65)
    except HelperProtocolError as exc:
        return _refuse(request, output, errors, "bad_input", str(exc), exc.exit_code)
    except EnrollmentError as exc:
        return _refuse(request, output, errors, exc.code, str(exc), exc.exit_code)

    try:
        policy = load_policy(policy_path, require_secure=require_secure)
        runtime = load_runtime_config(policy, require_secure=require_secure)
    except ConfigError as exc:
        return _refuse(
            request, output, errors, config_error_code(exc.exit_code), str(exc), exc.exit_code
        )

    if ask is None:
        identity = policy.status_identity
        if identity is None:
            return _refuse(
                request,
                output,
                errors,
                "dependency_unavailable",
                "the runtime policy names no status_identity, so a node cannot be asked "
                "whether it answers as itself",
                78,
            )

        def ask_with_status(node: Node) -> NodeResponse:
            return ask_node(node, identity)

        ask = ask_with_status

    try:
        #
        # The cluster's own lock: a deploy that is walking the node list must
        # not have it change under it, and neither may a second change.
        #
        with hold(request.cluster, operation=OPERATION, root=lock_root):
            if action == "add":
                outcome = node_enrollment.add(
                    policy,
                    runtime,
                    enrollment,
                    cluster=request.cluster,
                    host=host,
                    ask=ask,
                    locations=locations,
                    require_secure=require_secure,
                )
            else:
                outcome = node_enrollment.remove(
                    policy,
                    runtime,
                    cluster=request.cluster,
                    name=name,
                    ask=ask,
                    locations=locations,
                    require_secure=require_secure,
                )
    except LockBusy as exc:
        return _refuse(request, output, errors, "operation_locked", str(exc), exc.exit_code)
    except EnrollmentError as exc:
        return _refuse(request, output, errors, exc.code, str(exc), exc.exit_code)
    except OSError as exc:
        return _refuse(
            request,
            output,
            errors,
            "internal_error",
            f"a file could not be written ({exc}); every file was put back",
            74,
        )

    write_document(
        output,
        envelope(
            operation=OPERATION,
            outcome="done",
            cluster=request.cluster,
            request_id=request.request_id,
            result={"action": "added" if action == "add" else "removed", **outcome.as_dict()},
        ),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
