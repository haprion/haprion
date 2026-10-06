"""Change which nodes and clusters the manager knows, at the interface's request (B211).

Two operations, one helper and one socket:

* `cluster_node` names one cluster and adds a node from its enrollment block
  and the host name the manager is to reach it at, or removes one by name;
* `cluster_define` creates a cluster with its first two nodes, or removes one.

What each means - the files, the repository, the proof that every node answers
as itself, the refusals - is `node_enrollment`'s and `cluster_definition`'s,
exactly as when the operator types `haproxy-node` or `haproxy-cluster`; this
helper only carries the request across the privilege boundary.

Before either, under the same locks, a change an earlier run did not finish -
cut short by a reboot or a kill - is put back from `change_journal` (B247).
What was put back goes to the journal with the helper's other errors; the
result describes the request, as the contract says.

Not run through sudo, for the reason the receiver helper gives (B163): it
writes root's `known_hosts` and git configuration, the pull accounts'
`authorized_keys` and the operator editing policy, outside anything the
worker's sandbox leaves writable. It answers on
`/run/haproxy-mgmt/cluster-node.sock` from a unit of its own, and the worker
sends the request there with `haproxy-node-ask`. The terminal commands run it
directly, as root.
"""

from __future__ import annotations

import io
import json
import os
import sys
from collections.abc import Callable, Mapping, Sequence
from contextlib import ExitStack
from pathlib import Path
from typing import Any, BinaryIO, TextIO

from haproxy_mgmt import cert_registry, change_journal, cluster_definition, node_enrollment
from haproxy_mgmt.cert_lock import DEFAULT_LOCK_PATH as CERTIFICATE_LOCK
from haproxy_mgmt.cluster_lock import DEFAULT_LOCK_ROOT, LockBusy, hold
from haproxy_mgmt.config import (
    DEFAULT_POLICY_PATH,
    NAME,
    ConfigError,
    Node,
    PathPolicy,
    RuntimeConfig,
    load_policy,
    load_runtime_config,
)
from haproxy_mgmt.envelope import envelope, failure
from haproxy_mgmt.helper_protocol import (
    MAX_REQUEST_BYTES,
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
DEFINE = "cluster_define"
HELPER = "/opt/haproxy-mgmt/current/bin/haproxy-node-helper"
PARAMETERS = {
    OPERATION: frozenset({"action", "block", "host", "node"}),
    DEFINE: frozenset(
        {
            "action",
            "display_name",
            "vip",
            "node_path",
            "default_certificate",
            "blocks",
            "hosts",
            "address_prefix",
            "address_interface",
        }
    ),
}
ACTIONS = frozenset({"add", "remove"})
#
# Every change to the cluster file takes this as well as its cluster's own
# lock: two changes to two different clusters would otherwise read the same
# file and the second rename would lose the first.
#
CLUSTER_FILE_LOCK = "cluster-file"

__all__ = ["DEFINE", "HELPER", "OPERATION", "build_define_request", "build_request", "main"]


def _request(
    operation: str, cluster: str, request_id: str, parameters: dict[str, JsonValue]
) -> str:
    return json.dumps(
        {
            "schema_version": 1,
            "operation": operation,
            "cluster": cluster,
            "request_id": request_id,
            "parameters": parameters,
        },
        separators=(",", ":"),
    )


def build_request(
    cluster: str,
    request_id: str,
    *,
    action: str,
    block: str | None = None,
    host: str | None = None,
    node: str | None = None,
) -> str:
    """The exact bounded node request the worker and `haproxy-node` send."""

    parameters: dict[str, JsonValue] = {"action": action}
    for name, value in (("block", block), ("host", host), ("node", node)):
        if value is not None:
            parameters[name] = value
    return _request(OPERATION, cluster, request_id, parameters)


def build_define_request(
    cluster: str,
    request_id: str,
    *,
    action: str,
    display_name: str | None = None,
    vip: str | None = None,
    node_path: str | None = None,
    default_certificate: str | None = None,
    blocks: Sequence[str] = (),
    hosts: Sequence[str] = (),
    address_prefix: int | None = None,
    address_interface: str | None = None,
) -> str:
    """The exact bounded cluster request the worker and `haproxy-cluster` send."""

    parameters: dict[str, JsonValue] = {"action": action}
    if action == "add":
        parameters.update(
            {
                "display_name": display_name,
                "vip": vip,
                "node_path": node_path,
                "default_certificate": default_certificate,
                "blocks": list(blocks),
                "hosts": list(hosts),
            }
        )
        if address_prefix is not None:
            parameters["address_prefix"] = address_prefix
        if address_interface is not None:
            parameters["address_interface"] = address_interface
    return _request(DEFINE, cluster, request_id, parameters)


def _refuse(
    request: HelperRequest, output: TextIO, errors: TextIO, code: str, message: str, exit_code: int
) -> int:
    errors.write(f"ERROR: [{code}] {message}\n")
    write_document(
        output,
        failure(
            operation=request.operation,
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


def _texts(parameters: Mapping[str, JsonValue], key: str) -> list[str]:
    value = parameters.get(key)
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise HelperProtocolError(f"parameters.{key} must be a list of strings", exit_code=65)
    return [str(item) for item in value]


def _only(parameters: Mapping[str, JsonValue], allowed: set[str], what: str) -> None:
    extra = sorted(set(parameters) - allowed)
    if extra:
        raise HelperProtocolError(f"{what} takes no {', '.join(extra)}", exit_code=65)


type Work = Callable[[PathPolicy, RuntimeConfig, AskNode], Any]


def _node_work(request: HelperRequest, locations: Locations | None, require_secure: bool) -> Work:
    parameters = request.parameters
    action = _text(parameters, "action")
    if action not in ACTIONS:
        raise HelperProtocolError("parameters.action must be add or remove", exit_code=65)
    if action == "add":
        _only(parameters, {"action", "block", "host"}, "an addition")
        host = node_enrollment.host_name(_text(parameters, "host"))
        enrollment = node_enrollment.parse(_text(parameters, "block"))
        return lambda policy, runtime, ask: node_enrollment.add(
            policy,
            runtime,
            enrollment,
            cluster=request.cluster,
            host=host,
            ask=ask,
            locations=locations,
            require_secure=require_secure,
        )
    _only(parameters, {"action", "node"}, "a removal")
    name = _text(parameters, "node")
    if not NAME.fullmatch(name):
        raise HelperProtocolError("parameters.node is not a node name", exit_code=65)
    return lambda policy, runtime, ask: node_enrollment.remove(
        policy,
        runtime,
        cluster=request.cluster,
        name=name,
        ask=ask,
        locations=locations,
        require_secure=require_secure,
    )


def _define_work(
    request: HelperRequest,
    locations: Locations | None,
    places: cluster_definition.Places | None,
    tools: cluster_definition.Tools | None,
    require_secure: bool,
) -> Work:
    parameters = request.parameters
    action = _text(parameters, "action")
    if action not in ACTIONS:
        raise HelperProtocolError("parameters.action must be add or remove", exit_code=65)
    if action == "remove":
        _only(parameters, {"action"}, "a removal")
        return lambda policy, runtime, _ask: cluster_definition.remove(
            policy,
            runtime,
            cluster=request.cluster,
            locations=locations,
            places=places,
            tools=tools,
            require_secure=require_secure,
        )
    interface = parameters.get("address_interface")
    if interface is not None and not isinstance(interface, str):
        raise HelperProtocolError("parameters.address_interface must be a string", exit_code=65)
    spec = cluster_definition.definition(
        request.cluster,
        display_name=_text(parameters, "display_name"),
        vip=_text(parameters, "vip"),
        node_path=_text(parameters, "node_path"),
        default_certificate=_text(parameters, "default_certificate"),
        blocks=_texts(parameters, "blocks"),
        hosts=_texts(parameters, "hosts"),
        address_prefix=cluster_definition.parse_prefix(parameters.get("address_prefix")),
        address_interface=interface,
    )
    return lambda policy, runtime, ask: cluster_definition.add(
        policy,
        runtime,
        spec,
        ask=ask,
        locations=locations,
        places=places,
        tools=tools,
        require_secure=require_secure,
    )


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
    registry_lock: Path = CERTIFICATE_LOCK,
    journal: Path | None = None,
    locations: Locations | None = None,
    places: cluster_definition.Places | None = None,
    tools: cluster_definition.Tools | None = None,
    ask: AskNode | None = None,
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    output: TextIO = output_stream or sys.stdout
    errors: TextIO = error_stream or sys.stderr
    try:
        require_no_arguments(argv)
        if require_root and os.geteuid() != 0:
            raise HelperProtocolError("haproxy-node-helper must run as root", exit_code=77)
        #
        # Read once, then parsed as the operation it names: the two share a
        # socket, and each is held to its own parameters.
        #
        raw = (input_stream or sys.stdin.buffer).read(MAX_REQUEST_BYTES + 1)
        try:
            named = json.loads(raw).get("operation")
        except (ValueError, AttributeError):
            named = None
        operation = named if named in PARAMETERS else OPERATION
        request = read_helper_request(
            io.BytesIO(raw),
            expected_operation=operation,
            allowed_parameter_keys=PARAMETERS[operation],
        )
    except HelperProtocolError as exc:
        errors.write(f"ERROR: {exc}\n")
        return exc.exit_code

    try:
        work = (
            _node_work(request, locations, require_secure)
            if request.operation == OPERATION
            else _define_work(request, locations, places, tools, require_secure)
        )
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

    journal = journal or (locations or Locations()).journal
    try:
        pending = change_journal.read(journal)
    except change_journal.RecoveryError as exc:
        return _refuse(request, output, errors, exc.code, str(exc), exc.exit_code)
    try:
        with ExitStack() as locks:
            #
            # The cluster's own lock: a deploy walking the node list must not
            # have it change under it. The cluster file's, for the reason its
            # name gives. The registry's, where a cluster is created or removed
            # and a certificate's targets change with it.
            #
            locks.enter_context(hold(request.cluster, operation=request.operation, root=lock_root))
            locks.enter_context(
                hold(CLUSTER_FILE_LOCK, operation=request.operation, root=lock_root)
            )
            registry = request.operation == DEFINE and policy.certificate_registry is not None
            if registry:
                locks.enter_context(cert_registry.locked(registry_lock))
            if pending is not None:
                #
                # Held as the unfinished change held them: its cluster's lock,
                # and the registry's, which a cluster's change also wrote.
                #
                if pending.cluster != request.cluster:
                    locks.enter_context(
                        hold(pending.cluster, operation=request.operation, root=lock_root)
                    )
                if not registry and policy.certificate_registry is not None:
                    locks.enter_context(cert_registry.locked(registry_lock))
                recovered = change_journal.recover(journal)
                if recovered is not None:
                    errors.write(
                        f"NOTICE: a {recovered.operation} of cluster '{recovered.cluster}' "
                        f"did not finish and was put back: {', '.join(recovered.files)}\n"
                    )
                runtime = load_runtime_config(policy, require_secure=require_secure)
            outcome = work(policy, runtime, ask)
    except LockBusy as exc:
        return _refuse(request, output, errors, "operation_locked", str(exc), exc.exit_code)
    except cert_registry.RegistryError as exc:
        return _refuse(request, output, errors, exc.code, str(exc), exc.exit_code)
    except EnrollmentError as exc:
        return _refuse(request, output, errors, exc.code, str(exc), exc.exit_code)
    except change_journal.RecoveryError as exc:
        return _refuse(request, output, errors, exc.code, str(exc), exc.exit_code)
    except ConfigError as exc:
        return _refuse(
            request, output, errors, config_error_code(exc.exit_code), str(exc), exc.exit_code
        )
    except OSError as exc:
        return _refuse(
            request,
            output,
            errors,
            "internal_error",
            f"a file could not be written ({exc}); every file was put back",
            74,
        )

    result = outcome.as_dict()
    if request.operation == OPERATION:
        result = {
            "action": "added" if request.parameters["action"] == "add" else "removed",
            **result,
        }
    write_document(
        output,
        envelope(
            operation=request.operation,
            outcome="done",
            cluster=request.cluster,
            request_id=request.request_id,
            result=result,
        ),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
