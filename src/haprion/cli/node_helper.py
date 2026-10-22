"""Change which nodes and clusters the manager knows, at the interface's request (B211).

Two operations, one helper and one socket:

* `cluster_node` names one cluster and adds a node from its enrollment block
  and the host name the manager is to reach it at, removes one by name, or
  moves one to another host name (`host`, B295);
* `cluster_define` creates a cluster with its first node or two, or removes one.

What each means - the files, the repository, the proof that every node answers
as itself, the refusals - is `node_enrollment`'s and `cluster_definition`'s,
exactly as when the operator types `haprion-node` or `haprion-cluster`; this
helper only carries the request across the privilege boundary.

Before either, under the same locks, a change an earlier run did not finish -
cut short by a reboot or a kill - is put back from `change_journal` (B247).
What was put back goes to the journal with the helper's other errors; the
result describes the request, as the contract says.

Not run through sudo, for the reason the receiver helper gives (B163): it
writes root's `known_hosts` and git configuration, the pull accounts'
`authorized_keys` and the operator editing policy, outside anything the
worker's sandbox leaves writable. It answers on
`/run/haprion/cluster-node.sock` from a unit of its own, and the worker
sends the request there with `haprion-node-ask`. The terminal commands run it
directly, as root.
"""

from __future__ import annotations

import base64
import io
import json
import os
import pwd
import socket
import struct
import sys
from collections.abc import Callable, Mapping, Sequence
from contextlib import ExitStack
from dataclasses import replace
from pathlib import Path
from typing import Any, BinaryIO, TextIO

from haprion import (
    cert_registry,
    change_journal,
    cluster_definition,
    node_enrollment,
    node_join,
    node_publish,
    node_ssh,
    peers,
)
from haprion.cert_lock import DEFAULT_LOCK_PATH as CERTIFICATE_LOCK
from haprion.cli import deploy_helper
from haprion.cluster_lock import DEFAULT_LOCK_ROOT, LockBusy, hold
from haprion.config import (
    DEFAULT_POLICY_PATH,
    NAME,
    ConfigError,
    Node,
    PathPolicy,
    RuntimeConfig,
    load_policy,
    load_runtime_config,
)
from haprion.envelope import envelope, failure
from haprion.helper_protocol import (
    MAX_REQUEST_BYTES,
    HelperProtocolError,
    HelperRequest,
    JsonValue,
    config_error_code,
    read_helper_request,
    require_no_arguments,
    write_document,
)
from haprion.node_enrollment import AskNode, Enrollment, EnrollmentError, JoinNode, Locations
from haprion.status_collect import NodeResponse, ask_node, collect, read_target
from haprion.version_history import request_names

OPERATION = "cluster_node"
DEFINE = "cluster_define"
HELPER = "/opt/haprion/current/bin/haprion-node-helper"
PARAMETERS = {
    OPERATION: frozenset({"action", "block", "host", "node", "join_key", "requested_by"}),
    DEFINE: frozenset(
        {
            "action",
            "display_name",
            "vip",
            "node_path",
            "default_certificate",
            "blocks",
            "hosts",
            "join_keys",
            "address_prefix",
            "address_interface",
            "requested_by",
        }
    ),
}
ACTIONS = frozenset({"add", "remove"})
NODE_ACTIONS = ACTIONS | {"host"}
#
# What the result calls each node action; the contract's `action`.
#
DONE = {"add": "added", "remove": "removed", "host": "host_changed"}
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
    join_key: Mapping[str, str] | None = None,
    requested_by: str | None = None,
) -> str:
    """The exact bounded node request the worker and `haprion-node` send."""

    parameters: dict[str, JsonValue] = {"action": action}
    for name, value in (
        ("block", block),
        ("host", host),
        ("node", node),
        ("requested_by", requested_by),
    ):
        if value is not None:
            parameters[name] = value
    if join_key is not None:
        parameters["join_key"] = dict(join_key)
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
    join_keys: Sequence[Mapping[str, str] | None] | None = None,
    requested_by: str | None = None,
) -> str:
    """The exact bounded cluster request the worker and `haprion-cluster` send."""

    parameters: dict[str, JsonValue] = {"action": action}
    if requested_by is not None:
        parameters["requested_by"] = requested_by
    if action == "add":
        parameters.update(
            {
                "display_name": display_name,
                "vip": vip,
                "node_path": node_path,
                "blocks": list(blocks),
                "hosts": list(hosts),
            }
        )
        if default_certificate is not None:
            parameters["default_certificate"] = default_certificate
        if address_prefix is not None:
            parameters["address_prefix"] = address_prefix
        if address_interface is not None:
            parameters["address_interface"] = address_interface
        if join_keys is not None:
            parameters["join_keys"] = [None if key is None else dict(key) for key in join_keys]
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
    #
    # `requested_by` goes with any action: who asked, for the version (B335).
    #
    extra = sorted(set(parameters) - allowed - {"requested_by"})
    if extra:
        raise HelperProtocolError(f"{what} takes no {', '.join(extra)}", exit_code=65)


type Work = Callable[[PathPolicy, RuntimeConfig, AskNode, JoinNode], Any]


def _sealed(value: JsonValue, what: str) -> tuple[str, bytes] | None:
    """A one-time key as the web seals it (B317): its key ID and the box."""

    if value is None:
        return None
    if (
        not isinstance(value, dict)
        or set(value) != {"key_id", "ciphertext"}
        or not all(isinstance(value[name], str) and value[name] for name in value)
    ):
        raise HelperProtocolError(f"{what} must be a key_id and a ciphertext", exit_code=65)
    try:
        box = base64.b64decode(str(value["ciphertext"]), validate=True)
    except ValueError:
        raise HelperProtocolError(f"{what}'s ciphertext is not base64", exit_code=65) from None
    return str(value["key_id"]), box


def _keyed(
    policy: PathPolicy,
    enrollment: Enrollment,
    sealed: tuple[str, bytes] | None,
    *,
    cluster: str,
    require_secure: bool,
) -> Enrollment:
    """A v2 block with its one-time key: in the block as typed, or opened from its seal."""

    if enrollment.cluster is not None:
        if sealed is not None:
            raise EnrollmentError("enrollment_invalid", "a v1 block carries no one-time key")
        return enrollment
    if sealed is None:
        if enrollment.join_key is None:
            raise EnrollmentError(
                "enrollment_invalid", f"the block for {enrollment.name} has no one-time key"
            )
        return enrollment
    if enrollment.join_key is not None:
        raise EnrollmentError(
            "enrollment_invalid", "a block is sent with its key or sealed, not both"
        )
    profiles = policy.acme.dns_profiles if policy.acme is not None else None
    if profiles is None:
        raise EnrollmentError(
            "dependency_unavailable",
            "runtime policy.acme.dns_profiles is not configured, so a sealed key cannot be opened",
            78,
        )
    key_id, box = sealed
    for key in node_join.private_keys(profiles.private_keys, require_secure=require_secure):
        if key.key_id == key_id:
            opened = node_join.open_join_key(key, box, cluster=cluster, node=enrollment.name)
            return replace(enrollment, join_key=opened)
    raise EnrollmentError(
        "profile_key_unavailable", "the one-time key's sealing key is not here", 78
    )


def _leave_with(policy: PathPolicy) -> node_enrollment.LeaveNode | None:
    """The removed node's last deploy (B319), over the deploy identity; None without one."""

    identity = policy.deploy_identity
    if identity is None:
        return None

    def leave(node: Node) -> NodeResponse:
        said = io.StringIO()
        code = deploy_helper.run_trigger(
            node_ssh.ssh_argv(identity.key, identity.user, node.mgmt_host), node.name, said
        )
        return NodeResponse(exit_code=code, stdout=said.getvalue())

    return leave


def _node_work(
    request: HelperRequest,
    locations: Locations | None,
    require_secure: bool,
    publisher: Publish,
    leave: node_enrollment.LeaveNode | None = None,
) -> Work:
    parameters = request.parameters
    action = _text(parameters, "action")
    if action not in NODE_ACTIONS:
        raise HelperProtocolError("parameters.action must be add, remove or host", exit_code=65)
    if action == "host":
        _only(parameters, {"action", "node", "host"}, "a host change")
        moved = _text(parameters, "node")
        if not NAME.fullmatch(moved):
            raise HelperProtocolError("parameters.node is not a node name", exit_code=65)
        new_host = node_enrollment.host_name(_text(parameters, "host"))
        return lambda policy, runtime, ask, _join: node_enrollment.change_host(
            policy,
            runtime,
            cluster=request.cluster,
            name=moved,
            host=new_host,
            ask=ask,
            locations=locations,
            require_secure=require_secure,
        )
    if action == "add":
        _only(parameters, {"action", "block", "host", "join_key"}, "an addition")
        host = node_enrollment.host_name(_text(parameters, "host"))
        enrollment = node_enrollment.parse(_text(parameters, "block"))
        sealed = _sealed(parameters.get("join_key"), "parameters.join_key")
        return lambda policy, runtime, ask, join: node_enrollment.add(
            policy,
            runtime,
            _keyed(
                policy,
                enrollment,
                sealed,
                cluster=request.cluster,
                require_secure=require_secure,
            ),
            cluster=request.cluster,
            host=host,
            ask=ask,
            join_node=join,
            locations=locations,
            require_secure=require_secure,
        )
    _only(parameters, {"action", "node"}, "a removal")
    name = _text(parameters, "node")
    if not NAME.fullmatch(name):
        raise HelperProtocolError("parameters.node is not a node name", exit_code=65)

    def publish(remaining: Any) -> dict[str, Any]:
        return publisher(
            request, remaining, comment=f"{name} removed", require_secure=require_secure
        )

    return lambda policy, runtime, ask, _join: node_enrollment.remove(
        policy,
        runtime,
        cluster=request.cluster,
        name=name,
        ask=ask,
        publish=publish,
        leave=leave or _leave_with(policy),
        locations=locations,
        require_secure=require_secure,
    )


def _define_work(
    request: HelperRequest,
    locations: Locations | None,
    places: cluster_definition.Places | None,
    tools: cluster_definition.Tools | None,
    require_secure: bool,
    addresses: node_publish.Addresses,
) -> Work:
    parameters = request.parameters
    action = _text(parameters, "action")
    if action not in ACTIONS:
        raise HelperProtocolError("parameters.action must be add or remove", exit_code=65)
    if action == "remove":
        _only(parameters, {"action"}, "a removal")
        return lambda policy, runtime, _ask, _join: cluster_definition.remove(
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
        default_certificate=(
            _text(parameters, "default_certificate")
            if "default_certificate" in parameters
            else None
        ),
        blocks=_texts(parameters, "blocks"),
        hosts=_texts(parameters, "hosts"),
        address_prefix=cluster_definition.parse_prefix(parameters.get("address_prefix")),
        address_interface=interface,
    )
    raw_keys = parameters.get("join_keys")
    if raw_keys is not None and (
        not isinstance(raw_keys, list) or len(raw_keys) != len(spec.nodes)
    ):
        raise HelperProtocolError("parameters.join_keys must be one per block", exit_code=65)
    sealed_keys = [
        _sealed(value, "parameters.join_keys")
        for value in (raw_keys if raw_keys is not None else [None] * len(spec.nodes))
    ]

    def keyed(policy: PathPolicy) -> cluster_definition.Definition:
        return replace(
            spec,
            nodes=tuple(
                (
                    _keyed(
                        policy,
                        enrollment,
                        sealed,
                        cluster=request.cluster,
                        require_secure=require_secure,
                    ),
                    host,
                )
                for (enrollment, host), sealed in zip(spec.nodes, sealed_keys, strict=True)
            ),
        )

    return lambda policy, runtime, ask, join: cluster_definition.add(
        policy,
        runtime,
        keyed(policy),
        ask=ask,
        join_node=join,
        locations=locations,
        places=places,
        tools=tools,
        require_secure=require_secure,
        addresses=addresses,
    )


type Publish = Callable[..., dict[str, Any]]


def _caller(stream: Any) -> Mapping[str, str]:
    """Who sent the request, as `version_history.requester` reads it.

    Through sudo, the account sudo names. Over the socket the worker asks on
    (B211), nobody sets that: the kernel says who connected (`SO_PEERCRED` on
    the socket that is this helper's stdin), and only the root group's worker
    may. Run any other way, it is this process's own account.
    """

    if os.environ.get("SUDO_USER"):
        return os.environ
    try:
        with socket.socket(fileno=os.dup(stream.fileno())) as connected:
            credentials = connected.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
            )
        _pid, uid, _gid = struct.unpack("3i", credentials)
        return {"SUDO_USER": pwd.getpwuid(uid).pw_name}
    except (OSError, KeyError, ValueError, AttributeError, io.UnsupportedOperation):
        return os.environ


def _publish_with(addresses: node_publish.Addresses) -> Publish:
    def publish(request: HelperRequest, cluster: Any, **options: Any) -> dict[str, Any]:
        return node_publish.publish(request, cluster, addresses=addresses, **options)

    return publish


def _comment(request: HelperRequest, outcome: Any) -> str | None:
    """What the version a node change publishes says it did; None when it publishes none."""

    parameters = request.parameters
    action = parameters.get("action")
    if request.operation == DEFINE:
        return f"cluster {request.cluster} created" if action == "add" else None
    node = getattr(getattr(outcome, "node", None), "name", parameters.get("node"))
    if action == "add":
        return f"{node} added"
    if action == "remove":
        return f"{node} removed"
    return f"{node} moved to {parameters.get('host')}"


def _converged(runtime: Any, cluster: str, ask: AskNode) -> bool:
    """Whether every node of the cluster runs its published version, read as `haprion-status` reads it.

    Asked before a node is added or removed (B321): when it holds, the node
    change is the only difference a deploy would roll out, so the change may be
    deployed in the same job. Anything else - a version published and not
    deployed, a node that cannot be read, nothing published - is not, and the
    deploy is left to a person.
    """

    if cluster not in runtime.clusters:
        return False
    definition = runtime.clusters[cluster]
    report = collect(
        definition.nodes,
        ask,
        target=read_target(Path(definition.publish_path), definition.node_path),
    )
    summary = report.result.get("summary")
    return isinstance(summary, dict) and summary.get("release_state") == "converged"


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
    join_node: JoinNode | None = None,
    addresses: node_publish.Addresses = peers.addresses,
    publish: Publish | None = None,
    leave: node_enrollment.LeaveNode | None = None,
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    output: TextIO = output_stream or sys.stdout
    errors: TextIO = error_stream or sys.stderr
    try:
        require_no_arguments(argv)
        if require_root and os.geteuid() != 0:
            raise HelperProtocolError("haprion-node-helper must run as root", exit_code=77)
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

    #
    # Who the version a node change publishes is recorded for (B335): read once
    # the policy names the interface's worker, so the publisher takes it late.
    #
    names: list[tuple[str, str]] = [("root", "root")]
    base = publish or _publish_with(addresses)

    def publisher(request: HelperRequest, cluster: Any, **options: Any) -> dict[str, Any]:
        return base(request, cluster, names=names[0], **options)

    try:
        work = (
            _node_work(request, locations, require_secure, publisher, leave)
            if request.operation == OPERATION
            else _define_work(request, locations, places, tools, require_secure, addresses)
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
    try:
        names[0] = request_names(
            request.parameters,
            _caller(input_stream or sys.stdin.buffer),
            interface_account=policy.interface_account,
        )
    except HelperProtocolError as exc:
        return _refuse(request, output, errors, "bad_input", str(exc), exc.exit_code)

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

    if join_node is None:
        known_hosts = (locations or Locations()).root_known_hosts

        def join_over_ssh(node: Node, key: str, document: dict[str, Any]) -> NodeResponse:
            return node_join.ssh_join(node.mgmt_host, key, document, known_hosts=known_hosts)

        join_node = join_over_ssh

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
            converged_before = (
                _converged(runtime, request.cluster, ask)
                if request.operation == OPERATION
                and request.parameters.get("action") in ("add", "remove")
                else None
            )
            outcome = work(policy, runtime, ask, join_node)
            #
            # The node list changed, so the configuration did: published as a
            # version while the cluster's lock is still held (B318). A cluster
            # removed has nothing left to publish.
            #
            comment = _comment(request, outcome)
            #
            # A removal has published already, before its files (B319).
            #
            publication = getattr(outcome, "publication", None)
            if comment is not None and request.parameters.get("action") != "remove":
                changed = load_runtime_config(policy, require_secure=require_secure)
                publication = publisher(
                    request,
                    changed.cluster(request.cluster),
                    comment=comment,
                    require_secure=require_secure,
                )
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
            "action": DONE[str(request.parameters["action"])],
            **result,
        }
    if publication is not None:
        result["publication"] = publication
        #
        # A version the nodes do not run yet: owed until a deploy, which the
        # interface runs in the same job when the change is all it would roll
        # out (B321), and which the job page offers otherwise.
        #
        if request.operation == OPERATION and "error" not in publication:
            result["deployment_required"] = True
            result["next_command"] = f"haprion-deploy -c {request.cluster}"
    if converged_before is not None:
        result["converged_before"] = converged_before
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
