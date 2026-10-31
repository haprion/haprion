"""The privileged half of `haprion-server-state` - drain, maintenance or ready.

Takes no arguments; the request arrives on stdin, for the reason every helper
gives: PRIVILEGE.md forbids wildcards in sudoers argument matching, so one
no-argument rule covers every cluster.

Root for one thing: the server state identity's private key is root-owned,
because no application identity may hold a key that reaches a node. Nothing on
the manager is written, and the cluster lock is not taken - see
`haprion.server_state` for why a deploy at the same time is safe.

It also lifts dynamic blocks (`dynamic_unblock`, B271) over the same key: the
request names the operation, and each operation is held to its own parameters,
as `node_helper` does with its two.

What it does not trust: the servers. They are found in the object, in the
cluster's newest committed version, before any node is asked; the node then
validates the GUID and the state again before anything reaches HAProxy.
"""

from __future__ import annotations

import io
import json
import os
import sys
from pathlib import Path
from typing import BinaryIO, TextIO

from haprion import exit_codes
from haprion.config import (
    DEFAULT_POLICY_PATH,
    ConfigError,
    load_policy,
    load_runtime_config,
)
from haprion.envelope import Message, envelope
from haprion.git_command import GitError
from haprion.helper_protocol import (
    HelperProtocolError,
    config_error_code,
    peek_operation,
    read_helper_request,
    read_raw_request,
    require_no_arguments,
    write_document,
    write_failure,
)
from haprion.managed_publish import PROXY_PREFIX, managed_proxies
from haprion.proxy_model import ModelError
from haprion.repo_snapshot import PublishError, read_tree_files, resolve_head
from haprion.server_state import (
    OPERATION,
    STATES,
    UNBLOCK_OPERATION,
    Answer,
    NodeCall,
    ServerStateError,
    Target,
    UnblockCall,
    Unblocked,
    addresses,
    apply,
    ask_node,
    ask_unblock,
    blocking,
    find_object,
    object_name,
    resolve,
    unblock,
)

PARAMETERS = {
    OPERATION: frozenset({"object", "servers", "state"}),
    UNBLOCK_OPERATION: frozenset({"object", "addresses"}),
}

HELPER = "/opt/haprion/current/bin/haprion-server-state-helper"
SUDO = "/usr/bin/sudo"


def build_request(
    cluster_id: str, request_id: str, *, object_name: str, servers: list[str], state: str
) -> str:
    """The one request this helper reads, for the command line and the worker alike."""

    return json.dumps(
        {
            "schema_version": 1,
            "operation": OPERATION,
            "cluster": cluster_id,
            "request_id": request_id,
            "parameters": {"object": object_name, "servers": servers, "state": state},
        },
        separators=(",", ":"),
    )


def build_unblock_request(
    cluster_id: str, request_id: str, *, object_name: str, addresses: list[str]
) -> str:
    """An unblock, for the command line and the worker alike."""

    return json.dumps(
        {
            "schema_version": 1,
            "operation": UNBLOCK_OPERATION,
            "cluster": cluster_id,
            "request_id": request_id,
            "parameters": {"object": object_name, "addresses": addresses},
        },
        separators=(",", ":"),
    )


def _unblock_result(object_name: str, answers: tuple[Unblocked, ...]) -> dict[str, object]:
    return {
        "object": object_name,
        "nodes": [
            {
                "node": answer.node,
                "outcome": answer.outcome,
                "message": answer.message,
                "addresses": [
                    {"address": address, "outcome": outcome}
                    for address, outcome in answer.addresses
                ],
            }
            for answer in answers
        ],
    }


def _result(object_name: str, state: str, answers: tuple[Answer, ...]) -> dict[str, object]:
    nodes: dict[str, list[dict[str, object]]] = {}
    for answer in answers:
        nodes.setdefault(answer.node, []).append(
            {
                "server": answer.target.written,
                "guid": answer.target.guid,
                "outcome": answer.outcome,
                "message": answer.message,
            }
        )
    return {
        "object": object_name,
        "state": state,
        "nodes": [{"node": node, "servers": servers} for node, servers in nodes.items()],
    }


def main(
    argv: list[str] | None = None,
    *,
    policy_path: Path = DEFAULT_POLICY_PATH,
    input_stream: BinaryIO | None = None,
    output_stream: TextIO | None = None,
    error_stream: TextIO | None = None,
    require_secure: bool = True,
    require_root: bool = True,
    ask: NodeCall = ask_node,
    ask_unblocking: UnblockCall = ask_unblock,
) -> int:
    writer = output_stream or sys.stdout
    errors = error_stream or sys.stderr
    stream = input_stream or sys.stdin.buffer
    arguments = sys.argv[1:] if argv is None else argv

    try:
        require_no_arguments(arguments)
        if require_root and os.geteuid() != 0:
            raise HelperProtocolError(
                "server state helper must run as root", exit_code=exit_codes.NOT_ROOT
            )
        #
        # Read once, then parsed as the operation it names.
        #
        raw = read_raw_request(stream)
        named = peek_operation(raw)
        operation = named if named in PARAMETERS else OPERATION
        request = read_helper_request(
            io.BytesIO(raw),
            expected_operation=operation,
            allowed_parameter_keys=PARAMETERS[operation],
        )
    except HelperProtocolError as exc:
        errors.write(f"ERROR: {exc}\n")
        return exc.exit_code

    def refuse(code: str, message: str, exit_code: int) -> int:
        errors.write(f"ERROR: [{code}] {message}\n")
        return write_failure(
            writer,
            operation=request.operation,
            cluster=request.cluster,
            request_id=request.request_id,
            code=code,
            message=message,
            exit_code=exit_code,
        )

    parameters = request.parameters
    unblocking = request.operation == UNBLOCK_OPERATION
    state = parameters.get("state")
    servers = parameters.get("servers")
    wanted: tuple[str, ...] = ()
    if unblocking:
        try:
            wanted = addresses(parameters.get("addresses"))
        except ServerStateError as exc:
            return refuse(exc.code, str(exc), exc.exit_code)
    elif state not in STATES:
        return refuse("bad_input", f"state must be one of {', '.join(STATES)}", exit_codes.REFUSED)
    elif not isinstance(servers, list) or not all(isinstance(entry, str) for entry in servers):
        return refuse("bad_input", "servers must be a list of host:port", exit_codes.REFUSED)

    try:
        policy = load_policy(policy_path, require_secure=require_secure)
        cluster = load_runtime_config(policy, require_secure=require_secure).cluster(
            request.cluster
        )
    except ConfigError as exc:
        return refuse(config_error_code(exc.exit_code), str(exc), exc.exit_code)

    identity = policy.server_state_identity
    if identity is None:
        return refuse(
            "server_state_unavailable",
            "no server state identity is configured. Add server_state_identity with "
            "'user' and 'key' to the runtime policy.",
            exit_codes.CONFIG,
        )

    try:
        _branch, head = resolve_head(cluster.config_path)
        name = object_name(parameters.get("object"))
        #
        # The one object's file and not the whole directory: another object
        # that no longer loads must not stop a drain of this one.
        #
        files = read_tree_files(cluster.config_path, head, (f"{PROXY_PREFIX}{name}.yaml",))
        proxy = find_object(managed_proxies(files), name)
        targets: tuple[Target, ...] = ()
        if unblocking:
            blocking(proxy)
        elif isinstance(servers, list):
            targets = resolve(proxy, [str(entry) for entry in servers])
    except ServerStateError as exc:
        return refuse(exc.code, str(exc), exc.exit_code)
    except (ConfigError, GitError, PublishError, ModelError, OSError) as exc:
        return refuse(
            "dependency_unavailable",
            f"cannot read the cluster's newest version: {exc}",
            exit_codes.NOT_FOUND,
        )

    if unblocking:
        return write_unblocked(
            writer,
            request.cluster,
            request.request_id,
            proxy.name,
            unblock(cluster.nodes, identity, proxy, wanted, ask=ask_unblocking),
        )

    answers = apply(cluster.nodes, identity, targets, str(state), ask=ask)
    result = _result(proxy.name, str(state), answers)
    missed = [answer for answer in answers if answer.outcome != "done"]
    if not missed:
        return write_document(
            writer,
            envelope(
                operation=OPERATION,
                outcome="done",
                cluster=request.cluster,
                request_id=request.request_id,
                result=result,
            ),
            0,
        )

    warnings = tuple(
        Message(
            code="server_not_on_node"
            if answer.outcome == "refused"
            else "node_server_state_failed",
            message=f"{answer.target.written}: {answer.message}",
            node=answer.node,
        )
        for answer in missed
    )
    taken = len(answers) - len(missed)
    return write_document(
        writer,
        envelope(
            operation=OPERATION,
            outcome="partial" if taken else "failed",
            cluster=request.cluster,
            request_id=request.request_id,
            result=result,
            warnings=warnings,
            error=None
            if taken
            else Message(
                code="node_server_state_failed",
                message=f"no node took {state} for any of the servers",
            ),
        ),
        exit_codes.PARTIAL if taken else exit_codes.FAILED,
    )


def write_unblocked(
    writer: TextIO,
    cluster: str,
    request_id: str,
    name: str,
    answers: tuple[Unblocked, ...],
    *,
    operation: str = UNBLOCK_OPERATION,
) -> int:
    """`done` when every node took every address, `partial` when some did, else `failed`.

    For an unblock and for a block (`haprion-block-helper`) alike: the nodes
    answer both the same way.
    """

    placing = operation != UNBLOCK_OPERATION
    failed = "node_block_failed" if placing else "node_unblock_failed"

    result = _unblock_result(name, answers)
    missed = [answer for answer in answers if answer.outcome != "done"]
    if not missed:
        return write_document(
            writer,
            envelope(
                operation=operation,
                outcome="done",
                cluster=cluster,
                request_id=request_id,
                result=result,
            ),
            0,
        )
    warnings = tuple(
        Message(
            code="blocking_not_on_node" if answer.outcome == "refused" else failed,
            message=answer.message
            or ("the block was not placed" if placing else "the block was not lifted"),
            node=answer.node,
        )
        for answer in missed
    )
    taken = len(answers) - len(missed)
    return write_document(
        writer,
        envelope(
            operation=operation,
            outcome="partial" if taken else "failed",
            cluster=cluster,
            request_id=request_id,
            result=result,
            warnings=warnings,
            error=None
            if taken
            else Message(
                code=failed,
                message="no node placed the block" if placing else "no node lifted the block",
            ),
        ),
        exit_codes.PARTIAL if taken else exit_codes.FAILED,
    )


if __name__ == "__main__":
    raise SystemExit(main())
