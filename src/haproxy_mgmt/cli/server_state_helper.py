"""The privileged half of `haproxy-server-state` - drain, maintenance or ready.

Takes no arguments; the request arrives on stdin, for the reason every helper
gives: PRIVILEGE.md forbids wildcards in sudoers argument matching, so one
no-argument rule covers every cluster.

Root for one thing: the server state identity's private key is root-owned,
because no application identity may hold a key that reaches a node. Nothing on
the manager is written, and the cluster lock is not taken - see
`haproxy_mgmt.server_state` for why a deploy at the same time is safe.

What it does not trust: the servers. They are found in the object, in the
cluster's newest committed version, before any node is asked; the node then
validates the GUID and the state again before anything reaches HAProxy.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import BinaryIO, TextIO

from haproxy_mgmt.config import (
    DEFAULT_POLICY_PATH,
    ConfigError,
    load_policy,
    load_runtime_config,
)
from haproxy_mgmt.envelope import Message, envelope
from haproxy_mgmt.git_command import GitError
from haproxy_mgmt.helper_protocol import (
    HelperProtocolError,
    config_error_code,
    read_helper_request,
    require_no_arguments,
    write_document,
    write_failure,
)
from haproxy_mgmt.managed_publish import PROXY_PREFIX, managed_proxies
from haproxy_mgmt.proxy_model import ModelError
from haproxy_mgmt.repo_snapshot import PublishError, read_tree_files, resolve_head
from haproxy_mgmt.server_state import (
    OPERATION,
    STATES,
    Answer,
    NodeCall,
    ServerStateError,
    apply,
    ask_node,
    find_object,
    object_name,
    resolve,
)

PARAMETERS = frozenset({"object", "servers", "state"})

HELPER = "/opt/haproxy-mgmt/current/bin/haproxy-server-state-helper"
SUDO = "/usr/bin/sudo"

EXIT_NOT_ROOT = 77
EXIT_NO_IDENTITY = 78
#
# Some node did not take every server: `partial` when another did, `failed`
# when none did. Deploy's code for a cluster that did not converge.
#
EXIT_INCOMPLETE = 69


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
) -> int:
    writer = output_stream or sys.stdout
    errors = error_stream or sys.stderr
    stream = input_stream or sys.stdin.buffer
    arguments = sys.argv[1:] if argv is None else argv

    try:
        require_no_arguments(arguments)
        if require_root and os.geteuid() != 0:
            raise HelperProtocolError(
                "server state helper must run as root", exit_code=EXIT_NOT_ROOT
            )
        request = read_helper_request(
            stream, expected_operation=OPERATION, allowed_parameter_keys=PARAMETERS
        )
    except HelperProtocolError as exc:
        errors.write(f"ERROR: {exc}\n")
        return exc.exit_code

    def refuse(code: str, message: str, exit_code: int) -> int:
        errors.write(f"ERROR: [{code}] {message}\n")
        return write_failure(
            writer,
            operation=OPERATION,
            cluster=request.cluster,
            request_id=request.request_id,
            code=code,
            message=message,
            exit_code=exit_code,
        )

    parameters = request.parameters
    state = parameters.get("state")
    servers = parameters.get("servers")
    if state not in STATES:
        return refuse("bad_input", f"state must be one of {', '.join(STATES)}", 65)
    if not isinstance(servers, list) or not all(isinstance(entry, str) for entry in servers):
        return refuse("bad_input", "servers must be a list of host:port", 65)

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
            EXIT_NO_IDENTITY,
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
        targets = resolve(proxy, [str(entry) for entry in servers])
    except ServerStateError as exc:
        return refuse(exc.code, str(exc), exc.exit_code)
    except (ConfigError, GitError, PublishError, ModelError, OSError) as exc:
        return refuse(
            "dependency_unavailable", f"cannot read the cluster's newest version: {exc}", 66
        )

    answers = apply(cluster.nodes, identity, targets, str(state), ask=ask)
    result = _result(proxy.name, str(state), answers)
    missed = [answer for answer in answers if answer.outcome != "done"]
    if not missed:
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
    write_document(
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
    )
    return EXIT_INCOMPLETE


if __name__ == "__main__":
    raise SystemExit(main())
