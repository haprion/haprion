"""The privileged half of an outside block (B412): `haprion-block-ask` asks, this places it.

Started by `_haprion-block` through sudo, with the request on stdin and no
arguments, like every helper. That account is shared by every block client, so
the request names the client - and the client's word is the one its
`authorized_keys` line forces (`haprion-block-ask <id>`), which the client
cannot change. Before any node is asked:

- the client is in the registry, and the object is one of the objects it was
  given, in its own cluster;
- the object's newest version blocks at all;
- no address is one the object exempts, which the rules would never refuse.

Then the same key and forced command as *Unblock*, with the verb `block`
(`server_state.block`). This helper can do nothing else: it does not lift a
block, set a server's state or read anything back but the nodes' answers -
which is why it is a helper of its own rather than an operation of
`haprion-server-state-helper`, whose request could name any of those.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import BinaryIO, TextIO

import yaml

from haprion import block_clients, exit_codes, safe_yaml
from haprion.block_clients import BlockClientError
from haprion.cli.server_state_helper import write_unblocked
from haprion.config import (
    DEFAULT_POLICY_PATH,
    NETWORK_FILE,
    ConfigError,
    load_policy,
    load_runtime_config,
)
from haprion.git_command import GitError
from haprion.helper_protocol import (
    HelperProtocolError,
    config_error_code,
    read_helper_request,
    require_no_arguments,
    write_failure,
)
from haprion.managed_network import load_mapping
from haprion.managed_publish import PROXY_PREFIX, managed_proxies
from haprion.proxy_model import ModelError
from haprion.repo_snapshot import PublishError, read_tree_files, resolve_head
from haprion.server_state import (
    BLOCK_OPERATION,
    ServerStateError,
    UnblockCall,
    addresses,
    ask_unblock,
    block,
    blocking,
    exempted,
    find_object,
    object_name,
)

HELPER = "/opt/haprion/current/bin/haprion-block-helper"
PARAMETERS = frozenset({"client", "object", "addresses"})


def main(
    argv: list[str] | None = None,
    *,
    policy_path: Path = DEFAULT_POLICY_PATH,
    clients_file: Path = block_clients.CLIENTS_FILE,
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
                "block helper must run as root", exit_code=exit_codes.NOT_ROOT
            )
        request = read_helper_request(
            stream, expected_operation=BLOCK_OPERATION, allowed_parameter_keys=PARAMETERS
        )
    except HelperProtocolError as exc:
        errors.write(f"ERROR: {exc}\n")
        return exc.exit_code

    def refuse(code: str, message: str, exit_code: int) -> int:
        errors.write(f"ERROR: [{code}] {message}\n")
        return write_failure(
            writer,
            operation=BLOCK_OPERATION,
            cluster=request.cluster,
            request_id=request.request_id,
            code=code,
            message=message,
            exit_code=exit_code,
        )

    parameters = request.parameters
    try:
        wanted = addresses(parameters.get("addresses"))
        name = object_name(parameters.get("object"))
        clients = block_clients.read(clients_file)
        block_clients.may_block(
            clients, block_clients.client_id(parameters.get("client")), request.cluster, name
        )
    except (ServerStateError, BlockClientError) as exc:
        return refuse(exc.code, str(exc), exc.exit_code)

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
        files = read_tree_files(
            cluster.config_path, head, (f"{PROXY_PREFIX}{name}.yaml", str(NETWORK_FILE))
        )
        proxy = blocking(find_object(managed_proxies(files), name))
        written = files.get(str(NETWORK_FILE))
        networks = (
            load_mapping(
                safe_yaml.load(written), ownership_vip=cluster.vip, location=str(NETWORK_FILE)
            ).networks
            if written is not None
            else cluster.networks
        )
    except ServerStateError as exc:
        return refuse(exc.code, str(exc), exc.exit_code)
    except (ConfigError, GitError, PublishError, ModelError, OSError, yaml.YAMLError) as exc:
        return refuse(
            "dependency_unavailable",
            f"cannot read the cluster's newest version: {exc}",
            exit_codes.NOT_FOUND,
        )

    spared = exempted(proxy, wanted, networks)
    if spared:
        return refuse(
            "bad_input",
            f"{name} never blocks {', '.join(spared)}: the object exempts it",
            exit_codes.REFUSED,
        )
    return write_unblocked(
        writer,
        request.cluster,
        request.request_id,
        proxy.name,
        block(cluster.nodes, identity, proxy, wanted, ask=ask),
        operation=BLOCK_OPERATION,
    )


if __name__ == "__main__":
    raise SystemExit(main())
