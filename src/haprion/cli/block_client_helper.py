"""The privileged half of `haprion-block-client`: add or remove a block client (B412).

Root, no arguments, the request on stdin - from the command line through
sudo, and from the worker for the settings page. It writes two files and
nothing else: `_haprion-block`'s `authorized_keys` and the registry it is
rendered from (`block_clients.store`). The account, its home and the sudoers
rule that lets it start `haprion-block-helper` are the installation's
(01-manager-prepare, 02-manager-config), so a change here never runs useradd
or touches sshd.

An added client's objects must be in its cluster's newest version and block
there: a client given an object it can never block on would fail at its first
ban, at night, in fail2ban's log rather than here.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import BinaryIO, TextIO

from haprion import block_clients, exit_codes
from haprion.block_clients import BlockClientError
from haprion.cert_receiver import resolve_forward
from haprion.config import DEFAULT_POLICY_PATH, ConfigError, load_policy, load_runtime_config
from haprion.envelope import envelope
from haprion.git_command import GitError
from haprion.helper_protocol import (
    HelperProtocolError,
    config_error_code,
    read_helper_request,
    require_no_arguments,
    write_document,
    write_failure,
)
from haprion.managed_publish import PROXY_PREFIX, managed_proxies
from haprion.proxy_model import ModelError
from haprion.repo_snapshot import PublishError, read_tree_files, resolve_head

OPERATION = "block_client"
HELPER = "/opt/haprion/current/bin/haprion-block-client-helper"
PARAMETERS = frozenset({"action", "client", "host", "objects", "key", "by"})
ACTIONS = ("add", "remove")


def main(
    argv: list[str] | None = None,
    *,
    policy_path: Path = DEFAULT_POLICY_PATH,
    clients_file: Path = block_clients.CLIENTS_FILE,
    keys_file: Path = block_clients.KEYS_FILE,
    input_stream: BinaryIO | None = None,
    output_stream: TextIO | None = None,
    error_stream: TextIO | None = None,
    require_secure: bool = True,
    require_root: bool = True,
    forward: block_clients.Forward = resolve_forward,
) -> int:
    writer = output_stream or sys.stdout
    errors = error_stream or sys.stderr
    stream = input_stream or sys.stdin.buffer
    arguments = sys.argv[1:] if argv is None else argv

    try:
        require_no_arguments(arguments)
        if require_root and os.geteuid() != 0:
            raise HelperProtocolError(
                "block client helper must run as root", exit_code=exit_codes.NOT_ROOT
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
    action = parameters.get("action")
    if action not in ACTIONS:
        return refuse("bad_input", "action must be add or remove", exit_codes.REFUSED)
    by = parameters.get("by")
    actor = by if isinstance(by, str) and by else os.environ.get("SUDO_USER", "")
    try:
        clients = block_clients.read(clients_file)
        if action == "remove":
            identifier = block_clients.client_id(parameters.get("client"))
            changed = block_clients.removed(clients, identifier)
            shown = clients[identifier].shown()
        else:
            new = block_clients.client(
                parameters.get("client"),
                host=parameters.get("host"),
                cluster=request.cluster,
                objects=parameters.get("objects"),
                key=parameters.get("key"),
            )
            _blocking_objects(policy_path, request.cluster, new.objects, require_secure)
            changed = block_clients.added(clients, new, by=actor[:64])
            shown = changed[new.client_id].shown()
        block_clients.store(changed, forward, clients_file=clients_file, keys_file=keys_file)
    except BlockClientError as exc:
        return refuse(exc.code, str(exc), exc.exit_code)
    except OSError as exc:
        return refuse(
            "io_error", f"the block client files could not be written: {exc}", exit_codes.IO_ERROR
        )

    return write_document(
        writer,
        envelope(
            operation=OPERATION,
            outcome="done",
            cluster=request.cluster,
            request_id=request.request_id,
            result={"action": action, "client": shown},
        ),
        0,
    )


def _blocking_objects(
    policy_path: Path, cluster_id: str, names: tuple[str, ...], require_secure: bool
) -> None:
    """Refused unless every object is in the cluster's newest version and blocks."""

    try:
        policy = load_policy(policy_path, require_secure=require_secure)
        cluster = load_runtime_config(policy, require_secure=require_secure).cluster(cluster_id)
        _branch, head = resolve_head(cluster.config_path)
        files = read_tree_files(
            cluster.config_path, head, tuple(f"{PROXY_PREFIX}{name}.yaml" for name in names)
        )
        proxies = {proxy.name: proxy for proxy in managed_proxies(files)}
    except ConfigError as exc:
        raise BlockClientError(
            config_error_code(exc.exit_code), str(exc), exit_code=exc.exit_code
        ) from exc
    except (GitError, PublishError, ModelError, OSError) as exc:
        raise BlockClientError(
            "dependency_unavailable",
            f"cannot read the cluster's newest version: {exc}",
            exit_code=exit_codes.NOT_FOUND,
        ) from exc
    for name in names:
        proxy = proxies.get(name)
        if proxy is None:
            raise BlockClientError("bad_input", f"{cluster_id} has no object {name}")
        if proxy.dynamic_block is None:
            raise BlockClientError(
                "bad_input", f"{name} has no dynamic blocking; turn it on before a client may block"
            )


if __name__ == "__main__":
    raise SystemExit(main())
