"""The privileged, read-only half of ``haproxy-inventory``.

The poller may ask for a cluster by ID, but the helper chooses the repository
and the release inside the privilege boundary.  It reads the exact commit named
by the published RELEASE stamp; it never opens the repository working tree.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import BinaryIO, TextIO

from haproxy_mgmt.config import DEFAULT_POLICY_PATH, ConfigError, load_policy, load_runtime_config
from haproxy_mgmt.envelope import Message, envelope
from haproxy_mgmt.git_command import GitError
from haproxy_mgmt.helper_protocol import (
    HelperProtocolError,
    read_helper_request,
    require_no_arguments,
    write_document,
)
from haproxy_mgmt.inventory import InventoryError, inventory_result
from haproxy_mgmt.repo_snapshot import read_tree_files
from haproxy_mgmt.status_collect import read_target

OPERATION = "inventory"
PARAMETERS: frozenset[str] = frozenset()
EXIT_NOT_ROOT = 77

type ReadTree = Callable[[Path, str], Mapping[str, bytes]]


def main(
    argv: list[str] | None = None,
    *,
    policy_path: Path = DEFAULT_POLICY_PATH,
    input_stream: BinaryIO | None = None,
    output_stream: TextIO | None = None,
    error_stream: TextIO | None = None,
    require_secure: bool = True,
    require_root: bool = True,
    tree_reader: ReadTree = read_tree_files,
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    writer: TextIO = output_stream or sys.stdout
    errors: TextIO = error_stream or sys.stderr

    try:
        require_no_arguments(argv)
        if require_root and os.geteuid() != 0:
            raise HelperProtocolError(
                "haproxy-inventory-helper must run as root", exit_code=EXIT_NOT_ROOT
            )
        request = read_helper_request(
            input_stream or sys.stdin.buffer,
            expected_operation=OPERATION,
            allowed_parameter_keys=PARAMETERS,
        )
    except HelperProtocolError as exc:
        errors.write(f"ERROR: {exc}\n")
        return exc.exit_code

    try:
        policy = load_policy(policy_path, require_secure=require_secure)
        cluster = load_runtime_config(policy, require_secure=require_secure).cluster(
            request.cluster
        )
    except ConfigError as exc:
        errors.write(f"ERROR: {exc}\n")
        return exc.exit_code

    target = read_target(Path(cluster.publish_path), cluster.node_path)
    try:
        files: Mapping[str, bytes] = {}
        if target is not None:
            files = tree_reader(Path(cluster.config_path), target.hash)
        result = inventory_result(files, target)
    except GitError as exc:
        write_document(
            writer,
            envelope(
                operation=OPERATION,
                outcome="failed",
                cluster=request.cluster,
                request_id=request.request_id,
                result=None,
                error=Message(code="inventory_unavailable", message=str(exc)),
            ),
        )
        return exc.exit_code
    except InventoryError as exc:
        write_document(
            writer,
            envelope(
                operation=OPERATION,
                outcome="failed",
                cluster=request.cluster,
                request_id=request.request_id,
                result=None,
                error=Message(code="inventory_invalid", message=str(exc)),
            ),
        )
        return 65

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
