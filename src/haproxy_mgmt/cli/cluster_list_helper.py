"""Which clusters exist, for the interface's poller (Fas 16, B206/B211).

The cluster file, read inside the boundary the interface's identities are kept
out of, answered as the clusters' IDs and display names in the file's order.
The poller asks on every pass, so a cluster created or removed from Settings
is on the pages at the next pass instead of after somebody edits `ui.toml` and
restarts the services. Read-only, and nothing in the answer is a path.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import BinaryIO, TextIO

from haproxy_mgmt.config import (
    DEFAULT_POLICY_PATH,
    ConfigError,
    RuntimeConfig,
    load_policy,
    load_runtime_config,
)
from haproxy_mgmt.envelope import envelope
from haproxy_mgmt.helper_protocol import (
    HelperProtocolError,
    config_error_code,
    read_clusterless_request,
    require_no_arguments,
    write_document,
    write_failure,
)

OPERATION = "cluster_list"
HELPER = "/opt/haprion/current/bin/haprion-cluster-list-helper"
EXIT_NOT_ROOT = 77
SUDO = "/usr/bin/sudo"


def build_request(request_id: str) -> str:
    return json.dumps(
        {
            "schema_version": 1,
            "operation": OPERATION,
            "cluster": None,
            "request_id": request_id,
            "parameters": {},
        },
        separators=(",", ":"),
    )


def run_cluster_list_helper(request_id: str) -> subprocess.CompletedProcess[str]:
    """Ask the root helper which clusters exist; the poller's one sudo rule for it."""

    return subprocess.run(  # noqa: S603 - fixed helper path, no caller argv
        [SUDO, "-n", HELPER],
        input=build_request(request_id),
        capture_output=True,
        text=True,
        check=False,
    )


def list_result(runtime: RuntimeConfig) -> dict[str, object]:
    """Every cluster in the file's order, which is the order the pages draw them in."""

    return {
        "clusters": [
            {
                "id": cluster.cluster_id,
                "display_name": cluster.display_name,
                "nodes": len(cluster.nodes),
            }
            for cluster in runtime.clusters.values()
        ]
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
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    writer: TextIO = output_stream or sys.stdout
    errors: TextIO = error_stream or sys.stderr

    try:
        require_no_arguments(argv)
        if require_root and os.geteuid() != 0:
            raise HelperProtocolError(
                "haprion-cluster-list-helper must run as root", exit_code=EXIT_NOT_ROOT
            )
        request = read_clusterless_request(
            input_stream or sys.stdin.buffer, expected_operation=OPERATION
        )
    except HelperProtocolError as exc:
        errors.write(f"ERROR: {exc}\n")
        return exc.exit_code

    try:
        policy = load_policy(policy_path, require_secure=require_secure)
        result = list_result(load_runtime_config(policy, require_secure=require_secure))
    except ConfigError as exc:
        errors.write(f"ERROR: {exc}\n")
        return write_failure(
            writer,
            operation=OPERATION,
            cluster=None,
            request_id=request.request_id,
            code=config_error_code(exc.exit_code),
            message=str(exc),
            exit_code=exc.exit_code,
        )

    write_document(
        writer,
        envelope(
            operation=OPERATION,
            outcome="done",
            cluster=None,
            request_id=request.request_id,
            result=result,
        ),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
