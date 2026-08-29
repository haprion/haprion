"""The privileged, read-only half of ``haproxy-list``.

A human running `haproxy-list` can already read the cluster repository, so the
command itself needs no privilege. The interface's poller cannot and must not:
the configuration repositories are readable by the management group only, and
giving the web platform's poller a group membership to read them would hand it
every cluster's published configuration for the sake of a listing.

So it asks root for exactly this, through one sudoers rule, with no arguments.
The caller names a cluster; the helper chooses the repository inside the
privilege boundary and returns a version listing and nothing else. It opens no
file in the work tree and writes nothing anywhere.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import BinaryIO, TextIO

from haproxy_mgmt.config import DEFAULT_POLICY_PATH, ConfigError, load_policy, load_runtime_config
from haproxy_mgmt.envelope import Message, envelope
from haproxy_mgmt.git_command import GitError
from haproxy_mgmt.helper_protocol import (
    HelperProtocolError,
    read_helper_request,
    require_no_arguments,
)
from haproxy_mgmt.history import history_result
from haproxy_mgmt.repo_health import describe_problem, is_repo_root
from haproxy_mgmt.status_collect import read_target
from haproxy_mgmt.version_history import recent_versions

OPERATION = "list"
PARAMETERS: frozenset[str] = frozenset()
EXIT_NOT_ROOT = 77


def _write(writer: TextIO, document: dict[str, object]) -> None:
    writer.write(json.dumps(document, separators=(",", ":"), sort_keys=True) + "\n")


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
                "haproxy-list-helper must run as root", exit_code=EXIT_NOT_ROOT
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

    repo = Path(cluster.config_path)
    #
    # A missing or broken repository is the cluster's answer, not this process
    # failing to run. It is reported in the envelope so the interface can show
    # the cluster as unreadable while the others keep rendering.
    #
    if not is_repo_root(repo):
        _write(
            writer,
            envelope(
                operation=OPERATION,
                outcome="failed",
                cluster=request.cluster,
                request_id=request.request_id,
                result=None,
                error=Message(
                    code="history_unavailable",
                    message=describe_problem(request.cluster, repo),
                ),
            ),
        )
        return 68

    target = read_target(Path(cluster.publish_path), cluster.node_path)
    try:
        result = history_result(recent_versions(repo), target)
    except GitError as exc:
        _write(
            writer,
            envelope(
                operation=OPERATION,
                outcome="failed",
                cluster=request.cluster,
                request_id=request.request_id,
                result=None,
                error=Message(code="history_unavailable", message=str(exc)),
            ),
        )
        return exc.exit_code

    _write(
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
