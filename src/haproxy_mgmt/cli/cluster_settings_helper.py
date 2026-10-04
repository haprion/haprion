"""The privileged, read-only half of ``haproxy-cluster-settings`` (Fas 15).

The cluster's own settings - external log targets and the metrics exporter -
read from the published head of its repository inside the boundary the
interface's identities are kept out of, with the head they were read at, which
a change built from this reading must name.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import BinaryIO, TextIO

from haproxy_mgmt.cluster_settings import LOCATION, document_result, load_document
from haproxy_mgmt.config import (
    DEFAULT_POLICY_PATH,
    Cluster,
    ConfigError,
    load_policy,
    load_runtime_config,
)
from haproxy_mgmt.envelope import envelope
from haproxy_mgmt.helper_protocol import (
    HelperProtocolError,
    config_error_code,
    read_helper_request,
    require_no_arguments,
    write_document,
    write_failure,
)
from haproxy_mgmt.repo_snapshot import read_tree_files, resolve_head

OPERATION = "cluster_settings"
PARAMETERS: frozenset[str] = frozenset()
EXIT_NOT_ROOT = 77


def settings_result(cluster: Cluster) -> dict[str, object]:
    """The settings at the published head, and that head."""

    _branch, head = resolve_head(cluster.config_path)
    files = read_tree_files(cluster.config_path, head, (LOCATION,))
    return {
        "cluster": cluster.cluster_id,
        "head": head,
        "stored": LOCATION in files,
        **document_result(load_document(files.get(LOCATION))),
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
                "haproxy-cluster-settings-helper must run as root", exit_code=EXIT_NOT_ROOT
            )
        request = read_helper_request(
            input_stream or sys.stdin.buffer,
            expected_operation=OPERATION,
            allowed_parameter_keys=PARAMETERS,
        )
    except HelperProtocolError as exc:
        #
        # Deliberately stderr only, for the same reason every other helper does
        # it: the cluster and request ID an envelope must be bound to are
        # fields of the request that just failed to parse.
        #
        errors.write(f"ERROR: {exc}\n")
        return exc.exit_code

    try:
        policy = load_policy(policy_path, require_secure=require_secure)
        cluster = load_runtime_config(policy, require_secure=require_secure).cluster(
            request.cluster
        )
        result = settings_result(cluster)
    except ConfigError as exc:
        #
        # A malformed `managed/network.yaml` arrives here as a ConfigError and
        # is reported as one. Falling back to the engine's own tables when the
        # repository's description does not parse would answer with a different
        # network than the one somebody wrote, which is worse than refusing.
        #
        errors.write(f"ERROR: {exc}\n")
        return write_failure(
            writer,
            operation=OPERATION,
            cluster=request.cluster,
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
            cluster=request.cluster,
            request_id=request.request_id,
            result=result,
        ),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
