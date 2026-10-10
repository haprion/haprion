"""The privileged, read-only half of ``haprion-list-backups``.

The backup root is root-owned because the archives inside it hold password
hashes and private SSH keys. This helper is what lets an unprivileged caller
learn that a backup exists without being able to read one: it reports names,
sizes and times, and never opens an archive.

The caller names a cluster, never a directory. Which nodes that cluster has, and
which root their backups live under, are resolved inside the privilege boundary
from configuration - so a caller cannot ask this for a path of its choosing.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any, BinaryIO, TextIO

from haprion import backup_retention
from haprion.backup_schedule import ScheduleError, schedule_result
from haprion.backup_schedule_write import timer_unit
from haprion.backups import BackupError, backup_list_result
from haprion.config import (
    DEFAULT_POLICY_PATH,
    NAME,
    ConfigError,
    load_policy,
    load_runtime_config,
)
from haprion.envelope import Message, envelope
from haprion.helper_protocol import (
    HelperProtocolError,
    config_error_code,
    read_helper_request,
    require_no_arguments,
    write_document,
    write_failure,
)

OPERATION = "list_backups"
PARAMETERS: frozenset[str] = frozenset({"limit", "node"})
DEFAULT_LIMIT = 14
MAX_LIMIT = 1000
EXIT_NOT_ROOT = 77


def _limit(parameters: Mapping[str, Any]) -> int | None:
    """How many archives per node to report, with null meaning every one kept.

    Bounded even though the caller is the poller: a directory holds one file per
    retained backup, and an unbounded listing is one retention change away from
    an envelope nothing wants to read or store.

    One function rather than a validator and a separate reader, so "what counts
    as a valid limit" cannot be answered twice and differently.
    """

    raw = parameters.get("limit", DEFAULT_LIMIT)
    if raw is None:
        return None
    if not isinstance(raw, int) or isinstance(raw, bool) or not 1 <= raw <= MAX_LIMIT:
        raise HelperProtocolError(
            f"limit must be null or an integer between 1 and {MAX_LIMIT}", exit_code=65
        )
    return raw


def _node(parameters: Mapping[str, Any]) -> str | None:
    """Which single node to report, or null for every node in the cluster.

    Filtered here rather than by the caller, so a listing for one node reads
    exactly one directory. The caller is unprivileged and the boundary is the
    point: less crosses it, and nothing the caller does can widen what was
    asked for.
    """

    raw = parameters.get("node")
    if raw is None:
        return None
    if not isinstance(raw, str) or not NAME.fullmatch(raw):
        raise HelperProtocolError("node is not a valid node name", exit_code=64)
    return raw


def _validate_parameters(parameters: Mapping[str, Any]) -> None:
    """Reject a bad limit or node while the request is being read, not after."""

    _limit(parameters)
    _node(parameters)


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
                "haprion-list-backups-helper must run as root", exit_code=EXIT_NOT_ROOT
            )
        request = read_helper_request(
            input_stream or sys.stdin.buffer,
            expected_operation=OPERATION,
            allowed_parameter_keys=PARAMETERS,
            validate_parameters=_validate_parameters,
        )
    except HelperProtocolError as exc:
        #
        # Deliberately stderr only. The cluster and the request ID an envelope
        # must be bound to are fields of the request that just failed to parse;
        # an envelope invented here could not be bound to the caller's request
        # and would rightly be rejected as somebody else's answer.
        #
        errors.write(f"ERROR: {exc}\n")
        return exc.exit_code

    try:
        policy = load_policy(policy_path, require_secure=require_secure)
        cluster = load_runtime_config(policy, require_secure=require_secure).cluster(
            request.cluster
        )
    except ConfigError as exc:
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

    if policy.backup_root is None:
        write_document(
            writer,
            envelope(
                operation=OPERATION,
                outcome="failed",
                cluster=request.cluster,
                request_id=request.request_id,
                result=None,
                error=Message(
                    code="backup_metadata_unavailable",
                    message="the runtime policy declares no backup_root",
                ),
            ),
        )
        return 65

    selected = _node(request.parameters)
    nodes = tuple(node for node in cluster.nodes if selected is None or node.name == selected)
    if not nodes:
        #
        # An empty node list is refused rather than reported. The schema needs
        # at least one node, and an empty listing would read as "this node has
        # no backups" when the truth is "this cluster has no such node".
        #
        write_document(
            writer,
            envelope(
                operation=OPERATION,
                outcome="failed",
                cluster=request.cluster,
                request_id=request.request_id,
                result=None,
                error=Message(
                    code="bad_input",
                    message=f"cluster {request.cluster} has no node named {selected}",
                ),
            ),
        )
        return 64

    try:
        result, readings = backup_list_result(
            policy.backup_root, nodes, limit=_limit(request.parameters)
        )
        #
        # Read here rather than by the caller, and reported with the listing
        # rather than on its own: "these archives exist" and "something is still
        # producing them" are one question asked twice, and an interface that
        # had to correlate two commands to answer it would eventually show one
        # without the other.
        #
        result["schedule"] = schedule_result(
            timer_unit(request.cluster)
            if getattr(policy, "backup_identity", None) is not None
            else None
        )
        #
        # And how many each node keeps, from the same file the pruning reads.
        # It is reported beside the schedule because the page shows it there,
        # and a listing whose count came from the code's default would promise
        # fourteen on a cluster set to keep sixty.
        #
        if result["schedule"] is not None:
            result["schedule"]["retention"] = backup_retention.read(request.cluster)
    except (BackupError, ScheduleError, backup_retention.RetentionError) as exc:
        write_document(
            writer,
            envelope(
                operation=OPERATION,
                outcome="failed",
                cluster=request.cluster,
                request_id=request.request_id,
                result=None,
                error=Message(code="backup_metadata_unavailable", message=str(exc)),
            ),
        )
        return 65

    #
    # One unreadable node is `partial`, not `failed`: the other node's backups
    # are exactly what an operator needs during the incident where one node is
    # gone. Every node unreadable is still partial rather than failed, because
    # the answer is true - there are no backups to be found - and the per-node
    # errors say why.
    #
    unreadable = tuple(reading for reading in readings if reading.error is not None)
    if unreadable:
        write_document(
            writer,
            envelope(
                operation=OPERATION,
                outcome="partial",
                cluster=request.cluster,
                request_id=request.request_id,
                result=result,
                warnings=tuple(
                    Message(
                        code=reading.error or "backup_metadata_unavailable",
                        message="Backup metadata is unavailable for one node",
                        node=reading.name,
                    )
                    for reading in unreadable
                ),
            ),
        )
        return 0

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
