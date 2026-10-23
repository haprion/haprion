"""``haprion-state-backup`` - fetch complete DR state from configured nodes.

    haprion-state-backup [-c <cluster>]
    haprion-state-backup -c <cluster> --json

`--json` prints the envelope the interface's *Run backup now* job records
(`schemas/v1/haprion-backup-run`), for one cluster.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import TextIO

from haprion import exit_codes
from haprion.backup_retention import RetentionError
from haprion.backup_retention import read as read_retention
from haprion.cli import backup_job_helper
from haprion.config import (
    DEFAULT_POLICY_PATH,
    Cluster,
    ConfigError,
    DeployIdentity,
    load_policy,
    load_runtime_config,
)
from haprion.envelope import failure, new_request_id
from haprion.helper_protocol import write_document
from haprion.state_backup import BackupBusy, BackupResult, BackupRunError, run

USAGE = "Usage: haprion-state-backup [-c <cluster>] | -c <cluster> --json\n"

type Runner = Callable[[str, Cluster, DeployIdentity | None, Path | None, int], BackupResult]


def _parse(argv: list[str]) -> tuple[str | None, bool]:
    """(the cluster, or None for every one; --json, which needs one)."""

    json_mode = "--json" in argv
    rest = [item for item in argv if item != "--json"]
    if not rest and not json_mode:
        return None, False
    if len(rest) == 2 and rest[0] in {"-c", "--cluster"} and rest[1]:
        return rest[1], json_mode
    raise ValueError("invalid arguments")


def _write(result: BackupResult, writer: TextIO) -> None:
    writer.write(f"=== {result.cluster}: {result.outcome} ===\n")
    for node in result.nodes:
        if node.outcome == "done":
            writer.write(f"  {node.name}: {node.version}.tar.gz ({node.size_bytes} bytes)\n")
        else:
            writer.write(f"  {node.name}: FAILED [{node.error}]\n")


def main(
    argv: list[str] | None = None,
    *,
    policy_path: Path = DEFAULT_POLICY_PATH,
    output_stream: TextIO | None = None,
    error_stream: TextIO | None = None,
    require_secure: bool = True,
    require_root: bool = True,
    runner: Runner = run,
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    writer = output_stream or sys.stdout
    errors = error_stream or sys.stderr
    try:
        selected, json_mode = _parse(argv)
    except ValueError:
        errors.write(USAGE)
        return exit_codes.USAGE

    def refuse(cluster: str | None, code: str, message: str, exit_code: int) -> int:
        """Said on stderr, and with --json as the one document the contract promises."""

        errors.write(f"ERROR: {message}\n")
        if json_mode:
            write_document(
                writer,
                failure(
                    operation=backup_job_helper.RUN,
                    cluster=cluster,
                    request_id=new_request_id(),
                    code=code,
                    message=message,
                    exit_code=exit_code,
                ),
                exit_code,
            )
        return exit_code

    if require_root and os.geteuid() != 0:
        return refuse(
            selected, "not_root", "haprion-state-backup must run as root", exit_codes.NOT_ROOT
        )

    try:
        policy = load_policy(policy_path, require_secure=require_secure)
        runtime = load_runtime_config(policy, require_secure=require_secure)
        clusters = (
            ((selected, runtime.cluster(selected)),)
            if selected is not None
            else tuple(runtime.clusters.items())
        )
    except ConfigError as exc:
        return refuse(selected, "dependency_unavailable", str(exc), exc.exit_code)

    failed = False
    for cluster_id, cluster in clusters:
        try:
            #
            # The count the Backups page set for this cluster, read here and by
            # the socket helper alike: a terminal run prunes to the same number
            # the schedule promised.
            #
            retention = read_retention(cluster_id)
            result = runner(
                cluster_id, cluster, policy.backup_identity, policy.backup_root, retention
            )
        except (BackupRunError, RetentionError) as exc:
            refused = "backup_busy" if isinstance(exc, BackupBusy) else "backup_failed"
            refuse(cluster_id, refused, f"{cluster_id}: {exc}", exit_codes.FAILED)
            failed = True
            continue
        if json_mode:
            document, code = backup_job_helper.run_document(
                result, cluster=cluster_id, request_id=new_request_id()
            )
            return write_document(writer, document, code)
        _write(result, writer)
        failed = failed or result.outcome != "done"
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
