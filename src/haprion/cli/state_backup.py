"""``haprion-state-backup`` - fetch complete DR state from configured nodes."""

from __future__ import annotations

import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import TextIO

from haprion.backup_retention import RetentionError
from haprion.backup_retention import read as read_retention
from haprion.config import (
    DEFAULT_POLICY_PATH,
    Cluster,
    ConfigError,
    DeployIdentity,
    load_policy,
    load_runtime_config,
)
from haprion.state_backup import BackupResult, BackupRunError, run

EXIT_USAGE = 64
EXIT_NOT_ROOT = 77
USAGE = "Usage: haprion-state-backup [-c <cluster>]\n"

type Runner = Callable[[str, Cluster, DeployIdentity | None, Path | None, int], BackupResult]


def _parse(argv: list[str]) -> str | None:
    if not argv:
        return None
    if len(argv) == 2 and argv[0] in {"-c", "--cluster"} and argv[1]:
        return argv[1]
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
        selected = _parse(argv)
    except ValueError:
        errors.write(USAGE)
        return EXIT_USAGE

    if require_root and os.geteuid() != 0:
        errors.write("ERROR: haprion-state-backup must run as root\n")
        return EXIT_NOT_ROOT

    try:
        policy = load_policy(policy_path, require_secure=require_secure)
        runtime = load_runtime_config(policy, require_secure=require_secure)
        clusters = (
            ((selected, runtime.cluster(selected)),)
            if selected is not None
            else tuple(runtime.clusters.items())
        )
    except ConfigError as exc:
        errors.write(f"ERROR: {exc}\n")
        return exc.exit_code

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
            errors.write(f"ERROR: {cluster_id}: {exc}\n")
            failed = True
            continue
        _write(result, writer)
        failed = failed or result.outcome != "done"
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
