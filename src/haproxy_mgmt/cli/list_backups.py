"""``haproxy-list-backups`` - which state backups exist per node, read-only.

Replaces a shell implementation that read the backup directory directly with a
hardcoded node list. Two things change and one deliberately does not: the nodes
now come from cluster configuration, and the answer is a schema-checked
envelope. The CREATED column still shows the archive's modification time, which
is what the shell version showed - a reimplementation that quietly answered a
different question would be worse than no reimplementation.
"""

from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, TextIO

from haproxy_mgmt.cli.caller import usage
from haproxy_mgmt.config import ConfigError, load_policy, load_runtime_config
from haproxy_mgmt.envelope import new_request_id

OPERATION = "list_backups"
HELPER = "/opt/haproxy-mgmt/current/bin/haproxy-list-backups-helper"
SUDO = "/usr/bin/sudo"
DEFAULT_LIMIT = 10
EXIT_UNAVAILABLE = 68
USAGE = (
    "Usage:\n"
    "  haproxy-list-backups [-c <cluster>] [--node <name>] [--all] [--json]\n"
    "\n"
    "  -c      one cluster; without it, every configured cluster in turn\n"
    "  --node  one node, instead of every node in the cluster\n"
    "  --all   every retained backup, instead of the 10 most recent per node\n"
    "  --json  the raw envelope, which is one cluster's answer - so -c is required\n"
)

type RunHelper = Callable[..., subprocess.CompletedProcess[str]]


def run_list_backups_helper(
    cluster_id: str,
    request_id: str,
    limit: int | None = DEFAULT_LIMIT,
    node: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Ask the root helper which backups exist for one cluster's nodes."""

    request = {
        "schema_version": 1,
        "operation": OPERATION,
        "cluster": cluster_id,
        "request_id": request_id,
        "parameters": {"limit": limit, "node": node},
    }
    return subprocess.run(  # noqa: S603 - fixed helper path, no caller argv
        [SUDO, "-n", HELPER],
        input=json.dumps(request, separators=(",", ":")),
        capture_output=True,
        text=True,
        check=False,
    )


@dataclass(frozen=True, slots=True)
class Request:
    cluster: str | None
    node: str | None
    limit: int | None
    json_mode: bool


def _parse(argv: list[str]) -> Request:
    cluster: str | None = None
    node: str | None = None
    limit: int | None = DEFAULT_LIMIT
    json_mode = False

    rest = list(argv)
    while rest:
        flag = rest.pop(0)
        if flag in ("-c", "--cluster"):
            if not rest or cluster is not None:
                usage(USAGE)
            cluster = rest.pop(0)
        elif flag == "--node":
            if not rest or node is not None:
                usage(USAGE)
            node = rest.pop(0)
        elif flag == "--all":
            limit = None
        elif flag == "--json":
            json_mode = True
        else:
            usage(USAGE)

    #
    # The envelope is one cluster's answer, so there is no document that spans
    # several. Rather than inventing one - a JSON array, or one object per line -
    # the raw mode asks for the cluster it can actually answer for. A caller
    # that wants every cluster in JSON is asking for something the contract does
    # not define, and should call once per cluster and keep the envelopes.
    #
    if json_mode and cluster is None:
        usage(USAGE)
    return Request(cluster=cluster, node=node, limit=limit, json_mode=json_mode)


def _clusters_for(request: Request) -> tuple[str, ...]:
    """Which clusters to ask, when the caller named none.

    Read as the calling user, the same way `haproxy-cluster-config` reads it.
    This resolves nothing privileged - it only learns which clusters exist, and
    each helper call still resolves its own paths inside the boundary.
    """

    if request.cluster is not None:
        return (request.cluster,)
    config = load_runtime_config(load_policy())
    if request.node is None:
        return tuple(config.clusters)
    #
    # A node belongs to one cluster, so asking every cluster for it would make
    # each of the others answer "no such node" - a listing of errors for a
    # question that had one right answer.
    #
    return tuple(
        cluster_id
        for cluster_id, cluster in config.clusters.items()
        if any(node.name == request.node for node in cluster.nodes)
    )


class HelperFailure(ValueError):
    """The helper answered, and the answer is that it could not do the read."""


def _result(document: Mapping[str, Any]) -> Mapping[str, Any]:
    if document.get("operation") != OPERATION:
        raise ValueError("the backup helper returned an invalid result")
    #
    # A failed envelope is an answer, not a malformed one. Reporting it as
    # "invalid result" would send the reader to look for a bug in the helper
    # when the helper has just told them, in a structured field, exactly what is
    # wrong - a missing backup_root, most often.
    #
    error = document.get("error")
    if isinstance(error, Mapping):
        raise HelperFailure(f"{error.get('code')}: {error.get('message')}")
    result = document.get("result")
    if not isinstance(result, Mapping):
        raise ValueError("the backup helper returned an invalid result")
    return result


def _archive(version: str) -> str:
    """The name the backup has on disk, which is the name a restore is given.

    The envelope calls this field `version` and reports the stamp alone, which
    is right for a machine reading it and wrong to put in front of an operator:
    a version is a number, and this is a filename. `--backup` accepts it with or
    without the suffix, so the listing shows the form that can be copied.
    """

    return f"{version}.tar.gz"


def _local(created_at: str) -> str:
    """The UTC instant from the envelope, shown on the operator's own clock.

    The envelope stays UTC because it is read by machines and has to be
    unambiguous. A listing is read by a person, next to a version stamp the
    backup engine wrote in local time - and a CREATED column two hours off that
    stamp reads as a bug rather than as a timezone.
    """

    try:
        moment = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    except ValueError:
        return created_at
    return moment.astimezone().strftime("%Y-%m-%d %H:%M:%S")


def _size(size_bytes: int) -> str:
    #
    # Powers of 1024 with one unit per step, which is what `du -h` printed in
    # the shell version. Rendering is the operator's, so it stays where the
    # operator reads it and never reaches the JSON.
    #
    size = float(size_bytes)
    for unit in ("B", "K", "M"):
        if size < 1024:
            return f"{size:.0f}{unit}"
        size /= 1024
    return f"{size:.0f}G"


def _render(document: Mapping[str, Any], writer: TextIO) -> None:
    result = _result(document)
    nodes = result.get("nodes")
    if not isinstance(nodes, list):
        raise ValueError("the backup helper returned an invalid node list")
    writer.write(f"Cluster: {document.get('cluster')}\n")
    for node in nodes:
        if not isinstance(node, Mapping):
            raise ValueError("the backup helper returned an invalid node")
        writer.write(f"\n=== {node.get('name')} ===\n")
        if not node.get("available"):
            error = node.get("error")
            reason = error.get("code") if isinstance(error, Mapping) else "unavailable"
            writer.write(f"No backups could be read: {reason}\n")
            continue
        latest = node.get("latest_version")
        writer.write(f"latest -> {'MISSING' if latest is None else _archive(str(latest))}\n\n")
        backups = node.get("backups")
        if not isinstance(backups, list) or not backups:
            writer.write("(no backups)\n")
            continue
        writer.write(f"{'CREATED':<21}{'SIZE':>6}  BACKUP\n")
        writer.write(f"{'-' * 19:<21}{'-' * 6:>6}  {'-' * 26}\n")
        for backup in backups:
            if not isinstance(backup, Mapping):
                raise ValueError("the backup helper returned an invalid backup")
            writer.write(
                f"{_local(str(backup.get('created_at', ''))):<21}"
                f"{_size(int(backup.get('size_bytes', 0))):>6}  "
                f"{_archive(str(backup.get('version', '')))}\n"
            )


def main(
    argv: list[str] | None = None,
    *,
    stream_out: TextIO | None = None,
    stream_err: TextIO | None = None,
    run_helper: RunHelper = run_list_backups_helper,
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    writer: TextIO = stream_out or sys.stdout
    errors: TextIO = stream_err or sys.stderr
    request = _parse(argv)

    try:
        clusters = _clusters_for(request)
    except ConfigError as exc:
        errors.write(f"ERROR: {exc}\n")
        return exc.exit_code
    if not clusters:
        errors.write(f"ERROR: no configured cluster has a node named {request.node}\n")
        return 64

    worst = 0
    for index, cluster_id in enumerate(clusters):
        completed = run_helper(cluster_id, new_request_id(), request.limit, request.node)
        worst = worst or completed.returncode

        try:
            document = json.loads(completed.stdout)
        except json.JSONDecodeError:
            errors.write(completed.stderr.strip() or "ERROR: the backup helper returned no result")
            errors.write("\n")
            return completed.returncode or EXIT_UNAVAILABLE

        if request.json_mode:
            writer.write(json.dumps(document, separators=(",", ":"), sort_keys=True) + "\n")
            continue
        # One blank line between clusters. Without it the next cluster's heading
        # sits directly under the previous cluster's last backup and reads as
        # part of it.
        if index:
            writer.write("\n")
        try:
            _render(document, writer)
        except ValueError as exc:
            errors.write(f"ERROR: {exc}\n")
            return completed.returncode or EXIT_UNAVAILABLE
    return worst


if __name__ == "__main__":
    raise SystemExit(main())
