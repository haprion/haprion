"""``haprion-list-backups`` - which state backups exist per node, read-only.

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

from haprion.cli.caller import usage
from haprion.config import ConfigError, load_policy, load_runtime_config
from haprion.envelope import new_request_id
from haprion.helper_protocol import write_document

OPERATION = "list_backups"
HELPER = "/opt/haprion/current/bin/haprion-list-backups-helper"
SUDO = "/usr/bin/sudo"
DEFAULT_LIMIT = 14
EXIT_UNAVAILABLE = 68
USAGE = (
    "Usage:\n"
    "  haprion-list-backups [-c <cluster>] [--node <name>] [--all] [--json]\n"
    "\n"
    "  -c      one cluster; without it, every configured cluster in turn\n"
    "  --node  one node, instead of every node in the cluster. A short name is\n"
    "          accepted when it can only mean one node, so --node a02 finds\n"
    "          gateway-a02\n"
    "  --all   every retained backup, instead of the 14 most recent per node\n"
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


class Ambiguous(ValueError):
    """A short name that fits more than one node, which is not a name."""


def _resolve(request: Request) -> tuple[tuple[str, ...], str | None]:
    """Which clusters to ask, and the full name of the node that was meant.

    The cluster list is read as the calling user, the same way
    `haprion-cluster-config` reads it. This resolves nothing privileged - it
    only learns which clusters and nodes exist, and each helper call still
    resolves its own paths inside the boundary.
    """

    if request.cluster is not None and request.node is None:
        return (request.cluster,), None

    config = load_runtime_config(load_policy())
    if request.node is None:
        return tuple(config.clusters), None

    candidates = [
        (cluster_id, node.name)
        for cluster_id, cluster in config.clusters.items()
        if request.cluster in (None, cluster_id)
        for node in cluster.nodes
    ]
    #
    # The shell version this replaces took short names - "a02" for
    # "gateway-a02" - from a table of aliases written into the script. The
    # same convenience without the table: a name that is not a node's full name
    # may be the end of exactly one. Exact matches win outright, so a node whose
    # full name happens to end another node's name is never shadowed.
    #
    exact = [pair for pair in candidates if pair[1] == request.node]
    matched = exact or [pair for pair in candidates if pair[1].endswith(request.node)]
    if len(matched) > 1:
        #
        # Refused rather than guessed. A listing for the wrong node during an
        # incident is worse than a question, and the operator is one keystroke
        # from being exact.
        #
        names = ", ".join(sorted(name for _, name in matched))
        raise Ambiguous(f"{request.node} matches more than one node: {names}")
    if not matched:
        return (), request.node
    cluster_id, name = matched[0]
    return (cluster_id,), name


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


def _schedule(result: Mapping[str, Any], writer: TextIO) -> None:
    """The timer line, written above the nodes because it is read first.

    An installation that declares no timer gets no line at all. Printing
    "Schedule: unknown" would suggest something is missing, when the truthful
    reading is that this deployment never told the command what takes its
    backups.
    """

    schedule = result.get("schedule")
    if not isinstance(schedule, Mapping):
        return
    if not schedule.get("known"):
        writer.write(f"Schedule: {schedule.get('unit')} is not known to systemd\n")
        return
    state = "enabled" if schedule.get("enabled") else "DISABLED"
    calendar = schedule.get("calendar") or "no calendar"
    writer.write(f"Schedule: {calendar} ({state})\n")
    last = schedule.get("last_run")
    outcome = schedule.get("last_result")
    if last:
        writer.write(f"  last run {_local(str(last))}{f' ({outcome})' if outcome else ''}\n")
    following = schedule.get("next_run")
    if following:
        writer.write(f"  next run {_local(str(following))}\n")


def _render(document: Mapping[str, Any], writer: TextIO) -> None:
    result = _result(document)
    nodes = result.get("nodes")
    if not isinstance(nodes, list):
        raise ValueError("the backup helper returned an invalid node list")
    writer.write(f"Cluster: {document.get('cluster')}\n")
    _schedule(result, writer)
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
        clusters, node = _resolve(request)
    except ConfigError as exc:
        errors.write(f"ERROR: {exc}\n")
        return exc.exit_code
    except Ambiguous as exc:
        errors.write(f"ERROR: {exc}\n")
        return 64
    if not clusters:
        errors.write(f"ERROR: no configured cluster has a node named {request.node}\n")
        return 64

    worst = 0
    for index, cluster_id in enumerate(clusters):
        completed = run_helper(cluster_id, new_request_id(), request.limit, node)
        worst = worst or completed.returncode

        try:
            document = json.loads(completed.stdout)
        except json.JSONDecodeError:
            errors.write(completed.stderr.strip() or "ERROR: the backup helper returned no result")
            errors.write("\n")
            return completed.returncode or EXIT_UNAVAILABLE

        if request.json_mode:
            write_document(writer, document)
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
