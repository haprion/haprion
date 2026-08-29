"""An operator-created, one-way production display snapshot.

Development deliberately has neither production credentials nor a network path
to production.  When an operator needs realistic UI data, root runs the
snapshot command explicitly on the manager host.  It reads the already
privileged status helper and published configuration, reduces both to this
small schema, and writes it into the development platform as a root-owned
file.  The web process only reads that file; it never reaches production.
"""

from __future__ import annotations

import json
import stat
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from subprocess import CompletedProcess
from typing import Any

from haproxy_mgmt.cli.status import run_status_helper
from haproxy_mgmt.config import DEFAULT_POLICY_PATH, load_policy, load_runtime_config
from haproxy_mgmt.envelope import new_request_id
from haproxy_mgmt.inventory import inventory_result
from haproxy_mgmt.repo_snapshot import read_tree_files
from haproxy_mgmt.status_collect import read_target

from haproxy_ui.db import ClusterInventory, ClusterStatus

SNAPSHOT_NAME = "production-snapshot.json"
MAX_SNAPSHOT_BYTES = 1024 * 1024
SCHEMA_VERSION = 1


class SnapshotError(ValueError):
    """The local snapshot cannot safely be used as a display source."""


@dataclass(frozen=True, slots=True)
class ProductionSnapshot:
    captured_at: datetime
    clusters: tuple[str, ...]
    status_rows: tuple[ClusterStatus, ...]
    inventory_rows: tuple[ClusterInventory, ...]


def path_for_config(config_path: Path) -> Path:
    """The snapshot's fixed sibling path; configuration cannot redirect it."""

    return config_path.with_name(SNAPSHOT_NAME)


def _text(value: Any, *, limit: int = 253) -> str | None:
    return value if isinstance(value, str) and 0 < len(value) <= limit else None


def _number(value: Any) -> int | str | None:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return _text(value, limit=80)


def _boolean(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _status_node(value: Any) -> dict[str, Any]:
    source = _mapping(value)
    node: dict[str, Any] = {
        "name": _text(source.get("name"), limit=63),
        "mgmt_host": _text(source.get("mgmt_host")),
        "reachable": _boolean(source.get("reachable")),
        "status_ok": _boolean(source.get("status_ok")),
        "current": _boolean(source.get("current")),
    }
    status = _mapping(source.get("status"))
    if status:
        haproxy = _mapping(status.get("haproxy"))
        keepalived = _mapping(status.get("keepalived"))
        vip = _mapping(status.get("vip"))
        release = _mapping(status.get("release"))
        validation = _mapping(status.get("config_validation"))
        runtime = _mapping(status.get("runtime"))
        node["status"] = {
            "haproxy": {"active": _boolean(haproxy.get("active"))},
            "keepalived": {
                "active": _boolean(keepalived.get("active")),
                "state": _text(keepalived.get("state"), limit=32),
            },
            "vip": {"owner": _boolean(vip.get("owner"))},
            "release": {"version": _number(release.get("version"))},
            "config_validation": {"valid": _boolean(validation.get("valid"))},
            "stats_ok": _boolean(status.get("stats_ok")),
            "runtime": {
                "version": _text(runtime.get("version"), limit=80),
                "uptime_sec": _number(runtime.get("uptime_sec")),
            },
        }
    return node


def _status_result(value: Any) -> dict[str, Any]:
    source = _mapping(value)
    summary = _mapping(source.get("summary"))
    target = _mapping(summary.get("target"))
    nodes = source.get("nodes")
    return {
        "nodes": [_status_node(node) for node in nodes[:2]] if isinstance(nodes, list) else [],
        "summary": {
            "configured_nodes": _number(summary.get("configured_nodes")),
            "reachable_nodes": _number(summary.get("reachable_nodes")),
            "vip_state": _text(summary.get("vip_state"), limit=32),
            "vip_owners": [
                owner for owner in summary.get("vip_owners", []) if _text(owner, limit=63)
            ][:2]
            if isinstance(summary.get("vip_owners"), list)
            else [],
            "target": {"version": _number(target.get("version"))},
            "release_state": _text(summary.get("release_state"), limit=32),
        },
    }


def _status_document(cluster: str, completed: CompletedProcess[str]) -> dict[str, Any]:
    """Accept only the expected helper result, and never retain its stderr."""

    try:
        envelope = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return {"outcome": "failed", "result": {"nodes": [], "summary": {}}}
    if not isinstance(envelope, dict) or envelope.get("operation") != "status":
        return {"outcome": "failed", "result": {"nodes": [], "summary": {}}}
    if envelope.get("cluster") != cluster or envelope.get("outcome") not in {"done", "partial"}:
        return {"outcome": "failed", "result": {"nodes": [], "summary": {}}}
    return {"outcome": envelope["outcome"], "result": _status_result(envelope.get("result"))}


def collect_production_snapshot(
    *,
    policy_path: Path = DEFAULT_POLICY_PATH,
    now: datetime | None = None,
    status_runner: Any = run_status_helper,
) -> dict[str, object]:
    """Collect the restricted document emitted by the root-only CLI command."""

    policy = load_policy(policy_path)
    runtime = load_runtime_config(policy)
    captured_at = now or datetime.now(UTC)
    clusters: list[dict[str, object]] = []
    for cluster_id, cluster in sorted(runtime.clusters.items()):
        # The status helper owns the request schema and accepts UUID request
        # IDs only. Use the same generator as its public caller rather than
        # inventing a snapshot-specific correlation format.
        completed = status_runner(cluster_id, new_request_id())
        status = _status_document(cluster_id, completed)
        try:
            target = read_target(Path(cluster.publish_path), cluster.node_path)
            files = read_tree_files(Path(cluster.config_path), target.hash) if target else {}
            inventory: dict[str, object] = {
                "outcome": "done",
                "result": inventory_result(files, target, generated_at=captured_at),
            }
        except Exception:  # noqa: BLE001 - snapshot deliberately omits internal error detail
            inventory = {"outcome": "failed", "result": {"proxies": []}}
        clusters.append({"cluster": cluster_id, "status": status, "inventory": inventory})
    return {
        "schema_version": SCHEMA_VERSION,
        "source": "production",
        "captured_at": captured_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        "clusters": clusters,
    }


def _parse_time(value: Any) -> datetime:
    if not isinstance(value, str):
        raise SnapshotError("snapshot captured_at must be an ISO timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SnapshotError("snapshot captured_at must be an ISO timestamp") from exc
    if parsed.tzinfo is None:
        raise SnapshotError("snapshot captured_at must include a timezone")
    return parsed.astimezone(UTC)


def _read_document(path: Path, *, require_secure: bool) -> dict[str, Any]:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise SnapshotError(f"cannot stat production snapshot: {exc}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise SnapshotError("production snapshot must be a regular non-symlink")
    if metadata.st_size > MAX_SNAPSHOT_BYTES:
        raise SnapshotError("production snapshot exceeds 1 MiB")
    if require_secure and (metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o022):
        raise SnapshotError("production snapshot must be root-owned and not group/other-writable")
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SnapshotError(f"cannot read production snapshot: {exc}") from exc
    if not isinstance(loaded, dict):
        raise SnapshotError("production snapshot must contain an object")
    return loaded


def load_production_snapshot(path: Path, *, require_secure: bool = True) -> ProductionSnapshot:
    """Load the fixed local copy into the same row types normal views consume."""

    document = _read_document(path, require_secure=require_secure)
    if document.get("schema_version") != SCHEMA_VERSION or document.get("source") != "production":
        raise SnapshotError("production snapshot has an unsupported schema")
    captured_at = _parse_time(document.get("captured_at"))
    entries = document.get("clusters")
    if not isinstance(entries, list):
        raise SnapshotError("production snapshot clusters must be a list")
    clusters: list[str] = []
    statuses: list[ClusterStatus] = []
    inventories: list[ClusterInventory] = []
    for entry in entries:
        item = _mapping(entry)
        cluster = _text(item.get("cluster"), limit=63)
        if cluster is None or cluster in clusters:
            raise SnapshotError("production snapshot has an invalid cluster")
        clusters.append(cluster)
        for key in ("status", "inventory"):
            reading = _mapping(item.get(key))
            outcome = reading.get("outcome")
            result = reading.get("result")
            if outcome not in {"done", "partial", "failed"} or not isinstance(result, dict):
                raise SnapshotError(f"production snapshot {key} is invalid")
            row = {
                "cluster": cluster,
                "observed_at": captured_at,
                "outcome": outcome,
                "result": result,
                "warnings": [],
                "error": None,
                "poll_error": None,
            }
            if key == "status":
                statuses.append(ClusterStatus(**row))
            else:
                inventories.append(ClusterInventory(**row))
    return ProductionSnapshot(
        captured_at=captured_at,
        clusters=tuple(clusters),
        status_rows=tuple(statuses),
        inventory_rows=tuple(inventories),
    )


def _entry() -> int:
    """Write a restricted snapshot to stdout; the platform step owns the file."""

    try:
        document = collect_production_snapshot()
    except Exception as exc:  # noqa: BLE001 - root operator needs a concise failure
        print(f"ERROR: could not collect production snapshot: {exc}", file=sys.stderr)
        return 1
    encoded = json.dumps(document, separators=(",", ":"), sort_keys=True)
    if len(encoded.encode("utf-8")) > MAX_SNAPSHOT_BYTES:
        print("ERROR: production snapshot exceeds 1 MiB", file=sys.stderr)
        return 1
    sys.stdout.write(encoded + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(_entry())
