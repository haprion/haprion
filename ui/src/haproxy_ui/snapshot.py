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

from haproxy_mgmt.cli.cert_list import run_cert_list_helper
from haproxy_mgmt.cli.list_backups import run_list_backups_helper
from haproxy_mgmt.cli.status import run_status_helper
from haproxy_mgmt.config import DEFAULT_POLICY_PATH, load_policy, load_runtime_config
from haproxy_mgmt.envelope import new_request_id
from haproxy_mgmt.history import history_result
from haproxy_mgmt.inventory import inventory_result
from haproxy_mgmt.repo_snapshot import read_tree_files
from haproxy_mgmt.status_collect import read_target
from haproxy_mgmt.version_history import recent_versions

from haproxy_ui.db import (
    ClusterBackups,
    ClusterCertificates,
    ClusterHistory,
    ClusterInventory,
    ClusterStatus,
)

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
    history_rows: tuple[ClusterHistory, ...]
    certificate_rows: tuple[ClusterCertificates, ...]
    backup_rows: tuple[ClusterBackups, ...]


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


def _history_result(value: Any) -> dict[str, Any]:
    """Reduce a version listing to the fields the interface renders.

    A commit comment is free text written by an operator, so it is length-capped
    like every other string that crosses into the development platform, and the
    listing is capped at the ten versions the engine shows.
    """

    source = _mapping(value)
    entries = source.get("versions")
    versions: list[dict[str, Any]] = []
    if isinstance(entries, list):
        for entry in entries[:10]:
            item = _mapping(entry)
            versions.append(
                {
                    "version": _number(item.get("version")),
                    "hash": _text(item.get("hash"), limit=64),
                    "created_at": _text(item.get("created_at"), limit=40),
                    "comment": _text(item.get("comment"), limit=200),
                    "current": _boolean(item.get("current")),
                }
            )
    return {
        "current_version": _number(source.get("current_version")),
        "total_versions": _number(source.get("total_versions")),
        "versions": versions,
        "published_version": _number(source.get("published_version")),
        "published_hash": _text(source.get("published_hash"), limit=64),
        "unpublished": _number(source.get("unpublished")),
        "truncated": _boolean(source.get("truncated")),
    }


def _backup_result(value: Any) -> dict[str, Any]:
    """Reduce a backup listing to the fields the interface renders.

    Node names are the only sensitive thing in here and they are already in
    every other source, but the listing is reduced like the rest rather than
    copied through: archive counts are unbounded on a node with long retention,
    and this file has a size limit it must not be the reason to exceed.
    """

    source = _mapping(value)
    entries = source.get("nodes")
    nodes: list[dict[str, Any]] = []
    if isinstance(entries, list):
        for entry in entries[:4]:
            item = _mapping(entry)
            archives = item.get("backups")
            error = _mapping(item.get("error")).get("message")
            nodes.append(
                {
                    "name": _text(item.get("name"), limit=63),
                    "available": _boolean(item.get("available")),
                    "latest_version": _text(item.get("latest_version"), limit=32),
                    "backups": [
                        {
                            "version": _text(_mapping(archive).get("version"), limit=32),
                            "created_at": _text(_mapping(archive).get("created_at"), limit=40),
                            "size_bytes": _number(_mapping(archive).get("size_bytes")),
                            "latest": _boolean(_mapping(archive).get("latest")),
                        }
                        for archive in archives[:10]
                    ]
                    if isinstance(archives, list)
                    else [],
                    "error": {"message": _text(error, limit=200)} if error else None,
                }
            )
    return {"limit": _number(source.get("limit")), "nodes": nodes}


def _backup_document(cluster: str, completed: CompletedProcess[str]) -> dict[str, Any]:
    """Accept only this cluster's own backup listing, partial included.

    A partial listing is the interesting one: it means a node could not be read
    while the others could, and dropping it would turn the state the page exists
    to show into an empty card.
    """

    try:
        envelope = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return {"outcome": "failed", "result": {"nodes": []}}
    if not isinstance(envelope, dict) or envelope.get("operation") != "list_backups":
        return {"outcome": "failed", "result": {"nodes": []}}
    if envelope.get("cluster") != cluster or envelope.get("outcome") not in {"done", "partial"}:
        return {"outcome": "failed", "result": {"nodes": []}}
    return {"outcome": envelope["outcome"], "result": _backup_result(envelope.get("result"))}


def _certificate_result(value: Any) -> dict[str, Any]:
    """Reduce a certificate listing to the fields the interface renders.

    No fingerprint of real material and no private key can be in here to begin
    with - the helper never emits key material - but subjects and SANs are real
    hostnames, and this file is carried into a development platform. It is
    therefore reduced like every other source rather than copied through, and
    the catalogue is capped at what a page can usefully show.
    """

    source = _mapping(value)
    entries = source.get("certificates")
    certificates: list[dict[str, Any]] = []
    if isinstance(entries, list):
        for entry in entries[:50]:
            item = _mapping(entry)
            sans = item.get("sans")
            certificates.append(
                {
                    "id": _text(item.get("id"), limit=255),
                    "fingerprint_sha256": _text(item.get("fingerprint_sha256"), limit=64),
                    "common_name": _text(item.get("common_name")),
                    "sans": [name for name in sans if _text(name)][:20]
                    if isinstance(sans, list)
                    else [],
                    "not_before": _text(item.get("not_before"), limit=40),
                    "not_after": _text(item.get("not_after"), limit=40),
                    "issuer": _text(item.get("issuer"), limit=200),
                    "lifecycle": _text(item.get("lifecycle"), limit=16),
                    "valid": _boolean(item.get("valid")),
                    "referenced_by_cluster": _boolean(item.get("referenced_by_cluster")),
                    "deployable": _boolean(item.get("deployable")),
                    "validation_error": _text(item.get("validation_error"), limit=200),
                }
            )
    return {"certificates": certificates}


def _certificate_document(cluster: str, completed: CompletedProcess[str]) -> dict[str, Any]:
    """Accept only this cluster's own certificate result, and never its stderr."""

    try:
        envelope = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return {"outcome": "failed", "result": {"certificates": []}}
    if not isinstance(envelope, dict) or envelope.get("operation") != "cert_list":
        return {"outcome": "failed", "result": {"certificates": []}}
    if envelope.get("cluster") != cluster or envelope.get("outcome") != "done":
        return {"outcome": "failed", "result": {"certificates": []}}
    return {"outcome": "done", "result": _certificate_result(envelope.get("result"))}


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
    certificate_runner: Any = run_cert_list_helper,
    backup_runner: Any = run_list_backups_helper,
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
        certificates = _certificate_document(
            cluster_id, certificate_runner(cluster_id, new_request_id())
        )
        backups = _backup_document(cluster_id, backup_runner(cluster_id, new_request_id()))
        try:
            target = read_target(Path(cluster.publish_path), cluster.node_path)
            files = read_tree_files(Path(cluster.config_path), target.hash) if target else {}
            inventory: dict[str, object] = {
                "outcome": "done",
                "result": inventory_result(files, target, generated_at=captured_at),
            }
        except Exception:  # noqa: BLE001 - snapshot deliberately omits internal error detail
            inventory = {"outcome": "failed", "result": {"proxies": []}}
        try:
            listing = history_result(
                recent_versions(Path(cluster.config_path)),
                read_target(Path(cluster.publish_path), cluster.node_path),
                generated_at=captured_at,
            )
            history: dict[str, object] = {"outcome": "done", "result": _history_result(listing)}
        except Exception:  # noqa: BLE001 - snapshot deliberately omits internal error detail
            history = {"outcome": "failed", "result": {"versions": []}}
        clusters.append(
            {
                "cluster": cluster_id,
                "status": status,
                "inventory": inventory,
                "history": history,
                "certificates": certificates,
                "backups": backups,
            }
        )
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
    rows: dict[str, list[Any]] = {
        "status": [],
        "inventory": [],
        "history": [],
        "certificates": [],
        "backups": [],
    }
    #
    # A snapshot taken before a reading existed is loaded rather than refused:
    # the interface already renders a cluster with no row for a source as "no
    # data yet", and failing the whole file would take the other pages down
    # with it.
    #
    types = {
        "status": ClusterStatus,
        "inventory": ClusterInventory,
        "history": ClusterHistory,
        "certificates": ClusterCertificates,
        "backups": ClusterBackups,
    }
    for entry in entries:
        item = _mapping(entry)
        cluster = _text(item.get("cluster"), limit=63)
        if cluster is None or cluster in clusters:
            raise SnapshotError("production snapshot has an invalid cluster")
        clusters.append(cluster)
        for key, row_type in types.items():
            if key not in item:
                continue
            reading = _mapping(item.get(key))
            outcome = reading.get("outcome")
            result = reading.get("result")
            if outcome not in {"done", "partial", "failed"} or not isinstance(result, dict):
                raise SnapshotError(f"production snapshot {key} is invalid")
            rows[key].append(
                row_type(
                    cluster=cluster,
                    observed_at=captured_at,
                    outcome=outcome,
                    result=result,
                    warnings=[],
                    error=None,
                    poll_error=None,
                )
            )
    return ProductionSnapshot(
        captured_at=captured_at,
        clusters=tuple(clusters),
        status_rows=tuple(rows["status"]),
        inventory_rows=tuple(rows["inventory"]),
        history_rows=tuple(rows["history"]),
        certificate_rows=tuple(rows["certificates"]),
        backup_rows=tuple(rows["backups"]),
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
