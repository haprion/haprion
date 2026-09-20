"""The dashboard's read model, derived from cached engine results.

The status envelope's outcome answers whether collection completed.  It does
not answer whether HAProxy is serving traffic.  Keeping that distinction here,
outside the template, makes it testable and gives every later view one place to
derive the same health state from the node contract.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from haproxy_ui.cluster_identity import accent_index
from haproxy_ui.db import ClusterStatus

type Tone = Literal["healthy", "warning", "critical", "unknown"]


@dataclass(frozen=True, slots=True)
class NodeView:
    name: str
    management_host: str
    label: str
    tone: Tone
    detail: str
    keepalived: str
    vip: str
    version: str
    runtime: str
    stats: str
    current: bool | None


@dataclass(frozen=True, slots=True)
class ClusterView:
    cluster: str
    accent: int
    configured: bool
    label: str
    tone: Tone
    #
    # Behind, and nothing worse. Kept beside the tone rather than folded into
    # it: the badge should still be amber, because a deploy is outstanding, but
    # the counters must not report an outstanding deploy as a cluster in
    # trouble.
    #
    behind: bool
    detail: str
    observed_at: datetime | None
    observed_iso: str | None
    age_label: str
    stale: bool
    nodes: tuple[NodeView, ...]
    configured_nodes: int
    reachable_nodes: int
    vip: str
    version: str
    release_state: str
    #
    # How many addresses the cluster's VRRP instance carries. They move as
    # one - the nodes include one generated address list in one instance - so
    # the status helper's single `vip` answers for all of them, and the count
    # comes from the network description (`managed/network.yaml`). 1 where
    # that description is not cached: the status VIP is then the only one
    # known, and a card that said 0 would be wrong the other way.
    #
    vip_count: int = 1


@dataclass(frozen=True, slots=True)
class DashboardView:
    clusters: tuple[ClusterView, ...]
    healthy_clusters: int
    behind_clusters: int
    attention_clusters: int
    online_nodes: int
    total_nodes: int
    #
    # Addresses, not clusters. The card said 2 for an installation with three
    # VIPs until 2026-09-20, because it counted clusters whose VRRP state was
    # healthy; the number a person checks it against is the VIPs they know.
    #
    active_vips: int
    total_vips: int
    converged_clusters: int


#
# The one label for "the nodes are not running the published release". Named
# rather than written twice, because the counters below decide what to exclude
# by comparing against it.
#
BEHIND = "Not on the latest version"


def _vip_count(reading: Any) -> int:
    """How many VIPs the network helper listed for a cluster; 1 when it listed none."""

    rows = _mapping(getattr(reading, "result", None)).get("vips")
    listed = [row for row in rows if isinstance(row, Mapping)] if isinstance(rows, list) else []
    return len(listed) or 1


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _text(value: Any, fallback: str = "Unknown") -> str:
    return str(value) if value is not None and str(value) else fallback


def _version(value: Any) -> str:
    return f"v{value}" if isinstance(value, int | str) and str(value) else "—"


def _duration(seconds: Any) -> str:
    if not isinstance(seconds, int) or isinstance(seconds, bool) or seconds < 0:
        return "Unknown"
    if seconds < 60:
        return f"{seconds}s"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}m"
    hours = minutes // 60
    if hours < 48:
        return f"{hours}h {minutes % 60}m"
    return f"{hours // 24}d {hours % 24}h"


def relative_age(observed_at: datetime, now: datetime) -> str:
    """A compact age for an operations screen, never a future-looking value."""

    seconds = max(0, int((now - observed_at).total_seconds()))
    if seconds < 10:
        return "Just now"
    if seconds < 60:
        return f"{seconds}s ago"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}m ago"
    hours = minutes // 60
    if hours < 48:
        return f"{hours}h ago"
    return f"{hours // 24}d ago"


def observation_label(observed_at: datetime, now: datetime, *, captured: bool) -> str:
    """What a cluster card says about the freshness of its reading.

    One function for all five pages that carry such a card, because the wording
    is the part that was wrong and a wording repeated in five builders is a
    wording that will only be half fixed.

    In snapshot mode the readings are judged against the instant they were
    captured rather than against the wall clock - which is right, and argued for
    in `views.read_source` - but the label followed the clock into saying
    "Observed just now" about data that could be two days old, one line above a
    badge stating its true age. The relative age is dropped there entirely: it
    is a fact about the snapshot as a whole and the badge already states it once.

    What survives is the part that is still worth knowing: whether production's
    own reading was current when the picture was taken. A cluster that was
    already stale then still says so.
    """

    if captured:
        return "Current at capture"
    return f"Observed {relative_age(observed_at, now).lower()}"


def _node_view(value: Any) -> NodeView:
    node = _mapping(value)
    name = _text(node.get("name"), "Unnamed node")
    management_host = _text(node.get("mgmt_host"), "—")
    current = node.get("current") if isinstance(node.get("current"), bool) else None

    if node.get("reachable") is not True:
        return NodeView(
            name=name,
            management_host=management_host,
            label="Unreachable",
            tone="critical",
            detail="Management connection failed",
            keepalived="Unknown",
            vip="Unknown",
            version="—",
            runtime="Unknown",
            stats="Unknown",
            current=current,
        )

    if node.get("status_ok") is not True or not isinstance(node.get("status"), Mapping):
        return NodeView(
            name=name,
            management_host=management_host,
            label="Invalid status",
            tone="critical",
            detail="The node answered without usable status",
            keepalived="Unknown",
            vip="Unknown",
            version="—",
            runtime="Unknown",
            stats="Unknown",
            current=current,
        )

    status = _mapping(node["status"])
    haproxy = _mapping(status.get("haproxy"))
    keepalived = _mapping(status.get("keepalived"))
    vip = _mapping(status.get("vip"))
    release = _mapping(status.get("release"))
    runtime = _mapping(status.get("runtime"))
    validation = _mapping(status.get("config_validation"))

    keepalived_state = _text(keepalived.get("state"))
    vip_label = "Owner" if vip.get("owner") is True else "Standby"
    if vip.get("owner") is None:
        vip_label = "Unknown"

    label: str
    tone: Tone
    detail: str
    if haproxy.get("active") is not True:
        label, tone, detail = "HAProxy stopped", "critical", "The proxy service is not active"
    elif keepalived.get("active") is not True or keepalived_state not in {"MASTER", "BACKUP"}:
        label, tone, detail = (
            "Keepalived fault",
            "critical",
            "Failover state is not healthy",
        )
    elif status.get("stats_ok") is not True:
        label, tone, detail = "Stats unavailable", "warning", "Traffic may flow; stats do not"
    elif not runtime.get("version") or not isinstance(runtime.get("uptime_sec"), int):
        label, tone, detail = "Runtime unavailable", "warning", "Runtime details are incomplete"
    elif validation.get("valid") is False:
        label, tone, detail = "Invalid config", "warning", "Last configuration check failed"
    elif current is False:
        label, tone, detail = "Version drift", "warning", "Node is not on the target release"
    else:
        label, tone, detail = "Online", "healthy", "Serving and reporting normally"

    return NodeView(
        name=name,
        management_host=management_host,
        label=label,
        tone=tone,
        detail=detail,
        keepalived=keepalived_state,
        vip=vip_label,
        version=_version(release.get("version")),
        runtime=f"{_text(runtime.get('version'))} · {_duration(runtime.get('uptime_sec'))}",
        stats="Available" if status.get("stats_ok") is True else "Unavailable",
        current=current,
    )


def _empty_cluster(cluster: str, *, configured: bool) -> ClusterView:
    return ClusterView(
        cluster=cluster,
        accent=accent_index(cluster),
        configured=configured,
        label="No data",
        tone="unknown",
        behind=False,
        detail="Waiting for the first status collection",
        observed_at=None,
        observed_iso=None,
        age_label="Never",
        stale=False,
        nodes=(),
        configured_nodes=0,
        reachable_nodes=0,
        vip="Unknown",
        version="—",
        release_state="Unknown",
    )


def _cluster_view(
    reading: ClusterStatus,
    *,
    configured: bool,
    now: datetime,
    stale_after: timedelta,
    #
    # True only in snapshot mode, where the readings describe a moment that has
    # passed and `now` is that moment rather than the wall clock. It changes
    # what the freshness line says, not how staleness is judged. See
    # `dashboard.observation_label`.
    #
    captured: bool = False,
) -> ClusterView:
    result = _mapping(reading.result)
    summary = _mapping(result.get("summary"))
    node_values = result.get("nodes")
    nodes = (
        tuple(_node_view(value) for value in node_values) if isinstance(node_values, list) else ()
    )
    stale = now - reading.observed_at > stale_after

    configured_nodes = summary.get("configured_nodes")
    if not isinstance(configured_nodes, int) or isinstance(configured_nodes, bool):
        configured_nodes = len(nodes)
    reachable_nodes = summary.get("reachable_nodes")
    if not isinstance(reachable_nodes, int) or isinstance(reachable_nodes, bool):
        reachable_nodes = sum(node.tone != "critical" for node in nodes)

    vip_state = _text(summary.get("vip_state"), "unknown")
    owners = summary.get("vip_owners")
    owner_names = [str(owner) for owner in owners] if isinstance(owners, list) else []
    vip_label = (
        owner_names[0] if vip_state == "single_owner" and len(owner_names) == 1 else vip_state
    )

    target = _mapping(summary.get("target"))
    release_state = _text(summary.get("release_state"), "unknown")

    label: str
    tone: Tone
    detail: str
    if reading.poll_error:
        label, tone, detail = (
            "Collection unavailable",
            "critical",
            "The poller could not read status",
        )
    elif not nodes:
        label, tone, detail = "Status unavailable", "critical", "No node returned usable status"
    elif vip_state in {"split_brain", "no_owner"}:
        label, tone, detail = "VIP fault", "critical", f"VIP state: {vip_state.replace('_', ' ')}"
    elif any(node.tone == "critical" for node in nodes):
        affected = sum(node.tone == "critical" for node in nodes)
        label, tone, detail = "Needs attention", "critical", f"{affected} node(s) require attention"
    elif stale:
        label, tone, detail = "Stale data", "warning", "The latest reading is older than two polls"
    elif any(node.tone == "warning" for node in nodes):
        warned = [node for node in nodes if node.tone == "warning"]
        #
        # A node that is merely behind is named for what it is. "Degraded" says
        # the cluster is serving worse than it should, which is a different
        # claim and the one an operator acts on first - a release that has not
        # been deployed yet is not a fault, and calling it one teaches people to
        # ignore the badge.
        #
        if all(node.current is False for node in warned):
            label, tone, detail = (
                BEHIND,
                "warning",
                f"{len(warned)} node(s) are not running the published release",
            )
        else:
            label, tone, detail = (
                "Degraded",
                "warning",
                f"{len(warned)} node(s) report a warning",
            )
    elif release_state != "converged":
        label, tone, detail = BEHIND, "warning", "Nodes are not on one target release"
    else:
        label, tone, detail = "Healthy", "healthy", "All nodes are serving on the target release"

    if not configured:
        label, tone, detail = (
            "Not configured",
            "unknown",
            "Cached data remains for a removed cluster",
        )

    observed_at = reading.observed_at.astimezone(UTC)
    return ClusterView(
        cluster=reading.cluster,
        accent=accent_index(reading.cluster),
        behind=label == BEHIND,
        configured=configured,
        label=label,
        tone=tone,
        detail=detail,
        observed_at=observed_at,
        observed_iso=observed_at.isoformat(),
        age_label=observation_label(observed_at, now, captured=captured),
        stale=stale,
        nodes=nodes,
        configured_nodes=configured_nodes,
        reachable_nodes=reachable_nodes,
        vip=vip_label,
        version=_version(target.get("version")),
        release_state=release_state.replace("_", " ").title(),
    )


def build_dashboard(
    configured_clusters: Iterable[str],
    readings: Iterable[ClusterStatus],
    *,
    now: datetime | None = None,
    stale_after: timedelta,
    #
    # True only in snapshot mode, where the readings describe a moment that has
    # passed and `now` is that moment rather than the wall clock. It changes
    # what the freshness line says, not how staleness is judged. See
    # `dashboard.observation_label`.
    #
    captured: bool = False,
    #
    # The cached network descriptions, for the VIP count per cluster. Left
    # out by the callers that only need a cluster's serving state.
    #
    network_readings: Iterable[Any] = (),
) -> DashboardView:
    """Build one deterministic view from configuration and cached status rows."""

    clock = now or datetime.now(UTC)
    configured = tuple(configured_clusters)
    configured_set = frozenset(configured)
    by_cluster = {reading.cluster: reading for reading in readings}
    vip_counts = {reading.cluster: _vip_count(reading) for reading in network_readings}
    order = configured + tuple(sorted(set(by_cluster) - configured_set))
    clusters = tuple(
        replace(
            _cluster_view(
                by_cluster[cluster],
                configured=cluster in configured_set,
                now=clock,
                stale_after=stale_after,
                captured=captured,
            ),
            vip_count=vip_counts.get(cluster, 1),
        )
        if cluster in by_cluster
        else _empty_cluster(cluster, configured=True)
        for cluster in order
    )

    configured_views = tuple(cluster for cluster in clusters if cluster.configured)
    return DashboardView(
        clusters=clusters,
        healthy_clusters=sum(cluster.tone == "healthy" for cluster in configured_views),
        behind_clusters=sum(cluster.behind for cluster in configured_views),
        #
        # A cluster that is only behind is not counted here. An undeployed
        # release is a thing to finish, not a thing to investigate, and a
        # counter that cannot tell them apart makes both easy to ignore.
        #
        attention_clusters=sum(
            cluster.tone in {"critical", "warning"} and not cluster.behind
            for cluster in configured_views
        ),
        online_nodes=sum(
            node.tone in {"healthy", "warning"}
            for cluster in configured_views
            for node in cluster.nodes
        ),
        total_nodes=sum(cluster.configured_nodes for cluster in configured_views),
        active_vips=sum(
            cluster.vip_count
            for cluster in configured_views
            if cluster.vip not in {"Unknown", "unknown", "incomplete", "no_owner", "split_brain"}
        ),
        total_vips=sum(cluster.vip_count for cluster in configured_views),
        converged_clusters=sum(
            cluster.release_state == "Converged" for cluster in configured_views
        ),
    )
