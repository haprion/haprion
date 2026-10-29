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

from haprion import haproxy_versions, node_package, node_resources
from haprion.cluster_status import (
    BEHIND_RELEASE,
    ahead_of,
    ahead_words,
    behind_part,
    keepalived_state,
)

from haprion_ui import labels
from haprion_ui.cluster_identity import accent_index
from haprion_ui.db import ClusterStatus

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
    #
    # Why this node's HAProxy is older than it should be - behind the cluster's
    # newest, or behind the version this host validates with (Fas 16 punkt 3b).
    # The same sentence `haprion-status` prints; None when there is nothing to say.
    #
    runtime_note: str | None = None
    runtime_title: str | None = None
    #
    # Whether the release itself is the part behind, which is what the
    # Release column's *Behind target* says. False when the node runs the
    # target and a file the release activates afterwards is behind.
    #
    release_behind: bool = False
    #
    # The node package brings another step 4 than the one that last ran on it
    # (B363): Needs attention names the command. False for a node that does
    # not say, which an older node is.
    #
    prepare_pending: bool = False
    #
    # The node's haprion-node is not the one the manager's release carries
    # (26-10-29): the Runtime cell's note, and the sentence that is its hover
    # and Needs attention's row. None when they match or nothing can be said.
    #
    package_note: str | None = None
    package_message: str | None = None


@dataclass(frozen=True, slots=True)
class ResourceFigure:
    """One of the card's CPU and Memory columns (B239).

    The VIP owner's figure, since that node carries the traffic; every node's
    in `title`, for the hover; `high` when any node - the standby too - is at or
    above `node_resources.HIGH_PERCENT`, so a standby running out of memory is
    not hidden behind a quiet owner.
    """

    shown: str
    title: str
    high: bool


def _resource_figure(
    figures: list[tuple[str, int | None]], owner: str | None
) -> ResourceFigure | None:
    if not figures or all(value is None for _, value in figures):
        return None
    by_name = dict(figures)
    lead = by_name.get(owner) if owner in by_name else figures[0][1]
    return ResourceFigure(
        shown="–" if lead is None else f"{lead} %",
        title=" · ".join(
            f"{name} {'–' if value is None else f'{value} %'}" for name, value in figures
        ),
        high=any(
            value is not None and value >= node_resources.HIGH_PERCENT for _, value in figures
        ),
    )


@dataclass(frozen=True, slots=True)
class ClusterView:
    cluster: str
    accent: int | None
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
    #
    # The published version the reading names, as a number: what the deploy
    # buttons send, so the helper can refuse to roll out anything else.
    #
    target_version: int | None = None
    #
    # None when no node reports its resources - a node bundle from before
    # B239 - and the columns are then left out rather than shown as dashes.
    #
    cpu: ResourceFigure | None = None
    memory: ResourceFigure | None = None


@dataclass(frozen=True, slots=True)
class DashboardView:
    clusters: tuple[ClusterView, ...]
    healthy_clusters: int
    behind_clusters: int
    attention_clusters: int
    online_nodes: int
    total_nodes: int
    #
    # Clusters whose nodes the reading does not say: collection failed, no
    # node answered, or no reading yet. Their nodes are in neither figure
    # above, so the card said "All reporting" with a cluster dark (review
    # 2026-10-22, 2-1).
    #
    unread_clusters: int
    #
    # Clusters read, but not within two polls: their nodes are counted as last
    # read, and the card says so rather than "All reporting" in green (review
    # 26-10-24, 04-06).
    #
    stale_clusters: int
    #
    # Addresses, not clusters. The card said 2 for an installation with three
    # VIPs until 2026-09-20, because it counted clusters whose VRRP state was
    # healthy; the number a person checks it against is the VIPs they know.
    #
    active_vips: int
    total_vips: int
    converged_clusters: int
    configured_clusters: int
    #
    # The colour of each summary card's icon (B343, 26-10-20).
    # They were decoration - the release card red and the VIP card amber on an
    # installation where everything was in order. Now they say the card's
    # state: green when it is in order, amber for something to finish or look
    # at, red for something broken, grey before there is anything to count.
    #
    cluster_tone: Tone
    node_tone: Tone
    vip_tone: Tone
    release_tone: Tone


#
# The one label for "the nodes are not running the published version". Named
# rather than written twice, because the counters below decide what to exclude
# by comparing against it.
#
BEHIND = labels.BEHIND

#
# A node on an older version than the one published: a publish waiting for
# its deploy, which is somebody's choice. Needs attention leaves it out; the
# cluster card and Versions say it and offer the deploy (26-10-11).
#
VERSION_DRIFT = labels.BEHIND
#
# A node past the published version: this manager has no record of what it runs.
#
UNKNOWN_VERSION = "Unknown version"
#
# A node, or a whole cluster, that has never had a release: nothing has failed,
# there is nothing yet (Fas 18 finding 52). Before the first deploy a new
# cluster's nodes read keepalived not configured, no statistics and no VIP
# owner - each true, none of them a fault, and all of them on Needs attention.
#
NOT_DEPLOYED = "Not deployed"
#
# A node just added that has not answered yet (B329). Neither online nor down:
# the nodes card left it out of neither figure and turned red for a cluster
# that was healthy (review 2026-10-22, 1B-7), so it is out of both until it
# answers.
#
JOINING = "Joining"
#
# A cluster's own faults, which no node's row can say: every node reports
# Online while the VIP is in split brain or has no owner, and a reading that
# failed or returned no node has no node to name (review 2026-10-22, 2-1).
# Needs attention lists the cluster itself for these.
#
VIP_FAULT = "VIP fault"
COLLECTION_UNAVAILABLE = "Collection unavailable"
STATUS_UNAVAILABLE = "Status unavailable"
CLUSTER_FAULTS = frozenset({VIP_FAULT, COLLECTION_UNAVAILABLE, STATUS_UNAVAILABLE})


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


def _positive(value: Any) -> int | None:
    """A version number as a number, or nothing: what a deploy button binds to."""

    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    return None


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


def observation_label(observed_at: datetime, now: datetime) -> str:
    """What a cluster card says about the freshness of its reading.

    One function for all five pages that carry such a card, because the wording
    is the part that was wrong and a wording repeated in five builders is a
    wording that will only be half fixed.
    """

    return f"Observed {relative_age(observed_at, now).lower()}"


def node_package_words(installation: object, carried: object) -> tuple[str, str] | None:
    """The Runtime cell's note and Needs attention's sentence for a node's haprion-node.

    Read against the node package the manager's release carries, the one the
    nodes should run (26-10-29). None when they match or nothing can be said.
    """

    version = installation.get("version") if isinstance(installation, dict) else None
    if (
        isinstance(installation, dict)
        and isinstance(version, str)
        and installation.get("configured") is False
    ):
        return (
            "Node package not configured",
            f"haprion-node {node_package.short_version(version)} is installed but not configured",
        )
    standing = haproxy_versions.against_carried(installation, carried)
    if standing is None:
        return None
    installed, order = standing
    manager = node_package.short_version(str(carried))
    if order > 0:
        return (
            "Newer node package",
            f"haprion-node {node_package.short_version(str(installed))} is installed,"
            f" newer than the manager's {manager}",
        )
    if installed is None:
        return "Older node package", f"haprion-node is older than the manager's {manager}"
    return (
        "Older node package",
        f"haprion-node {node_package.short_version(installed)} is installed; the manager's is {manager}",
    )


def _node_view(
    value: Any,
    target_hash: str | None = None,
    target_version: object = None,
    carried: object = None,
) -> NodeView:
    node = _mapping(value)
    name = _text(node.get("name"), "Unnamed node")
    management_host = _text(node.get("mgmt_host"), "—")
    current = node.get("current") if isinstance(node.get("current"), bool) else None

    if node.get("reachable") is not True and node.get("joining") is True:
        #
        # Added, and not answered yet (B329): the poller marks it, since the
        # status helper only sees that the connection failed.
        #
        return NodeView(
            name=name,
            management_host=management_host,
            label=JOINING,
            tone="unknown",
            detail="Waiting for its first answer",
            keepalived="—",
            vip="—",
            version="—",
            runtime="—",
            stats="—",
            current=current,
        )
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
    prepare_pending = _mapping(status.get("preparation")).get("current") is False
    package_note, package_message = node_package_words(status.get("installation"), carried) or (
        None,
        None,
    )
    haproxy = _mapping(status.get("haproxy"))
    keepalived = _mapping(status.get("keepalived"))
    vip = _mapping(status.get("vip"))
    release = _mapping(status.get("release"))
    runtime = _mapping(status.get("runtime"))
    validation = _mapping(status.get("config_validation"))

    reported_state = _text(keepalived.get("state"))
    vip_label = "Owner" if vip.get("owner") is True else "Standby"
    if vip.get("owner") is None:
        vip_label = "Unknown"

    label: str
    tone: Tone
    detail: str
    if haproxy.get("active") is not True:
        label, tone, detail = "HAProxy stopped", "critical", "The proxy service is not active"
    elif release.get("version") is None and release.get("hash") is None:
        label, tone, detail = NOT_DEPLOYED, "unknown", "No version deployed yet"
    elif keepalived.get("configured") == "missing":
        #
        # Nothing has failed: there is no configuration yet. For a cluster
        # created in the interface the first deploy writes it (B313); "fault"
        # sent people looking for something broken.
        #
        label, tone, detail = (
            "Keepalived not configured",
            "warning",
            "No keepalived.conf on this node yet",
        )
    elif keepalived.get("active") is not True or reported_state not in {"MASTER", "BACKUP"}:
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
    elif current is False and (ahead := ahead_of(status, target_version)) is not None:
        #
        # Not behind: past what this manager published, which only a restore
        # of the manager leaves. The deploy offered for *Behind* would put the
        # older version on it (R2 26-10-27, F18).
        #
        label, tone = UNKNOWN_VERSION, "critical"
        detail = ahead_words(*ahead)
        detail = detail[:1].upper() + detail[1:]
    elif current is False:
        part = behind_part(status, target_hash)
        label, tone = VERSION_DRIFT, "warning"
        detail = (
            "Node is not on the published version"
            if part in (None, BEHIND_RELEASE)
            else f"The {part} is older than the published version"
        )
    else:
        label, tone, detail = "Online", "healthy", "Serving and reporting normally"

    if label == NOT_DEPLOYED:
        #
        # Said once. Before its first release a node has no failover state, no
        # address, no runtime and no statistics to report, and the row said so
        # four more times in four other words (Fas 18, finding 61).
        #
        return NodeView(
            name=name,
            management_host=management_host,
            label=label,
            tone=tone,
            detail="",
            keepalived="",
            vip="",
            version="—",
            runtime="",
            stats="",
            current=current,
            prepare_pending=prepare_pending,
            package_note=package_note,
            package_message=package_message,
        )

    return NodeView(
        name=name,
        management_host=management_host,
        label=label,
        tone=tone,
        detail=detail,
        keepalived=_text(keepalived_state(keepalived)),
        vip=vip_label,
        version=_version(release.get("version")),
        runtime=f"{_text(runtime.get('version'))} · {_duration(runtime.get('uptime_sec'))}",
        stats="Available" if status.get("stats_ok") is True else "Unavailable",
        current=current,
        release_behind=current is False
        and behind_part(status, target_hash) in (None, BEHIND_RELEASE),
        prepare_pending=prepare_pending,
        package_note=package_note,
        package_message=package_message,
    )


#
# How long after a reading is due the page asks for itself again, and how soon
# it asks again when the reading has not come yet: a pass reads every cluster
# over SSH, so a reading lands a little after its interval.
#
READING_MARGIN = 2.0
READING_RETRY = 3.0


def next_reading(
    rows: Iterable[ClusterStatus], interval: int, now: datetime | None = None
) -> float | None:
    """Seconds until the page should look for the poller's next reading, or None.

    A page that redrew on its own clock fell out of step with the poller's:
    every redraw came some 17 s after the reading it showed, and a change on a
    node took up to two intervals to appear (Fas 18, 26-10-16). Timed from the
    newest reading instead, the page shows one a couple of seconds after it is
    taken. None when there is no reading, or when the newest is older than two
    intervals - a poller that has stopped is not asked after every few seconds.
    """

    moment = now or datetime.now(UTC)
    newest = max((row.observed_at for row in rows), default=None)
    if newest is None:
        return None
    age = (moment - newest).total_seconds()
    if age > 2 * interval:
        return None
    due = interval - age + READING_MARGIN
    return due if due > 0 else READING_RETRY


def behind(reading: Any | None) -> bool:
    """The nodes answered and are not on the published release: a deploy is due.

    The deploy button says so where it is drawn (review 2026-10-22, 7-19); it
    looked the same on a converged cluster. An unread or half-read cluster is
    not called behind - nothing measured that.
    """

    result = _mapping(reading.result if reading is not None else None)
    return _mapping(result.get("summary")).get("release_state") == "behind"


def not_deployed(reading: Any | None) -> bool:
    """The cluster's card would say *Not deployed*: nodes, none with a release yet."""

    values = _mapping(reading.result if reading is not None else None).get("nodes")
    if not isinstance(values, list) or not values:
        return False
    return all(_node_view(value).label == NOT_DEPLOYED for value in values)


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


#
# How long after a reload a node's counters may still be on their way to the
# other nodes before that is a warning (B270).
#
PEERS_SETTLE_SECONDS = 120


def _with_shared_counters(
    nodes: tuple[NodeView, ...], node_values: list[Any]
) -> tuple[NodeView, ...]:
    """A node whose counters are not shared with the others, named (B270).

    Only where the cluster shares at all - some node reports a peer - and only
    on a node that is otherwise healthy. A node that reports no peer while
    another does is in no `peer` line: its host name is not its node name, or
    it runs a release from before sharing was turned on. A node that reports a
    peer it is not connected to cannot reach it - the port is closed between
    them, or the address has changed since the last publish.
    """

    reported = {
        _text(value.get("name")): _mapping(value.get("status")).get("peers")
        for value in node_values
        if isinstance(value, Mapping) and value.get("status_ok") is True
    }
    if not any(isinstance(peers, list) and peers for peers in reported.values()):
        return nodes
    #
    # A publish reloads the nodes one after the other, and each one's peers
    # connect again only once both run the new configuration: the reading
    # right after a deploy named both nodes as not reaching each other, and
    # they were connected a minute later (26-10-11). Said only once every
    # node has run long enough for that to be over.
    #
    uptimes = [
        _mapping(_mapping(value.get("status")).get("runtime")).get("uptime_sec")
        for value in node_values
        if isinstance(value, Mapping) and value.get("status_ok") is True
    ]
    if any(isinstance(uptime, int) and uptime < PEERS_SETTLE_SECONDS for uptime in uptimes):
        return nodes
    detail: dict[str, str] = {}
    for name, peers in reported.items():
        if not isinstance(peers, list):
            continue
        if not peers:
            detail[name] = "Shares no counters with the other nodes"
            continue
        missing = [
            _text(peer.get("name"))
            for peer in peers
            if isinstance(peer, Mapping) and peer.get("connected") is not True
        ]
        if missing:
            detail[name] = f"Counters not reaching {', '.join(missing)}"
    return tuple(
        replace(node, label="Counters not shared", tone="warning", detail=detail[node.name])
        if node.name in detail and node.tone == "healthy"
        else node
        for node in nodes
    )


def _cluster_view(
    reading: ClusterStatus,
    *,
    configured: bool,
    now: datetime,
    stale_after: timedelta,
) -> ClusterView:
    result = _mapping(reading.result)
    summary = _mapping(result.get("summary"))
    node_values = result.get("nodes")
    target_hash = _mapping(summary.get("target")).get("hash")
    target_version = _mapping(summary.get("target")).get("version")
    nodes = (
        tuple(
            _node_view(
                value,
                target_hash if isinstance(target_hash, str) else None,
                target_version,
                summary.get("node_package_version"),
            )
            for value in node_values
        )
        if isinstance(node_values, list)
        else ()
    )
    if isinstance(node_values, list):
        running = {
            _text(value.get("name")): _mapping(_mapping(value.get("status")).get("runtime")).get(
                "version"
            )
            for value in node_values
            if isinstance(value, Mapping) and value.get("status_ok") is True
        }
        packages = {
            _text(value.get("name")): _mapping(value.get("status")).get("packages")
            for value in node_values
            if isinstance(value, Mapping) and value.get("status_ok") is True
        }
        validator = summary.get("validator_version")
        #
        # One line in the cell, the exact versions in its title (26-10-09): a
        # full package version did not fit beside the runtime at 1280.
        #
        behind = haproxy_versions.notes(running, validator, packages, short=True)
        exact = haproxy_versions.notes(running, validator, packages)
        nodes = tuple(
            replace(
                node,
                runtime_note=behind.get(node.name),
                runtime_title=exact.get(node.name)
                if exact.get(node.name) != behind.get(node.name)
                else None,
            )
            for node in nodes
        )
        if summary.get("waf_published") is True:
            #
            # The release has WAF rules and this node's engine is not running
            # them (review 2026-10-04 F3). Only on a node that is otherwise
            # healthy: a stopped HAProxy or a fault already says more.
            #
            stopped = {
                _text(value.get("name"))
                for value in node_values
                if isinstance(value, Mapping)
                and value.get("status_ok") is True
                and _mapping(_mapping(value.get("status")).get("waf_engine"))
                and _mapping(_mapping(value.get("status")).get("waf_engine")).get("active")
                is not True
            }
            nodes = tuple(
                replace(
                    node,
                    label="WAF engine stopped",
                    tone="warning",
                    detail="The WAF engine is not running",
                )
                if node.name in stopped and node.tone == "healthy"
                else node
                for node in nodes
            )
        nodes = _with_shared_counters(nodes, node_values)
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
        owner_names[0]
        if vip_state == "single_owner" and len(owner_names) == 1
        else _vip_words(vip_state, len(owner_names))
    )

    target = _mapping(summary.get("target"))
    release_state = _text(summary.get("release_state"), "unknown")

    reporting = [
        _mapping(value)
        for value in (node_values if isinstance(node_values, list) else [])
        if isinstance(value, Mapping)
        and value.get("status_ok") is True
        and isinstance(_mapping(value.get("status")).get("resources"), Mapping)
    ]
    owner = owner_names[0] if len(owner_names) == 1 else None
    cpu_figure = _resource_figure(
        [
            (
                _text(value.get("name")),
                value.get("cpu_percent") if isinstance(value.get("cpu_percent"), int) else None,
            )
            for value in reporting
        ],
        owner,
    )
    memory_figure = _resource_figure(
        [
            (
                _text(value.get("name")),
                node_resources.memory_percent(_mapping(value.get("status")).get("resources")),
            )
            for value in reporting
        ],
        owner,
    )
    if reporting and cpu_figure is None:
        #
        # Counters but no share yet - the first reading after a gap. A dash
        # rather than no column, so the card does not change shape for one poll.
        #
        cpu_figure = ResourceFigure(
            shown="–",
            title=" · ".join(f"{_text(value.get('name'))} –" for value in reporting),
            high=False,
        )

    label: str
    tone: Tone
    detail: str
    if reading.poll_error:
        label, tone, detail = (
            COLLECTION_UNAVAILABLE,
            "critical",
            "The poller could not read status",
        )
    elif not nodes:
        label, tone, detail = STATUS_UNAVAILABLE, "critical", "No node returned usable status"
    elif all(node.label == NOT_DEPLOYED for node in nodes):
        label, tone, detail = NOT_DEPLOYED, "unknown", "No version deployed yet"
    elif vip_state in {"split_brain", "no_owner"}:
        label, tone, detail = VIP_FAULT, "critical", f"VIP state: {vip_state.replace('_', ' ')}"
    elif any(node.tone == "critical" for node in nodes):
        affected = sum(node.tone == "critical" for node in nodes)
        label, tone, detail = (
            "Needs attention",
            "critical",
            f"{labels.counted(affected, 'node')} {'requires' if affected == 1 else 'require'} attention",
        )
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
                f"{labels.counted(len(warned), 'node')} {'is' if len(warned) == 1 else 'are'} not running the published version",
            )
        else:
            label, tone, detail = (
                "Degraded",
                "warning",
                f"{labels.counted(len(warned), 'node')} {'reports' if len(warned) == 1 else 'report'} a warning",
            )
    elif release_state != "converged":
        label, tone, detail = BEHIND, "warning", "Nodes are not on the published version"
    else:
        label, tone, detail = "Healthy", "healthy", "All nodes serve the published version"

    if not configured:
        label, tone, detail = (
            "Not configured",
            "unknown",
            "Cached data remains for a removed cluster",
        )

    observed_at = reading.observed_at.astimezone(UTC)
    if stale:
        #
        # What the nodes said when last read, not what they say now: "Serving
        # and reporting normally" beside "Stale data" contradicted the badge
        # (review 26-10-24, 04-06).
        #
        last_read = f"Last read {relative_age(observed_at, now).lower()}"
        nodes = tuple(
            replace(node, detail=last_read) if node.label == "Online" else node for node in nodes
        )
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
        age_label=observation_label(observed_at, now),
        stale=stale,
        nodes=nodes,
        configured_nodes=configured_nodes,
        reachable_nodes=reachable_nodes,
        vip=vip_label,
        version=_version(target.get("version")),
        release_state=release_state.replace("_", " ").title(),
        target_version=_positive(target.get("version")),
        cpu=cpu_figure,
        memory=memory_figure,
    )


#
# The cluster's VIP state in words, where a node name stands when one node
# holds it; the status code itself (`no_owner`) was shown before (B335).
#
VIP_WORDS = {
    "no_owner": "None",
    "split_brain": "Split brain",
    "unknown": "Unknown",
    "incomplete": "Not every node read",
}
VIP_NOT_HELD = frozenset(VIP_WORDS.values())


def _vip_words(state: str, owners: int) -> str:
    words = VIP_WORDS.get(state, "Unknown")
    if state == "split_brain" and owners > 1:
        return f"{words} ({owners} nodes)"
    return words


def build_dashboard(
    configured_clusters: Iterable[str],
    readings: Iterable[ClusterStatus],
    *,
    now: datetime | None = None,
    stale_after: timedelta,
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
            ),
            vip_count=vip_counts.get(cluster, 1),
        )
        if cluster in by_cluster
        else _empty_cluster(cluster, configured=True)
        for cluster in order
    )

    configured_views = tuple(cluster for cluster in clusters if cluster.configured)
    counted = len(configured_views)
    healthy = sum(cluster.tone == "healthy" for cluster in configured_views)
    online_nodes = sum(
        node.tone in {"healthy", "warning"} or node.label == NOT_DEPLOYED
        for cluster in configured_views
        for node in cluster.nodes
    )
    total_nodes = sum(cluster.configured_nodes for cluster in configured_views) - sum(
        node.label == JOINING for cluster in configured_views for node in cluster.nodes
    )
    unread = sum(not cluster.nodes for cluster in configured_views)
    stale_clusters = sum(cluster.stale and bool(cluster.nodes) for cluster in configured_views)
    active_vips = sum(
        cluster.vip_count
        for cluster in configured_views
        if cluster.vip not in VIP_NOT_HELD and not cluster.vip.startswith("Split brain")
    )
    total_vips = sum(cluster.vip_count for cluster in configured_views)
    converged = sum(cluster.release_state == "Converged" for cluster in configured_views)
    cluster_tone: Tone = (
        "unknown"
        if not counted
        else "critical"
        if any(cluster.tone == "critical" for cluster in configured_views)
        else "healthy"
        if healthy == counted
        else "warning"
    )
    node_tone: Tone = (
        "critical"
        if unread and (total_nodes or counted > unread)
        else "unknown"
        if not total_nodes
        else "critical"
        if online_nodes != total_nodes
        else "warning"
        if stale_clusters
        else "healthy"
    )
    vip_tone: Tone = (
        "unknown"
        if not total_vips
        else "critical"
        if any(cluster.vip.startswith("Split brain") for cluster in configured_views)
        else "healthy"
        if active_vips == total_vips
        else "warning"
    )
    release_tone: Tone = (
        "unknown" if not counted else "healthy" if converged == counted else "warning"
    )
    return DashboardView(
        clusters=clusters,
        healthy_clusters=healthy,
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
        online_nodes=online_nodes,
        total_nodes=total_nodes,
        unread_clusters=unread,
        stale_clusters=stale_clusters,
        active_vips=active_vips,
        total_vips=total_vips,
        converged_clusters=converged,
        configured_clusters=counted,
        cluster_tone=cluster_tone,
        node_tone=node_tone,
        vip_tone=vip_tone,
        release_tone=release_tone,
    )
