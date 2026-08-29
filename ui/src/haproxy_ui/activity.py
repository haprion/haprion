"""A compact, read-only view of the latest stored observations.

This deliberately does not claim to be an audit trail. Phase 5 has one current
status reading per cluster, so this view makes that fact useful without
inventing a history that the cache does not hold.
"""

from __future__ import annotations

from dataclasses import dataclass

from haproxy_ui.dashboard import DashboardView, Tone


@dataclass(frozen=True, slots=True)
class ActivitySummary:
    """The two counters above the feed.

    Both are derived from the entries themselves rather than read again from
    the dashboard, so the numbers can never disagree with the list below them.
    """

    observation_count: int
    cluster_count: int
    attention_count: int


@dataclass(frozen=True, slots=True)
class ActivityEntry:
    cluster: str
    accent: int
    subject: str
    detail: str
    tone: Tone
    age_label: str
    observed_iso: str | None


def build_activity(dashboard: DashboardView) -> tuple[ActivityEntry, ...]:
    """Flatten current cluster and node observations into a compact feed."""

    entries: list[ActivityEntry] = []
    for cluster in dashboard.clusters:
        entries.append(
            ActivityEntry(
                cluster=cluster.cluster,
                accent=cluster.accent,
                subject=cluster.label,
                detail=cluster.detail,
                tone=cluster.tone,
                age_label=cluster.age_label,
                observed_iso=cluster.observed_iso,
            )
        )
        for node in cluster.nodes:
            entries.append(
                ActivityEntry(
                    cluster=cluster.cluster,
                    accent=cluster.accent,
                    subject=node.name,
                    detail=f"{node.label} · {node.keepalived} · {node.version}",
                    tone=node.tone,
                    age_label=cluster.age_label,
                    observed_iso=cluster.observed_iso,
                )
            )
    return tuple(entries)


def summarise_activity(entries: tuple[ActivityEntry, ...]) -> ActivitySummary:
    """Count the feed. Anything not healthy is worth a second look, including
    `unknown` - an observation the collector could not classify is not a pass."""

    return ActivitySummary(
        observation_count=len(entries),
        cluster_count=len({entry.cluster for entry in entries}),
        attention_count=sum(entry.tone != "healthy" for entry in entries),
    )
