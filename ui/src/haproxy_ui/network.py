"""Read model for a cluster's network description.

Three tables of addresses, as the poller last read them: where traffic arrives,
where it leaves from, and who may reach it. Like every other page, this layer
knows only the cached envelope - it cannot open the cluster repository, and the
identities it runs as are deliberately not in the group that could.

The one judgement made here is `editable`. A description read from
`managed/network.yaml` can be changed by publishing to the repository, the same
way a proxy object is; one derived from the engine's own configuration cannot,
because the interface has no path to that file and should not have one. The
page has to say which it is looking at rather than offering an edit that would
fail, so the distinction is carried out of the envelope and named here.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Literal

import yaml

from haproxy_ui.cluster_identity import accent_index
from haproxy_ui.dashboard import observation_label
from haproxy_ui.db import ClusterNetwork

type Tone = Literal["healthy", "warning", "critical", "unknown"]


@dataclass(frozen=True, slots=True)
class VipView:
    """One address a frontend binds, and what leaves from it by default."""

    name: str
    address: str
    source: str | None
    is_default: bool


@dataclass(frozen=True, slots=True)
class SourceView:
    """One address this cluster connects out from, and what reaches it that way.

    Both kinds of source address are in this list, and that is the point. The
    configuration separates the address a VIP pairs with from the extra ones an
    object may ask for by name, because they are decided in different places -
    but a page that showed only the second told a cluster with a paired source
    that it had none. The distinction belongs in a column, not in whether the
    row exists.
    """

    name: str
    address: str
    used_by: str


@dataclass(frozen=True, slots=True)
class GroupView:
    """One named set of addresses an object may restrict itself to."""

    name: str
    members: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class NetworkClusterView:
    cluster: str
    accent: int
    label: str
    tone: Tone
    detail: str
    observed_at: str | None
    observed_iso: str | None
    age_label: str
    stale: bool
    #
    # Whether the tables below can be changed from here at all. False means the
    # cluster still keeps them in the engine's configuration, which this
    # interface can neither read nor write.
    #
    editable: bool
    head: str | None
    document: str | None
    default_vip_object_count: int
    ownership_vip: str
    default_vip: str
    vips: tuple[VipView, ...]
    sources: tuple[SourceView, ...]
    groups: tuple[GroupView, ...]


def _text(value: Any, fallback: str = "—") -> str:
    return value if isinstance(value, str) and value else fallback


def _rows(result: Mapping[str, Any], key: str) -> list[Mapping[str, Any]]:
    rows = result.get(key)
    if not isinstance(rows, list):
        return []
    return [row for row in rows if isinstance(row, Mapping)]


def _vips(result: Mapping[str, Any], default_vip: str) -> tuple[VipView, ...]:
    return tuple(
        VipView(
            name=_text(row.get("name")),
            address=_text(row.get("address")),
            source=row.get("source") if isinstance(row.get("source"), str) else None,
            is_default=row.get("name") == default_vip,
        )
        for row in _rows(result, "vips")
    )


def _sources(result: Mapping[str, Any]) -> tuple[SourceView, ...]:
    paired = tuple(
        SourceView(
            name=_text(row.get("name")),
            address=_text(row.get("source")),
            used_by=f"default for VIP {_text(row.get('name'))}",
        )
        for row in _rows(result, "vips")
        if isinstance(row.get("source"), str) and row.get("source")
    )
    named = tuple(
        SourceView(
            name=_text(row.get("name")),
            address=_text(row.get("address")),
            used_by="named; an object must ask for it",
        )
        for row in _rows(result, "sources")
    )
    return paired + named


def _groups(result: Mapping[str, Any]) -> tuple[GroupView, ...]:
    return tuple(
        GroupView(
            name=_text(row.get("name")),
            members=tuple(
                member for member in row.get("members", []) if isinstance(member, str) and member
            ),
        )
        for row in _rows(result, "groups")
    )


def _document(result: Mapping[str, Any], default_vip: str) -> str:
    """Rebuild the one editable document from the bounded cached result."""

    vips: dict[str, dict[str, str]] = {}
    for vip in _vips(result, default_vip):
        if vip.name != "—" and vip.address != "—":
            entry = {"address": vip.address}
            if vip.source:
                entry["source"] = vip.source
            vips[vip.name] = entry
    document: dict[str, object] = {"vips": vips, "default_vip": default_vip}
    sources = {
        str(entry["name"]): str(entry["address"])
        for entry in _rows(result, "sources")
        if isinstance(entry.get("name"), str) and isinstance(entry.get("address"), str)
    }
    if sources:
        document["sources"] = sources
    groups = {
        group.name: list(group.members)
        for group in _groups(result)
        if group.name != "—" and group.members
    }
    if groups:
        document["networks"] = groups
    return yaml.safe_dump(document, sort_keys=False, default_flow_style=False)


def _empty(cluster: str) -> NetworkClusterView:
    return NetworkClusterView(
        cluster=cluster,
        accent=accent_index(cluster),
        label="No network description yet",
        tone="unknown",
        detail="Waiting for the first reading",
        observed_at=None,
        observed_iso=None,
        age_label="Never",
        stale=False,
        editable=False,
        head=None,
        document=None,
        default_vip_object_count=0,
        ownership_vip="—",
        default_vip="—",
        vips=(),
        sources=(),
        groups=(),
    )


def _unavailable(reading: ClusterNetwork, *, stale: bool, age_label: str) -> NetworkClusterView:
    error = reading.error or {}
    message = error.get("message") if isinstance(error, Mapping) else None
    return NetworkClusterView(
        cluster=reading.cluster,
        accent=accent_index(reading.cluster),
        label="Could not be read",
        tone="critical",
        detail=_text(message or reading.poll_error, "The helper did not answer"),
        observed_at=reading.observed_at.strftime("%Y-%m-%d %H:%M"),
        observed_iso=reading.observed_at.isoformat(),
        age_label=age_label,
        stale=stale,
        editable=False,
        head=None,
        document=None,
        default_vip_object_count=0,
        ownership_vip="—",
        default_vip="—",
        vips=(),
        sources=(),
        groups=(),
    )


def _view(reading: ClusterNetwork, *, stale: bool, age_label: str) -> NetworkClusterView:
    if reading.outcome != "done":
        return _unavailable(reading, stale=stale, age_label=age_label)

    result = reading.result if isinstance(reading.result, Mapping) else {}
    default_vip = _text(result.get("default_vip"))
    head = result.get("head") if isinstance(result.get("head"), str) else None
    editable = result.get("origin") == "repository" and head is not None
    detail = (
        "Edited here and published to the cluster repository"
        if editable
        else "Still described in the engine's configuration, which this interface cannot write"
    )
    return NetworkClusterView(
        cluster=reading.cluster,
        accent=accent_index(reading.cluster),
        label="Read-only" if not editable else "Editable",
        tone="healthy" if editable else "warning",
        detail=detail,
        observed_at=reading.observed_at.strftime("%Y-%m-%d %H:%M"),
        observed_iso=reading.observed_at.isoformat(),
        age_label=age_label,
        stale=stale,
        editable=editable,
        head=head,
        document=_document(result, default_vip) if editable else None,
        default_vip_object_count=(
            result["default_vip_object_count"]
            if isinstance(result.get("default_vip_object_count"), int)
            and not isinstance(result.get("default_vip_object_count"), bool)
            else 0
        ),
        ownership_vip=_text(result.get("ownership_vip")),
        default_vip=default_vip,
        vips=_vips(result, default_vip),
        sources=_sources(result),
        groups=_groups(result),
    )


def build_network_overview(
    clusters: Iterable[str],
    readings: Iterable[ClusterNetwork],
    *,
    now: datetime | None,
    stale_after: timedelta,
    captured: bool,
) -> tuple[NetworkClusterView, ...]:
    """One card per configured cluster, whether or not it has been read yet."""

    moment = now or datetime.now(tz=None).astimezone()
    by_cluster = {reading.cluster: reading for reading in readings}
    views: list[NetworkClusterView] = []
    for cluster in clusters:
        reading = by_cluster.get(cluster)
        if reading is None:
            views.append(_empty(cluster))
            continue
        age = moment - reading.observed_at
        views.append(
            _view(
                reading,
                stale=age > stale_after,
                age_label=observation_label(reading.observed_at, moment, captured=captured),
            )
        )
    return tuple(views)
