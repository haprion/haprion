"""Read model for the published proxy overview.

This layer deliberately knows only the frozen inventory envelope cached by the
poller.  It cannot reach Git, YAML or a cluster; a browser view remains a fast
database read even while a managed pair is unavailable.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from haproxy_ui.cluster_identity import accent_index
from haproxy_ui.dashboard import relative_age
from haproxy_ui.db import ClusterInventory

type Tone = Literal["healthy", "warning", "critical", "unknown"]


@dataclass(frozen=True, slots=True)
class ProxyView:
    name: str
    protocol: str
    managed: bool
    enabled: bool
    hostnames: tuple[str, ...]
    ports: tuple[int, ...]
    backend_count: int


@dataclass(frozen=True, slots=True)
class ProxyClusterView:
    cluster: str
    accent: int
    configured: bool
    label: str
    tone: Tone
    detail: str
    observed_at: datetime | None
    observed_iso: str | None
    age_label: str
    stale: bool
    version: str
    proxies: tuple[ProxyView, ...]


@dataclass(frozen=True, slots=True)
class ProxyOverview:
    clusters: tuple[ProxyClusterView, ...]
    proxy_count: int
    managed_count: int
    unmanaged_count: int


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _text(value: Any, fallback: str = "—") -> str:
    return str(value) if isinstance(value, str) and value else fallback


def _ports(value: Any) -> tuple[int, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(port for port in value if isinstance(port, int) and not isinstance(port, bool))


def _hostnames(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(hostname for hostname in value if isinstance(hostname, str) and hostname)


def _proxy_view(value: Any) -> ProxyView | None:
    proxy = _mapping(value)
    name = _text(proxy.get("name"), "")
    if not name:
        return None
    protocol = _text(proxy.get("protocol"), "unknown")
    return ProxyView(
        name=name,
        protocol=protocol,
        managed=proxy.get("managed") is True,
        enabled=proxy.get("enabled") is True,
        hostnames=_hostnames(proxy.get("hostnames")),
        ports=_ports(proxy.get("bind_ports")),
        backend_count=(
            proxy["backend_count"]
            if isinstance(proxy.get("backend_count"), int)
            and not isinstance(proxy.get("backend_count"), bool)
            else 0
        ),
    )


def _empty(cluster: str, *, configured: bool) -> ProxyClusterView:
    return ProxyClusterView(
        cluster=cluster,
        accent=accent_index(cluster),
        configured=configured,
        label="No inventory yet",
        tone="unknown",
        detail="Waiting for the first inventory collection",
        observed_at=None,
        observed_iso=None,
        age_label="Never",
        stale=False,
        version="—",
        proxies=(),
    )


def _cluster_view(
    reading: ClusterInventory,
    *,
    configured: bool,
    now: datetime,
    stale_after: timedelta,
) -> ProxyClusterView:
    result = _mapping(reading.result)
    values = result.get("proxies")
    parsed_proxies: list[ProxyView] = []
    if isinstance(values, list):
        for value in values:
            proxy = _proxy_view(value)
            if proxy is not None:
                parsed_proxies.append(proxy)
    proxies = tuple(parsed_proxies)
    stale = now - reading.observed_at > stale_after
    version = result.get("version")

    label: str
    tone: Tone
    detail: str
    if reading.poll_error:
        label, tone, detail = (
            "Collection unavailable",
            "critical",
            "The poller could not read inventory",
        )
    elif reading.outcome != "done":
        label, tone, detail = (
            "Inventory unavailable",
            "critical",
            "The published inventory could not be read",
        )
    elif stale:
        label, tone, detail = "Stale data", "warning", "Inventory needs a fresh poll"
    elif version is None:
        label, tone, detail = "Nothing published", "unknown", "No configuration release exists yet"
    elif not proxies:
        label, tone, detail = "No proxies", "unknown", "The published release defines no frontends"
    else:
        label, tone, detail = "Current", "healthy", "Published proxy inventory"

    return ProxyClusterView(
        cluster=reading.cluster,
        accent=accent_index(reading.cluster),
        configured=configured,
        label=label,
        tone=tone,
        detail=detail,
        observed_at=reading.observed_at,
        observed_iso=reading.observed_at.astimezone(UTC).isoformat(),
        age_label=relative_age(reading.observed_at, now),
        stale=stale,
        version=f"v{version}"
        if isinstance(version, int) and not isinstance(version, bool)
        else "—",
        proxies=proxies,
    )


def build_proxy_overview(
    configured_clusters: Iterable[str],
    readings: Iterable[ClusterInventory],
    *,
    now: datetime | None = None,
    stale_after: timedelta,
) -> ProxyOverview:
    """Combine configured clusters and their newest cached inventory rows."""

    now = now or datetime.now(UTC)
    configured = tuple(configured_clusters)
    rows = {reading.cluster: reading for reading in readings}
    clusters: list[ProxyClusterView] = []
    for cluster in configured:
        reading = rows.pop(cluster, None)
        clusters.append(
            _empty(cluster, configured=True)
            if reading is None
            else _cluster_view(reading, configured=True, now=now, stale_after=stale_after)
        )
    for cluster in sorted(rows):
        clusters.append(
            _cluster_view(rows[cluster], configured=False, now=now, stale_after=stale_after)
        )

    proxies = tuple(proxy for cluster in clusters for proxy in cluster.proxies)
    return ProxyOverview(
        clusters=tuple(clusters),
        proxy_count=len(proxies),
        managed_count=sum(proxy.managed for proxy in proxies),
        unmanaged_count=sum(not proxy.managed for proxy in proxies),
    )
