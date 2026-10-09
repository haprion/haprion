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
from urllib.parse import urlencode

from haproxy_ui import sorting
from haproxy_ui.addresses import order_key
from haproxy_ui.cluster_identity import accent_index
from haproxy_ui.dashboard import observation_label
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
    #
    # The backend names the runtime knows, empty where the manager reporting this
    # is older than the field. Empty is "not told", not "has none" - the count
    # beside it is what says how many there are.
    #
    backends: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ProxyClusterView:
    cluster: str
    accent: int | None
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
    """The clusters and their published frontends.

    It counts nothing. A frontend is not a proxy anybody wrote: the generator
    names one after the address and protocol it binds, so an https object that
    redirects plain HTTP is two of them, and every object on one address shares
    the same one. Counting frontends therefore both over- and under-counted the
    work, and disagreed with the table underneath it. `objects.counted` does the
    counting now, from the same rows the table draws.
    """

    clusters: tuple[ProxyClusterView, ...]


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _text(value: Any, fallback: str = "—") -> str:
    return str(value) if isinstance(value, str) and value else fallback


def _ports(value: Any) -> tuple[int, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(port for port in value if isinstance(port, int) and not isinstance(port, bool))


def _strings(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(entry for entry in value if isinstance(entry, str) and entry)


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
        hostnames=_strings(proxy.get("hostnames")),
        ports=_ports(proxy.get("bind_ports")),
        backend_count=(
            proxy["backend_count"]
            if isinstance(proxy.get("backend_count"), int)
            and not isinstance(proxy.get("backend_count"), bool)
            else 0
        ),
        backends=_strings(proxy.get("backends")),
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
    #
    # Alphabetical, not the order the sections happen to sit in the generated
    # file. That order is an artefact of how the configuration was assembled -
    # it changes when a frontend is added - and a list whose order moves for
    # reasons the reader cannot see is one they have to search every time.
    #
    proxies = tuple(sorted(parsed_proxies, key=lambda proxy: proxy.name))
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
        age_label=observation_label(reading.observed_at, now),
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

    return ProxyOverview(clusters=tuple(clusters))


#
# The proxy tables are sortable (THEME.md). A row is the macro's
# `(name, kind, item)`: a draft, a removal waiting for its deploy, a managed
# object or an unmanaged frontend. A draft and a removal have no protocol,
# hostnames or health to sort on and come last in those columns. One choice
# orders every cluster's table on the page, and the rows' refresh keeps it.
#
def _served(row: tuple[str, str, Any]) -> Any:
    _name, kind, item = row
    return item if kind in ("written", "foreign") else None


def _protocol(row: tuple[str, str, Any], _context: Any) -> str | None:
    item = _served(row)
    return sorting.text(item.protocol) if item is not None else None


def _hosts(row: tuple[str, str, Any], _context: Any) -> str | None:
    item = _served(row)
    return sorting.text(", ".join(item.hostnames)) if item is not None else None


def _address(row: tuple[str, str, Any], _context: Any) -> Any:
    _name, kind, item = row
    found = getattr(item, "addresses", None) if kind == "written" else None
    if found is None:
        return None
    source = found.source.address if found.source else ""
    return (order_key(found.vip.shown), order_key(source))


def _health(row: tuple[str, str, Any], lamps: Any) -> tuple[int, str] | None:
    name, kind, _item = row
    lamp = (lamps or {}).get(name) if kind == "written" else None
    return None if lamp is None else (sorting.tone_rank(lamp.tone), lamp.label or "")


def _ownership(row: tuple[str, str, Any], _context: Any) -> str | None:
    kind = row[1]
    return {"written": "managed", "removed": "managed", "foreign": "unmanaged"}.get(kind)


#
# A cluster's table shows this many rows at a time, and only a cluster with
# more than this has pages at all (B222, 2026-10-01). Ten thousand rows
# on one page measured 1.2 s and 9.6 MB on every view and every refresh.
#
PAGE_SIZE = 100
PAGE_PREFIX = "page-"


def pages_asked(query: Mapping[str, str]) -> dict[str, int]:
    """Which page of each cluster's table the address asks for."""

    asked = {}
    for key, value in query.items():
        if key.startswith(PAGE_PREFIX) and value.isdecimal() and 0 < int(value) <= 100000:
            asked[key.removeprefix(PAGE_PREFIX)] = int(value)
    return asked


def page_link(paging: Mapping[str, int], cluster: str, page: int) -> str:
    """The listing with one cluster's table on another page and the others where they were."""

    chosen = {**paging, cluster: page}
    query = urlencode(
        {f"{PAGE_PREFIX}{name}": number for name, number in sorted(chosen.items()) if number > 1}
    )
    return f"/proxies?{query}" if query else "/proxies"


TABLE = sorting.Table(
    columns=(
        sorting.Column("name", lambda row, _: sorting.text(row[0])),
        sorting.Column("protocol", _protocol),
        sorting.Column("hosts", _hosts),
        sorting.Column("address", _address),
        sorting.Column("health", _health),
        sorting.Column("ownership", _ownership),
    ),
    cookie="haproxy_ui_proxies_sort",
    path="/proxies",
)
