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

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Literal

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
class NamedSourceView:
    """One named source address, as the document itself stores it.

    Deliberately not `SourceView`. That one is the reading: it merges in the
    addresses paired with a VIP, because a person asking "what do we leave
    from" wants both. The form may not, because a paired address belongs to
    its VIP's own row - editing it in two places would let one submission
    carry two answers for one value.
    """

    name: str
    address: str


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
    default_vip_object_count: int
    ownership_vip: str
    default_vip: str
    vips: tuple[VipView, ...]
    sources: tuple[SourceView, ...]
    paired_sources: tuple[SourceView, ...]
    named_sources: tuple[NamedSourceView, ...]
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


def _paired_sources(result: Mapping[str, Any]) -> tuple[SourceView, ...]:
    """The addresses a VIP carries, which are edited in that VIP's own row."""

    return tuple(
        SourceView(
            name=_text(row.get("name")),
            address=_text(row.get("source")),
            used_by=f"default for VIP {_text(row.get('name'))}",
        )
        for row in _rows(result, "vips")
        if isinstance(row.get("source"), str) and row.get("source")
    )


def _sources(result: Mapping[str, Any]) -> tuple[SourceView, ...]:
    named = tuple(
        SourceView(
            name=_text(row.get("name")),
            address=_text(row.get("address")),
            used_by="named; an object must ask for it",
        )
        for row in _rows(result, "sources")
    )
    return _paired_sources(result) + named


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


def _named_sources(result: Mapping[str, Any]) -> tuple[NamedSourceView, ...]:
    return tuple(
        NamedSourceView(name=_text(row.get("name")), address=_text(row.get("address")))
        for row in _rows(result, "sources")
    )


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
        default_vip_object_count=0,
        ownership_vip="—",
        default_vip="—",
        vips=(),
        sources=(),
        paired_sources=(),
        named_sources=(),
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
        default_vip_object_count=0,
        ownership_vip="—",
        default_vip="—",
        vips=(),
        sources=(),
        paired_sources=(),
        named_sources=(),
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
        paired_sources=_paired_sources(result),
        named_sources=_named_sources(result),
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


#
# The write side. The form is a set of parallel row fields rather than a
# document to hand-write, so this is where rows become the one shape the
# engine parses. It stops at the shape: names, pairing and the default's
# identity are decided here because getting them wrong loses a row silently,
# while every question about an address's validity is left to the helper,
# which is the authority and answers it against the cluster.
#


class FormProblem(Exception):
    """The rows cannot be turned into a document, and saying so is the answer."""


@dataclass(frozen=True, slots=True)
class NetworkForm:
    """One submission of the network tables, still in the browser's shape."""

    vip_names: tuple[str, ...]
    vip_addresses: tuple[str, ...]
    vip_sources: tuple[str, ...]
    default_vip_row: str
    source_names: tuple[str, ...]
    source_addresses: tuple[str, ...]
    group_names: tuple[str, ...]
    group_members: tuple[str, ...]


def _cell(values: tuple[str, ...], row: int) -> str:
    return values[row].strip() if row < len(values) else ""


def _named_rows(
    names: tuple[str, ...], values: tuple[str, ...], *, what: str, needs: str
) -> list[tuple[int, str, str]]:
    """Keep the rows that were filled in; refuse the ones half filled in.

    A spare row nobody touched is how this form removes and adds: both are
    blank and both are dropped. A row with a name and no address is neither,
    and guessing which was meant would either delete an address or publish an
    empty one.

    A refusal names the row's position and never its contents. These strings
    are shown to the person who submitted them, and a message built from a
    field is a field echoed back - the same reason the operations route
    answers a bad payload without quoting it.
    """

    rows: list[tuple[int, str, str]] = []
    seen: set[str] = set()
    for row in range(max(len(names), len(values))):
        name = _cell(names, row)
        value = _cell(values, row)
        if not name and not value:
            continue
        if not name:
            raise FormProblem(f"{what} row {row + 1} needs a name.")
        if not value:
            raise FormProblem(f"{what} row {row + 1} needs {needs}.")
        if name in seen:
            raise FormProblem(f"{what} row {row + 1} repeats a name used above it.")
        seen.add(name)
        rows.append((row, name, value))
    return rows


def _members(raw: str) -> list[str]:
    """One address or range per line, the way the preview form takes them."""

    return [member.strip() for member in raw.replace(",", "\n").splitlines() if member.strip()]


def document_from_form(form: NetworkForm) -> str:
    """Render one submission as the document the helper parses.

    JSON is YAML 1.2. Rendering this as JSON avoids teaching the interface a
    second YAML emitter; the privileged helper remains the one parser and the
    canonical publisher, so what leaves here only has to be unambiguous.
    """

    vips = _named_rows(form.vip_names, form.vip_addresses, what="VIP", needs="an address")
    if not vips:
        raise FormProblem("A cluster needs at least one VIP.")

    default_vip = ""
    for row, name, _ in vips:
        if str(row) == form.default_vip_row:
            default_vip = name
    if not default_vip:
        #
        # Reachable by clearing the name of the row the radio still points at.
        # Falling back to the first VIP would move every object that does not
        # name one, which is the change this form makes a person confirm.
        #
        raise FormProblem("Choose which VIP is the default.")

    document: dict[str, object] = {
        "vips": {
            name: (
                {"address": address, "source": source}
                if (source := _cell(form.vip_sources, row))
                else {"address": address}
            )
            for row, name, address in vips
        },
        "default_vip": default_vip,
    }

    sources = _named_rows(
        form.source_names, form.source_addresses, what="Source address", needs="an address"
    )
    if sources:
        document["sources"] = {name: address for _, name, address in sources}

    groups = _named_rows(
        form.group_names, form.group_members, what="Group", needs="at least one address"
    )
    if groups:
        document["networks"] = {name: _members(raw) for _, name, raw in groups}

    return json.dumps(document, indent=2) + "\n"
