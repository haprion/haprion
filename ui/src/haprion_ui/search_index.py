"""What the header's search finds, as rows the poller writes (B222).

Each reading the poller makes is turned into the values somebody might search
for - an object's name, hostnames, description, VIP and backends, a VIP's address, a
certificate's names, a node's name - one row per value. The search page is then
one query against an index rather than a pass over every document in Python,
which at ten thousand objects was the difference between milliseconds and most
of ten seconds (measured 2026-10-01).

Nothing here reads a document. The objects helper reports each object's VIP,
source and servers, worked out by the generator's own rule (B222), so this is a
reshaping of fields and not a second reader of the same file.

The same functions build the rows for the demo fixture, which has no rows in
the database; it filters them in memory with `matching`.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import quote, urlencode

#
# Bounds a value can be written with, the same as the table's checks. A value
# longer than this is not something anybody types into a search field.
#
MAX_TITLE = 255
MAX_LABEL = 64
MAX_VALUE = 512

#
# Which source wrote a row. A reading replaces its own rows and only those, so
# a failed certificate listing cannot take a cluster's objects out of the
# search.
#
SOURCES = ("objects", "network", "cert_list", "status", "cluster_list")
#
# The order the groups are shown in, and their headings.
#
KINDS = {
    "proxy": "Proxies",
    "address": "Addresses",
    "certificate": "Certificates",
    "cluster": "Clusters and nodes",
}


@dataclass(frozen=True, slots=True)
class Entry:
    #
    # None for the manager's own rows (B304): its certificates, which belong
    # to no cluster.
    #
    cluster: str | None
    source: str
    kind: str
    title: str
    #
    # What the value is, shown before it in the result: "Host", "Backend",
    # "VIP main". Empty for the thing's own name.
    #
    label: str
    value: str
    href: str
    #
    # A backend address. The object page is admin-only because its document
    # names every one of them (B68); a search must not answer the same question
    # for a reader one guess at a time.
    #
    admin_only: bool = False


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _sequence(value: Any) -> Sequence[Any]:
    return value if isinstance(value, Sequence) and not isinstance(value, (str, bytes)) else ()


def _text(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _entries(
    cluster: str | None,
    source: str,
    kind: str,
    title: str,
    href: str,
    values: Iterable[tuple[str, str]],
    *,
    admin_only: Iterable[tuple[str, str]] = (),
) -> list[Entry]:
    """One row per non-empty value, each bounded, none repeated."""

    found: dict[tuple[str, str, bool], Entry] = {}
    for hidden, pairs in ((False, values), (True, admin_only)):
        for label, value in pairs:
            if not value:
                continue
            key = (label, value, hidden)
            found.setdefault(
                key,
                Entry(
                    cluster=cluster,
                    source=source,
                    kind=kind,
                    title=title[:MAX_TITLE],
                    label=label[:MAX_LABEL],
                    value=value[:MAX_VALUE],
                    href=href,
                    admin_only=hidden,
                ),
            )
    return list(found.values())


def object_entries(cluster: str, result: Mapping[str, Any]) -> list[Entry]:
    rows: list[Entry] = []
    for entry in _sequence(result.get("objects")):
        entry = _mapping(entry)
        name = _text(entry.get("name"))
        if not name:
            continue
        vip = _mapping(entry.get("vip"))
        source = _mapping(entry.get("source"))
        values = [
            ("", name),
            *(("Host", _text(host)) for host in _sequence(entry.get("hostnames"))),
        ]
        if _text(entry.get("description")):
            values.append(("Description", _text(entry.get("description"))))
        if vip:
            values.append((f"VIP {_text(vip.get('name'))}", _text(vip.get("address"))))
        if source:
            label = (
                f"Source {_text(source.get('name'))}"
                if source.get("name")
                else f"Source of VIP {_text(vip.get('name'))}"
            )
            values.append((label, _text(source.get("address"))))
        rows += _entries(
            cluster,
            "objects",
            "proxy",
            name,
            f"/proxies/{quote(cluster, safe='')}/{quote(name, safe='')}",
            values,
            admin_only=(
                (BACKEND_LABEL, _text(server)) for server in _sequence(entry.get("servers"))
            ),
        )
    return rows


def network_entries(cluster: str, result: Mapping[str, Any]) -> list[Entry]:
    rows: list[Entry] = []
    default = _text(result.get("default_vip"))
    for vip in _sequence(result.get("vips")):
        vip = _mapping(vip)
        name = _text(vip.get("name"))
        if not name:
            continue
        title = f"VIP {name}" + (" (default)" if name == default else "")
        values = [("", name), ("", _text(vip.get("address"))), ("Source", _text(vip.get("source")))]
        rows += _entries(cluster, "network", "address", title, "/network", values)
    for source in _sequence(result.get("sources")):
        source = _mapping(source)
        name = _text(source.get("name"))
        if name:
            values = [("", name), ("", _text(source.get("address")))]
            rows += _entries(cluster, "network", "address", f"Source {name}", "/network", values)
    return rows


def certificate_entries(cluster: str, result: Mapping[str, Any]) -> list[Entry]:
    """A cluster's certificates that no registry entry names, linked to its listing.

    The registered ones are the manager's rows (`manager_entries`, B304), found
    once with a link to their own row, however many clusters list them.
    """

    from haprion_ui import certificates
    from haprion_ui.db import ClusterCertificates

    registered = {
        _text(_mapping(entry).get("id"))
        for entry in _sequence(result.get("certificates"))
        if _mapping(entry).get("source") is not None
    }
    reading = ClusterCertificates(
        cluster=cluster,
        observed_at=datetime.now(UTC),
        outcome="done",
        result=dict(result),
        warnings=[],
        error=None,
        poll_error=None,
    )
    overview = certificates.build_certificate_overview(
        [cluster], [reading], stale_after=timedelta(days=1)
    )
    rows: list[Entry] = []
    for view in overview.clusters:
        for certificate in view.certificates:
            if certificate.identifier in registered:
                continue
            values = [("", certificate.identifier), *(("", san) for san in certificate.sans)]
            rows += _entries(
                cluster,
                "cert_list",
                "certificate",
                certificate.identifier,
                "/certificates?view=clusters",
                values,
            )
    return rows


def manager_entries(result: Mapping[str, Any]) -> list[Entry]:
    """The registry's certificates, as the Certificates page lists them (B304).

    Built by the page's own function, so a search cannot find a certificate
    the page it links to would not show. No cluster: they are the manager's.
    """

    from haprion_ui import certificates
    from haprion_ui.db import ManagerCertificates

    reading = ManagerCertificates(
        observed_at=datetime.now(UTC),
        outcome="done",
        result=dict(result),
        warnings=[],
        error=None,
        poll_error=None,
    )
    overview = certificates.build_certificate_overview(
        (), (), stale_after=timedelta(days=1), manager=reading
    )
    rows: list[Entry] = []
    for certificate in overview.registry.certificates if overview.registry else ():
        href = "/certificates?" + urlencode({"open": certificate.identifier})
        values = [("", certificate.identifier), *(("", san) for san in certificate.sans)]
        rows += _entries(None, "manager", "certificate", certificate.identifier, href, values)
    return rows


def node_entries(cluster: str, result: Mapping[str, Any]) -> list[Entry]:
    rows: list[Entry] = []
    for node in _sequence(result.get("nodes")):
        node = _mapping(node)
        name = _text(node.get("name"))
        if name:
            values = [("", name), ("Host", _text(node.get("mgmt_host")))]
            rows += _entries(cluster, "status", "cluster", name, "/", values)
    return rows


def cluster_entries(clusters: Iterable[str]) -> list[Entry]:
    return [
        entry
        for cluster in clusters
        for entry in _entries(cluster, "cluster_list", "cluster", cluster, "/", [("", cluster)])
    ]


BUILDERS = {
    "objects": object_entries,
    "network": network_entries,
    "cert_list": certificate_entries,
    "status": node_entries,
}


def entries_for(source: str, cluster: str, result: Mapping[str, Any]) -> list[Entry] | None:
    """This reading's rows; None for a source the search does not read."""

    build = BUILDERS.get(source)
    return None if build is None else build(cluster, result)


#
# Which other objects reach the same server (26-10-18): the object page's
# server rows say so, because a drain or maintenance is one object's and the
# same `host:port` in another object still takes traffic. The search's own
# Backend rows answer it - the objects helper's servers, advanced config's
# among them - so this is not a second reader of the documents. Only the same
# `host:port` counts: another port on the same host, or another name for the
# same address, is not the same server and is not guessed at.
#
BACKEND_LABEL = "Backend"


@dataclass(frozen=True, slots=True)
class Sharer:
    title: str
    href: str


def backend_rows(entries: Iterable[Entry], cluster: str) -> list[tuple[str, str, str]]:
    """(server, object, link) for each object's servers in one cluster, from built rows."""

    return [
        (entry.value, entry.title, entry.href)
        for entry in entries
        if entry.cluster == cluster
        and entry.source == "objects"
        and entry.kind == "proxy"
        and entry.label == BACKEND_LABEL
    ]


def shared_servers(
    rows: Iterable[tuple[str, str, str]], object_name: str, addresses: Iterable[str]
) -> dict[str, tuple[Sharer, ...]]:
    """Each of `addresses` that another object also names, with those objects by name."""

    wanted = set(addresses)
    found: dict[str, dict[str, Sharer]] = {}
    for value, title, href in rows:
        if value in wanted and title != object_name:
            found.setdefault(value, {}).setdefault(title, Sharer(title, href))
    return {
        value: tuple(sorted(sharers.values(), key=lambda sharer: sharer.title.casefold()))
        for value, sharers in found.items()
    }


#
# The page.
#
PAGE_SIZE = 100
MAX_QUERY = 120


@dataclass(frozen=True, slots=True)
class Hit:
    kind: str
    cluster: str | None
    title: str
    #
    # Which values matched, so `192.0.2.1` finding `192.0.2.10` says so.
    #
    matched: str
    href: str


@dataclass(frozen=True, slots=True)
class Group:
    label: str
    hits: tuple[Hit, ...]


@dataclass(frozen=True, slots=True)
class Results:
    query: str
    groups: tuple[Group, ...]
    total: int
    page: int

    @property
    def pages(self) -> int:
        return max(1, -(-self.total // PAGE_SIZE))

    @property
    def first(self) -> int:
        return (self.page - 1) * PAGE_SIZE + 1 if self.total else 0

    @property
    def last(self) -> int:
        return min(self.page * PAGE_SIZE, self.total)


def normalise(query: str) -> str:
    return query.strip()[:MAX_QUERY]


def matched_text(label: str, value: str) -> str:
    return f"{label} {value}" if label else value


def reader_href(kind: str, href: str, role: str) -> str:
    """A reader cannot open an object, so its row goes to the listing it is in."""

    return "/proxies" if kind == "proxy" and role != "admin" else href


def grouped(hits: Sequence[Hit]) -> tuple[Group, ...]:
    """The page's hits under their headings, in the order the kinds are shown."""

    return tuple(
        Group(label, tuple(hit for hit in hits if hit.kind == kind))
        for kind, label in KINDS.items()
        if any(hit.kind == kind for hit in hits)
    )


def matching(
    entries: Iterable[Entry], query: str, *, role: str, clusters: Iterable[str], page: int = 1
) -> Results:
    """The search done in memory, for the demo fixture.

    The same grouping and order as the database query in `db.search`, so the
    two modes draw the same page.
    """

    query = normalise(query)
    if not query:
        return Results(query, (), 0, 1)
    needle = query.casefold()
    listed = set(clusters)
    found: dict[tuple[str, str, str, str], list[str]] = {}
    for entry in entries:
        if entry.cluster not in listed or (entry.admin_only and role != "admin"):
            continue
        if needle not in entry.value.casefold():
            continue
        cluster = "" if entry.kind == "certificate" else entry.cluster
        text = matched_text(entry.label, entry.value)
        values = found.setdefault((entry.kind, cluster, entry.title, entry.href), [])
        if text not in values:
            values.append(text)
    order = list(KINDS)
    keys = sorted(found, key=lambda key: (order.index(key[0]), key[1], key[2].casefold()))
    page = max(1, page)
    shown = keys[(page - 1) * PAGE_SIZE : page * PAGE_SIZE]
    hits = [
        Hit(
            kind=kind,
            cluster=cluster or None,
            title=title,
            matched=", ".join(sorted(found[(kind, cluster, title, href)])),
            href=reader_href(kind, href, role),
        )
        for kind, cluster, title, href in shown
    ]
    return Results(query, grouped(hits), len(keys), page)
