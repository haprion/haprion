"""The search in the header (B221): where is this name or address used?

Read entirely from what the poller has already cached - objects, network
descriptions, certificate listings and node status - so a search asks no node
anything and costs what rendering a page costs. It looks for things somebody
comes looking for in configuration: proxies, addresses, certificates, clusters
and nodes. Jobs, users and versions are left out; they answer different
questions and would bury the ones this page is for.

A match is a case-blind substring, which is what a person typing part of an
address or a name expects: `192.0.2.1` finds `.1` and `.10` alike, and the
result says which value matched.

Backend server addresses are searched for administrators only. The object page
is admin-only because its document carries every backend address behind a site
(B68), and a search that answered "yes, 192.0.2.10 is behind shop" would hand a
reader the same fact one guess at a time.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlencode

from haproxy_ui.addresses import network_result, resolve, servers
from haproxy_ui.certificates import CertificateOverview
from haproxy_ui.objects import cluster_object_views

#
# Long enough for an IPv6 address or a long hostname, short enough that a pasted
# paragraph is not matched against every field on every row.
#
MAX_QUERY = 120


@dataclass(frozen=True, slots=True)
class Hit:
    title: str
    #
    # Which value matched and what it is, so `192.0.2.1` finding `192.0.2.10`
    # says so instead of leaving the reader to wonder why the row is there.
    #
    matched: str
    href: str
    cluster: str | None = None


@dataclass(frozen=True, slots=True)
class Group:
    label: str
    hits: tuple[Hit, ...]


@dataclass(frozen=True, slots=True)
class Results:
    query: str
    groups: tuple[Group, ...]

    @property
    def count(self) -> int:
        return sum(len(group.hits) for group in self.groups)


def normalise(query: str) -> str:
    return query.strip()[:MAX_QUERY]


def _matches(needle: str, facets: Iterable[tuple[str, str]]) -> tuple[str, ...]:
    """Each `kind value` whose value contains the needle, in the order given."""

    return tuple(
        f"{kind} {value}" if kind else value
        for kind, value in facets
        if value and needle in value.casefold()
    )


def _hit(
    needle: str, title: str, facets: Sequence[tuple[str, str]], href: str, cluster: str | None
) -> Hit | None:
    found = _matches(needle, facets)
    return Hit(title, ", ".join(found), href, cluster) if found else None


def _proxies(
    needle: str, role: str, object_rows: Iterable[Any], network_rows: Iterable[Any]
) -> list[Hit]:
    networks = {row.cluster: network_result(row) for row in network_rows}
    hits = []
    for row in object_rows:
        network = networks.get(row.cluster, {})
        for view in cluster_object_views(row):
            facets: list[tuple[str, str]] = [("", view.name)]
            facets += [("Host", hostname) for hostname in view.hostnames]
            at = resolve(view.name, view.document, network) if view.readable else None
            if at is not None:
                facets.append((f"VIP {at.vip_name}", at.vip.address))
                if at.source is not None:
                    facets.append((at.source.label, at.source.address))
            if role == "admin" and view.readable:
                facets += [("Backend", server) for server in servers(view.name, view.document)]
            #
            # A reader cannot open the object page, so the row takes them to
            # the listing it is in rather than to a refusal.
            #
            href = (
                f"/proxies/{quote(row.cluster, safe='')}/{quote(view.name, safe='')}"
                if role == "admin"
                else "/proxies"
            )
            hit = _hit(needle, view.name, facets, href, row.cluster)
            if hit is not None:
                hits.append(hit)
    return hits


def _addresses(needle: str, network_rows: Iterable[Any]) -> list[Hit]:
    hits = []
    for row in network_rows:
        result = network_result(row)
        default = str(result.get("default_vip") or "")
        for entry in result.get("vips") or ():
            if not isinstance(entry, dict) or not entry.get("name"):
                continue
            name = str(entry["name"])
            title = f"VIP {name}" + (" (default)" if name == default else "")
            facets = [("", name), ("", str(entry.get("address") or ""))]
            facets.append(("Source", str(entry.get("source") or "")))
            hit = _hit(needle, title, facets, "/network", row.cluster)
            if hit is not None:
                hits.append(hit)
        for entry in result.get("sources") or ():
            if not isinstance(entry, dict) or not entry.get("name"):
                continue
            name = str(entry["name"])
            facets = [("", name), ("", str(entry.get("address") or ""))]
            hit = _hit(needle, f"Source {name}", facets, "/network", row.cluster)
            if hit is not None:
                hits.append(hit)
    return hits


def _certificates(needle: str, overview: CertificateOverview | None) -> list[Hit]:
    if overview is None:
        return []
    if overview.registry is not None:
        return [
            hit
            for certificate in overview.registry.certificates
            if (
                hit := _hit(
                    needle,
                    certificate.identifier,
                    [("", certificate.identifier), *(("", san) for san in certificate.sans)],
                    "/certificates?" + urlencode({"open": certificate.identifier}),
                    None,
                )
            )
            is not None
        ]
    #
    # No registry: the cluster listings are all there is, and one certificate
    # shared by both clusters is one result rather than two.
    #
    seen: dict[str, Hit] = {}
    for view in overview.clusters:
        for certificate in view.certificates:
            if certificate.identifier in seen:
                continue
            hit = _hit(
                needle,
                certificate.identifier,
                [("", certificate.identifier), *(("", san) for san in certificate.sans)],
                "/certificates?view=clusters",
                None,
            )
            if hit is not None:
                seen[certificate.identifier] = hit
    return list(seen.values())


def _clusters(needle: str, clusters: Iterable[str], status_rows: Iterable[Any]) -> list[Hit]:
    hits = []
    for cluster in clusters:
        hit = _hit(needle, cluster, [("", cluster)], "/", None)
        if hit is not None:
            hits.append(hit)
    for row in status_rows:
        result = row.result if isinstance(row.result, dict) else {}
        for node in result.get("nodes") or ():
            if not isinstance(node, dict) or not node.get("name"):
                continue
            name = str(node["name"])
            facets = [("", name), ("Host", str(node.get("mgmt_host") or ""))]
            hit = _hit(needle, name, facets, "/", row.cluster)
            if hit is not None:
                hits.append(hit)
    return hits


def search(
    query: str,
    *,
    role: str,
    clusters: Iterable[str],
    object_rows: Iterable[Any],
    network_rows: Iterable[Any],
    status_rows: Iterable[Any],
    certificates: CertificateOverview | None,
) -> Results:
    query = normalise(query)
    if not query:
        return Results(query, ())
    needle = query.casefold()
    network_rows = tuple(network_rows)
    groups = (
        Group("Proxies", tuple(_proxies(needle, role, object_rows, network_rows))),
        Group("Addresses", tuple(_addresses(needle, network_rows))),
        Group("Certificates", tuple(_certificates(needle, certificates))),
        Group("Clusters and nodes", tuple(_clusters(needle, clusters, status_rows))),
    )
    return Results(query, tuple(group for group in groups if group.hits))
