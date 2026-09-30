"""The Nodes card and pages under Settings: which nodes a cluster has (B211).

The list is the poller's status reading - the names and hosts the engine read
from `clusters.yaml`, and whether each node answered and holds the VIP - so
this page reaches no helper. Adding a node reads the block the node printed,
here in the web process, only to show the administrator what it says before
anything is queued; the root helper parses it again and is the authority.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from haproxy_mgmt import node_enrollment
from haproxy_mgmt.config import MAX_NODES, MIN_NODES


class FormProblem(ValueError):
    """What the form says back, in a sentence."""


@dataclass(frozen=True, slots=True)
class NodeRow:
    name: str
    host: str
    owner: bool
    reachable: bool


@dataclass(frozen=True, slots=True)
class ClusterRow:
    cluster: str
    nodes: tuple[str, ...]
    href: str
    running: str | None


def _nodes(result: Mapping[str, Any] | None) -> list[NodeRow]:
    rows: list[NodeRow] = []
    for entry in (result or {}).get("nodes") or ():
        if not isinstance(entry, Mapping):
            continue
        raw_status = entry.get("status")
        status: Mapping[str, Any] = raw_status if isinstance(raw_status, Mapping) else {}
        raw_vip = status.get("vip")
        vip: Mapping[str, Any] = raw_vip if isinstance(raw_vip, Mapping) else {}
        rows.append(
            NodeRow(
                name=str(entry.get("name", "")),
                host=str(entry.get("mgmt_host", "")),
                owner=vip.get("owner") is True,
                reachable=bool(entry.get("reachable")),
            )
        )
    return sorted(rows, key=lambda row: row.name)


def node_rows(status: Any | None) -> list[NodeRow]:
    """One cluster's nodes, alphabetical, from its status reading."""

    return _nodes(status.result if status is not None else None)


def card_rows(
    clusters: Iterable[str], statuses: Iterable[Any], *, running: Mapping[str, str]
) -> list[ClusterRow]:
    by_cluster = {row.cluster: row for row in statuses}
    return [
        ClusterRow(
            cluster=cluster,
            nodes=tuple(row.name for row in node_rows(by_cluster.get(cluster))),
            href=f"/settings/nodes/{cluster}",
            running=running.get(cluster),
        )
        for cluster in sorted(clusters)
    ]


@dataclass(frozen=True, slots=True)
class Addition:
    """A pasted block, read, with the host the manager will use."""

    block: str
    name: str
    host: str
    suggested_host: str
    fingerprint: str
    certificates: bool


def read_addition(block: str, *, cluster: str, host: str, count: int) -> Addition:
    try:
        enrollment = node_enrollment.parse(block)
        chosen = node_enrollment.host_name(host) if host.strip() else enrollment.host
    except node_enrollment.EnrollmentError as refused:
        raise FormProblem(str(refused)) from None
    if enrollment.cluster != cluster:
        raise FormProblem(
            f"This block was made for {enrollment.cluster}. Run 04-node-prepare on the node "
            f"with {cluster}."
        )
    if count >= MAX_NODES:
        raise FormProblem(f"A cluster has at most {MAX_NODES} nodes.")
    return Addition(
        block="".join(block.split()),
        name=enrollment.name,
        host=chosen,
        suggested_host=enrollment.host,
        fingerprint=node_enrollment.fingerprint(enrollment.host_key),
        certificates=enrollment.cert_pull_key is not None,
    )


def removable(rows: list[NodeRow], name: str) -> str | None:
    """Why this node cannot be removed, or None. The helper asks the node again."""

    if name not in {row.name for row in rows}:
        return f"{name} is not a node of this cluster."
    if len(rows) <= MIN_NODES:
        return f"A cluster keeps at least {MIN_NODES} nodes."
    if any(row.name == name and row.owner for row in rows):
        return f"{name} holds the VIP. Move the address to another node first."
    return None
