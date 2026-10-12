"""The Nodes card and pages under Settings: which nodes a cluster has (B211).

The list is the poller's status reading - the names and hosts the engine read
from `clusters.yaml`, and whether each node answered and holds the VIP - so
this page reaches no helper. Adding a node reads the block the node printed,
here in the web process, only to show the administrator what it says before
anything is queued; the root helper parses it again and is the authority.

Creating a cluster is read the same way, by the engine's own
`cluster_definition.definition` - the check `haprion-cluster` and the helper
make - so a form the page accepts is a request the helper reads alike.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from haprion import cluster_definition, node_enrollment
from haprion.config import MAX_NODES, MIN_NODES


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


def card_rows(clusters: Iterable[str], statuses: Iterable[Any]) -> list[ClusterRow]:
    by_cluster = {row.cluster: row for row in statuses}
    return [
        ClusterRow(
            cluster=cluster,
            nodes=tuple(row.name for row in node_rows(by_cluster.get(cluster))),
            href=f"/settings/nodes/{cluster}",
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


def read_host_change(rows: list[NodeRow], name: str, host: str) -> str:
    """The new host, checked as the helper will check it, or why it cannot be (B295).

    The helper is the authority - it asks the node at the new name - but a
    typo, the host the node already has or another node's host is said here,
    before a job is queued.
    """

    row = next((row for row in rows if row.name == name), None)
    if row is None:
        raise FormProblem(f"{name} is not a node of this cluster.")
    try:
        checked = node_enrollment.host_name(host.strip())
    except node_enrollment.EnrollmentError:
        raise FormProblem("Host — not a host name or an address.") from None
    if checked == row.host:
        raise FormProblem(f"{name} is already reached at {checked}.")
    if any(other.host == checked for other in rows):
        raise FormProblem(f"{checked} is another node's host.")
    return checked


# ------------------------------------------------------------ whole clusters


@dataclass(frozen=True, slots=True)
class NewNode:
    name: str
    host: str
    fingerprint: str


@dataclass(frozen=True, slots=True)
class Creation:
    """A new cluster's form, read, with its first two nodes."""

    cluster: str
    display_name: str
    vip: str
    node_path: str
    default_certificate: str
    address_prefix: int | None
    address_interface: str | None
    blocks: tuple[str, ...]
    nodes: tuple[NewNode, ...]

    def payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "action": "add",
            "display_name": self.display_name,
            "vip": self.vip,
            "node_path": self.node_path,
            "default_certificate": self.default_certificate,
            "blocks": list(self.blocks),
            "hosts": [node.host for node in self.nodes],
        }
        if self.address_prefix is not None:
            payload["address_prefix"] = self.address_prefix
        if self.address_interface is not None:
            payload["address_interface"] = self.address_interface
        return payload


CREATION_FIELDS = (
    "cluster",
    "display_name",
    "vip",
    "address_prefix",
    "address_interface",
    "node_path",
    "default_certificate",
    "block_1",
    "host_1",
    "block_2",
    "host_2",
)


def read_creation(
    form: Mapping[str, str], *, listed: Iterable[str], certificates: Iterable[str]
) -> Creation:
    cluster = form.get("cluster", "").strip()
    if cluster in set(listed):
        raise FormProblem(f"There is already a cluster {cluster}.")
    certificate = form.get("default_certificate", "")
    if certificate not in set(certificates):
        raise FormProblem("Choose the default certificate from the registry.")
    blocks = ["".join(form.get(f"block_{n}", "").split()) for n in (1, 2)]
    try:
        #
        # An empty host is the block's own suggestion, as for a single node;
        # an empty node path is the cluster's ID, as step 2 names it.
        #
        hosts = [
            form.get(f"host_{n}", "").strip() or node_enrollment.parse(blocks[n - 1]).host
            for n in (1, 2)
        ]
        spec = cluster_definition.definition(
            cluster,
            display_name=form.get("display_name", ""),
            vip=form.get("vip", "").strip(),
            node_path=form.get("node_path", "").strip() or cluster,
            default_certificate=certificate,
            blocks=blocks,
            hosts=hosts,
            address_prefix=cluster_definition.parse_prefix(
                form.get("address_prefix", "").strip() or None
            ),
            address_interface=form.get("address_interface", "").strip() or None,
        )
    except node_enrollment.EnrollmentError as refused:
        raise FormProblem(_sentence(str(refused))) from None
    return Creation(
        cluster=spec.cluster,
        display_name=spec.display_name,
        vip=spec.vip,
        node_path=spec.node_path,
        default_certificate=spec.default_certificate,
        address_prefix=spec.address_prefix,
        address_interface=spec.address_interface,
        blocks=tuple(blocks),
        nodes=tuple(
            NewNode(
                name=enrollment.name,
                host=host,
                fingerprint=node_enrollment.fingerprint(enrollment.host_key),
            )
            for enrollment, host in spec.nodes
        ),
    )


def _sentence(text: str) -> str:
    text = text[:1].upper() + text[1:]
    return text if text.endswith(".") else f"{text}."


def cluster_removable(listed: Iterable[str], cluster: str) -> str | None:
    """Why this cluster cannot be removed, or None. The helper checks again."""

    names = list(listed)
    if cluster not in names:
        return f"{cluster} is not a cluster."
    if len(names) <= 1:
        return "The manager keeps at least one cluster."
    return None
