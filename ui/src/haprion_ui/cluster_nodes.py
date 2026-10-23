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

import base64
from collections.abc import Collection, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from haprion import cluster_definition, node_enrollment, node_join
from haprion.config import MAX_NODES, MIN_NODES
from haprion.dns_profile_keys import DnsProfilePublicKey

from haprion_ui import jobs
from haprion_ui.db import Job


class FormProblem(ValueError):
    """What the form says back, in a sentence."""


@dataclass(frozen=True, slots=True)
class NodeRow:
    name: str
    host: str
    owner: bool
    reachable: bool
    # Added and not answered yet (B329), as the poller marks it.
    joining: bool = False


@dataclass(frozen=True, slots=True)
class ClusterRow:
    cluster: str
    nodes: tuple[str, ...]
    href: str | None
    # A cluster being created: the running badge until the poller has read
    # it (finding 51).
    creating: str | None = None


@dataclass(frozen=True, slots=True)
class Creating:
    """A cluster asked for and not yet on the cluster list."""

    cluster: str
    running: str | None
    failed: str | None
    message: str | None
    job: int
    #
    # What was asked for, from the job: the guide fills its form with it after
    # a failed creation, so trying again does not start from empty fields
    # (review 2026-10-18, U1). The node block is not among it - it is sealed in
    # the job, and the node may have spent its key.
    #
    asked: Mapping[str, str] = field(default_factory=dict)


def _asked(job: Job) -> dict[str, str]:
    asked = {"cluster": job.cluster or ""}
    for key in ("display_name", "vip"):
        value = job.payload.get(key)
        if isinstance(value, str):
            asked[key] = value
    return asked


def creations(
    recent: Iterable[Job], listed: Collection[str], *, now: datetime, settle: timedelta
) -> list[Creating]:
    """Clusters whose newest cluster job is a creation the list does not show yet.

    A new cluster is on no card until its job has succeeded and the poller has
    read the cluster file, and after Create cluster the admin landed on Jobs to
    see anything (Fas 18 finding 51). Busy while the job is queued or running,
    and after it succeeded for as long as a poller takes to read it - two
    intervals, the age at which a reading is called stale; past that it is
    left to the list. A creation that failed is kept with its reason, for the
    page that asked to be shown it.
    """

    seen: set[str] = set()
    found: list[Creating] = []
    for job in recent:
        if job.operation != "cluster_define" or job.cluster is None or job.cluster in seen:
            continue
        seen.add(job.cluster)
        if job.cluster in listed or job.payload.get("action") != "add":
            continue
        settling = (
            job.state == "done" and job.finished_at is not None and now - job.finished_at <= settle
        )
        if job.state in {"pending", "running"} or settling:
            found.append(Creating(job.cluster, jobs.running_label(job), None, None, job.id))
        elif job.state in jobs.ATTENTION:
            found.append(
                Creating(
                    job.cluster,
                    None,
                    jobs.failure_label(job),
                    jobs.error_message(job),
                    job.id,
                    _asked(job),
                )
            )
    return found


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
                joining=entry.get("joining") is True,
            )
        )
    return sorted(rows, key=lambda row: row.name)


def node_rows(status: Any | None) -> list[NodeRow]:
    """One cluster's nodes, alphabetical, from its status reading."""

    return _nodes(status.result if status is not None else None)


def card_rows(
    clusters: Iterable[str], statuses: Iterable[Any], creating: Iterable[Creating] = ()
) -> list[ClusterRow]:
    by_cluster = {row.cluster: row for row in statuses}
    rows = [
        ClusterRow(
            cluster=cluster,
            nodes=tuple(row.name for row in node_rows(by_cluster.get(cluster))),
            href=f"/settings/nodes/{cluster}",
        )
        for cluster in clusters
    ]
    rows += [
        ClusterRow(cluster=entry.cluster, nodes=(), href=None, creating=entry.running)
        for entry in creating
        if entry.running
    ]
    return sorted(rows, key=lambda row: row.cluster)


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
    if not node_enrollment.made_for(enrollment, cluster):
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


def sealed_block(
    block: str, *, cluster: str, public_key: DnsProfilePublicKey | None
) -> tuple[str, dict[str, str] | None]:
    """The block as a job may store it, and its one-time key sealed for root (B317).

    A v1 block goes as it is. A v2 block goes without its key, and the key goes
    sealed against the installation's public key, bound to the cluster and the
    node: neither the job row nor the audit holds it in the clear.
    """

    try:
        enrollment = node_enrollment.parse(block)
    except node_enrollment.EnrollmentError as refused:
        raise FormProblem(str(refused)) from None
    if enrollment.join_key is None:
        return "".join(block.split()), None
    if public_key is None:
        raise FormProblem(
            "This installation has no key to seal the node's one-time key with (platform "
            "step 15). Add the node on the manager with haprion-node instead."
        )
    box = node_join.seal_join_key(
        public_key, cluster=cluster, node=enrollment.name, key=enrollment.join_key
    )
    stored = node_enrollment.render(node_enrollment.without_join_key(enrollment))
    return stored, {"key_id": public_key.key_id, "ciphertext": base64.b64encode(box).decode()}


def removable(rows: list[NodeRow], name: str) -> str | None:
    """Why this node cannot be removed, or None. The helper asks the node again."""

    if name not in {row.name for row in rows}:
        return f"{name} is not a node of this cluster."
    if len(rows) <= MIN_NODES:
        return (
            "A cluster keeps its last node; remove the cluster instead."
            if MIN_NODES == 1
            else f"A cluster keeps at least {MIN_NODES} nodes."
        )
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
    """A new cluster's form, read, with its first node or two (B302)."""

    cluster: str
    display_name: str
    vip: str
    node_path: str
    default_certificate: str | None
    address_prefix: int | None
    address_interface: str | None
    blocks: tuple[str, ...]
    nodes: tuple[NewNode, ...]

    def payload(self, public_key: DnsProfilePublicKey | None = None) -> dict[str, Any]:
        sealed = [
            sealed_block(block, cluster=self.cluster, public_key=public_key)
            for block in self.blocks
        ]
        payload: dict[str, Any] = {
            "action": "add",
            "display_name": self.display_name,
            "vip": self.vip,
            "node_path": self.node_path,
            "blocks": [stored for stored, _key in sealed],
            "hosts": [node.host for node in self.nodes],
        }
        if any(key is not None for _stored, key in sealed):
            payload["join_keys"] = [key for _stored, key in sealed]
        if self.default_certificate is not None:
            payload["default_certificate"] = self.default_certificate
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


def name_problem(form: Mapping[str, str], *, listed: Iterable[str]) -> str | None:
    """Why the first cluster's ID, display name or VIP cannot be used, or None (B315).

    The engine's own check, so the guide's first step refuses what *Create
    cluster* would refuse a step later.
    """

    cluster = form.get("cluster", "").strip()
    if cluster in set(listed):
        return f"There is already a cluster {cluster}."
    try:
        cluster_definition.check_name(
            cluster, display_name=display_name(form), vip=form.get("vip", "").strip()
        )
    except node_enrollment.EnrollmentError as refused:
        return _sentence(str(refused))
    return None


def display_name(form: Mapping[str, str]) -> str:
    """The name given, or the cluster's ID: no page shows it, so asking for one was a field to fill for
    nothing (review 2026-10-22, 7-16). `haprion-cluster add` takes the same default."""

    return form.get("display_name", "").strip() or form.get("cluster", "").strip()


def read_creation(
    form: Mapping[str, str], *, listed: Iterable[str], certificates: Iterable[str]
) -> Creation:
    cluster = form.get("cluster", "").strip()
    if cluster in set(listed):
        raise FormProblem(f"There is already a cluster {cluster}.")
    #
    # A certificate is optional (B302): a new installation has none, and a
    # cluster serves plain HTTP and TCP until one is issued for it.
    #
    certificate = form.get("default_certificate", "") or None
    if certificate is not None and certificate not in set(certificates):
        raise FormProblem("Choose the default certificate from the registry.")
    #
    # The first node's block, and the second's when one is given; a further
    # node is added from the cluster's Nodes card.
    #
    numbers = [n for n in (1, 2) if n == 1 or "".join(form.get(f"block_{n}", "").split())]
    blocks = ["".join(form.get(f"block_{n}", "").split()) for n in numbers]
    try:
        #
        # An empty host is the block's own suggestion, as for a single node;
        # an empty node path is the cluster's ID, as step 2 names it.
        #
        hosts = [
            form.get(f"host_{n}", "").strip() or node_enrollment.parse(blocks[i]).host
            for i, n in enumerate(numbers)
        ]
        spec = cluster_definition.definition(
            cluster,
            display_name=display_name(form),
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
    return None
