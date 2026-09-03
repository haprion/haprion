"""What the nodes report about one object's pool members.

The question a person authoring an object actually has is "does my health check
work", and the only place with a real answer is the node: HAProxy there has been
running the check, from that node, against the servers it was told about. This
module does no probing of its own - it reads the verdict the poller already
collected and lines it up with the object being edited.

Nothing here is a fresh measurement. A reading is as old as the poll that took
it, and the page says so rather than implying the numbers are from now.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from haproxy_mgmt.cluster_status import ServerHealth
from haproxy_mgmt.generate import PREFIX


def backend_name(obj: str, pool: str) -> str:
    """What this object's pool is called in the generated configuration.

    The same rule the generator uses, and the reason a member can be found at
    all: the runtime knows nothing about objects, only about backends.
    """

    return f"{PREFIX}-{obj}-{pool}"


@dataclass(frozen=True, slots=True)
class NodeMembers:
    """One node's verdict on the members of one pool."""

    node: str
    members: tuple[ServerHealth, ...]
    #
    # None means the node did not say - an older status script, or a runtime
    # socket that could not be read. Distinct from a node that answered and
    # knows nothing about this backend, which is a deploy that has not happened.
    #
    said: bool
    #
    # Whether this node carries the cluster's VIP, and with it the source
    # address an object leaves from. `None` is a node that did not say.
    #
    vip_owner: bool | None = None


@dataclass(frozen=True, slots=True)
class PoolHealth:
    """Every node's answer about one pool, and when it was taken."""

    backend: str
    nodes: tuple[NodeMembers, ...]
    observed_at: datetime | None

    @property
    def held_by(self) -> tuple[str, ...]:
        """The nodes carrying the VIP, named when the others were left out.

        Once a node is off the card, a single row reads as a cluster with one
        node - and which one it is happens to be the most useful fact here,
        because it is the node the traffic is on.
        """

        return tuple(node.node for node in self.nodes if node.vip_owner is True)

    @property
    def known(self) -> bool:
        """Whether any node reported members for this pool at all."""

        return any(node.members for node in self.nodes)

    @property
    def failing(self) -> tuple[NodeMembers, ...]:
        return tuple(node for node in self.nodes if any(not member.up for member in node.members))


def _members(status: Any) -> tuple[bool, list[dict[str, Any]]]:
    if not isinstance(status, dict):
        return False, []
    entries = status.get("servers")
    if not isinstance(entries, list):
        return False, []
    return True, [entry for entry in entries if isinstance(entry, dict)]


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _count(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def pool_health(
    rows: Iterable[Any], *, cluster: str, obj: str, pool: str, source: str = ""
) -> PoolHealth:
    """The nodes' verdict on one object's pool, from the poller's newest reading.

    Read out of the stored status document rather than through `parse_status`,
    because a poll that failed still carries the nodes that answered - and a
    page that showed nothing at all whenever one node was unreachable would hide
    the half of the cluster that is fine.
    """

    name = backend_name(obj, pool)
    reading = next((row for row in rows if getattr(row, "cluster", None) == cluster), None)
    if reading is None:
        return PoolHealth(backend=name, nodes=(), observed_at=None)

    result = reading.result if isinstance(reading.result, dict) else {}
    entries = result.get("nodes")
    nodes: list[NodeMembers] = []
    for entry in entries if isinstance(entries, Sequence) else ():
        if not isinstance(entry, dict):
            continue
        said, rows_for_node = _members(entry.get("status"))
        members = tuple(
            ServerHealth(
                backend=str(row.get("backend")),
                server=str(row.get("server")),
                status=_text(row.get("status")),
                check_status=_text(row.get("check_status")),
                check_code=_text(row.get("check_code")),
                check_duration_ms=_count(row.get("check_duration_ms")),
                last_change_sec=_count(row.get("last_change_sec")),
            )
            for row in rows_for_node
            if row.get("backend") == name and _text(row.get("server"))
        )
        status = entry.get("status")
        vip = status.get("vip") if isinstance(status, dict) else None
        held = vip.get("owner") if isinstance(vip, dict) else None
        nodes.append(
            NodeMembers(
                node=str(entry.get("name", "")),
                members=members,
                said=said,
                vip_owner=held if isinstance(held, bool) else None,
            )
        )

    #
    # An object that leaves from a source address can only be checked from the
    # node that carries it. The other one runs the same check, binds an address
    # it does not have, and reports the pool down - which is HAProxy telling the
    # truth about the binding and a lie about the pool.
    #
    # A node that did not say whether it owns the VIP is kept. Hiding a node on
    # a fact nobody stated is worse than one row too many.
    #
    if source:
        nodes = [node for node in nodes if node.vip_owner is not False]

    return PoolHealth(
        backend=name,
        nodes=tuple(nodes),
        observed_at=getattr(reading, "observed_at", None),
    )
