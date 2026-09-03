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
from haproxy_mgmt.proxy_model import ModelError, read_document


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


@dataclass(frozen=True, slots=True)
class ObjectHealth:
    """One object's pools rolled up to the one thing a listing can show.

    The listing cannot probe. A probe is an SSH operation against a node, and a
    page that ran one per row on every load would turn opening a list into a
    burst of connections nobody asked for. So this is the passive answer - what
    HAProxy on the nodes has already decided about the servers it was told
    about - read out of the poller's newest reading like every other cell.
    """

    tone: str
    label: str
    detail: str
    up: int
    total: int


def _attributed(backend: str, obj: str, others: Iterable[str]) -> bool:
    """Whether a generated backend name belongs to this object.

    The generator names a backend `mgd-<object>-<pool>`, and both halves may
    contain a hyphen - so `mgd-shop-web` is what object `shop` with pool `web`
    is called, and equally what object `shop-web` with a pool called nothing
    would be. A prefix test alone would lend one object's servers to another
    whose name happens to be shorter.

    The longest name that fits wins, which is the same answer a person reading
    the two documents would give.
    """

    prefix = f"{PREFIX}-{obj}-"
    if not backend.startswith(prefix):
        return False
    return not any(
        other != obj and len(other) > len(obj) and backend.startswith(f"{PREFIX}-{other}-")
        for other in others
    )


def has_health_check(document: str) -> bool | None:
    """Whether any of this object's pools is checked at all.

    `None` is a document that could not be read, which is not the same answer:
    an object nobody can parse has an unknown check, not a missing one.

    Read through the engine's own reader rather than a second YAML parser here,
    for the reason that reader gives - a page that disagreed with the engine
    about what a document says would disagree exactly where it matters.
    """

    try:
        data = read_document("object", document.encode())
    except (ModelError, ValueError, UnicodeError):
        return None
    backends = data.get("backends")
    if not isinstance(backends, dict):
        return False
    #
    # `type: disabled` is a written-down decision not to check, and the model
    # spells it out rather than leaving it as the absence of the section. It
    # counts as no check here for the same reason: what the lamp reports on is
    # whether something is checking, not whether the key is present.
    #
    return any(
        isinstance(pool, dict)
        and isinstance(pool.get("health"), dict)
        and pool["health"].get("type") not in (None, "disabled")
        for pool in backends.values()
    )


def object_health(
    rows: Iterable[Any],
    *,
    cluster: str,
    obj: str,
    others: Iterable[str] = (),
    checked: bool | None = True,
) -> ObjectHealth:
    """Every node's verdict on every pool behind one object, as one lamp.

    Counted per node and not per server. A member that is up on one node and
    down on the other is a real fault - the traffic that lands on the second
    node does not reach it - and averaging the two into "up" would hide exactly
    the case this column exists to show.

    Nothing reported is `unknown` and never green. An object waiting for a
    deploy, a node running an older status script, and a pool whose every
    member is down are three different answers, and only the last one is red.
    """

    #
    # An object with no health check gets an unlit lamp rather than a colour.
    # HAProxy reports an unchecked server as UP - it has nothing to say
    # otherwise - so green here would claim a reachability nothing measured.
    # The distinction the column exists to draw is between checked-and-up and
    # not checked at all.
    #
    if checked is False:
        return ObjectHealth("off", "No check", "This object defines no health check", 0, 0)

    others = tuple(others)
    reading = next((row for row in rows if getattr(row, "cluster", None) == cluster), None)
    result = reading.result if reading is not None and isinstance(reading.result, dict) else {}
    entries = result.get("nodes")

    up = 0
    total = 0
    nodes = 0
    for entry in entries if isinstance(entries, Sequence) else ():
        if not isinstance(entry, dict):
            continue
        said, members = _members(entry.get("status"))
        mine = [
            member
            for member in members
            if isinstance(member.get("backend"), str)
            and _attributed(member["backend"], obj, others)
            and _text(member.get("server"))
        ]
        if not mine:
            continue
        nodes += 1
        total += len(mine)
        up += sum(1 for member in mine if str(member.get("status", "")).upper().startswith("UP"))

    if total == 0:
        return ObjectHealth(
            tone="unknown",
            label="Not reported",
            detail="No node reported servers for this object",
            up=0,
            total=0,
        )
    where = "on one node" if nodes == 1 else f"across {nodes} nodes"
    if up == total:
        return ObjectHealth("healthy", f"{up}/{total} up", f"Every member is up {where}", up, total)
    if up == 0:
        return ObjectHealth("critical", f"0/{total} up", f"No member is up {where}", up, total)
    return ObjectHealth(
        "warning",
        f"{up}/{total} up",
        f"{total - up} of {total} members are down {where}",
        up,
        total,
    )
