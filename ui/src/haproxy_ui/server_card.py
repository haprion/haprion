"""The object page's *Servers* card: each server's state on each node (Fas 20, B263).

One row per server the object is written with, one column per node, and the
sessions and weight beside them. The boxes and the buttons above them queue a
`server_state` job; this module only reads.

Where a node's answer comes from
--------------------------------
The poller's newest status reading, as every other card on the page. A node
names a server by its position (`s1`, `s2`, ...), which is the generator's name
for it, so a row is found by its place in the pool. That is only the same
server while the nodes run the version the page shows: an edit that reorders a
pool and is not yet deployed would put one server's state on another's row.
So the cells are drawn only while the object is served as written, and say
so otherwise. The buttons stay - the job names servers by address and the node
by GUID, and a node that does not have one yet says so.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from haproxy_mgmt.cluster_status import ServerHealth
from haproxy_mgmt.generate import backend_name, legacy_backend_name
from haproxy_mgmt.guid import server_guid
from haproxy_mgmt.proxy_model import Proxy

from haproxy_ui.health import answers_for, member_health, vip_owner

#
# HAProxy's own weight for a server line that names none.
#
DEFAULT_WEIGHT = 1


@dataclass(frozen=True, slots=True)
class Cell:
    """One node's word for one server, and the colour of its dot."""

    label: str
    tone: str
    title: str = ""


@dataclass(frozen=True, slots=True)
class ServerRow:
    #
    # What the job is asked for: always with the pool, so a server written in
    # two pools of one object is never ambiguous.
    #
    target: str
    shown: str
    backup: bool
    weight: int
    cells: tuple[Cell, ...]
    sessions: int | None


@dataclass(frozen=True, slots=True)
class ServerCard:
    pools: tuple[str, ...]
    nodes: tuple[str, ...]
    rows: tuple[ServerRow, ...]
    observed_at: datetime | None
    #
    # Whether the nodes serve the object as written; the cells are blank
    # otherwise (see the module's note).
    #
    current: bool


NOT_CURRENT = Cell("—", "unknown", "The nodes do not run this version of the object yet")
NOT_SAID = Cell("—", "unknown", "The node did not report this server")
#
# An object that leaves from a source address is checked only where that
# address is: on the node holding the VIP. The other node's check binds an
# address it does not have and fails - HAProxy telling the truth about the
# binding and a lie about the server (`health.answers_for`). Its drain or maintenance is still its own, and still shown. BACKUP
# is keepalived's word for that node, the one the dashboard's Failover column shows.
#
BACKUP = Cell("BACKUP", "unknown", "The object leaves from an address only the VIP holder carries")


def lost(state: str) -> Cell:
    """A drain or maintenance the node keeps for the server but HAProxy does not hold.

    A reload or a start that could not put it back (review 26-10-09, F1): the
    server takes traffic on this node although somebody took it out.
    """

    return Cell(
        f"{state.upper()} LOST",
        "critical",
        f"Kept as {state} on this node, but HAProxy does not hold it. Set it again.",
    )


def cell(member: ServerHealth | None, *, standby: bool = False) -> Cell:
    """A server as one node reports it: drain or maintenance first, then the check."""

    if member is None:
        return NOT_SAID
    check = (member.status or "").strip()
    if member.held:
        held = member.admin or check.lower()
        title = f"Check: {check}" if check else ""
        if held == "maint":
            return Cell("MAINT", "unknown", title)
        return Cell("DRAIN", "warning", title)
    if standby:
        return BACKUP
    upper = check.upper()
    if upper.startswith("UP"):
        return Cell("UP", "healthy", check if check != "UP" else "")
    if upper.startswith("DOWN"):
        return Cell("DOWN", "critical", check if check != "DOWN" else "")
    if check.lower() == "no check":
        return Cell("UP", "healthy", "No health check")
    return Cell(upper or "—", "unknown")


def _members(entry: Mapping[str, Any]) -> list[ServerHealth]:
    status = entry.get("status")
    found = status.get("servers") if isinstance(status, Mapping) else None
    return [
        member_health(row)
        for row in (found if isinstance(found, list) else ())
        if isinstance(row, Mapping)
    ]


def build(
    proxy: Proxy, rows: Iterable[Any], *, cluster: str, current: bool, sourced: bool = False
) -> ServerCard | None:
    """The card for one object, or None where it has no HAProxy servers.

    A dns or syslog object's servers are run by dnsdist and keepalived, which
    have no drain or maintenance (the helper refuses them), and an object with
    only redirects has no servers at all. `sourced` is an object leaving
    from a fixed address (`ObjectView.sourced`).
    """

    if proxy.listen.protocol in ("dns", "syslog"):
        return None
    pools = tuple(name for name, backend in sorted(proxy.backends.items()) if backend.servers)
    if not pools:
        return None

    reading = next((row for row in rows if getattr(row, "cluster", None) == cluster), None)
    result = reading.result if reading is not None and isinstance(reading.result, Mapping) else {}
    entries = result.get("nodes")
    nodes: list[tuple[str, dict[tuple[str, str], ServerHealth]]] = []
    standby: list[bool] = []
    unapplied: list[Mapping[str, Any]] = []
    for entry in entries if isinstance(entries, Sequence) else ():
        if not isinstance(entry, Mapping):
            continue
        nodes.append(
            (
                str(entry.get("name", "")),
                {(member.backend, member.server): member for member in _members(entry)},
            )
        )
        status = entry.get("status")
        kept = status.get("server_state_unapplied") if isinstance(status, Mapping) else None
        unapplied.append(kept if isinstance(kept, Mapping) else {})
        standby.append(not answers_for(sourced, vip_owner(status)))

    listed: list[ServerRow] = []
    for pool in pools:
        names = (backend_name(proxy, pool), legacy_backend_name(proxy.name, pool))
        for index, server in enumerate(proxy.backends[pool].servers):
            position = f"s{index + 1}"
            found = [
                next(
                    (members[(name, position)] for name in names if (name, position) in members),
                    None,
                )
                for _node, members in nodes
            ]
            sessions = [
                member.counters["scur"]
                for member in found
                if member is not None and "scur" in member.counters
            ]
            address = f"{server.host}:{server.port}"
            guid = server_guid(proxy.name, pool, server)
            listed.append(
                ServerRow(
                    target=f"{pool}/{address}",
                    shown=address if len(pools) == 1 else f"{pool}/{address}",
                    backup=server.backup,
                    weight=server.weight if server.weight is not None else DEFAULT_WEIGHT,
                    cells=tuple(
                        lost(str(kept[guid]))
                        if kept.get(guid) in ("drain", "maint")
                        else cell(member, standby=aside)
                        if current
                        else NOT_CURRENT
                        for member, aside, kept in zip(found, standby, unapplied, strict=True)
                    ),
                    sessions=sum(sessions) if current and sessions else None,
                )
            )

    return ServerCard(
        pools=pools,
        nodes=tuple(name for name, _members in nodes),
        # Alphabetical, as every list here is; the position is not the reader's.
        rows=tuple(sorted(listed, key=lambda row: row.shown)),
        observed_at=getattr(reading, "observed_at", None),
        current=current,
    )
