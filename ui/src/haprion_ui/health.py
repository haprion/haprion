"""What the nodes report about one object's backend members.

The question a person authoring an object actually has is "does my health check
work", and the only place with a real answer is the node: HAProxy there has been
running the check, from that node, against the servers it was told about. This
module does no probing of its own - it reads the verdict the poller already
collected and lines it up with the object being edited.

Nothing here is a fresh measurement. A reading is as old as the poll that took
it, and the page says so rather than implying the numbers are from now.
"""

from __future__ import annotations

from collections.abc import Callable, Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from haprion.cluster_status import ADMIN_STATES, ServerHealth, ipvs_unread
from haprion.digits import is_digits

#
# HAProxy's own check codes, as sentences. The codes are the machine's language
# on a page built for people, and reading `L6RSP` cost an evening once - but a
# code somebody can search the internet for is worth keeping, so it stays as the
# cell's title rather than being replaced.
#
# The meanings are HAProxy 3.4.4's own, from `configuration.txt` on this
# machine under `tcp-check expect`. `INI` and `SOCKERR` are not in that list -
# they come from the stats output - and are written from what they were
# measured to mean here.
#
CHECK_PHRASES = {
    "L7OK": "answered",
    "L7OKC": "answered, held out of the backend",
    "L7STS": "answered",
    "L7RSP": "the answer was not valid",
    "L7TOUT": "no answer in time",
    "L6OK": "the handshake succeeded",
    "L6RSP": "TLS: the answer was not valid",
    "L6TOUT": "the handshake timed out",
    "L4OK": "the port answered",
    "L4CON": "could not connect",
    "L4TOUT": "no answer in time",
    "SOCKERR": "the connection failed",
    "INI": "not checked yet",
    "UNK": "not known",
}


def check_phrase(status: str, code: str = "") -> str:
    """One code as a sentence, with whatever number came with it.

    An unknown code is returned as it stands. A translation table that guessed
    would be worse than the code: somebody can look a code up, and cannot look
    up a sentence this file invented.
    """

    if not status:
        return ""
    phrase = CHECK_PHRASES.get(status)
    if phrase is None:
        return f"{status} {code}".strip()
    return f"{phrase} {code}".strip() if code else phrase


def backend_owners(
    views: Iterable[Any], removed: Mapping[str, Iterable[str]] | None = None
) -> dict[str, str]:
    """Which object each backend HAProxy reports belongs to (B250).

    A pool is named by itself, so its name no longer says whose it is. The
    objects helper says (`runtime_backends`), and so does a removal's own
    bookkeeping for an object the repository no longer has but the nodes still
    serve. A name neither knows belongs to no object.
    """

    owners: dict[str, str] = {}
    for name, backends in (removed or {}).items():
        for backend in backends:
            owners.setdefault(backend, name)
    for view in views:
        for backend in getattr(view, "runtime_backends", None) or ():
            owners[backend] = view.name
    return owners


@dataclass(frozen=True, slots=True)
class NodeMembers:
    """One node's verdict on the members of one backend."""

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
class BackendHealth:
    """Every node's answer about one backend, and when it was taken."""

    backend: str
    nodes: tuple[NodeMembers, ...]
    observed_at: datetime | None
    #
    # The addresses the author wrote, in the order they wrote them. The runtime
    # knows a backend member as `s1`, which is the generator's own name for the
    # position - deliberately not the address, since that is a column of its
    # own in `show stat`. On this card it is the wrong way round: the person
    # reading wrote `198.51.100.10:8080` and has never seen `s1`.
    #
    addresses: tuple[str, ...] = ()

    def address(self, server: str) -> str:
        """The address behind a runtime server name, where one can be named.

        Empty for anything that is not `s<n>` within the backend as it now stands.
        A backend edited since the deploy can have more names than addresses, and
        guessing there would put somebody else's address beside a member.
        """

        if not server.startswith("s") or not is_digits(server[1:]):
            return ""
        index = int(server[1:]) - 1
        return self.addresses[index] if 0 <= index < len(self.addresses) else ""

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
        """Whether any node reported members for this backend at all."""

        return any(node.members for node in self.nodes)

    @property
    def failing(self) -> tuple[NodeMembers, ...]:
        return tuple(
            node
            for node in self.nodes
            if any(not member.up and not member.held for member in node.members)
        )


def _members(status: Any) -> tuple[bool, list[dict[str, Any]]]:
    """HAProxy's servers, and dnsdist's and IPVS's beside them in the same shape.

    A dns pool's servers are checked by dnsdist and reported with its counters,
    `UP` or `DOWN` under the pool's name (Fas 19a B5), and a syslog pool's
    receivers by keepalived, under the pool the node's file names (Fas 19b B4).
    Read here, every page that reads a
    backend's servers reads them: the listing's lamp, which objects are served,
    and the editor's table. Whether the node said anything is HAProxy's answer,
    as it was.
    """

    if not isinstance(status, dict):
        return False, []
    others = _dns_members(status) + _ipvs_members(status)
    entries = status.get("servers")
    if not isinstance(entries, list):
        return False, others
    return True, [entry for entry in entries if isinstance(entry, dict)] + others


def node_members(status: Any) -> tuple[bool, list[dict[str, Any]]]:
    """One node's servers of every kind, as the lamp reads them; see `_members`."""

    return _members(status)


def is_member(row: Mapping[str, Any]) -> bool:
    """Whether a server row is a member rather than a pool's own row."""

    return _is_member(row)


def _dns_members(status: Mapping[str, Any]) -> list[dict[str, Any]]:
    listener = status.get("dns_listener")
    counted = listener.get("counters") if isinstance(listener, Mapping) else None
    entries = counted.get("servers") if isinstance(counted, Mapping) else None
    return [
        {"backend": entry["pool"], "server": entry["server"], "status": entry.get("status")}
        for entry in (entries if isinstance(entries, list) else ())
        if isinstance(entry, Mapping)
        and isinstance(entry.get("pool"), str)
        and isinstance(entry.get("server"), str)
    ]


def _ipvs_members(status: Mapping[str, Any]) -> list[dict[str, Any]]:
    """A syslog pool's receivers, as IPVS holds them (Fas 19b B4).

    keepalived checks them and takes a receiver whose check fails out of the
    kernel; the node reports it `DOWN` under its pool then, and `UP` while the
    kernel holds it. A pool with no check is never taken out, and reads `UP`
    as an unchecked HAProxy server does - the lamp asks whether there is a
    check before it believes either.
    """

    section = status.get("ipvs")
    services = section.get("services") if isinstance(section, Mapping) else None
    members: list[dict[str, Any]] = []
    for service in services if isinstance(services, list) else ():
        if not isinstance(service, Mapping) or not isinstance(service.get("pool"), str):
            continue
        receivers = service.get("receivers")
        members += [
            {"backend": service["pool"], "server": entry["server"], "status": entry.get("status")}
            for entry in (receivers if isinstance(receivers, list) else ())
            if isinstance(entry, Mapping) and isinstance(entry.get("server"), str)
        ]
    return members


def _every_node(
    rows: Iterable[Any], cluster: str, ready: Callable[[Mapping[str, Any]], bool]
) -> bool:
    """Whether every node of the cluster answered, and said `ready` of its status.

    The WAF engine's rule (B231): a node from before the field, or one that did
    not answer, is a node the feature cannot be counted on, and a release that
    needs it is refused there.
    """

    reading = next((row for row in rows if getattr(row, "cluster", None) == cluster), None)
    result = reading.result if reading is not None and isinstance(reading.result, Mapping) else {}
    entries = result.get("nodes")
    nodes = (
        [entry for entry in entries if isinstance(entry, Mapping)]
        if isinstance(entries, list)
        else []
    )
    if not nodes:
        return False
    for entry in nodes:
        status = entry.get("status")
        if not isinstance(status, Mapping) or not ready(status):
            return False
    return True


def syslog_unforwarded(rows: Iterable[Any], *, cluster: str) -> tuple[str, ...]:
    """The nodes whose release asks for virtual servers their keepalived does not read.

    Review 26-10-08 F1: the include in keepalived.conf is missing there, so the
    cluster's syslog objects are forwarded nowhere by that node, and a deploy
    is refused until a person adds it. The engine's own reading.
    """

    reading = next((row for row in rows if getattr(row, "cluster", None) == cluster), None)
    result = reading.result if reading is not None and isinstance(reading.result, Mapping) else {}
    entries = result.get("nodes")
    return tuple(
        str(entry.get("name", ""))
        for entry in (entries if isinstance(entries, list) else ())
        if isinstance(entry, Mapping)
        and isinstance(entry.get("status"), Mapping)
        and ipvs_unread(entry["status"])
    )


def dns_everywhere(rows: Iterable[Any], *, cluster: str) -> bool:
    """Whether every node of the cluster reports dnsdist installed (Fas 19a B5)."""

    def ready(status: Mapping[str, Any]) -> bool:
        listener = status.get("dns_listener")
        return isinstance(listener, Mapping) and isinstance(listener.get("version"), str)

    return _every_node(rows, cluster, ready)


def syslog_everywhere(rows: Iterable[Any], *, cluster: str) -> bool:
    """Whether every node's keepalived reads the syslog objects' file (Fas 19b B4).

    Until `keepalived.conf` includes it at its top level, the node installs
    the file and nothing forwards: a syslog object published then is one the
    node accepts and no message reaches. The include is a person's line, one
    node at a time (B57's order), so the form waits for the last of them.
    """

    def ready(status: Mapping[str, Any]) -> bool:
        section = status.get("ipvs")
        return isinstance(section, Mapping) and section.get("included") is True

    return _every_node(rows, cluster, ready)


#
# What HAProxy reports for a server nobody is checking. Measured against 3.4.4
# on this machine rather than assumed: the row is there, with this in the status
# column instead of UP or DOWN.
#
# It is not a verdict, so it must not be counted as one. Counting it as "not up"
# turned an object whose check exists in the document but not yet on the nodes -
# a check added and not deployed - into a red lamp saying the backend was down.
#
UNCHECKED = "no check"


#
# `show stat` emits a pseudo-row per proxy summarising the whole backend, and
# the node reports it alongside the real ones - it filters `FRONTEND` and keeps
# this. It is not a member: counting it made one server on two nodes read as
# four things to be up, and put a row called BACKEND in a list of servers.
#
PSEUDO_MEMBERS = {"BACKEND", "FRONTEND"}


def _is_member(row: Mapping[str, Any]) -> bool:
    name = row.get("server")
    return isinstance(name, str) and bool(name) and name not in PSEUDO_MEMBERS


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _count(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _counters(value: Any) -> dict[str, int]:
    if not isinstance(value, Mapping):
        return {}
    return {
        str(name): number for name, count in value.items() if (number := _count(count)) is not None
    }


def _admin(value: Any) -> str | None:
    return value if isinstance(value, str) and value in ADMIN_STATES else None


def vip_owner(status: Any) -> bool | None:
    """Whether a node says it holds its cluster's VIP; None when it did not say."""

    vip = status.get("vip") if isinstance(status, Mapping) else None
    held = vip.get("owner") if isinstance(vip, Mapping) else None
    return held if isinstance(held, bool) else None


def answers_for(held_only: bool, owner: bool | None) -> bool:
    """Whether a node's check answers for an object's servers.

    An object that leaves from a source address can only be checked from the
    node that carries it. The other one runs the same check, binds an address
    it does not have, and reports the backend down - which is HAProxy telling
    the truth about the binding and a lie about the backend. A syslog object
    leaves from no address, but its messages pass only the VIP holder, and the
    same holds (Fas 19b B5). A node that did not say whether it owns the VIP
    answers: hiding a node on a fact nobody stated is worse than one row too
    many. One rule for the lamp, the editor's card and the Servers card (review
    26-10-09, F3).
    """

    return not (held_only and owner is False)


def member_health(row: Mapping[str, Any]) -> ServerHealth:
    """One server row of a stored status document, read the way the engine reads it."""

    return ServerHealth(
        backend=str(row.get("backend")),
        server=str(row.get("server")),
        status=_text(row.get("status")),
        check_status=_text(row.get("check_status")),
        check_code=_text(row.get("check_code")),
        check_duration_ms=_count(row.get("check_duration_ms")),
        last_change_sec=_count(row.get("last_change_sec")),
        counters=_counters(row.get("counters")),
        admin=_admin(row.get("admin")),
    )


def backend_health(
    rows: Iterable[Any],
    *,
    cluster: str,
    obj: str,
    backend: str,
    source: str = "",
    addresses: Iterable[str] = (),
    deployed: Iterable[str] = (),
    held_only: bool = False,
) -> BackendHealth:
    """The nodes' verdict on one object's backend, from the poller's newest reading.

    Read out of the stored status document rather than through `parse_status`,
    because a poll that failed still carries the nodes that answered - and a
    page that showed nothing at all whenever one node was unreachable would hide
    the half of the cluster that is fine.

    `addresses` are the form's and `deployed` the published document's. A
    runtime name is a position in the backend the nodes run, so the form's
    address goes beside it only when the two lists agree and every node runs
    the published version: a draft, a saved change or a publish not yet
    deployed can hold another address at that position, and the card put it
    beside the old one's health (review 26-10-24, 02-10).
    """

    name = backend
    reading = next((row for row in rows if getattr(row, "cluster", None) == cluster), None)
    if reading is None:
        return BackendHealth(backend=name, nodes=(), observed_at=None)

    result = reading.result if isinstance(reading.result, dict) else {}
    summary = result.get("summary")
    written = tuple(address.strip() for address in addresses if address.strip())
    running = isinstance(summary, dict) and summary.get("release_state") == "converged"
    if not running or written != tuple(address.strip() for address in deployed if address.strip()):
        written = ()
    entries = result.get("nodes")
    nodes: list[NodeMembers] = []
    for entry in entries if isinstance(entries, Sequence) else ():
        if not isinstance(entry, dict):
            continue
        said, rows_for_node = _members(entry.get("status"))
        members = tuple(
            member_health(row)
            for row in rows_for_node
            if row.get("backend") == name and _is_member(row)
        )
        nodes.append(
            NodeMembers(
                node=str(entry.get("name", "")),
                members=members,
                said=said,
                vip_owner=vip_owner(entry.get("status")),
            )
        )

    nodes = [node for node in nodes if answers_for(bool(source) or held_only, node.vip_owner)]

    return BackendHealth(
        backend=name,
        nodes=tuple(nodes),
        observed_at=getattr(reading, "observed_at", None),
        addresses=written,
    )


@dataclass(frozen=True, slots=True)
class ObjectHealth:
    """One object's backends rolled up to the one thing a listing can show.

    The listing cannot probe. A probe is an SSH operation against a node, and a
    page that ran one per row on every load would turn opening a list into a
    burst of connections nobody asked for. So this is the passive answer - what
    HAProxy on the nodes has already decided about the servers it was told
    about - read out of the poller's newest reading like every other cell.
    """

    tone: str
    #
    # Empty where there is nothing to count. A grey lamp says "no answer" on
    # its own, and the two ways of having none - no check written, or nothing
    # reported yet - are a sentence in the title rather than two words in a
    # column of numbers.
    #
    label: str
    detail: str
    up: int
    total: int


def clusters_behind(rows: Iterable[Any]) -> frozenset[str]:
    """Clusters whose nodes are not yet running the published configuration.

    The same fact the dashboard names "Not on the latest version", asked here
    because this is the page somebody is on when it matters. Publishing does
    not deploy - deliberately, and stated everywhere except the listing itself,
    where an object could be edited, published and left showing nothing at all
    about the nodes still serving the previous version. An object being added
    or removed already says "deploy to add" or "deploy to remove"; a *changed*
    object said nothing, because it is neither.

    Read from the nodes rather than from the release. A node that has not been
    read says nothing, and silence is not a claim that it is up to date - so
    only an explicit `false` counts.
    """

    behind: set[str] = set()
    for row in rows:
        result = row.result if hasattr(row, "result") else None
        if not isinstance(result, Mapping):
            continue
        nodes = result.get("nodes")
        if not isinstance(nodes, list):
            continue
        for node in nodes:
            if not isinstance(node, Mapping):
                continue
            if node.get("reachable") is True and node.get("current") is False:
                behind.add(getattr(row, "cluster", ""))
    behind.discard("")
    return frozenset(behind)


def object_states(rows: Iterable[Any], *, cluster: str) -> dict[str, str]:
    """Per object, whether the nodes are serving the version that is published.

    The engine decides this by comparing two release manifests - the published
    one against the one each node reports - and the answer arrives in the
    status document already made. Nothing is derived here: a second derivation
    in the web layer is exactly the drift that made this comparison necessary
    in the first place, when the listing and the object page each read the job
    history their own way.

    A name with no entry is not present in the mapping, and a caller that finds
    none reports unknown. That includes every cluster whose published release
    was built before manifests existed.
    """

    for row in rows:
        if getattr(row, "cluster", None) != cluster:
            continue
        result = row.result if hasattr(row, "result") else None
        if not isinstance(result, Mapping):
            continue
        entries = result.get("objects")
        if not isinstance(entries, Mapping):
            continue
        states: dict[str, str] = {}
        for name, entry in entries.items():
            state = entry.get("state") if isinstance(entry, Mapping) else None
            if isinstance(name, str) and isinstance(state, str):
                states[name] = state
        return states
    return {}


def served_objects(
    rows: Iterable[Any],
    *,
    cluster: str,
    names: Iterable[str],
    owners: Mapping[str, str] | None = None,
) -> frozenset[str]:
    """The objects some node reports a backend for: what is on the nodes now.

    Measured where the traffic is, rather than derived from a release. The
    published inventory is the *released* configuration, so an object counted
    as served the moment it was published - while the nodes went on serving the
    release they had, sometimes for days.

    A server with no health check is reported too, with `no check` where a
    verdict would be, so this answers for an object nobody is checking.

    Empty when no node said anything at all. That is not "nothing is served" -
    it is a cluster whose nodes have not been read, and the caller falls back to
    what the release says rather than treating silence as an answer.
    """

    names = frozenset(names)
    reading = next((row for row in rows if getattr(row, "cluster", None) == cluster), None)
    result = reading.result if reading is not None and isinstance(reading.result, dict) else {}
    entries = result.get("nodes")

    served: set[str] = set()
    for entry in entries if isinstance(entries, Sequence) else ():
        if not isinstance(entry, dict):
            continue
        said, members = _members(entry.get("status"))
        if not said:
            continue
        for member in members:
            backend = member.get("backend")
            if not isinstance(backend, str) or not _is_member(member):
                continue
            owner = (owners or {}).get(backend)
            if owner is not None and owner in names:
                served.add(owner)
    return frozenset(served)


def object_health(
    rows: Iterable[Any],
    *,
    cluster: str,
    obj: str,
    others: Iterable[str] = (),
    checked: bool | None = True,
    sourced: bool = False,
    owners: Mapping[str, str] | None = None,
) -> ObjectHealth:
    """One object's lamp; see `object_healths`, which this asks for one name."""

    known: dict[str, tuple[bool | None, bool]] = {name: (True, False) for name in others}
    known[obj] = (checked, sourced)
    return object_healths(rows, cluster=cluster, objects=known, owners=owners)[obj]


def object_healths(
    rows: Iterable[Any],
    *,
    cluster: str,
    objects: Mapping[str, tuple[bool | None, bool]],
    owners: Mapping[str, str] | None = None,
) -> dict[str, ObjectHealth]:
    """Every node's verdict on every backend behind each object, as one lamp each.

    `objects` maps each name to whether it is health checked and whether it
    leaves from a source address. Read in one pass over the nodes' servers,
    each attributed to its object once (2026-10-01): asking per object read
    every server of the cluster once for every object, which at ten thousand
    objects took a hundred seconds.

    Counted in servers, because that is what somebody wrote down. Both nodes
    run the same configuration and report the same backend, so counting readings
    made one server behind a two-node cluster read as `2/2` - and a person who
    had written one server and one check had no way to reach that number.

    A server is up only where every node that reported it says so. The two
    nodes are not averaged: traffic landing on the node that cannot reach it
    does not reach it, and that is the case this lamp exists to show. The node
    that disagrees is named, since which one it is decides what to look at.
    """

    names = frozenset(objects)
    reading = next((row for row in rows if getattr(row, "cluster", None) == cluster), None)
    result = reading.result if reading is not None and isinstance(reading.result, dict) else {}
    entries = result.get("nodes")

    #
    # Keyed by backend and server, because two backends behind one object may name a
    # server the same and they are not the same server.
    #
    healthy: dict[str, dict[tuple[str, str], bool]] = {name: {} for name in names}
    #
    # And whether any node at all could reach it. A server down on one node and
    # up on the other is a partial fault, not a dead backend, and the two must not
    # come out as the same colour.
    #
    reachable: dict[str, dict[tuple[str, str], bool]] = {name: {} for name in names}
    complaining: dict[str, set[str]] = {name: set() for name in names}
    #
    # Drained or in maintenance on purpose (B263): not a fault, so not counted
    # either way on the node that holds it, and named in the lamp's sentence.
    #
    held: dict[str, set[tuple[str, str]]] = {name: set() for name in names}
    nodes: dict[str, int] = dict.fromkeys(names, 0)
    for entry in entries if isinstance(entries, Sequence) else ():
        if not isinstance(entry, dict):
            continue
        _said, members = _members(entry.get("status"))
        grouped: dict[str, list[dict[str, Any]]] = {}
        for member in members:
            backend = member.get("backend")
            if not isinstance(backend, str) or not _is_member(member):
                continue
            owner = (owners or {}).get(backend)
            if owner is not None and owner in names:
                grouped.setdefault(owner, []).append(member)
        holds = vip_owner(entry.get("status"))
        node = str(entry.get("name") or entry.get("node") or "")
        for obj, mine in grouped.items():
            if not answers_for(objects[obj][1], holds):
                continue
            nodes[obj] += 1
            for member in mine:
                key = (str(member["backend"]), str(member["server"]))
                reported = str(member.get("status", "") or "")
                if member_health(member).held:
                    held[obj].add(key)
                    continue
                if reported.strip().lower() == UNCHECKED:
                    #
                    # Nothing is checking this server, so the node has no opinion
                    # about it. Skipped rather than counted either way.
                    #
                    continue
                reports_up = reported.upper().startswith("UP")
                healthy[obj][key] = healthy[obj].get(key, True) and reports_up
                reachable[obj][key] = reachable[obj].get(key, False) or reports_up
                if not reports_up and node:
                    complaining[obj].add(node)

    return {
        name: _lamp(
            checked=objects[name][0],
            healthy=healthy[name],
            reachable=reachable[name],
            complaining=complaining[name],
            nodes=nodes[name],
            held=len(held[name]),
        )
        for name in names
    }


#
# The lamp of an object whose every server was taken out on purpose (B263): the
# attention list tells it from a fault by this label.
#
HELD_LABEL = "Held"


def _lamp(
    *,
    checked: bool | None,
    healthy: Mapping[tuple[str, str], bool],
    reachable: Mapping[tuple[str, str], bool],
    complaining: Collection[str],
    nodes: int,
    held: int = 0,
) -> ObjectHealth:
    #
    # Every server taken out on purpose (B263) serves nothing new, checked or
    # not, and that is what the lamp says before anything else.
    #
    total = len(healthy)
    if held and total == 0:
        return ObjectHealth(
            "warning", HELD_LABEL, "Every server is drained or in maintenance", 0, held
        )
    aside = f" · {held} drained or in maintenance" if held else ""
    #
    # An object with no health check gets an unlit lamp rather than a colour.
    # HAProxy reports an unchecked server as UP - it has nothing to say
    # otherwise - so green here would claim a reachability nothing measured.
    # The distinction the column exists to draw is between checked-and-up and
    # not checked at all.
    #
    if checked is False:
        return ObjectHealth("unknown", "", f"This proxy defines no health check{aside}", 0, 0)

    if total == 0:
        return ObjectHealth(
            tone="unknown",
            label="",
            detail="No node reported servers for this proxy",
            up=0,
            total=0,
        )

    up = sum(1 for ok in healthy.values() if ok)
    unreachable = sum(1 for ok in reachable.values() if not ok)
    servers = "server" if total == 1 else "servers"
    seen = "one node" if nodes == 1 else f"{nodes} nodes"
    if up == total:
        return ObjectHealth(
            "healthy",
            f"{up}/{total} up",
            f"Every server is up, as seen by {seen}{aside}",
            up,
            total,
        )
    #
    # Named, because a server up on one node and down on the other is a
    # different problem from one that is down everywhere, and the name is where
    # somebody would start looking.
    #
    reported = f" · reported down by {', '.join(sorted(complaining))}" if complaining else ""
    #
    # Red is reserved for a backend no node can reach. Anything else - one member
    # of three, or one node of two - is amber: it is still serving, and calling
    # that an outage teaches somebody to disbelieve the colour.
    #
    if unreachable == total:
        return ObjectHealth(
            "critical", f"0/{total} up", f"No {servers} reachable{reported}{aside}", up, total
        )
    return ObjectHealth(
        "warning",
        f"{up}/{total} up",
        f"{total - up} of {total} {servers} not up everywhere{reported}{aside}",
        up,
        total,
    )
