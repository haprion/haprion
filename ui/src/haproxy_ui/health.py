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

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from haproxy_mgmt.cluster_status import ServerHealth
from haproxy_mgmt.generate import PREFIX
from haproxy_mgmt.proxy_model import ModelError, read_document

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
    "L7OKC": "answered, held out of the pool",
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
    #
    # The addresses the author wrote, in the order they wrote them. The runtime
    # knows a pool member as `s1`, which is the generator's own name for the
    # position - deliberately not the address, since that is a column of its
    # own in `show stat`. On this card it is the wrong way round: the person
    # reading wrote `198.51.100.10:8080` and has never seen `s1`.
    #
    addresses: tuple[str, ...] = ()

    def address(self, server: str) -> str:
        """The address behind a runtime server name, where one can be named.

        Empty for anything that is not `s<n>` within the pool as it now stands.
        A pool edited since the deploy can have more names than addresses, and
        guessing there would put somebody else's address beside a member.
        """

        if not server.startswith("s") or not server[1:].isdigit():
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


#
# What HAProxy reports for a server nobody is checking. Measured against 3.4.4
# on this machine rather than assumed: the row is there, with this in the status
# column instead of UP or DOWN.
#
# It is not a verdict, so it must not be counted as one. Counting it as "not up"
# turned an object whose check exists in the document but not yet on the nodes -
# a check added and not deployed - into a red lamp saying the pool was down.
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


def pool_health(
    rows: Iterable[Any],
    *,
    cluster: str,
    obj: str,
    pool: str,
    source: str = "",
    addresses: Iterable[str] = (),
) -> PoolHealth:
    """The nodes' verdict on one object's pool, from the poller's newest reading.

    Read out of the stored status document rather than through `parse_status`,
    because a poll that failed still carries the nodes that answered - and a
    page that showed nothing at all whenever one node was unreachable would hide
    the half of the cluster that is fine.
    """

    name = backend_name(obj, pool)
    written = tuple(address.strip() for address in addresses if address.strip())
    reading = next((row for row in rows if getattr(row, "cluster", None) == cluster), None)
    if reading is None:
        return PoolHealth(backend=name, nodes=(), observed_at=None, addresses=written)

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
            if row.get("backend") == name and _is_member(row)
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
        addresses=written,
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


def leaves_from_source(document: str, *, default_vip: str, vip_sources: Mapping[str, str]) -> bool:
    """Whether this object's traffic leaves from a source address.

    It does when it names one, and it does when the VIP it is served on carries
    one - which is the usual case here, since the address lives in keepalived
    and follows the VIP. What an ADC calls the SNIP.

    It decides which nodes may answer for the pool. Only the node holding the
    VIP can bind the address; the other binds an address it does not have,
    fails, and reports the pool down - HAProxy telling the truth about the
    binding and a lie about the pool.
    """

    try:
        data = read_document("object", document.encode())
    except (ModelError, ValueError, UnicodeError):
        return False
    listen = data.get("listen")
    listen = listen if isinstance(listen, dict) else {}
    if listen.get("source"):
        return True
    vip = str(listen.get("vip") or "") or default_vip
    return bool(vip_sources.get(vip))


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


def served_objects(rows: Iterable[Any], *, cluster: str, names: Iterable[str]) -> frozenset[str]:
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

    names = tuple(names)
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
            for name in names:
                if _attributed(backend, name, names):
                    served.add(name)
    return frozenset(served)


def object_health(
    rows: Iterable[Any],
    *,
    cluster: str,
    obj: str,
    others: Iterable[str] = (),
    checked: bool | None = True,
    sourced: bool = False,
) -> ObjectHealth:
    """Every node's verdict on every pool behind one object, as one lamp.

    Counted in servers, because that is what somebody wrote down. Both nodes
    run the same configuration and report the same pool, so counting readings
    made one server behind a two-node cluster read as `2/2` - and a person who
    had written one server and one check had no way to reach that number.

    A server is up only where every node that reported it says so. The two
    nodes are not averaged: traffic landing on the node that cannot reach it
    does not reach it, and that is the case this lamp exists to show. The node
    that disagrees is named, since which one it is decides what to look at.
    """

    #
    # An object with no health check gets an unlit lamp rather than a colour.
    # HAProxy reports an unchecked server as UP - it has nothing to say
    # otherwise - so green here would claim a reachability nothing measured.
    # The distinction the column exists to draw is between checked-and-up and
    # not checked at all.
    #
    if checked is False:
        return ObjectHealth("unknown", "", "This object defines no health check", 0, 0)

    others = tuple(others)
    reading = next((row for row in rows if getattr(row, "cluster", None) == cluster), None)
    result = reading.result if reading is not None and isinstance(reading.result, dict) else {}
    entries = result.get("nodes")

    #
    # Keyed by pool and server, because two pools behind one object may name a
    # server the same and they are not the same server.
    #
    healthy: dict[tuple[str, str], bool] = {}
    #
    # And whether any node at all could reach it. A server down on one node and
    # up on the other is a partial fault, not a dead pool, and the two must not
    # come out as the same colour.
    #
    reachable: dict[tuple[str, str], bool] = {}
    complaining: set[str] = set()
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
            and _is_member(member)
        ]
        if not mine:
            continue
        #
        # The same rule the editor's card applies, and for the same reason: an
        # object that leaves from a source address can only be answered for by
        # the node that carries it. A node that says it does not is not a
        # verdict on the pool. One that says nothing is kept - hiding a node on
        # a fact nobody stated is worse than one row too many.
        #
        status = entry.get("status")
        vip = status.get("vip") if isinstance(status, dict) else None
        owner = vip.get("owner") if isinstance(vip, dict) else None
        if sourced and owner is False:
            continue
        nodes += 1
        node = str(entry.get("name") or entry.get("node") or "")
        for member in mine:
            key = (str(member["backend"]), str(member["server"]))
            reported = str(member.get("status", "") or "")
            if reported.strip().lower() == UNCHECKED:
                #
                # Nothing is checking this server, so the node has no opinion
                # about it. Skipped rather than counted either way.
                #
                continue
            reports_up = reported.upper().startswith("UP")
            healthy[key] = healthy.get(key, True) and reports_up
            reachable[key] = reachable.get(key, False) or reports_up
            if not reports_up and node:
                complaining.add(node)

    total = len(healthy)
    if total == 0:
        return ObjectHealth(
            tone="unknown",
            label="",
            detail="No node reported servers for this object",
            up=0,
            total=0,
        )

    up = sum(1 for ok in healthy.values() if ok)
    unreachable = sum(1 for ok in reachable.values() if not ok)
    servers = "server" if total == 1 else "servers"
    seen = "one node" if nodes == 1 else f"{nodes} nodes"
    if up == total:
        return ObjectHealth(
            "healthy", f"{up}/{total} up", f"Every server is up, as seen by {seen}", up, total
        )
    #
    # Named, because a server up on one node and down on the other is a
    # different problem from one that is down everywhere, and the name is where
    # somebody would start looking.
    #
    reported = f" · reported down by {', '.join(sorted(complaining))}" if complaining else ""
    #
    # Red is reserved for a pool no node can reach. Anything else - one member
    # of three, or one node of two - is amber: it is still serving, and calling
    # that an outage teaches somebody to disbelieve the colour.
    #
    if unreachable == total:
        return ObjectHealth(
            "critical", f"0/{total} up", f"No {servers} reachable{reported}", up, total
        )
    return ObjectHealth(
        "warning",
        f"{up}/{total} up",
        f"{total - up} of {total} {servers} not up everywhere{reported}",
        up,
        total,
    )
