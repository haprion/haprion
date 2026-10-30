"""What the nodes did on their own, between two status readings (26-10-12).

*Events → Nodes*: a server that went down or came back, the VIP moving to
the other node, a node that stopped answering or answers again. Nobody did
these, so the audit record has none of them, and the status reading only ever
says what is true now. This module compares a reading with the last state
kept, and names what changed.

Servers are read from the node that holds the VIP, as the metrics are (B94):
the other node's check leaves from an address it does not have and reports
down servers that are up. So a server is one state per cluster, seen by
whichever node holds the address, and the VIP moving changes nothing about
it. A server somebody holds (drain, maintenance) or nobody checks keeps its
last state until it is checked again.

A key seen for the first time is a starting point, not an event: a new
server, a new installation and the first reading after this table existed
say nothing happened.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

from haprion_ui import health, moments

type Event = Literal["server_down", "server_up", "vip_moved", "node_silent", "node_back"]
EVENTS: tuple[Event, ...] = ("server_down", "server_up", "vip_moved", "node_silent", "node_back")

#
# The state kept per cluster, by kind and subject. A server's subject is its
# pool and name; the VIP has one; a node's is its name.
#
SERVER = "server"
VIP = "vip"
NODE = "node"
VIP_SUBJECT = ""

#
# A node's state before it has ever answered (B329, 26-10-18): a node just
# added was shown as unreachable for minutes, and its first answer was logged
# as answering again. It is joining until it answers, and that answer is no event.
#
JOINING = "joining"

#
# HAProxy's `last_change_sec` is how long ago the server changed. Beyond a day
# it is not a moment between two readings, whatever it says; the reading's own
# time is the better answer then.
#
MAX_CHANGE_SECONDS = 86_400


@dataclass(frozen=True, slots=True)
class Change:
    event: Event
    node: str
    subject: str
    #
    # How long before the reading it happened, where the node said; None is
    # the reading's own moment.
    #
    seconds_ago: int | None = None
    detail: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Observed:
    """One reading's state, and what a server's change would say."""

    state: dict[tuple[str, str], str]
    #
    # Servers the VIP holder listed at all, held or unchecked included: a key
    # that is not among them has gone from the configuration.
    #
    listed: frozenset[str] | None
    holder: str | None
    changed_ago: dict[str, int | None]
    checks: dict[str, Mapping[str, str]]
    #
    # The nodes the reading listed, answering or not; None when it had no node
    # list. A node that is not among them has been taken out, and one added
    # again under its name starts as joining (review 2026-10-30, E7).
    #
    nodes: frozenset[str] | None = None


def _text(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _verdict(member: Mapping[str, Any]) -> str | None:
    """`up` or `down` by the status's first word; None for what is no verdict."""

    if health.member_health(member).held:
        return None
    word = _text(member.get("status")).strip().split(" ")[0].upper()
    if word == "UP":
        return "up"
    if word == "DOWN":
        return "down"
    return None


def observe(result: Mapping[str, Any]) -> Observed:
    state: dict[tuple[str, str], str] = {}
    listed: set[str] | None = None
    changed_ago: dict[str, int | None] = {}
    checks: dict[str, Mapping[str, str]] = {}
    holders: list[str] = []
    entries = result.get("nodes")
    for entry in entries if isinstance(entries, list) else ():
        if not isinstance(entry, Mapping):
            continue
        name = _text(entry.get("name"))
        if not name:
            continue
        answered = entry.get("status_ok") is True
        state[(NODE, name)] = "answering" if answered else "silent"
        if not answered or health.vip_owner(entry.get("status")) is not True:
            continue
        holders.append(name)
        said, members = health.node_members(entry.get("status"))
        if not said:
            continue
        listed = set()
        for member in members:
            backend, server = _text(member.get("backend")), _text(member.get("server"))
            if not backend or not server or not health.is_member(member):
                continue
            subject = f"{backend}/{server}"
            listed.add(subject)
            verdict = _verdict(member)
            if verdict is None:
                continue
            state[(SERVER, subject)] = verdict
            ago = member.get("last_change_sec")
            changed_ago[subject] = (
                ago
                if isinstance(ago, int)
                and not isinstance(ago, bool)
                and 0 <= ago <= MAX_CHANGE_SECONDS
                else None
            )
            checks[subject] = {
                key: _text(member.get(key))
                for key in ("check_status", "check_code")
                if _text(member.get(key))
            }
    #
    # Two nodes both saying they hold it is keepalived split in two; neither
    # is the holder until one of them stops.
    #
    holder = holders[0] if len(holders) == 1 else None
    if holder is not None:
        state[(VIP, VIP_SUBJECT)] = holder
    else:
        listed = None
        state = {key: value for key, value in state.items() if key[0] != SERVER}
    return Observed(
        state=state,
        listed=frozenset(listed) if listed is not None else None,
        holder=holder,
        changed_ago=changed_ago,
        checks=checks,
        nodes=frozenset(key[1] for key in state if key[0] == NODE)
        if isinstance(entries, list)
        else None,
    )


def compare(
    previous: Mapping[tuple[str, str], str], observed: Observed
) -> tuple[list[Change], dict[tuple[str, str], str], list[tuple[str, str]]]:
    """What changed, the state to keep, and the keys to forget.

    A key absent from the reading keeps its state, except a server the VIP
    holder no longer lists and a node a reading with a node list no longer
    names: those have left the configuration.
    """

    changes: list[Change] = []
    state = dict(observed.state)
    for key, value in sorted(observed.state.items()):
        before = previous.get(key)
        if key[0] == NODE and before in (None, JOINING):
            if value != "answering":
                state[key] = JOINING
            continue
        if before is None or before == value:
            continue
        kind, subject = key
        if kind == NODE:
            changes.append(
                Change("node_back" if value == "answering" else "node_silent", subject, subject)
            )
        elif kind == VIP:
            changes.append(Change("vip_moved", value, subject, detail={"from": before}))
        else:
            changes.append(
                Change(
                    "server_up" if value == "up" else "server_down",
                    observed.holder or "",
                    subject,
                    seconds_ago=observed.changed_ago.get(subject),
                    detail=observed.checks.get(subject, {}),
                )
            )
    gone = [
        key
        for key in previous
        if (key[0] == SERVER and observed.listed is not None and key[1] not in observed.listed)
        or (key[0] == NODE and observed.nodes is not None and key[1] not in observed.nodes)
    ]
    return changes, state, gone


def joining(state: Mapping[tuple[str, str], str]) -> frozenset[str]:
    """The nodes that have not answered yet, from the state `compare` keeps."""

    return frozenset(
        subject for (kind, subject), value in state.items() if kind == NODE and value == JOINING
    )


def split(subject: str) -> tuple[str, str]:
    """A server's subject as its pool and its name."""

    backend, _, server = subject.partition("/")
    return backend, server


def described(event: str, subject: str, detail: Mapping[str, Any], node: str) -> str:
    """One event as a sentence, for the *Nodes* view."""

    if event in ("server_down", "server_up"):
        backend, server = split(subject)
        status = _text(detail.get("check_status"))
        why = health.check_phrase(status, _text(detail.get("check_code"))) if status else ""
        verb = "went down" if event == "server_down" else "came back up"
        return f"Server {server} in {backend} {verb}" + (f" · {why}" if why else "")
    if event == "vip_moved":
        source = _text(detail.get("from"))
        return f"The VIP moved to {node}" + (f" from {source}" if source else "")
    if event == "node_silent":
        return f"{node} stopped reporting its status"
    if event == "node_back":
        return f"{node} reports its status again"
    return event


@dataclass(frozen=True, slots=True)
class Row:
    id: int
    at: Any
    shown_at: str
    node: str
    what: str
    cluster: str
    #
    # The object a server's pool belongs to now, for the link; empty for the
    # VIP, a node, or a pool no object owns any longer.
    #
    obj: str


def rows(events: Iterable[Any], owners: Mapping[str, Mapping[str, str]]) -> tuple[Row, ...]:
    built: list[Row] = []
    for event in events:
        detail = event.detail if isinstance(event.detail, Mapping) else {}
        server = event.event in ("server_down", "server_up")
        built.append(
            Row(
                id=event.id,
                at=event.at,
                shown_at=moments.moment(event.at),
                node=event.node,
                what=described(event.event, event.subject, detail, event.node),
                cluster=event.cluster,
                obj=(
                    owners.get(event.cluster, {}).get(split(event.subject)[0], "") if server else ""
                ),
            )
        )
    return tuple(built)
