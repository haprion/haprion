"""Servers somebody took out of service, per object, for the dashboard (26-10-10).

Drain and maintenance outlive a deploy and a restart until somebody sets the
server ready again, which is what makes them easy to forget. The object page's
*Servers* card says it for one object; this says it for a cluster, beside the
blocked addresses on the *Operations* line, so a server left drained last week
is seen without opening every object.

Read from the poller's newest status reading, as the *Servers* card is: a server
counts when any node's HAProxy holds it in drain or maintenance. A state the node
keeps but HAProxy does not hold (*DRAIN LOST* on the card) is a server taking
traffic, not one out of service, and the card is where it is said.

A backend is the object's by the objects' own account (`health.backend_owners`):
a pool is named by itself, so its name does not say whose it is. One no object
claims is listed by its backend name, so a held server is never left out.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from haprion_ui.health import member_health

#
# How many objects the line names before it says how many more (26-10-10):
# one line on the card however many are held.
#
SHOWN = 3


@dataclass(frozen=True, slots=True)
class HeldObject:
    name: str
    servers: int
    owned: bool
    """False for a backend no object claims; drawn without a link."""


@dataclass(frozen=True, slots=True)
class HeldServers:
    objects: tuple[HeldObject, ...]

    @property
    def total(self) -> int:
        return sum(item.servers for item in self.objects)

    @property
    def shown(self) -> tuple[HeldObject, ...]:
        return self.objects[:SHOWN]

    @property
    def rest(self) -> tuple[HeldObject, ...]:
        return self.objects[SHOWN:]


def held_backends(rows: Iterable[Any], *, cluster: str) -> dict[str, set[str]]:
    """Each backend's servers any node of the cluster holds in drain or maintenance."""

    reading = next((row for row in rows if getattr(row, "cluster", None) == cluster), None)
    result = reading.result if reading is not None and isinstance(reading.result, Mapping) else {}
    entries = result.get("nodes")
    held: dict[str, set[str]] = {}
    for entry in entries if isinstance(entries, Sequence) else ():
        status = entry.get("status") if isinstance(entry, Mapping) else None
        servers = status.get("servers") if isinstance(status, Mapping) else None
        for row in servers if isinstance(servers, list) else ():
            if not isinstance(row, Mapping):
                continue
            member = member_health(row)
            if member.held:
                held.setdefault(member.backend, set()).add(member.server)
    return held


def by_object(held: Mapping[str, set[str]], owners: Mapping[str, str]) -> HeldServers | None:
    """The held servers counted per object, objects in name order; None where none is held."""

    counted: dict[tuple[str, bool], int] = {}
    for backend, servers in held.items():
        owner = owners.get(backend)
        key = (owner, True) if owner is not None else (backend, False)
        counted[key] = counted.get(key, 0) + len(servers)
    if not counted:
        return None
    return HeldServers(
        objects=tuple(
            HeldObject(name=name, servers=count, owned=owned)
            for (name, owned), count in sorted(counted.items())
        )
    )
