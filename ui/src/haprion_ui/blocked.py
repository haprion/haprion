"""Addresses dynamic blocking holds, as the nodes report them (B271).

Read from the poller's newest status reading, as the *Servers* card is: each
node's `blocked` names, per object, how many addresses its table holds and the
first hundred of them with the milliseconds left. The object page lists them
with a box each and an *Unblock* button; the dashboard says how many there are
per cluster and which objects hold them.

How many is the largest count any node reports, or the number of different
addresses listed if that is more. With shared counters every node holds the
same block, so the largest count is the block; without them each node blocks
on its own, and the list is the union of what each one said.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any


@dataclass(frozen=True, slots=True)
class BlockedAddress:
    address: str
    nodes: tuple[str, ...]
    until: datetime | None
    """When the longest of the nodes' blocks ends, from the reading's time."""


@dataclass(frozen=True, slots=True)
class BlockedCard:
    addresses: tuple[BlockedAddress, ...]
    count: int
    observed_at: datetime | None

    @property
    def more(self) -> int:
        """How many the nodes hold beyond the ones they listed."""

        return max(self.count - len(self.addresses), 0)


def _reading(rows: Iterable[Any], cluster: str) -> Mapping[str, Any]:
    row = next((row for row in rows if getattr(row, "cluster", None) == cluster), None)
    return row.result if row is not None and isinstance(row.result, Mapping) else {}


def _observed(rows: Iterable[Any], cluster: str) -> datetime | None:
    row = next((row for row in rows if getattr(row, "cluster", None) == cluster), None)
    observed = getattr(row, "observed_at", None) if row is not None else None
    return observed if isinstance(observed, datetime) else None


def _blocked(entry: Mapping[str, Any]) -> Mapping[str, Any]:
    status = entry.get("status")
    found = status.get("blocked") if isinstance(status, Mapping) else None
    return found if isinstance(found, Mapping) else {}


def _nodes(rows: Iterable[Any], cluster: str) -> list[tuple[str, Mapping[str, Any]]]:
    entries = _reading(rows, cluster).get("nodes")
    return [
        (str(entry.get("name", "")), _blocked(entry))
        for entry in (entries if isinstance(entries, Sequence) else ())
        if isinstance(entry, Mapping)
    ]


def object_card(rows: Iterable[Any], *, cluster: str, name: str) -> BlockedCard | None:
    """The object's blocked addresses on every node, or None where none is blocked."""

    rows = list(rows)
    observed = _observed(rows, cluster)
    counts: list[int] = []
    found: dict[str, tuple[list[str], int]] = {}
    for node, blocked in _nodes(rows, cluster):
        mine = blocked.get(name)
        if not isinstance(mine, Mapping):
            continue
        count = mine.get("count")
        counts.append(count if isinstance(count, int) and not isinstance(count, bool) else 0)
        listed = mine.get("addresses")
        for item in listed if isinstance(listed, list) else ():
            if not isinstance(item, Mapping) or not isinstance(item.get("address"), str):
                continue
            left = item.get("expires_in_ms")
            left = left if isinstance(left, int) and not isinstance(left, bool) else 0
            nodes, longest = found.get(item["address"], ([], 0))
            found[item["address"]] = ([*nodes, node], max(longest, left))
    count = max([*counts, len(found)], default=0)
    if not count:
        return None
    addresses = tuple(
        BlockedAddress(
            address=address,
            nodes=tuple(nodes),
            until=observed + timedelta(milliseconds=left) if observed is not None else None,
        )
        for address, (nodes, left) in sorted(found.items(), key=lambda pair: _sort_key(pair[0]))
    )
    return BlockedCard(addresses=addresses, count=count, observed_at=observed)


def cluster_counts(rows: Iterable[Any], *, cluster: str) -> dict[str, int]:
    """How many addresses each object of the cluster holds blocked, objects in name order."""

    counts: dict[str, int] = {}
    for _node, blocked in _nodes(rows, cluster):
        for name, mine in blocked.items():
            if not isinstance(mine, Mapping):
                continue
            count = mine.get("count")
            if isinstance(count, int) and not isinstance(count, bool) and count > 0:
                counts[str(name)] = max(counts.get(str(name), 0), count)
    return dict(sorted(counts.items()))


def time_left(until: datetime | None, now: datetime | None = None) -> str:
    """`27 min`, `1 h 5 min`, `< 1 min`; a dash where the reading had no time."""

    if until is None:
        return "—"
    seconds = (until - (now or datetime.now(UTC))).total_seconds()
    minutes = int(seconds // 60)
    if minutes < 1:
        return "< 1 min"
    hours, minutes = divmod(minutes, 60)
    if not hours:
        return f"{minutes} min"
    return f"{hours} h {minutes} min" if minutes else f"{hours} h"


def _sort_key(address: str) -> tuple[int, int, str]:
    """IPv4 before IPv6, each in address order: `192.0.2.7` before `192.0.2.10`."""

    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return (2, 0, address)
    return (parsed.version, int(parsed), address)
