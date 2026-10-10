"""How fresh each cluster's country lists are (Fas 21, B228).

New location data reaches a cluster at its next publish, never on its own. This
is what says one is due: the database's date, read by the engine when it lists
a cluster's objects, beside the date the cluster's published files carry.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class LocationRow:
    cluster: str
    published: str
    current: bool


@dataclass(frozen=True, slots=True)
class LocationCard:
    database: str
    rows: tuple[LocationRow, ...]


def _short(stamp: str) -> str:
    """`2026-10-01` as the interface writes a date, `26-10-01`."""

    return stamp[2:] if len(stamp) == 10 else stamp


def card(object_rows: Iterable[Any]) -> LocationCard | None:
    """The card, or None when no cluster names a country - then there is nothing to say."""

    database = ""
    rows: list[LocationRow] = []
    for row in object_rows:
        result = row.result if isinstance(row.result, dict) else {}
        found = result.get("geo")
        geo = found if isinstance(found, dict) else {}
        stamp = geo.get("database")
        if isinstance(stamp, str) and stamp > database:
            database = stamp
        published = geo.get("published")
        if isinstance(published, str):
            rows.append(LocationRow(row.cluster, published, current=True))
    if not rows:
        return None
    return LocationCard(
        database=_short(database) if database else "",
        rows=tuple(
            LocationRow(
                row.cluster,
                _short(row.published),
                current=not database or row.published >= database,
            )
            for row in sorted(rows, key=lambda item: item.cluster)
        ),
    )
