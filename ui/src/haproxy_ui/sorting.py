"""Tables the reader sorts by clicking a heading (THEME.md, Sortable tables).

One mechanism for every such table, so they cannot drift into three
behaviours. The order is chosen on the server with `?sort=<column>`, and
`-<column>` turns it round; no script is involved, so whole-row links and the
pages' own refreshes keep working. The choice is remembered in a cookie scoped
to the page's path, which the refreshes send too.

The first click gives the order a reader most often wants: text from the top,
states and health with the problems first, counts from the most, past times
from the newest and expiry from the soonest. Rows that tie keep the table's
default order, and a missing value comes last in both directions - "Never" or
"—" is not a value to sort among values.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

from fastapi import Request, Response

#
# Status columns sort on their tone, problems first. A label only breaks a
# tie between rows of the same tone.
#
TONE_ORDER = {"critical": 0, "warning": 1, "info": 2, "unknown": 3, "healthy": 4}


def tone_rank(tone: str) -> int:
    return TONE_ORDER.get(tone, len(TONE_ORDER))


@dataclass(frozen=True, slots=True)
class Column:
    name: str
    #
    # The value a row sorts on, or None when the row has none. The context is
    # whatever the page passes beside the rows (the proxy table's health
    # lamps); most keys ignore it.
    #
    key: Callable[[Any, Any], Any]
    descending_first: bool = False


@dataclass(frozen=True, slots=True)
class SortLink:
    href: str
    arrow: str
    aria: str


@dataclass(frozen=True, slots=True)
class Table:
    columns: tuple[Column, ...]
    cookie: str
    path: str
    anchor: str = ""

    @property
    def default(self) -> str:
        return self.columns[0].name

    @property
    def sorts(self) -> frozenset[str]:
        names = [column.name for column in self.columns]
        return frozenset([*names, *(f"-{name}" for name in names)])

    def chosen(self, request: Request) -> tuple[str, bool]:
        """The order to draw, and whether the request asked for it by name."""

        asked = request.query_params.get("sort")
        if asked in self.sorts:
            return asked, True
        remembered = request.cookies.get(self.cookie)
        return (remembered if remembered in self.sorts else self.default), False

    def remember(self, response: Response, sort: str, *, secure: bool) -> None:
        response.set_cookie(
            self.cookie,
            sort,
            max_age=31536000,
            httponly=True,
            secure=secure,
            samesite="lax",
            path=self.path,
        )

    def _column(self, sort: str) -> Column:
        name = sort.lstrip("-")
        return next((column for column in self.columns if column.name == name), self.columns[0])

    def descending(self, sort: str) -> bool:
        return self._column(sort).descending_first != sort.startswith("-")

    def ordered(self, rows: Iterable[Any], sort: str, context: Any = None) -> list[Any]:
        first = self.columns[0]
        base = sorted(rows, key=lambda row: _ascending(first.key(row, context)))
        column = self._column(sort)
        if column is first and not self.descending(sort):
            return base
        present = [row for row in base if column.key(row, context) is not None]
        missing = [row for row in base if column.key(row, context) is None]
        #
        # Stable in both directions: `reverse` keeps equal rows in the order
        # they came, which is the default order.
        #
        present.sort(key=lambda row: column.key(row, context), reverse=self.descending(sort))
        return present + missing

    def links(self, sort: str, query: Mapping[str, str] | None = None) -> dict[str, SortLink]:
        """Each heading's link, and the arrow on the chosen one (▲ A-Z or least first)."""

        chosen = self._column(sort).name
        links = {}
        for column in self.columns:
            if column.name == chosen:
                target = column.name if sort.startswith("-") else f"-{column.name}"
                arrow = "▼" if self.descending(sort) else "▲"
                aria = "descending" if self.descending(sort) else "ascending"
            else:
                target, arrow, aria = column.name, "", ""
            parameters = urlencode({**(query or {}), "sort": target})
            anchor = f"#{self.anchor}" if self.anchor else ""
            links[column.name] = SortLink(f"{self.path}?{parameters}{anchor}", arrow, aria)
        return links


def _ascending(value: Any) -> tuple[bool, Any]:
    return (value is None, value if value is not None else 0)


def text(value: str | None) -> str | None:
    """Text as a reader compares it: without case, and empty as missing."""

    return value.casefold() if value else None
