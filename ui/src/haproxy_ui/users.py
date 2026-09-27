"""Settings -> Users: the accounts as a person reads them (Fas 13, §16.4 U4).

The accounts live in the interface's own database, and the web writes them
within the column grants of 0039. `haproxy-ui-user` stays the break-glass path
and does the same verbs; this module only turns rows into what the page draws.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import quote

from haproxy_ui import metrics
from haproxy_ui.db import AccountRow

type Tone = Literal["healthy", "warning", "critical"]

ROLES = ("admin", "reader")

#
# What a finished change says on the account's page. `save` writes the role
# and a new password together and lands on whichever of `role`, `password`
# and `saved` it did; the other keys are the page's buttons.
#
DONE = {
    "created": "Account created.",
    "role": "Role changed.",
    "password": "Password set. The account's sessions were ended.",
    "saved": "Role changed and password set. The account's sessions were ended.",
    "disable": "Account disabled. Its sessions were ended.",
    "enable": "Account enabled.",
    "revoke": "Sessions ended.",
    "unlock": "Unlocked.",
}
#
# The form's `action` values; anything else is refused before it reaches the
# database.
#
ACTIONS = frozenset({"save", "disable", "enable", "revoke", "unlock"})


@dataclass(frozen=True, slots=True)
class UserView:
    username: str
    href: str
    role: str
    state: str
    tone: Tone
    disabled: bool
    locked: bool
    sessions: int
    last_sign_in: str
    own: bool


def href(username: str) -> str:
    """The account's page. Quoted whole: a name is any text the CLI accepted."""

    return f"/settings/users/{quote(username, safe='')}"


def user_view(row: AccountRow, *, signed_in_as: str) -> UserView:
    state: str
    tone: Tone
    if row.disabled:
        state, tone = "Disabled", "critical"
    elif row.locked:
        state, tone = "Locked", "warning"
    else:
        state, tone = "Active", "healthy"
    return UserView(
        username=row.username,
        href=href(row.username),
        role=row.role,
        state=state,
        tone=tone,
        disabled=row.disabled,
        locked=row.locked,
        sessions=row.sessions,
        last_sign_in="Never"
        if row.last_sign_in is None
        else metrics.shown(row.last_sign_in).strftime(metrics.TIMESTAMP),
        own=row.username.lower() == signed_in_as.lower(),
    )


#
# Every column is an order the reader may pick by clicking its heading
# (2026-09-27). The first click gives the column's natural order - names, roles
# and states from the top, sessions and sign-ins from the most and the newest -
# and a second click turns it round. Rows that tie keep their name order, and
# accounts that never signed in come last either way: "Never" is not a time.
#
COLUMNS = ("name", "role", "state", "sessions", "signin")
DESCENDING_FIRST = frozenset({"sessions", "signin"})
SORTS = (*COLUMNS, *(f"-{column}" for column in COLUMNS))
DEFAULT_SORT = "name"
STATE_ORDER = {"Active": 0, "Locked": 1, "Disabled": 2}


@dataclass(frozen=True, slots=True)
class SortLink:
    href: str
    arrow: str


def sort_of(value: str | None) -> str:
    return value if value in SORTS else DEFAULT_SORT


def _descending(sort: str) -> bool:
    column = sort.lstrip("-")
    return (column in DESCENDING_FIRST) != sort.startswith("-")


def _key(column: str, row: AccountRow) -> Any:
    if column == "role":
        return row.role
    if column == "state":
        return STATE_ORDER[user_view(row, signed_in_as="").state]
    if column == "sessions":
        return row.sessions
    return row.last_sign_in


def ordered(rows: Iterable[AccountRow], sort: str) -> list[AccountRow]:
    column = sort.lstrip("-")
    descending = _descending(sort)
    by_name = sorted(rows, key=lambda row: (row.username.lower(), row.username))
    if column == "name":
        return by_name[::-1] if descending else by_name
    never = []
    if column == "signin":
        never = [row for row in by_name if row.last_sign_in is None]
        by_name = [row for row in by_name if row.last_sign_in is not None]
    #
    # Stable in both directions: ties keep their name order.
    #
    if descending:
        ranked = sorted(by_name, key=lambda row: _key(column, row), reverse=True)
    else:
        ranked = sorted(by_name, key=lambda row: _key(column, row))
    return ranked + never


def sort_links(sort: str) -> dict[str, SortLink]:
    """Each heading's link, and the arrow on the chosen one (▲ A-Z or least first)."""

    links = {}
    for column in COLUMNS:
        chosen = sort.lstrip("-") == column
        target = (column if sort.startswith("-") else f"-{column}") if chosen else column
        links[column] = SortLink(
            href=f"/settings?sort={target}",
            arrow=("▼" if _descending(sort) else "▲") if chosen else "",
        )
    return links


def user_views(
    rows: Iterable[AccountRow], *, signed_in_as: str, sort: str = DEFAULT_SORT
) -> tuple[UserView, ...]:
    return tuple(user_view(row, signed_in_as=signed_in_as) for row in ordered(rows, sort))
