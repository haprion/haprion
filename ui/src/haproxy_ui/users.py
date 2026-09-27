"""Settings -> Users: the accounts as a person reads them (Fas 13, §16.4 U4).

The accounts live in the interface's own database, and the web writes them
within the column grants of 0039. `haproxy-ui-user` stays the break-glass path
and does the same verbs; this module only turns rows into what the page draws.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal
from urllib.parse import quote

from haproxy_ui import metrics
from haproxy_ui.db import AccountRow

type Tone = Literal["healthy", "warning", "critical"]

ROLES = ("admin", "reader")

#
# What a finished action says on the account's page. The keys are the form's
# `action` values; anything else is refused before it reaches the database.
#
DONE = {
    "created": "Account created.",
    "role": "Role changed.",
    "disable": "Account disabled. Its sessions were ended.",
    "enable": "Account enabled.",
    "password": "Password set. The account's sessions were ended.",
    "revoke": "Sessions ended.",
    "unlock": "Unlocked.",
}
ACTIONS = frozenset(DONE) - {"created"}


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


def user_views(rows: Iterable[AccountRow], *, signed_in_as: str) -> tuple[UserView, ...]:
    return tuple(user_view(row, signed_in_as=signed_in_as) for row in rows)
