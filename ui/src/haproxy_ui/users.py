"""Settings -> Users: the accounts as a person reads them (Fas 13, §16.4 U4).

The accounts live in the interface's own database, and the web writes them
within the column grants of 0039. `haprion-user` stays the break-glass path
and does the same verbs; this module only turns rows into what the page draws.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal
from urllib.parse import quote

from haproxy_mgmt.version_history import UnfitName, trailer_name

from haproxy_ui import metrics, sorting
from haproxy_ui.db import AccountRow

type Tone = Literal["healthy", "warning", "critical"]

ROLES = ("admin", "reader")

NAME_PROBLEM = (
    "An account name is at most 64 characters, with no line breaks, invisible characters "
    "or spaces at either end."
)


def name_problem(username: str) -> str | None:
    """Why a name cannot be an account here, or None (2026-09-29).

    A version records the name as who published it (B207), so an account is
    only made under a name that can stand there - checked where the account is
    made, rather than on its first publish, where a refusal could only say that
    the publish could not be built.
    """

    try:
        trailer_name(username)
    except UnfitName:
        return NAME_PROBLEM
    return None


#
# What a finished change says on the account's page. `save` writes the role,
# a new password and the break-glass mark together and lands on whichever of
# `role`, `password`, `break_glass` or `saved` it did; the other keys are the
# page's buttons.
#
DONE = {
    "role": "Role changed.",
    "password": "Password set. The account's sessions were ended.",
    "break_glass": "Break-glass changed.",
    "saved": "Changes saved.",
    "saved_password": "Changes saved. The account's sessions were ended.",
    "disable": "Account disabled. Its sessions were ended.",
    "enable": "Account enabled.",
    "revoke": "Sessions ended.",
    "unlock": "Unlocked.",
}
#
# The form's `action` values; anything else is refused before it reaches the
# database.
#
ACTIONS = frozenset({"save", "disable", "enable", "revoke", "unlock", "delete"})


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
    #
    # `oidc` accounts belong to the provider (0041): no password here, and the
    # role comes from their groups at every sign-in.
    #
    provider: bool
    break_glass: bool


def href(username: str) -> str:
    """The account's page. Quoted whole: a name is any text the CLI accepted."""

    return f"/settings/users/{quote(username, safe='')}"


def _state(row: AccountRow) -> tuple[str, Tone]:
    if row.disabled:
        return "Disabled", "critical"
    if row.locked:
        return "Locked", "warning"
    return "Active", "healthy"


def user_view(row: AccountRow, *, signed_in_as: str) -> UserView:
    state, tone = _state(row)
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
        provider=row.source == "oidc",
        break_glass=row.break_glass,
    )


def user_views(
    rows: Iterable[AccountRow], *, signed_in_as: str, sort: str = "name"
) -> tuple[UserView, ...]:
    return tuple(user_view(row, signed_in_as=signed_in_as) for row in TABLE.ordered(rows, sort))


#
# Settings -> Users is a sortable table (THEME.md): every column, with the
# account's name as the default and the tie-break.
#
TABLE = sorting.Table(
    columns=(
        sorting.Column("name", lambda row, _: sorting.text(row.username)),
        sorting.Column("role", lambda row, _: row.role),
        sorting.Column("state", lambda row, _: (sorting.tone_rank(_state(row)[1]), _state(row)[0])),
        sorting.Column("sessions", lambda row, _: row.sessions, descending_first=True),
        sorting.Column("signin", lambda row, _: row.last_sign_in, descending_first=True),
    ),
    cookie="haproxy_ui_users_sort",
    path="/settings",
    anchor="users",
)
