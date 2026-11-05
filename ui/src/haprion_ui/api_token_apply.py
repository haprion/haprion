"""API tokens made, listed, extended, revoked and removed: the part the page and `haprion-api-token` share (B416).

Settings -> API tokens and the command line are two ways to the same table, so
the rules live once, here: what a request may ask for, the sentences a refusal
is made of, what is written to the audit record, and what a token is called
when it is listed. A refusal read on the page and one read in a terminal are
the same string, and a test holds them to it.

The secret is made here and handed back to the caller once. It is never
written to the audit record, the log or a redirect.
"""

from __future__ import annotations

from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

import yaml
from haprion import address_ranges, safe_yaml

from haprion_ui import api_tokens, db, moments
from haprion_ui.objects import cluster_object_views

OPERATION = "api_token"
SOURCES_LIMIT = 32

type State = Literal["active", "revoked", "expired"]


class Refused(Exception):
    """A request the installation says no to, with the contract's code for it."""

    def __init__(self, message: str, *, code: str = "bad_input") -> None:
        super().__init__(message)
        self.code = code


def blocking_objects(readings: Iterable[db.ClusterObjects], cluster: str) -> tuple[str, ...]:
    """The cluster's objects with dynamic blocking, by name, from its newest reading."""

    reading = next((entry for entry in readings if entry.cluster == cluster), None)
    names: list[str] = []
    for view in cluster_object_views(reading):
        try:
            document: Any = safe_yaml.load(view.document)
        except yaml.YAMLError:
            continue
        if isinstance(document, dict) and isinstance(document.get("dynamic_block"), dict):
            names.append(view.name)
    return tuple(sorted(names))


@dataclass(frozen=True, slots=True)
class NewToken:
    name: str
    level: str
    clusters: tuple[str, ...]
    objects: tuple[str, ...]
    sources: tuple[str, ...]
    days: int


def sources_from_text(text: str) -> tuple[str, ...]:
    """The page's box: one address or network a line, a comma also parting two."""

    return tuple(line.strip() for line in text.replace(",", "\n").splitlines() if line.strip())


def _sources_problem(sources: Sequence[str]) -> str:
    if len(sources) > SOURCES_LIMIT:
        return f"At most {SOURCES_LIMIT} addresses or networks."
    if problem := api_tokens.sources_problem(sources):
        return f"{problem[0].upper()}{problem[1:]}."
    for source in sources:
        # The table keeps networks, and a network with host bits is a typo for
        # one address or a wider network; taking it would guess which.
        if address_ranges.has_host_bits(source):
            return f"{source!r}: {address_ranges.HOST_BITS}."
    return ""


def normalised_sources(sources: Iterable[str]) -> tuple[str, ...]:
    """Each source as the network the table stores, once, in the order given."""

    kept: dict[str, None] = {}
    for source in sources:
        kept[str(address_ranges.plain_network(source, strict=False))] = None
    return tuple(kept)


def problem(
    new: NewToken, *, clusters: Collection[str], blocking: Mapping[str, Collection[str]]
) -> str:
    """Why a request cannot be a token, as a sentence, or ''.

    `clusters` are the ones this installation has and `blocking` the objects
    with dynamic blocking in each: the only ones a `block` token can name.
    """

    if text := api_tokens.name_problem(new.name):
        return f"The name {text}."
    if new.level not in api_tokens.LEVELS:
        return "The level must be read, block or write."
    for cluster in new.clusters:
        if cluster not in clusters:
            return f"{cluster} is not a cluster this installation has."
    if new.objects and new.level != "block":
        return "Proxies can only be chosen for a block token."
    #
    # A block token names its objects, and a token that blocks on all of
    # them would be the widest one the installation can make, by omission.
    #
    if new.level == "block" and not new.objects:
        return "A block token names the proxies it may block on."
    reachable = new.clusters or tuple(blocking)
    for item in new.objects:
        if not any(item in blocking.get(cluster, ()) for cluster in reachable):
            return f"{item} is not a proxy with dynamic blocking in the chosen clusters."
    if text := _sources_problem(new.sources):
        return text
    if text := api_tokens.days_problem(new.days):
        return f"The validity {text}."
    return ""


def audit_detail(issued: db.ApiToken, *, via: str) -> dict[str, Any]:
    """What the record says of a token: its name and reach, never its hash or secret."""

    return {
        "name": issued.name,
        "level": issued.level,
        "clusters": list(issued.clusters),
        "objects": list(issued.objects),
        "sources": list(issued.sources),
        "via": via,
    }


def issue(connection: Any, new: NewToken, *, actor: str, via: str) -> tuple[db.ApiToken, str]:
    """Store a token and its audit event; the secret comes back here and nowhere else."""

    secret = api_tokens.new_secret()
    try:
        made = db.create_api_token(
            connection,
            name=new.name,
            level=new.level,
            clusters=new.clusters,
            objects=new.objects,
            sources=normalised_sources(new.sources),
            token_hash=api_tokens.secret_hash(secret),
            prefix=api_tokens.shown_prefix(secret),
            created_by=actor,
            days=new.days,
        )
    except db.TokenNameTaken:
        raise Refused(f"A token named {new.name} already exists.", code="already_exists") from None
    db.record_audit_event(
        connection,
        actor=actor,
        action="api_token_created",
        detail={**audit_detail(made, via=via), "expires_at": made.expires_at.isoformat()},
    )
    return made, secret


def _named(connection: Any, name: str) -> db.ApiToken:
    for token in db.api_tokens(connection):
        if token.name == name:
            return token
    raise Refused(f"There is no token named {name}.", code="not_found")


def extend(connection: Any, name: str, *, days: int, actor: str, via: str) -> db.ApiToken:
    """Give a token a new end date, from today; the secret stays. The caller commits.

    Returns the token as it is after. The record keeps the date it had and the
    date it has, so the audit says how long it was given.
    """

    token = _named(connection, name)
    if token.revoked_at is not None:
        raise Refused(f"{name} is revoked and cannot be extended.")
    if text := api_tokens.days_problem(days):
        raise Refused(f"The validity {text}.")
    #
    # Extending gives a token more time, never less (review 26-10-31, P2-1); the
    # table refuses it too. An ended token may be given any length.
    #
    now = datetime.now(UTC)
    if token.expires_at > now and now + timedelta(days=days) <= token.expires_at:
        raise Refused(
            f"{name} already runs until {moments.day(token.expires_at)}; "
            f"{days} days from today would end it sooner."
        )
    try:
        extended = db.extend_api_token(connection, name, days=days)
    except db.TokenRevoked:
        raise Refused(f"{name} is revoked and cannot be extended.") from None
    if extended is None:
        raise Refused(f"There is no token named {name}.", code="not_found")
    db.record_audit_event(
        connection,
        actor=actor,
        action="api_token_extended",
        detail={
            "name": name,
            "previous_expires_at": token.expires_at.isoformat(),
            "expires_at": extended.expires_at.isoformat(),
            "via": via,
        },
    )
    return extended


def revoke(connection: Any, name: str, *, actor: str, via: str) -> db.ApiToken:
    """End a token for good. The caller commits."""

    token = _named(connection, name)
    if token.revoked_at is not None or not db.revoke_api_token(connection, name, by=actor):
        raise Refused(f"{name} is already revoked.")
    db.record_audit_event(
        connection, actor=actor, action="api_token_revoked", detail=audit_detail(token, via=via)
    )
    return token


def remove(connection: Any, name: str, *, actor: str, via: str) -> db.ApiToken:
    """Delete a token that is revoked or has expired. The caller commits."""

    token = _named(connection, name)
    try:
        gone = db.delete_api_token(connection, name)
    except db.TokenInUse:
        raise Refused(f"{name} is still in use; revoke it first.") from None
    if not gone:
        raise Refused(f"There is no token named {name}.", code="not_found")
    db.record_audit_event(
        connection, actor=actor, action="api_token_removed", detail=audit_detail(token, via=via)
    )
    return token


def state(issued: db.ApiToken, now: datetime) -> State:
    if issued.revoked_at is not None:
        return "revoked"
    return "expired" if now >= issued.expires_at else "active"


def ending(issued: db.ApiToken, now: datetime) -> bool:
    """Whether the page marks its end: within the warning, or past. A revoked token ends nothing."""

    return api_tokens.ends_soon(issued, now)


def scope(issued: db.ApiToken) -> str:
    """Where a token reaches, as one line: its clusters, then its objects, or All."""

    parts = [", ".join(issued.clusters), ", ".join(issued.objects)]
    return " · ".join(part for part in parts if part) or "All"


def last_used(issued: db.ApiToken) -> str:
    if issued.last_used_at is None:
        return "Never"
    shown = moments.moment(issued.last_used_at)
    return f"{shown} · {issued.last_used_from}" if issued.last_used_from else shown


def summary(tokens: Iterable[db.ApiToken], now: datetime) -> tuple[int, int]:
    """How many tokens work, and how many of all end soon or have ended: the Settings card."""

    listed = list(tokens)
    active = sum(state(token, now) == "active" for token in listed)
    return active, sum(ending(token, now) for token in listed)


def document(issued: db.ApiToken, now: datetime) -> dict[str, Any]:
    """A token as `haprion-api-token --json` lists it: never the hash, the prefix only."""

    def stamp(moment: datetime | None) -> str | None:
        return None if moment is None else moment.isoformat()

    return {
        "name": issued.name,
        "level": issued.level,
        "clusters": list(issued.clusters),
        "objects": list(issued.objects),
        "sources": list(issued.sources),
        "prefix": issued.prefix,
        "state": state(issued, now),
        "created_at": stamp(issued.created_at),
        "created_by": issued.created_by,
        "expires_at": stamp(issued.expires_at),
        "revoked_at": stamp(issued.revoked_at),
        "last_used_at": stamp(issued.last_used_at),
        "last_used_from": issued.last_used_from,
    }
