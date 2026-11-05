"""API tokens (B416): the secret, the levels, and whether a call may use a token.

The rules here are the ones the page, `haprion-api-token` and the API itself
share, so a token made in one place means the same in the others.

* **The secret is shown once and never stored.** 256 bits from the system
  CSPRNG behind a fixed `hap_` marker, so a secret scanner or a person can
  tell what a leaked string is. The table keeps its SHA-256 (`auth.token_hash`)
  and the first twelve characters, enough to tell two tokens apart in a list.
* **A token is looked up by its hash.** The lookup's timing can only say how
  much of the SHA-256 of a guess matches a stored hash, which is no step
  towards the secret; there is no stored secret to compare with in the first
  place.
* **Every failure is one answer to the caller**: unknown, revoked, expired
  or called from outside its addresses are all "not a valid token". The
  reason goes to the service log, where the operator is looking.
"""

from __future__ import annotations

import ipaddress
import re
import secrets
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta

from haprion import address_ranges

from haprion_ui import auth
from haprion_ui.db import ApiToken

LEVELS = ("read", "block", "write")
DEFAULT_DAYS = 365
LONGEST_DAYS = 730
EXPIRY_WARNING = timedelta(days=30)

SECRET_MARKER = "hap_"  # noqa: S105 - the marker every secret starts with, not a secret
SECRET_SHAPE = re.compile(r"hap_[A-Za-z0-9_-]{43}")
SHOWN_CHARACTERS = 12
#
# A new name holds 58 characters, so `token:` and the name fit the 64 a saved
# change's author and the commit trailer hold whole: two names cut to the same
# 64 would be one author (review 26-11-01, omvända 3 P3-1). The table's own
# check stays at 64 for a token made before.
#
NAME_SHAPE = re.compile(r"[a-z0-9]([a-z0-9-]{0,56}[a-z0-9])?")


def new_secret() -> str:
    """A new token's secret: the marker and 32 random bytes, URL-safe."""

    return SECRET_MARKER + secrets.token_urlsafe(32)


def shown_prefix(secret: str) -> str:
    """What the list shows of a secret: the marker and eight characters."""

    return secret[:SHOWN_CHARACTERS]


def secret_hash(secret: str) -> bytes:
    """What the table stores for a secret."""

    return auth.token_hash(secret)


def bearer_secret(header: str | None) -> str | None:
    """The secret in an `Authorization: Bearer` header, or None.

    A value that is not the shape of a secret is None here, before any
    database is asked: it cannot be a token, and a lookup for it would be
    work done for whoever sends garbage.
    """

    if not header:
        return None
    scheme, _, value = header.partition(" ")
    if scheme.lower() != "bearer":
        return None
    value = value.strip()
    return value if SECRET_SHAPE.fullmatch(value) else None


def name_problem(name: str) -> str:
    """What is wrong with a token's name, as the end of a sentence, or ''."""

    if not NAME_SHAPE.fullmatch(name):
        return (
            "must be 1 to 58 lowercase letters, digits and hyphens, "
            "starting and ending with a letter or digit"
        )
    return ""


def days_problem(days: int) -> str:
    if not 1 <= days <= LONGEST_DAYS:
        return f"must be between 1 and {LONGEST_DAYS} days"
    return ""


def sources_problem(sources: Iterable[str]) -> str:
    for source in sources:
        try:
            address_ranges.plain_network(source, strict=False)
        except ValueError:
            return f"{source!r} is not an address or a network"
        if (written := address_ranges.mapped_ipv4(source)) is not None:
            return f"{source!r} is an IPv4 address written as IPv6; write it as {written}"
    return ""


def reaches(held: str, needed: str) -> bool:
    """Whether a token of level `held` may do what needs `needed`.

    `block` reaches `read` only for its own blocks; that narrowing is the
    block routes' own, so here it reaches what it is named for and nothing
    above.
    """

    if held == needed:
        return True
    return held == "write" and needed in ("read", "block")


def reads_everything(held: str) -> bool:
    """Whether a token is given all that an admin is shown: a reader reads everything.

    `read` is a reader and `write` an admin, and both see the same data (the
    object documents, drafts, server states, the helpers' sentences); only
    `write` changes anything. A `block` token reads its own blocks and
    nothing of the rest.
    """

    return held in ("read", "write")


@dataclass(frozen=True, slots=True)
class Verdict:
    """Whether a token may be used for this call, and if not, why (for the log)."""

    usable: bool
    reason: str = ""


def evaluate(issued: ApiToken | None, *, now: datetime, source: str) -> Verdict:
    """Apply an issued token's own limits to a call from `source` at `now`."""

    if issued is None:
        return Verdict(False, "unknown")
    if issued.revoked_at is not None:
        return Verdict(False, "revoked")
    if now >= issued.expires_at:
        return Verdict(False, "expired")
    if issued.sources and not from_sources(source, issued.sources):
        return Verdict(False, "outside_sources")
    return Verdict(True)


def from_sources(source: str, sources: Iterable[str]) -> bool:
    try:
        address = ipaddress.ip_address(source)
    except ValueError:
        return False
    for network in sources:
        try:
            if address in ipaddress.ip_network(network, strict=False):
                return True
        except ValueError:
            continue
    return False


def covers(issued: ApiToken, cluster: str, item: str | None = None) -> bool:
    """Whether a cluster - and, for a `block` token, an object - is within the token's scope."""

    if issued.clusters and cluster not in issued.clusters:
        return False
    return item is None or not issued.objects or item in issued.objects


def ends_soon(issued: ApiToken, now: datetime) -> bool:
    """Revoked tokens end nothing; one expired or ending within the warning does."""

    return issued.revoked_at is None and issued.expires_at - now <= EXPIRY_WARNING
