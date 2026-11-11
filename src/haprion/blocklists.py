"""Blocklists: address lists fetched from a URL and refused under *Denied* (B496 nr 13, B500).

A blocklist is a list somebody else keeps - CrowdSec's raw IP list, Spamhaus
DROP, FireHOL - fetched by the manager on a schedule and sent to the nodes as a
file beside the configuration, the way certificates are: no configuration
version, an atomic swap through the admin socket. Each list is a group an
object can name under *Denied — groups*, and nowhere else.

This module is what every reader of a list shares: the name rule, the format,
the limits, the exceptions, and the file the nodes load. Fetching is here too,
with the same hardening as the OIDC client: https only, no proxy from the
environment, no redirects, a size and a time limit.

The format is one address or network to a line. Text after `#` or `;` is a
comment, which is how all three lists above annotate theirs (Spamhaus writes
`192.0.2.0/24 ; SBL123`). A line that is not an address is skipped and counted,
so a list that changed its format says so instead of shrinking quietly.
"""

from __future__ import annotations

import base64
import ipaddress
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass

from haprion import address_ranges, http_answer

#
# A list's name is the group's name under *Denied — groups*, so it must be one
# an object can name: the network file's rule (`config.NAME`) and the object's
# reference rule (`proxy_model.NAME`, 40 characters) at once.
#
NAME = re.compile(r"^[a-z][a-z0-9-]{0,39}$")
DESCRIPTION_MAX = 200
URL_MAX = 2048
USERNAME_MAX = 200
SECRET_MAX = 4096

#
# B500: a list over either limit is refused, and the last good one stays.
#
MAX_BYTES = 4 * 1024 * 1024
MAX_ENTRIES = 100_000
TIMEOUT_SECONDS = 30

FETCH_HOURS = (1, 6, 12, 24)
AUTHORIZATIONS = ("none", "basic", "bearer")

Network = ipaddress.IPv4Network | ipaddress.IPv6Network
_MAPPED = ipaddress.IPv6Network("::ffff:0:0/96")


class BlocklistError(Exception):
    """Why a list could not be fetched or read, as a stable code and a sentence."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class Definition:
    """One list as Settings holds it; the secret is kept apart, sealed."""

    name: str
    url: str
    every_hours: int
    authorization: str = "none"
    username: str = ""
    description: str = ""
    excepts: tuple[str, ...] = ()


@dataclass(frozen=True)
class Parsed:
    """A list as read: its networks, collapsed and sorted, and the lines that were not addresses."""

    networks: tuple[Network, ...]
    skipped: int


@dataclass(frozen=True)
class Excepted:
    """A list once its exceptions are taken out."""

    networks: tuple[Network, ...]
    excepted: int
    unknown_groups: tuple[str, ...]


# - the definition --------------------------------------------------------


def checked_name(value: object) -> str:
    if not isinstance(value, str) or not NAME.fullmatch(value):
        raise ValueError(
            "a blocklist's name is lowercase letters, digits and '-', starts with a letter, "
            "and is at most 40 characters"
        )
    return value


def checked_url(value: object) -> str:
    """An absolute https URL with a host and no credentials in it."""

    if not isinstance(value, str) or not value or len(value) > URL_MAX:
        raise ValueError("the URL is missing or too long")
    if any(character.isspace() for character in value):
        raise ValueError("the URL may not hold spaces")
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("the URL must start with https:// and name a host")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("the URL may not carry a username or password; use Authorization")
    if parsed.fragment:
        raise ValueError("the URL may not have a fragment")
    return value


def checked_except(entries: Iterable[str]) -> tuple[str, ...]:
    """An address, a network or a group's name per entry, each once, in the order written."""

    seen: list[str] = []
    for raw in entries:
        entry = raw.strip()
        if not entry:
            continue
        if NAME.fullmatch(entry):
            value = entry
        else:
            try:
                network = address_ranges.plain_network(entry, strict=True)
            except ValueError as exc:
                raise ValueError(f"{entry} is not an address, a network or a group's name") from exc
            if network.prefixlen == 0:
                raise ValueError(f"{entry} names an entire address family")
            value = str(network)
        if value in seen:
            raise ValueError(f"{entry} is listed twice")
        seen.append(value)
    return tuple(seen)


def definition(
    *,
    name: object,
    url: object,
    every_hours: object,
    authorization: object = "none",
    username: object = "",
    description: object = "",
    excepts: Sequence[str] = (),
) -> Definition:
    """A definition from untrusted fields, or `ValueError` saying which field is wrong."""

    if (
        not isinstance(every_hours, int)
        or isinstance(every_hours, bool)
        or every_hours not in FETCH_HOURS
    ):
        raise ValueError("Fetch every is 1, 6, 12 or 24 hours")
    if authorization not in AUTHORIZATIONS:
        raise ValueError("Authorization is None, Basic or Bearer")
    if not isinstance(username, str) or len(username) > USERNAME_MAX or ":" in username:
        raise ValueError("the username is too long or holds ':'")
    if authorization == "basic" and not username:
        raise ValueError("Basic authorization needs a username")
    if authorization != "basic" and username:
        raise ValueError("a username goes with Basic authorization only")
    if not isinstance(description, str) or len(description) > DESCRIPTION_MAX:
        raise ValueError(f"the description is at most {DESCRIPTION_MAX} characters")
    if any(not character.isprintable() for character in description):
        raise ValueError("the description is one line of printable text")
    return Definition(
        name=checked_name(name),
        url=checked_url(url),
        every_hours=every_hours,
        authorization=str(authorization),
        username=username,
        description=description,
        excepts=checked_except(excepts),
    )


# - the list --------------------------------------------------------------


def _network(text: str) -> Network | None:
    try:
        network = address_ranges.plain_network(text, strict=False)
    except ValueError:
        return None
    if isinstance(network, ipaddress.IPv6Network) and network.subnet_of(_MAPPED):
        mapped = address_ranges.mapped_ipv4(text)
        network = address_ranges.plain_network(mapped, strict=False) if mapped else network
    if network.prefixlen == 0:
        return None
    return network


def parse(body: bytes) -> Parsed:
    """The networks in a fetched list, or `BlocklistError` when it is not one worth keeping.

    A list with no address in it is refused: an empty answer is far likelier a
    broken source than a world with nobody to block, and keeping it would
    unblock everyone the last good list held.
    """

    if len(body) > MAX_BYTES:
        raise BlocklistError("too_large", f"the list is over {MAX_BYTES // (1024 * 1024)} MiB")
    text = body.decode("utf-8", errors="replace")
    #
    # Kept as ranges, not as the network objects read: an object per entry
    # held for the whole list is most of what reading one cost.
    #
    ranges: dict[int, list[tuple[int, int]]] = {4: [], 6: []}
    read = 0
    skipped = 0
    for line in text.splitlines():
        entry = re.split(r"[#;]", line, maxsplit=1)[0].strip()
        if not entry:
            continue
        network = _network(entry)
        if network is None:
            skipped += 1
            continue
        ranges[network.version].append(_span(network))
        read += 1
        if read > MAX_ENTRIES:
            raise BlocklistError(
                "too_many", f"the list holds more than {MAX_ENTRIES:,} addresses".replace(",", " ")
            )
    if not read:
        raise BlocklistError("empty", "the list holds no address")
    return Parsed(networks=_merged(ranges), skipped=skipped)


def _span(network: Network) -> tuple[int, int]:
    """The first and last address of a network, as integers.

    From the prefix length rather than `broadcast_address`, which is cached on
    the network object and would keep an address object per entry alive.
    """

    first = int(network.network_address)
    return first, first + (1 << (network.max_prefixlen - network.prefixlen)) - 1


def _merged(ranges: Mapping[int, list[tuple[int, int]]]) -> tuple[Network, ...]:
    """The fewest networks covering the ranges, IPv4 first, each family in address order.

    What `ipaddress.collapse_addresses` answers, worked out on integers: it
    made an address object for every entry, and 100 000 entries took 160 MB
    (26-11-11). Overlapping and touching ranges merge; each merged range is
    then cut into the networks that cover exactly it.
    """

    found: list[Network] = []
    for version, kind in ((4, ipaddress.IPv4Address), (6, ipaddress.IPv6Address)):
        merged: list[list[int]] = []
        for first, last in sorted(ranges.get(version, ())):
            if merged and first <= merged[-1][1] + 1:
                merged[-1][1] = max(merged[-1][1], last)
            else:
                merged.append([first, last])
        for first, last in merged:
            found.extend(ipaddress.summarize_address_range(kind(first), kind(last)))
    return tuple(found)


def _collapsed(networks: Iterable[Network]) -> tuple[Network, ...]:
    ranges: dict[int, list[tuple[int, int]]] = {4: [], 6: []}
    for network in networks:
        ranges[network.version].append(_span(network))
    return _merged(ranges)


def except_networks(
    excepts: Sequence[str], groups: Mapping[str, Sequence[str]]
) -> tuple[tuple[Network, ...], tuple[str, ...]]:
    """The networks an exception list stands for in one cluster, and the groups it does not define."""

    networks: list[Network] = []
    unknown: list[str] = []
    for entry in excepts:
        if NAME.fullmatch(entry):
            members = groups.get(entry)
            if members is None:
                unknown.append(entry)
                continue
            networks.extend(address_ranges.plain_network(m, strict=False) for m in members)
        else:
            networks.append(address_ranges.plain_network(entry, strict=False))
    return _collapsed(networks), tuple(unknown)


def _outs(taken: Sequence[Network]) -> list[tuple[int, int, int, Network]]:
    return [(out.version, *_span(out), out) for out in taken]


def _hits(
    version: int, first: int, last: int, outs: Sequence[tuple[int, int, int, Network]]
) -> list[Network]:
    """The exceptions a range overlaps, compared as integers: `overlaps` caches
    an address object on every network it is asked about, which is the memory
    `_merged` saved."""

    return [
        out for kind, low, high, out in outs if kind == version and low <= last and first <= high
    ]


def excepted(
    networks: Sequence[Network], excepts: Sequence[str], groups: Mapping[str, Sequence[str]]
) -> tuple[int, tuple[str, ...]]:
    """What `subtract` counts, without making the list: the entries an exception
    takes out or cuts into, and the groups the cluster does not define."""

    taken, unknown = except_networks(excepts, groups)
    outs = _outs(taken)
    count = sum(1 for network in networks if _hits(network.version, *_span(network), outs))
    return count, unknown


def subtract(
    networks: Sequence[Network], excepts: Sequence[str], groups: Mapping[str, Sequence[str]]
) -> Excepted:
    """The list without its exceptions; a network an exception sits inside is split around it.

    `excepted` counts the list's entries an exception took out or cut into.
    """

    taken, unknown = except_networks(excepts, groups)
    outs = _outs(taken)
    ranges: dict[int, list[tuple[int, int]]] = {4: [], 6: []}
    excepted = 0
    for network in networks:
        first, last = _span(network)
        hits = _hits(network.version, first, last, outs)
        if not hits:
            ranges[network.version].append((first, last))
            continue
        excepted += 1
        pieces: list[Network] = [network]
        for out in hits:
            next_pieces: list[Network] = []
            for piece in pieces:
                if not piece.overlaps(out):
                    next_pieces.append(piece)
                elif not piece.subnet_of(out):  # type: ignore[arg-type]
                    next_pieces.extend(piece.address_exclude(out))  # type: ignore[arg-type]
            pieces = next_pieces
        for piece in pieces:
            ranges[piece.version].append(_span(piece))
    return Excepted(networks=_merged(ranges), excepted=excepted, unknown_groups=unknown)


def render(networks: Sequence[Network]) -> bytes:
    """The file a node loads with `acl … -f`: one network to a line, a single address bare."""

    lines = [
        str(network.network_address) if network.prefixlen == network.max_prefixlen else str(network)
        for network in networks
    ]
    return ("\n".join(lines) + "\n").encode("ascii") if lines else b""


def contains(networks: Sequence[Network], address: str) -> Network | None:
    """The network in the list that holds `address`, or None."""

    wanted = address_ranges.plain_address(address)
    for network in networks:
        if wanted in network:
            return network
    return None


# - fetching --------------------------------------------------------------


def _headers(item: Definition, secret: str) -> dict[str, str]:
    headers = {"Accept": "text/plain, */*"}
    if item.authorization == "basic":
        token = base64.b64encode(f"{item.username}:{secret}".encode()).decode("ascii")
        headers["Authorization"] = f"Basic {token}"
    elif item.authorization == "bearer":
        headers["Authorization"] = f"Bearer {secret}"
    return headers


def fetch(
    item: Definition,
    secret: str = "",
    *,
    timeout: float = TIMEOUT_SECONDS,
    context: ssl.SSLContext | None = None,
) -> bytes:
    """The list's body, or `BlocklistError`: https with the system's CAs, nothing followed or proxied."""

    if item.authorization != "none" and not secret:
        raise BlocklistError("no_secret", "the list's password or token is not set")
    if any(character in secret for character in "\r\n") or len(secret) > SECRET_MAX:
        raise BlocklistError("no_secret", "the list's password or token cannot be sent")
    url = checked_url(item.url)
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context or ssl.create_default_context()),
        http_answer.NoRedirect(),
    )
    request = urllib.request.Request(url, headers=_headers(item, secret))  # noqa: S310 - https only
    deadline = time.monotonic() + timeout
    host = urllib.parse.urlsplit(url).hostname
    try:
        with opener.open(request, timeout=timeout) as response:
            body = http_answer.read_body(response, MAX_BYTES, deadline=deadline)
    except urllib.error.HTTPError as exc:
        with exc:
            if 300 <= exc.code < 400:
                raise BlocklistError(
                    "redirected", f"{host} answered with a redirect, which is not followed"
                ) from exc
            raise BlocklistError("refused", f"{host} answered {exc.code}") from exc
    except ssl.SSLError as exc:
        raise BlocklistError("tls", f"{host}: TLS failed: {exc.reason or exc}") from exc
    except TimeoutError as exc:
        raise BlocklistError("unreachable", f"{host} took longer than {timeout:g} s") from exc
    except http_answer.BROKEN as exc:
        reason = getattr(exc, "reason", exc)
        if isinstance(reason, ssl.SSLError):
            raise BlocklistError("tls", f"{host}: TLS failed: {reason.reason or reason}") from exc
        text = reason if isinstance(reason, str) else http_answer.said(reason)
        raise BlocklistError("unreachable", f"{host} could not be reached: {text}") from exc
    if len(body) > MAX_BYTES:
        raise BlocklistError("too_large", f"the list is over {MAX_BYTES // (1024 * 1024)} MiB")
    return body
