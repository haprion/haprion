"""Bounded, read-only reading of the traffic the collector maintains.

The rows are the database's, and the freshness comes from the metadata files
beside the mirror.

Everything here treats the files as untrusted text. A node writes its own log,
and a node can be compromised; what it must never be able to do is decide how
much this process reads, how long a field is, or what a template renders.
"""

from __future__ import annotations

import builtins
import ipaddress
import json
import os
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, cast

from haprion.digits import is_digits
from haprion.generate import WAF_INTERRUPTED, backend_name
from haprion.proxy_model import Proxy, server_name, wildcard_expression, wildcard_matches
from psycopg import Connection, sql
from psycopg.rows import class_row

NODE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
MAX_NODES = 64
MAX_META_BYTES = 4096
MAX_SEARCH_TOKENS = 64
MAX_SEARCH_DEPTH = 12
META_SUFFIX = ".meta.json"
POSITIONAL_SERVER = re.compile(r"^s[1-9][0-9]*$")


@dataclass(frozen=True, slots=True)
class Entry:
    cluster: str
    node: str
    at: datetime
    request: int
    client: str
    method: str
    host: str
    path: str
    frontend: str
    backend: str
    server: str
    status: int
    request_time: int
    queue_time: int
    connect_time: int
    response_time: int
    total_time: int
    bytes: int
    rule: str = ""
    """The access rule the request met, as `name:log` or `name:deny`; empty if none."""
    termination: str = ""
    """HAProxy's two letters for how the session ended (0106); `--` normally."""
    event: builtins.bytes = b""
    """The row's own identity (its 32-byte `event_id`): the last tie-break in the order (0111)."""

    @property
    def ended(self) -> str:
        """How the session ended, in words; empty when it ended normally or is not known."""

        return ended_in_words(self.termination)


#
# HAProxy's termination state (configuration.txt, "Session state at
# disconnection"): who ended the session, then where it was.
#
_ENDED_BY = {
    "C": "The client ended it",
    "S": "The server ended it",
    "P": "The proxy ended it",
    "L": "The proxy answered it itself",
    "R": "The proxy ran out of a resource",
    "I": "An internal error ended it",
    "D": "The server was marked down",
    "U": "A backup server took over",
    "K": "An administrator ended it",
}
_ENDED_WHILE = {
    "R": " while the request came in",
    "Q": " while it waited in the queue",
    "C": " while connecting to the server",
    "H": " while waiting for the server's headers",
    "D": " while the data was sent",
    "L": " while the last data went out",
    "T": " while it was held back",
}


def ended_in_words(termination: str) -> str:
    if len(termination) != 2 or termination == "--":
        return ""
    who, where = termination[0], termination[1]
    said = _ENDED_BY.get(who)
    if said is None:
        return ""
    return said + _ENDED_WHILE.get(where, "")


LASTING_RUNS = 5
#
# The collector's JOINING_SECONDS: a node never reached and first tried less
# than this ago is one still being joined, not a fault (26-10-27, F25).
#
JOINING_SECONDS = 300


@dataclass(frozen=True, slots=True)
class Freshness:
    """When the manager last managed to talk to one node.

    This is the part that makes a silent node visible. Without it a node that
    stopped answering an hour ago looks exactly like a node nobody is calling,
    and the page would be most reassuring precisely when it should not be.
    """

    cluster: str
    node: str
    last_attempt: datetime | None
    last_success: datetime | None
    outcome: str
    current_complete: bool | None = None
    remaining_bytes: int | None = None
    pending_days: int | None = None
    #
    # Successful runs in a row that ended with today incomplete (26-10-12).
    # `None` from a collector older than the count.
    #
    behind_runs: int | None = None
    #
    # The collector's first try at this node; `None` from a collector older
    # than the field.
    #
    first_attempt: datetime | None = None
    #
    # Why a run was `budget`: `share` when this node's own parts are what fill
    # the manager's copy (the other nodes are fetched as usual), `volume` when
    # the filesystem is short of room for another reason (review 2026-11-05,
    # T02).
    #
    budget_reason: str | None = None

    def being_joined(self, *, now: datetime) -> bool:
        return (
            self.last_success is None
            and self.outcome == "ssh"
            and self.first_attempt is not None
            and (now - self.first_attempt).total_seconds() < JOINING_SECONDS
        )

    def catching_up(self) -> bool:
        return self.current_complete is False or bool(self.pending_days)

    def lasting_backlog(self) -> bool:
        """Behind for longer than a burst takes: older days waiting, or run after run.

        A burst is caught up in a run or two (26-10-12); what is left after
        LASTING_RUNS is a node the collector does not keep up with.
        """

        return bool(self.pending_days) or (self.behind_runs or 0) >= LASTING_RUNS

    def stale_seconds(self, *, now: datetime) -> float | None:
        if self.last_success is None:
            return None
        return max(0.0, (now - self.last_success).total_seconds())

    def attempt_seconds(self, *, now: datetime) -> float | None:
        if self.last_attempt is None:
            return None
        return max(0.0, (now - self.last_attempt).total_seconds())

    def latest_attempt_failed(self) -> bool:
        return (
            self.outcome not in {"ok", "unknown"}
            and self.last_attempt is not None
            and (self.last_success is None or self.last_attempt >= self.last_success)
        )


@dataclass(frozen=True, slots=True)
class Reading:
    entries: tuple[Entry, ...]
    nodes: tuple[Freshness, ...]
    malformed: int
    unavailable: bool
    filter_error: str | None = None


class SearchSyntaxError(ValueError):
    """A bounded search expression that cannot be interpreted."""


@dataclass(frozen=True, slots=True)
class _Token:
    kind: Literal["term", "and", "or", "not", "left", "right"]
    value: str = ""


@dataclass(frozen=True, slots=True)
class _Term:
    value: str


@dataclass(frozen=True, slots=True)
class _Not:
    value: _Expression


@dataclass(frozen=True, slots=True)
class _And:
    left: _Expression
    right: _Expression


@dataclass(frozen=True, slots=True)
class _Or:
    left: _Expression
    right: _Expression


type _Expression = _Term | _Not | _And | _Or


def _tokens(query: str) -> tuple[_Token, ...]:
    result: list[_Token] = []
    position = 0
    while position < len(query):
        if query[position].isspace():
            position += 1
            continue
        if query[position] in "()":
            result.append(_Token("left" if query[position] == "(" else "right"))
            position += 1
        elif query[position] == '"':
            position += 1
            phrase: list[str] = []
            while position < len(query) and query[position] != '"':
                if query[position] == "\\" and position + 1 < len(query):
                    position += 1
                phrase.append(query[position])
                position += 1
            if position == len(query):
                raise SearchSyntaxError("The search has an unterminated quoted phrase.")
            position += 1
            if not phrase:
                raise SearchSyntaxError("A quoted search phrase cannot be empty.")
            result.append(_Token("term", "".join(phrase).casefold()))
        else:
            end = position
            while end < len(query) and not query[end].isspace() and query[end] not in "()":
                end += 1
            word = query[position:end]
            operator = word.casefold()
            if operator in {"and", "or", "not"}:
                kind = cast(Literal["and", "or", "not"], operator)
                result.append(_Token(kind))
            else:
                result.append(_Token("term", operator))
            position = end
        if len(result) > MAX_SEARCH_TOKENS:
            raise SearchSyntaxError("The search expression has too many parts.")
    return tuple(result)


class _Parser:
    def __init__(self, tokens: tuple[_Token, ...]) -> None:
        self.tokens = tokens
        self.position = 0
        self.depth = 0

    def parse(self) -> _Expression:
        if not self.tokens:
            return _Term("")
        expression = self._or()
        if self.position != len(self.tokens):
            raise SearchSyntaxError("The search expression has an unexpected closing parenthesis.")
        return expression

    def _peek(self, *kinds: str) -> bool:
        return self.position < len(self.tokens) and self.tokens[self.position].kind in kinds

    def _take(self) -> _Token:
        token = self.tokens[self.position]
        self.position += 1
        return token

    def _or(self) -> _Expression:
        expression = self._and()
        while self._peek("or"):
            self._take()
            expression = _Or(expression, self._and())
        return expression

    def _and(self) -> _Expression:
        expression = self._not()
        while self._peek("and", "term", "not", "left"):
            if self._peek("and"):
                self._take()
            expression = _And(expression, self._not())
        return expression

    def _not(self) -> _Expression:
        if self._peek("not"):
            self._take()
            return _Not(self._not())
        return self._atom()

    def _atom(self) -> _Expression:
        if self._peek("term"):
            return _Term(self._take().value)
        if self._peek("left"):
            self._take()
            self.depth += 1
            if self.depth > MAX_SEARCH_DEPTH:
                raise SearchSyntaxError("The search expression is nested too deeply.")
            if self._peek("right"):
                raise SearchSyntaxError("A parenthesized search expression cannot be empty.")
            expression = self._or()
            if not self._peek("right"):
                raise SearchSyntaxError("The search expression is missing a closing parenthesis.")
            self._take()
            self.depth -= 1
            return expression
        raise SearchSyntaxError("The search expression ends with an operator.")


def like_pattern(query: str) -> str:
    """A substring pattern that matches the text and nothing it could mean to LIKE."""

    escaped = query.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


type _Ip = ipaddress.IPv4Address | ipaddress.IPv6Address
type _Net = ipaddress.IPv4Network | ipaddress.IPv6Network


def _plain(address: _Ip) -> _Ip:
    """An IPv4-mapped IPv6 address as the IPv4 address, as the rest of the interface reads one."""

    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def _ip_term(value: str) -> _Ip | _Net | None:
    """The address or network a term is, or None; a network with a zone is refused.

    `fe80::%eth0/64` is a network Python reads and PostgreSQL does not, and a
    zone names an interface of one machine, which no client in a log has
    (review 26-11-01, P3-1). An address with a zone is text.
    """

    try:
        if "/" in value:
            if "%" in value:
                raise SearchSyntaxError("A network in the search cannot name an interface zone.")
            network = ipaddress.ip_network(value, strict=False)
            if isinstance(network, ipaddress.IPv6Network) and network.prefixlen >= 96:
                mapped = network.network_address.ipv4_mapped
                if mapped is not None:
                    return ipaddress.ip_network((mapped, network.prefixlen - 96))
            return network
        if "%" in value:
            return None
        return _plain(ipaddress.ip_address(value))
    except ValueError as exc:
        if isinstance(exc, SearchSyntaxError):
            raise
        return None


def client_match(value: str) -> tuple[str, list[str]] | None:
    """How a term names a client: `("address", texts)` or `("network", [cidr, ...])`, else None.

    An address is written the way the log writes it: an IPv4-mapped IPv6 address
    is the IPv4 address (as the rest of the interface reads one), and the log
    may carry either form, so both are asked for. A network is any `address/bits`
    and asked for in both forms too, so a network matches the mapped clients an
    address does and a mapped network the IPv4 ones (review 26-11-01, P3-2).
    """

    term = _ip_term(value)
    if term is None:
        return None
    if isinstance(term, ipaddress.IPv4Network):
        mapped = ipaddress.ip_network((f"::ffff:{term.network_address}", 96 + term.prefixlen))
        return "network", [str(term), str(mapped)]
    if isinstance(term, ipaddress.IPv6Network):
        return "network", [str(term)]
    if isinstance(term, ipaddress.IPv4Address):
        return "address", [str(term), f"::ffff:{term}"]
    return "address", [str(term)]


def _endpoint(text: str) -> tuple[str, str]:
    """A destination or a term as `(host, port)`: `host:port` or `[v6]:port`; the port may be empty."""

    if text.startswith("["):
        host, _, rest = text[1:].partition("]")
        return host, rest.removeprefix(":")
    host, separator, port = text.rpartition(":")
    return (host, port) if separator and ":" not in host else (text, "")


def _destinations(
    value: str, addresses: Mapping[tuple[str, str, str], str]
) -> list[tuple[str, str, str]]:
    """The generated servers whose configured destination the term names.

    A term that is an address names the destinations on that host and no
    other (`192.0.2.3` is not `192.0.2.33`); `address:port` the one destination;
    a network the hosts in it. Any other term is part of the text, as before
    (review 26-11-01, P2-2).
    """

    needle = value.lower()
    term = _ip_term(needle)
    wanted_host, wanted_port = _endpoint(needle)
    try:
        wanted = _plain(ipaddress.ip_address(wanted_host)) if term is None and wanted_port else None
    except ValueError:
        wanted = None
    found = []
    for key, address in addresses.items():
        if term is None and wanted is None:
            if needle in address.lower():
                found.append(key)
            continue
        host, port = _endpoint(address.lower())
        try:
            actual = _plain(ipaddress.ip_address(host))
        except ValueError:
            continue
        if isinstance(term, ipaddress.IPv4Network | ipaddress.IPv6Network):
            hit = actual.version == term.version and actual in term
        elif term is not None:
            hit = actual == term
        else:
            hit = actual == wanted and port == wanted_port
        if hit:
            found.append(key)
    return found


def _search_sql(
    expression: _Expression,
    parameters: list[Any],
    destinations: Mapping[tuple[str, str, str], str] | None = None,
) -> sql.Composable:
    # Keep this expression byte-for-byte aligned with the per-partition
    # pg_trgm index created by migration 0030: the planner uses it only for
    # this exact expression, and only through `traffic_log_read` (0083).
    searchable = sql.SQL("(host || ' ' || path || ' ' || backend)")
    if isinstance(expression, _Term):
        if not expression.value:
            return sql.SQL("true")
        #
        # A term is text to find: `_` and `%` are characters in a backend's
        # name or an encoded path, not LIKE's wildcards (review 2026-10-20, D1).
        #
        parameters.append(like_pattern(expression.value))
        found: list[sql.Composable] = [sql.SQL("{} ilike %s").format(searchable)]
        #
        # The client, which is a column of its own: an address is that client
        # (the index of 0111), a network every client in it, both as the
        # expression the index holds, which never fails on what a node wrote.
        # The text above is still searched, as a host can be an address.
        #
        client = client_match(expression.value)
        if client is not None:
            if client[0] == "address":
                found.append(sql.SQL("traffic_log_client_inet(client) = any(%s::inet[])"))
                parameters.append(client[1])
            else:
                found.append(
                    sql.SQL("({})").format(
                        sql.SQL(" or ").join(
                            sql.SQL("traffic_log_client_inet(client) <<= %s::inet")
                            for _ in client[1]
                        )
                    )
                )
                parameters.extend(client[1])
        #
        # The destination is configuration, not a column: the generated names
        # the log carries (`s2`) are resolved before the query, and the servers
        # whose destination holds the term are asked for here. Only a reader
        # shown destinations is given them to search (`destinations`). One
        # hashed array of `cluster backend server` (no name holds a space): a
        # subplan per term made the planner's cost pass the point where
        # PostgreSQL compiles the query, which cannot be cancelled (P2-1).
        #
        servers = _destinations(expression.value, destinations) if destinations else []
        if servers:
            found.append(sql.SQL("(cluster || ' ' || backend || ' ' || server) = any(%s::text[])"))
            parameters.append([" ".join(key) for key in servers])
        return sql.SQL("({})").format(sql.SQL(" or ").join(found))
    if isinstance(expression, _Not):
        return sql.SQL("not ({})").format(_search_sql(expression.value, parameters, destinations))
    operator = sql.SQL(" and " if isinstance(expression, _And) else " or ")
    #
    # Wrapped as a whole: joined to the cluster, status and time with `and`, a
    # bare `a or b` would let `b` through every one of them.
    #
    return sql.SQL("(({}){}({}))").format(
        _search_sql(expression.left, parameters, destinations),
        operator,
        _search_sql(expression.right, parameters, destinations),
    )


def configured_server_addresses(
    cluster: str, proxies: Iterable[Proxy]
) -> dict[tuple[str, str, str], str]:
    """Configured destination behind each generated HAProxy server name.

    Generated backend members are positional: the first configured server is
    called ``s1``, the second ``s2``, and so on.  Keep the complete runtime
    backend in the key instead of trying to split it; object and backend names may
    themselves contain hyphens.

    Under the pool's own name, which the log rows carry.
    """

    result: dict[tuple[str, str, str], str] = {}
    for proxy in proxies:
        for pool, backend in proxy.backends.items():
            runtime_backend = backend_name(proxy, pool)
            for index, server in enumerate(backend.servers):
                host = f"[{server.host}]" if ":" in server.host else server.host
                address = f"{host}:{server.port}"
                result[(cluster, runtime_backend, server_name(index))] = address
    return result


def resolve_server_addresses(
    reading: Reading, addresses: Mapping[tuple[str, str, str], str]
) -> Reading:
    """Replace generated ``sN`` aliases with their configured destinations.

    A named server from unmanaged HAProxy configuration remains useful and is
    left alone.  An unresolved generated alias is omitted: ``s3`` without the
    configuration that gave it meaning is not a destination and must not be
    presented as one.
    """

    entries = tuple(
        replace(
            entry,
            server=addresses.get((entry.cluster, entry.backend, entry.server), ""),
        )
        if POSITIONAL_SERVER.fullmatch(entry.server)
        else entry
        for entry in reading.entries
    )
    return replace(reading, entries=entries)


def _resolved_server(entry: Entry, addresses: Mapping[tuple[str, str, str], str]) -> Entry:
    if not POSITIONAL_SERVER.fullmatch(entry.server):
        return entry
    return replace(entry, server=addresses.get((entry.cluster, entry.backend, entry.server), ""))


def _stamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _freshness(path: Path, cluster: str, node: str) -> Freshness:
    """Read one node's collector metadata, or say the collector left none."""

    try:
        raw = _read_bounded(path, maximum=MAX_META_BYTES)
        value = json.loads(raw)
    except (OSError, UnicodeError, ValueError):
        return Freshness(cluster, node, None, None, "unknown")
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        return Freshness(cluster, node, None, None, "unknown")
    outcome = value.get("outcome")
    complete = value.get("current_complete")
    remaining = value.get("remaining_bytes")
    pending = value.get("pending_days")
    behind = value.get("behind_runs")
    reason = value.get("budget_reason")
    return Freshness(
        cluster=cluster,
        node=node,
        last_attempt=_stamp(value.get("last_attempt")),
        last_success=_stamp(value.get("last_success")),
        outcome=outcome if isinstance(outcome, str) and len(outcome) <= 64 else "unknown",
        current_complete=complete if isinstance(complete, bool) else None,
        remaining_bytes=remaining
        if type(remaining) is int and 0 <= remaining <= 2**63 - 1
        else None,
        pending_days=pending if type(pending) is int and 0 <= pending <= 90 else None,
        behind_runs=behind if type(behind) is int and 0 <= behind <= 2**31 else None,
        first_attempt=_stamp(value.get("first_attempt")),
        budget_reason=reason if reason in {"share", "volume"} else None,
    )


def _read_bounded(path: Path, *, maximum: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags)
    try:
        return os.read(descriptor, maximum)
    finally:
        os.close(descriptor)


def _targets(directory: Path, clusters: tuple[str, ...]) -> tuple[list[tuple[str, str]], bool]:
    """Every cluster/node the collector left metadata for.

    A node that has never answered has metadata and no rows. Listing only the
    nodes with rows would drop exactly the node an operator most needs to see.
    """

    found: set[tuple[str, str]] = set()
    unavailable = False
    for cluster in clusters:
        try:
            names = sorted(item.name for item in directory.glob(f"{cluster}--*{META_SUFFIX}"))
        except OSError:
            unavailable = True
            continue
        for name in names:
            node = name[len(f"{cluster}--") : -len(META_SUFFIX)]
            if NODE_ID.fullmatch(node):
                found.add((cluster, node))
    return sorted(found)[:MAX_NODES], unavailable


def owned_hosts(hostnames: Sequence[str], others: Iterable[str]) -> tuple[str, ...]:
    """One object's names for the log filter: its own, and `!name` for each name it yields (B278)."""

    patterns = [name for name in hostnames if name.startswith("*.")]
    yielded = sorted(
        {
            name
            for name in others
            if not name.startswith("*.") and any(wildcard_matches(p, name) for p in patterns)
        }
    )
    return (*hostnames, *(f"!{name}" for name in yielded))


def read_database(
    connection: Connection[Any],
    directory: Path,
    clusters: tuple[str, ...],
    *,
    limit: int = 500,
    cluster: str = "",
    status: str = "",
    substring: str = "",
    from_at: datetime | None = None,
    to_at: datetime | None = None,
    server_addresses: Mapping[tuple[str, str, str], str] | None = None,
    waf: str = "",
    owned: tuple[Sequence[str], Sequence[str]] | None = None,
    before: tuple[datetime, int, str, bytes] | None = None,
) -> Reading:
    """Read indexed rows while retaining the collector's per-node freshness files.

    `waf` narrows to the requests an access rule met (`hits`) or did not
    (`none`); empty is every request (Fas 21).

    `owned` narrows to one object (26-10-10): its backends, and its hostnames
    for the requests refused or redirected before any backend - an access rule,
    a dynamic block, the WAF - which carry the frontend's name instead. A name
    is compared without its port and case, as the Host header may carry both.

    `before` is the place a page ended at - a row's time, request number, node
    and own identity - and the rows read are those after it in the order shown, so a page
    that follows another neither repeats a row nor drops one that shares the
    time (26-11-01).
    """

    wanted = (cluster,) if cluster else clusters
    if cluster and cluster not in clusters:
        return Reading((), (), 0, False)
    status_code = int(status) if is_digits(status) and len(status) == 3 else None
    status_class = (
        int(status[0]) if len(status) == 3 and status[1:] == "xx" and is_digits(status[0]) else None
    )
    if status and status_code is None and status_class is None:
        return Reading((), (), 0, False)
    try:
        expression = _Parser(_tokens(substring[:200])).parse()
    except SearchSyntaxError as exc:
        return Reading((), (), 0, False, str(exc))

    conditions: list[sql.Composable] = [sql.SQL("cluster = any(%s)")]
    parameters: list[Any] = [list(wanted)]
    if status_code is not None:
        conditions.append(sql.SQL("status = %s"))
        parameters.append(status_code)
    elif status_class is not None:
        conditions.append(sql.SQL("status between %s and %s"))
        parameters.extend((status_class * 100, status_class * 100 + 99))
    if substring:
        try:
            conditions.append(_search_sql(expression, parameters, server_addresses))
        except SearchSyntaxError as exc:
            return Reading((), (), 0, False, str(exc))
    if owned is not None:
        backends, hosts = owned
        names = [host.lower() for host in hosts if not host.startswith(("!", "*."))]
        excluded = [host[1:].lower() for host in hosts if host.startswith("!")]
        #
        # A subdomain is one label then its suffix (B278), as the generator
        # matches it, less the exact names other objects claim under it.
        #
        patterns = [wildcard_expression(host.lower()) for host in hosts if host.startswith("*.")]
        conditions.append(
            sql.SQL(
                "(backend = any(%s) or split_part(lower(host), ':', 1) = any(%s)"
                " or (split_part(lower(host), ':', 1) ~ any(%s)"
                " and not split_part(lower(host), ':', 1) = any(%s)))"
            )
        )
        parameters.extend((list(backends), names, patterns, excluded))
    #
    # A request the client cancelled while the WAF was checking it carries a
    # rule name, since a rule closes it, but no rule decided anything: it is not
    # a hit (B434, 26-11-02). It stays in the log, under "no rule hits".
    #
    if waf == "hits":
        conditions.append(sql.SQL("rule <> '' and rule not like %s"))
        parameters.append(f"{WAF_INTERRUPTED}:%")
    elif waf == "none":
        conditions.append(sql.SQL("(rule = '' or rule like %s)"))
        parameters.append(f"{WAF_INTERRUPTED}:%")
    if from_at is not None:
        conditions.append(sql.SQL("occurred_at >= %s"))
        parameters.append(from_at)
    if to_at is not None:
        conditions.append(sql.SQL("occurred_at <= %s"))
        parameters.append(to_at)
    if before is not None:
        conditions.append(
            sql.SQL("(occurred_at, request_number, node, event_id) < (%s, %s, %s, %s)")
        )
        parameters.extend(before)
    parameters.append(min(max(limit, 1), 10_000))
    statement = sql.SQL("""
        select cluster, node, occurred_at as at, request_number as request,
               client, method, host, path, frontend, backend, server, status,
               request_time, queue_time, connect_time, response_time, total_time, bytes,
               rule, termination, event_id as event
          from traffic_log_read
         where {}
         order by occurred_at desc, request_number desc, node desc, event_id desc
         limit %s
    """).format(sql.SQL(" and ").join(conditions))
    with connection.cursor(row_factory=class_row(Entry)) as cursor:
        cursor.execute(statement, parameters)
        entries = tuple(_resolved_server(row, server_addresses or {}) for row in cursor.fetchall())

    return replace(read_freshness(directory, tuple(wanted)), entries=entries)


def read_freshness(directory: Path, clusters: tuple[str, ...]) -> Reading:
    """The collector's per-node freshness files alone, without a row of the log.

    What the log page's warning says, read on its own so the page can ask
    again every few seconds without querying the table (26-10-12).
    """

    targets, unavailable = _targets(directory, clusters)
    nodes = tuple(
        _freshness(directory / f"{cluster_id}--{node}{META_SUFFIX}", cluster_id, node)
        for cluster_id, node in targets
    )
    return Reading((), nodes, 0, unavailable)
