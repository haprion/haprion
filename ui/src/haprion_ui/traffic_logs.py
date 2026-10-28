"""Bounded, read-only reading of the traffic mirror the collector maintains.

Everything here treats the files as untrusted text. A node writes its own log,
and a node can be compromised; what it must never be able to do is decide how
much this process reads, how long a field is, or what a template renders.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, cast

from haprion.digits import is_digits
from haprion.generate import backend_name
from haprion.proxy_model import Proxy, server_name, wildcard_expression, wildcard_matches
from psycopg import Connection, sql
from psycopg.rows import class_row

NODE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
MAX_RECORD_BYTES = 16 * 1024
MAX_NODES = 64
MAX_META_BYTES = 4096
MAX_SEARCH_TOKENS = 64
MAX_SEARCH_DEPTH = 12
MIRROR_SUFFIX = ".jsonl"
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


def _search_sql(expression: _Expression, parameters: list[Any]) -> sql.Composable:
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
        return sql.SQL("{} ilike %s").format(searchable)
    if isinstance(expression, _Not):
        return sql.SQL("not ({})").format(_search_sql(expression.value, parameters))
    operator = sql.SQL(" and " if isinstance(expression, _And) else " or ")
    return sql.SQL("({}){}({})").format(
        _search_sql(expression.left, parameters),
        operator,
        _search_sql(expression.right, parameters),
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
                address = f"{server.host}:{server.port}"
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


def _text(value: Any, *, maximum: int) -> str:
    if not isinstance(value, str) or len(value) > maximum:
        raise ValueError("invalid text field")
    return value


def _number(value: Any, *, low: int = -1, high: int = 2**63 - 1) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        raise ValueError("invalid numeric field")
    return value


def parse(line: bytes, cluster: str, node: str) -> Entry:
    if len(line) > MAX_RECORD_BYTES:
        raise ValueError("record too large")
    value = json.loads(line)
    if not isinstance(value, dict) or value.get("schema") != 1:
        raise ValueError("unsupported record")
    stamp = _number(value.get("at"), low=0)
    #
    # Tolerated rather than required. A mirror can still hold records written
    # before the request counter was added, and refusing them would report a
    # format change as corruption.
    #
    counter = value.get("request", 0)
    return Entry(
        cluster=cluster,
        node=node,
        at=datetime.fromtimestamp(stamp, UTC),
        request=_number(counter, low=0),
        client=_text(value.get("client"), maximum=64),
        method=_text(value.get("method"), maximum=16),
        host=_text(value.get("host"), maximum=253),
        path=_text(value.get("path"), maximum=8192),
        frontend=_text(value.get("frontend"), maximum=128),
        backend=_text(value.get("backend"), maximum=128),
        server=_text(value.get("server"), maximum=128),
        status=_number(value.get("status"), low=0, high=999),
        request_time=_number(value.get("request_time")),
        queue_time=_number(value.get("queue_time")),
        connect_time=_number(value.get("connect_time")),
        response_time=_number(value.get("response_time")),
        total_time=_number(value.get("total_time")),
        bytes=_number(value.get("bytes"), low=0),
        rule=_text(value.get("rule", ""), maximum=160),
    )


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
    )


def _read_bounded(path: Path, *, maximum: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags)
    try:
        return os.read(descriptor, maximum)
    finally:
        os.close(descriptor)


def _targets(directory: Path, clusters: tuple[str, ...]) -> tuple[list[tuple[str, str]], bool]:
    """Every cluster/node the mirror knows about, from both kinds of file.

    A node that has never answered has metadata and no log. Listing only the
    logs would drop exactly the node an operator most needs to see.
    """

    found: set[tuple[str, str]] = set()
    unavailable = False
    for cluster in clusters:
        for suffix in (MIRROR_SUFFIX, META_SUFFIX):
            try:
                names = sorted(item.name for item in directory.glob(f"{cluster}--*{suffix}"))
            except OSError:
                unavailable = True
                continue
            for name in names:
                node = name[len(f"{cluster}--") : -len(suffix)]
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
) -> Reading:
    """Read indexed rows while retaining the collector's per-node freshness files.

    `waf` narrows to the requests an access rule met (`hits`) or did not
    (`none`); empty is every request (Fas 21).

    `owned` narrows to one object (26-10-10): its backends, and its hostnames
    for the requests refused or redirected before any backend - an access rule,
    a dynamic block, the WAF - which carry the frontend's name instead. A name
    is compared without its port and case, as the Host header may carry both.
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
        conditions.append(_search_sql(expression, parameters))
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
    if waf == "hits":
        conditions.append(sql.SQL("rule <> ''"))
    elif waf == "none":
        conditions.append(sql.SQL("rule = ''"))
    if from_at is not None:
        conditions.append(sql.SQL("occurred_at >= %s"))
        parameters.append(from_at)
    if to_at is not None:
        conditions.append(sql.SQL("occurred_at <= %s"))
        parameters.append(to_at)
    parameters.append(min(max(limit, 1), 10_000))
    statement = sql.SQL("""
        select cluster, node, occurred_at as at, request_number as request,
               client, method, host, path, frontend, backend, server, status,
               request_time, queue_time, connect_time, response_time, total_time, bytes,
               rule
          from traffic_log_read
         where {}
         order by occurred_at desc, request_number desc
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
