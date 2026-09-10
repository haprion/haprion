"""Bounded, read-only reading of the traffic mirror the collector maintains.

Everything here treats the files as untrusted text. A node writes its own log,
and a node can be compromised; what it must never be able to do is decide how
much this process reads, how long a field is, or what a template renders.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

NODE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
MAX_RECORD_BYTES = 16 * 1024
MAX_SCAN_BYTES = 16 * 1024 * 1024
# One node cannot make the page expensive by growing, and a directory full of
# names cannot make it expensive by counting. Both limits are on this side.
MAX_TOTAL_SCAN_BYTES = 64 * 1024 * 1024
MAX_NODES = 64
MAX_META_BYTES = 4096
MIRROR_SUFFIX = ".jsonl"
META_SUFFIX = ".meta.json"


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
            and (self.last_success is None or self.last_attempt > self.last_success)
        )


@dataclass(frozen=True, slots=True)
class Reading:
    entries: tuple[Entry, ...]
    nodes: tuple[Freshness, ...]
    malformed: int
    unavailable: bool
    truncated: bool


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
    return Freshness(
        cluster=cluster,
        node=node,
        last_attempt=_stamp(value.get("last_attempt")),
        last_success=_stamp(value.get("last_success")),
        outcome=outcome if isinstance(outcome, str) and len(outcome) <= 64 else "unknown",
    )


def _read_bounded(path: Path, *, maximum: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags)
    try:
        return os.read(descriptor, maximum)
    finally:
        os.close(descriptor)


def _tail(path: Path, *, budget: int) -> tuple[bytes, bool]:
    """Read a bounded tail without following a symlink.

    The collector replaces a mirror by rename, so this either opens the previous
    complete snapshot or the new one. There is no state in which it reads half a
    fetch, and a file that disappears between listing and opening is reported as
    unavailable rather than as empty.
    """

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags)
    try:
        size = os.fstat(descriptor).st_size
        window = min(budget, MAX_SCAN_BYTES)
        start = max(0, size - window)
        os.lseek(descriptor, start, os.SEEK_SET)
        remaining = min(size, window)
        chunks: list[bytes] = []
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
    finally:
        os.close(descriptor)
    return data, start > 0


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


def read(
    directory: Path,
    clusters: tuple[str, ...],
    *,
    limit: int = 500,
    cluster: str = "",
    proxy: str = "",
    status: str = "",
    substring: str = "",
) -> Reading:
    wanted = (cluster,) if cluster else clusters
    if cluster and cluster not in clusters:
        return Reading((), (), 0, False, False)
    status_code = int(status) if status.isdigit() and len(status) == 3 else None
    status_class = (
        int(status[0]) if len(status) == 3 and status[1:] == "xx" and status[0].isdigit() else None
    )
    if status and status_code is None and status_class is None:
        return Reading((), (), 0, False, False)
    needle = substring.casefold()[:200]
    proxy_needle = proxy.casefold()[:128]

    targets, unavailable = _targets(directory, tuple(wanted))
    entries: list[Entry] = []
    nodes: list[Freshness] = []
    malformed = 0
    any_truncated = False
    budget = MAX_TOTAL_SCAN_BYTES

    for cluster_id, node in targets:
        nodes.append(_freshness(directory / f"{cluster_id}--{node}{META_SUFFIX}", cluster_id, node))
        path = directory / f"{cluster_id}--{node}{MIRROR_SUFFIX}"
        try:
            data, truncated = _tail(path, budget=budget)
        except FileNotFoundError:
            continue
        except OSError:
            unavailable = True
            continue
        budget -= len(data)
        any_truncated = any_truncated or truncated
        lines = data.splitlines()
        #
        # The first line of a truncated window is a record cut in half. Dropping
        # it is not defensive tidying: parsing it would count as malformed and
        # report the size limit as corrupt data.
        #
        if truncated and lines:
            lines = lines[1:]
        for line in lines:
            try:
                entry = parse(line, cluster_id, node)
            except (OSError, UnicodeError, ValueError, OverflowError):
                malformed += 1
                continue
            if status_code is not None and entry.status != status_code:
                continue
            if status_class is not None and entry.status // 100 != status_class:
                continue
            if proxy_needle not in f"{entry.frontend} {entry.backend}".casefold():
                continue
            searchable = (
                f"{entry.client} {entry.method} {entry.host} {entry.path} "
                f"{entry.frontend} {entry.backend} {entry.server} {entry.status}"
            ).casefold()
            if needle not in searchable:
                continue
            entries.append(entry)

    #
    # The accept time is whole seconds, so a busy second holds many records and
    # sorting on it alone leaves their order to chance. The per-process request
    # counter breaks the tie within one node, which is the only place it means
    # anything - it restarts with the process, and two nodes never share one.
    #
    entries.sort(key=lambda item: (item.at, item.node, item.request), reverse=True)
    return Reading(tuple(entries[:limit]), tuple(nodes), malformed, unavailable, any_truncated)
