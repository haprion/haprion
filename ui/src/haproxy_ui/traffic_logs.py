"""Bounded, read-only access to the JSON lines written by rsyslog."""

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


@dataclass(frozen=True, slots=True)
class Entry:
    cluster: str
    node: str
    at: datetime
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
class Reading:
    entries: tuple[Entry, ...]
    malformed: int
    unavailable: bool


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
    return Entry(
        cluster=cluster,
        node=node,
        at=datetime.fromtimestamp(stamp, UTC),
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


def _tail(path: Path) -> tuple[bytes, bool]:
    """Read a bounded tail without following a symlink.

    Rotation may replace the pathname before or after open.  Either inode is a
    complete valid snapshot; disappearance is reported as unavailable and the
    next request simply retries the new name.
    """

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags)
    try:
        size = os.fstat(descriptor).st_size
        start = max(0, size - MAX_SCAN_BYTES)
        os.lseek(descriptor, start, os.SEEK_SET)
        remaining = min(size, MAX_SCAN_BYTES)
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
        return Reading((), 0, False)
    status_code = int(status) if status.isdigit() and len(status) == 3 else None
    status_class = (
        int(status[0]) if len(status) == 3 and status[1:] == "xx" and status[0].isdigit() else None
    )
    if status and status_code is None and status_class is None:
        return Reading((), 0, False)
    needle = substring.casefold()[:200]
    proxy_needle = proxy.casefold()[:128]
    entries: list[Entry] = []
    malformed = 0
    unavailable = False

    for cluster_id in wanted:
        try:
            paths = tuple(sorted(directory.glob(f"{cluster_id}--*.jsonl")))
        except OSError:
            unavailable = True
            continue
        for path in paths:
            prefix = f"{cluster_id}--"
            node = path.name[len(prefix) : -len(".jsonl")]
            if not NODE_ID.fullmatch(node):
                continue
            try:
                data, truncated = _tail(path)
            except OSError:
                unavailable = True
                continue
            lines = data.splitlines()
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

    entries.sort(key=lambda item: item.at, reverse=True)
    return Reading(tuple(entries[:limit]), malformed, unavailable)
