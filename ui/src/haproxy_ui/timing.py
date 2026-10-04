"""Where a page's time goes: the database, the template, and the rest.

A page that feels slow can be slow in three places - waiting for PostgreSQL,
drawing the template, or the Python between them - and each calls for a
different remedy. Guessing which one it is costs a release per guess, so every
response says it itself: a `Server-Timing` header the browser's network panel
shows beside the request, and one line in the service log.

The numbers are collected per request in a context variable. The object it
holds is shared, not copied, so a read handed to a worker thread (the traffic
pages read two at a time) adds to the same request. Database time is then a
sum over connections and can exceed the wall clock; the query count says how
many there were.

Only durations and the path are recorded. The query string is left out: the
traffic log's search field travels in it, and a timing line is no place for
what someone searched for.
"""

from __future__ import annotations

import logging
import sys
import threading
import time
from collections.abc import Awaitable, Callable, MutableMapping
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, Self

import psycopg

logger = logging.getLogger("haproxy_ui.timing")

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

# Asset requests are many, cheap and served the same way every time.
UNTIMED_PREFIXES = ("/static/",)


@dataclass
class Timing:
    """What one request has spent so far, in seconds."""

    database: float = 0.0
    queries: int = 0
    render: float = 0.0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def add_query(self, seconds: float) -> None:
        with self._lock:
            self.database += seconds
            self.queries += 1

    def add_render(self, seconds: float) -> None:
        with self._lock:
            self.render += seconds


_CURRENT: ContextVar[Timing | None] = ContextVar("request_timing", default=None)


def current() -> Timing | None:
    return _CURRENT.get()


class TimedCursor(psycopg.Cursor[Any]):
    """A cursor that adds each statement's time to the request it serves.

    Outside a request - the poller, the worker, a test - there is nothing to
    add to, and the cursor behaves exactly like the one it replaces.
    """

    def execute(self, *args: Any, **kwargs: Any) -> Self:
        timing = _CURRENT.get()
        if timing is None:
            super().execute(*args, **kwargs)
            return self
        started = time.perf_counter()
        try:
            super().execute(*args, **kwargs)
        finally:
            timing.add_query(time.perf_counter() - started)
        return self


def rendered[T](render: Callable[[], T]) -> T:
    """Run `render` and count its time as the template's."""

    timing = _CURRENT.get()
    if timing is None:
        return render()
    started = time.perf_counter()
    try:
        return render()
    finally:
        timing.add_render(time.perf_counter() - started)


def server_timing(timing: Timing, total: float) -> str:
    """The header value. Durations in milliseconds, as the format prescribes."""

    rest = max(total - timing.database - timing.render, 0.0)
    return ", ".join(
        (
            f'db;dur={timing.database * 1000:.1f};desc="{timing.queries} queries"',
            f"render;dur={timing.render * 1000:.1f}",
            f"app;dur={rest * 1000:.1f}",
            f"total;dur={total * 1000:.1f}",
        )
    )


def log_handler() -> None:
    """Send the timing lines to stderr, which systemd puts in the journal.

    The web service configures no logging of its own - uvicorn configures only
    its own loggers - so without this the lines would go nowhere.
    """

    if logger.handlers:
        return
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(levelname)s:     %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False


class TimingMiddleware:
    """Times each request and reports it in the response and the log."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        path = scope.get("path", "")
        if scope["type"] != "http" or path.startswith(UNTIMED_PREFIXES):
            await self.app(scope, receive, send)
            return
        timing = Timing()
        token = _CURRENT.set(timing)
        started = time.perf_counter()
        status = 0

        async def timed_send(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
                headers = list(message.get("headers", []))
                value = server_timing(timing, time.perf_counter() - started)
                headers.append((b"server-timing", value.encode("ascii")))
                message["headers"] = headers
            await send(message)

        try:
            await self.app(scope, receive, timed_send)
        finally:
            _CURRENT.reset(token)
            total = time.perf_counter() - started
            logger.info(
                "timing %s %s %s total=%.0fms db=%.0fms/%d render=%.0fms",
                scope.get("method", ""),
                path,
                status,
                total * 1000,
                timing.database * 1000,
                timing.queries,
                timing.render * 1000,
            )
