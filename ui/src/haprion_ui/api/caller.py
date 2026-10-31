"""Who is calling the API: the bearer token, judged once per request (B416).

The API reads no cookie and the pages read no bearer token. That boundary is
what lets the API go without CSRF tokens - a browser sends a cookie on its
own, never an `Authorization` header - and a test walks every route on both
sides of it (`test_api_boundary`).

* **Every failure is the same 401.** Unknown, revoked, expired, or called
  from outside the token's addresses: the caller learns that the token is not
  valid here, and the service log says why.
* **Guesses are counted harder than calls.** nginx limits every source on
  `/api/`; a source that sends ten guesses a minute - a token nobody issued,
  or a header that is not a token - is answered 429 here for the rest of that
  minute. A valid token is served whatever the count: the count is a source's,
  and another integration on the same host with an expired token (a known
  caller, not a guess, and in the log already) must not take the others'
  service. Counted in this process, which is the only one serving: a restart
  forgets the count, which costs a guesser one minute.
* **At most `CONCURRENT_CALLS` calls at once**, answered 429 `busy` beyond
  that: the pages share the pool with the API, and the API may not take the
  pages' connections from them.
* **A use is written at most once a minute** (`touch_api_token`), so a busy
  integration is not a write per call.
"""

from __future__ import annotations

import ipaddress
import logging
import threading
import time
from collections import OrderedDict
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from haprion_ui import api_tokens, db
from haprion_ui.access import client_address
from haprion_ui.api.answers import Refusal

logger = logging.getLogger("haprion_ui.api")

FAILURES_PER_MINUTE = 10
REMEMBERED_SOURCES = 4096

#
# The web's pool is six connections. Half of them are the API's at most, and
# a call that cannot have one is told to come back, not queued.
#
CONCURRENT_CALLS = 3

#
# What counts as guessing. A missing header, a revoked or expired token and a
# token used from outside its addresses are callers that are configured wrong.
#
GUESSES = frozenset({"unknown", "malformed"})

#
# Declared for the OpenAPI document, which then says how to authenticate;
# `auto_error` off, because the refusal is this module's and not FastAPI's.
#
BEARER = HTTPBearer(auto_error=False, description="An API token, made under Settings → API tokens")


@dataclass(frozen=True, slots=True)
class Caller:
    issued: db.ApiToken
    source: str

    @property
    def actor(self) -> str:
        """Who the history names for what this call does."""

        return f"token:{self.issued.name}"


def source_key(source: str) -> str:
    """The address a count is kept under: an IPv6 host is its /64, which one subscriber owns.

    `client_address` has already made an IPv4 client on a dual-stack socket
    (::ffff:a.b.c.d) its IPv4 address.
    """

    try:
        address = ipaddress.ip_address(source)
    except ValueError:
        return source
    if address.version == 6:
        return str(ipaddress.ip_network(f"{address}/64", strict=False))
    return source


class Failures:
    """Sources that sent guesses, for the last minute; the oldest forgotten when full."""

    def __init__(
        self,
        limit: int = FAILURES_PER_MINUTE,
        window: float = 60.0,
        remembered: int = REMEMBERED_SOURCES,
    ) -> None:
        self.limit = limit
        self.window = window
        self.remembered = remembered
        self._lock = threading.Lock()
        self._seen: OrderedDict[str, list[float]] = OrderedDict()
        self._told: OrderedDict[str, float] = OrderedDict()

    def _recent(self, key: str, now: float) -> list[float]:
        kept = [moment for moment in self._seen.get(key, []) if now - moment < self.window]
        if kept:
            self._seen[key] = kept
        else:
            self._seen.pop(key, None)
        return kept

    def refused(self, source: str, now: float | None = None) -> bool:
        with self._lock:
            return len(self._recent(source_key(source), now or time.monotonic())) >= self.limit

    def note(self, source: str, now: float | None = None) -> None:
        key = source_key(source)
        moment = now or time.monotonic()
        with self._lock:
            self._recent(key, moment)
            self._seen.setdefault(key, []).append(moment)
            self._seen.move_to_end(key)
            while len(self._seen) > self.remembered:
                self._seen.popitem(last=False)

    def first_refusal(self, source: str, now: float | None = None) -> bool:
        """True once per source and window, so a refusal is logged and not every repeat of it."""

        key = source_key(source)
        moment = now or time.monotonic()
        with self._lock:
            told = self._told.get(key)
            if told is not None and moment - told < self.window:
                return False
            self._told[key] = moment
            self._told.move_to_end(key)
            while len(self._told) > self.remembered:
                self._told.popitem(last=False)
            return True


FAILURES = Failures()

NOT_VALID = Refusal(
    401,
    "unauthorized",
    "The request needs a valid API token, sent as Authorization: Bearer <token>.",
    headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
)
TOO_MANY = Refusal(
    429,
    "rate_limited",
    "Too many requests with a token that is not valid; try again in a minute.",
    headers={"Retry-After": "60"},
)
BUSY = Refusal(
    429,
    "busy",
    "The manager is answering other API calls; try again in a second.",
    headers={"Retry-After": "1"},
)


def a_call_at_a_time(request: Request) -> Iterator[None]:
    """One of the API's `CONCURRENT_CALLS` places, held until the call is answered."""

    slots: threading.BoundedSemaphore = request.app.state.slots
    if not slots.acquire(blocking=False):
        logger.warning(
            "api: %s %s from %s refused: busy",
            request.method,
            request.url.path,
            client_address(request),
        )
        raise BUSY
    try:
        yield
    finally:
        slots.release()


def current_caller(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(BEARER),  # noqa: B008 - FastAPI's way
    _place: None = Depends(a_call_at_a_time),
) -> Caller:
    """The token this request carries, judged; a `Refusal` when it may not be used."""

    del credentials  # read below from the header itself, the one place it is parsed
    source = client_address(request)
    secret = api_tokens.bearer_secret(request.headers.get("authorization"))
    token = None
    if secret is not None:
        with request.app.state.pool.connection() as connection:
            token = db.api_token_by_hash(connection, api_tokens.secret_hash(secret))
            verdict = api_tokens.evaluate(token, now=datetime.now(UTC), source=source)
            if verdict.usable and token is not None:
                db.touch_api_token(connection, token.id, source)
                connection.commit()
                return Caller(issued=token, source=source)
    else:
        verdict = api_tokens.Verdict(
            False, "malformed" if request.headers.get("authorization") else "missing"
        )
    if FAILURES.refused(source):
        if FAILURES.first_refusal(source):
            logger.warning(
                "api: %s %s from %s refused: too many guesses, closed for a minute",
                request.method,
                request.url.path,
                source,
            )
        raise TOO_MANY
    if verdict.reason in GUESSES:
        FAILURES.note(source)
    logger.warning(
        "api: %s %s from %s refused: %s%s",
        request.method,
        request.url.path,
        source,
        verdict.reason,
        f" (token {token.name})" if token is not None else "",
    )
    raise NOT_VALID


class Needs:
    """A dependency: a caller whose token reaches `level`, or a 403.

    A class rather than a closure so the level can be read back off a route:
    `test_api_boundary` walks every route and asks each level of token.
    """

    def __init__(self, level: str) -> None:
        if level not in api_tokens.LEVELS:
            raise ValueError(level)
        self.level = level

    def __call__(self, caller: Caller = Depends(current_caller)) -> Caller:  # noqa: B008
        if not api_tokens.reaches(caller.issued.level, self.level):
            raise Refusal(
                403,
                "forbidden",
                f"This token's level ({caller.issued.level}) does not reach {self.level}.",
            )
        return caller


def needs(level: str) -> Needs:
    return Needs(level)


def in_scope(caller: Caller, cluster: str, item: str | None = None) -> None:
    """Refuse a cluster or object outside the token's scope, as if it were not there.

    404 rather than 403: a token limited to one cluster has no business
    learning which other clusters exist.
    """

    if not api_tokens.covers(caller.issued, cluster, item):
        raise Refusal(404, "not_found", "No such cluster or object.")
