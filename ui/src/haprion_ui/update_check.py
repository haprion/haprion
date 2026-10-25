"""Whether a newer release exists (B334, B342): asked of GitHub by the poller, said by the header.

The one thing the application fetches from the internet while it runs, so it
is behind a switch that is off until somebody turns it on. The poller asks the
project's repository for its latest release at most once a day; when GitHub
does not answer, the last answer stands and the poller asks again an hour
later, until it answers. Nothing about it is ever on *Needs attention*: an
installation that cannot reach GitHub is not broken.

No proxy: the ask goes straight out, as the manager's own network allows.

The ask runs on a thread of its own, one at a time (review 2026-10-20, A1):
GitHub answering a byte at a time, or a name that does not resolve, must not
hold up the clusters' readings, which the same pass makes.

The web never asks. It reads the row and draws `vX available` beside the
version in the header when the release is newer than the one running.
"""

from __future__ import annotations

import http.client
import json
import logging
import re
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from haprion_ui import db

logger = logging.getLogger(__name__)

SWITCH = "update_check"
URL = "https://api.github.com/repos/haprion/haprion/releases/latest"
#
# The answer with its assets measured 23 KB (26-10-20). A body past this is not
# an answer about one release.
#
MAX_BYTES = 1024 * 1024
TIMEOUT_SECONDS = 10
EVERY = timedelta(days=1)
RETRY = timedelta(hours=1)

TAG = re.compile(r"v(\d{1,4})\.(\d{1,4})\.(\d{1,4})")
#
# The header links to what this names, so it is held to the release page of the
# project's own repository - the table's constraint says the same.
#
RELEASE_PAGE = re.compile(r"https://github\.com/haprion/haprion/releases/tag/v[0-9.]{5,14}")


class NoAnswer(Exception):
    """GitHub did not give an answer this can use; the message says why."""


@dataclass(frozen=True, slots=True)
class Release:
    tag: str
    url: str


def parse(body: bytes) -> Release:
    """The release in GitHub's answer, or NoAnswer for anything else."""

    try:
        document = json.loads(body)
    except ValueError as exc:
        raise NoAnswer("the answer is not JSON") from exc
    if not isinstance(document, dict):
        raise NoAnswer("the answer is not a release")
    tag, url = document.get("tag_name"), document.get("html_url")
    if not isinstance(tag, str) or TAG.fullmatch(tag) is None:
        raise NoAnswer("the release's tag is not a version")
    if not isinstance(url, str) or RELEASE_PAGE.fullmatch(url) is None:
        raise NoAnswer("the release's page is not on the project's repository")
    return Release(tag=tag, url=url)


def fetch(installed: str, *, url: str = URL) -> bytes:
    """GitHub's answer, bounded in size and time. Raises NoAnswer.

    The socket's timeout bounds each read, not the answer: one sent a byte at a
    time would never trip it. So the body is read in pieces against a deadline
    for the whole answer, which one stalled read can overrun by its own timeout.
    """

    deadline = time.monotonic() + TIMEOUT_SECONDS
    request = urllib.request.Request(  # noqa: S310 - a fixed https address
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": f"haprion/{installed}",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:  # noqa: S310 - fixed https address
            body = _read_by(response, deadline)
    except urllib.error.HTTPError as exc:
        raise NoAnswer(f"GitHub answered {exc.code}") from exc
    except (urllib.error.URLError, OSError, http.client.HTTPException) as exc:
        #
        # A broken answer - cut short, or no status line - is no answer too.
        # It was not recorded as a failure, so the check stayed due and asked
        # again on every pass (review 26-10-24, 07-08).
        #
        raise NoAnswer(f"GitHub could not be reached: {exc}") from exc
    if len(body) > MAX_BYTES:
        raise NoAnswer("the answer is larger than one release")
    return body


def _read_by(response: Any, deadline: float) -> bytes:
    body = bytearray()
    while len(body) <= MAX_BYTES:
        if time.monotonic() >= deadline:
            raise NoAnswer(f"GitHub took longer than {TIMEOUT_SECONDS} s to answer")
        piece: bytes = response.read1(MAX_BYTES + 1 - len(body))
        if not piece:
            break
        body += piece
    return bytes(body)


def version_of(text: str) -> tuple[int, int, int] | None:
    """`v0.9.2` or `0.9.2` (with anything after it, as a package's local version) as numbers."""

    match = re.match(r"v?(\d{1,4})\.(\d{1,4})\.(\d{1,4})", text)
    return (int(match[1]), int(match[2]), int(match[3])) if match else None


def newer(installed: str, tag: str) -> bool:
    running, latest = version_of(installed), version_of(tag)
    return running is not None and latest is not None and latest > running


def due(row: db.UpdateCheck | None, now: datetime) -> bool:
    """Whether to ask now: never asked, an answer a day old, or a failure an hour old."""

    if row is None:
        return True
    if row.failing_since is not None or row.checked_at is None:
        return now - row.attempted_at >= RETRY
    return now - row.checked_at >= EVERY


def check(
    pool: Any,
    *,
    installed: str,
    now: datetime,
    ask: Callable[[str], bytes] = fetch,
) -> None:
    """One pass's turn: ask GitHub when the switch is on and it is due. Never raises."""

    try:
        with pool.connection() as connection:
            if not db.switch_enabled(connection, SWITCH):
                return
            if not due(db.update_check(connection), now):
                return
        try:
            release = parse(ask(installed))
        except NoAnswer as exc:
            logger.warning("update check: %s", exc)
            with pool.connection() as connection:
                db.record_update_failure(connection, error=str(exc), at=now)
                connection.commit()
            return
        with pool.connection() as connection:
            db.record_update_answer(connection, tag=release.tag, url=release.url, at=now)
            connection.commit()
        logger.info("update check: the latest release is %s", release.tag)
    except Exception as exc:  # noqa: BLE001 - a cluster's readings must still be made
        logger.warning("update check not recorded: %s", exc)


class Asker:
    """The poller's way to `check`: on a thread, never more than one at a time.

    A pass starts it and goes on to the clusters. A pass that finds the last ask
    still waiting on GitHub starts none, so threads cannot pile up behind a
    network that swallows them.
    """

    def __init__(self) -> None:
        self._thread: threading.Thread | None = None

    def start(
        self,
        pool: Any,
        *,
        installed: str,
        now: datetime,
        ask: Callable[[str], bytes] = fetch,
    ) -> bool:
        if self._thread is not None and self._thread.is_alive():
            return False
        self._thread = threading.Thread(
            target=check,
            args=(pool,),
            kwargs={"installed": installed, "now": now, "ask": ask},
            name="update-check",
            daemon=True,
        )
        self._thread.start()
        return True

    def join(self, timeout: float | None = None) -> None:
        if self._thread is not None:
            self._thread.join(timeout)


@dataclass(frozen=True, slots=True)
class Available:
    """A newer release, as the header links to it."""

    tag: str
    url: str


def available(row: db.UpdateCheck | None, *, on: bool, installed: str) -> Available | None:
    if not on or row is None or row.latest_tag is None or row.latest_url is None:
        return None
    if not newer(installed, row.latest_tag):
        return None
    return Available(tag=row.latest_tag, url=row.latest_url)


def detail(row: db.UpdateCheck | None, *, on: bool, shown: Callable[[datetime], str]) -> str:
    """What the switch's row says beside its name."""

    if not on or row is None:
        return ""
    if row.failing_since is not None:
        return f"GitHub has not answered since {shown(row.failing_since)}"
    if row.checked_at is not None:
        return f"Last checked {shown(row.checked_at)}"
    return ""


#
# This request's answer for the header, read beside the switches (B342). Unset
# on every page outside a session - the login page draws no release news.
#
_AVAILABLE: ContextVar[Available | None] = ContextVar("update_available", default=None)


def read_in(row: db.UpdateCheck | None, *, on: bool, installed: str) -> None:
    _AVAILABLE.set(available(row, on=on, installed=installed))


def header() -> Available | None:
    return _AVAILABLE.get()
