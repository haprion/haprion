"""The pages that answer a request that cannot go on (K01, review 2026-10-28).

A refusal with the menu and a way back, a conflict said as what happened, a
page that is not there, a database that is not answering, a form the
framework could not read. A browser gets a page; a script reading JSON keeps
the plain answer it asked for.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from typing import Any
from urllib.parse import urlsplit

import psycopg
from fastapi import Request, Response
from fastapi.responses import (
    PlainTextResponse,
    RedirectResponse,
)

from haprion_ui import (
    auth,
    db,
)
from haprion_ui.access import current_session
from haprion_ui.config import Config
from haprion_ui.templates import TEMPLATES

logger = logging.getLogger("haprion_ui")

#
# The page a refusal sends back to, by the first segment of its path: the
# menu's own name for it, and the menu entry to mark. The button read the raw
# path - "Open certificates?view=registry&open=x fresh" - and the menu marked
# nothing (review 26-10-24, 12-07).
#
BACK_PLACES = {
    "": ("dashboard", "the dashboard"),
    "history": ("history", "Versions"),
    "proxies": ("proxies", "Proxies"),
    "certificates": ("certificates", "Certificates"),
    "metrics": ("metrics", "Metrics"),
    "logs": ("logs", "Traffic logs"),
    "waf": ("waf", "WAF logs"),
    "network": ("network", "Network"),
    "backups": ("backups", "Node backups"),
    "jobs": ("jobs", "Events"),
    "settings": ("settings", "Settings"),
    "first-cluster": ("", "the first cluster guide"),
    "dns-profiles": ("certificates", "DNS profiles"),
    "ndes-profiles": ("certificates", "NDES profiles"),
    "clusters": ("metrics", "Metrics"),
    "account": ("", "Change password"),
    "search": ("", "Search"),
}


def back_place(back: str) -> tuple[str, str]:
    """The menu section and the name of the page `back` leads to."""

    path = back.split("?", 1)[0].split("#", 1)[0]
    return BACK_PLACES.get(path.lstrip("/").split("/", 1)[0], ("", "the page"))


def refusal_page(
    request: Request,
    config: Config,
    message: str,
    *,
    back: str,
    stale: bool = False,
    saved: bool = False,
    status_code: int = 400,
) -> Response:
    """A refusal a person met mid-form, drawn inside the interface's own chrome.

    Module level so the editor can reach it as well as the closure that queues
    operations. The message is the caller's sentence and never an echo of what
    was typed - the same rule the network form's refusals follow, and for the
    same reason.

    `stale` is for the one refusal where going back is the wrong move. Most
    refusals are about what was typed, and the browser's back button returns to
    the form with it still in place. A draft conflict is not about what was
    typed at all: the form is holding a revision that has since moved, and
    going back submits that same revision again for the same refusal. The page
    said "go back" to everybody, which made the one case it could not help the
    one it advised most confidently.

    `saved` is for the refusals that come after the draft was stored. The page
    said "Nothing was written" above a message saying the draft was saved, and
    only one of the two was true (review 2026-09-28 F05).
    """

    session = current_session(request)
    if session is None:
        return RedirectResponse("/login", status_code=303)
    token = request.cookies.get(auth.SESSION_COOKIE, "")
    section, back_label = back_place(back)
    return TEMPLATES.TemplateResponse(
        request,
        "refusal.html",
        {
            "username": session.username,
            "role": session.role,
            "management_writes": config.management_writes,
            "csrf_token": auth.csrf_token(token),
            "message": message,
            "stale": stale,
            "saved": saved,
            "back": back,
            "back_label": back_label,
            "section": section,
            "demo_fixture": config.demo_fixture,
        },
        status_code=status_code,
    )


#
# The one sentence each refusal of the queue or the drafts is answered with,
# wherever it is met (review 26-10-24, 07-02). A draft's conflict carries its
# own sentence, which names the draft.
#
CONFLICT_SENTENCES: dict[type[Exception], str] = {
    db.ClusterBusy: "This cluster is already running a job. Try again when it has finished.",
    db.CertificateBusy: (
        "A certificate job is already running. Wait for it to finish, then try again."
    ),
    db.RequestConflict: (
        "This form was already sent for something else. Reload the page and try again."
    ),
}


def _from_a_browser(request: Request) -> bool:
    """A page asked for or a form posted: what is answered with a page (CR-06)."""

    kind = request.headers.get("content-type", "")
    return request.method in ("GET", "HEAD") or kind.startswith(
        ("application/x-www-form-urlencoded", "multipart/form-data")
    )


def _page_it_came_from(request: Request) -> str:
    """The path of the page the request was sent from, when it is one of ours; else `/`."""

    referer = urlsplit(request.headers.get("referer", ""))
    if referer.netloc and referer.netloc != request.url.netloc:
        return "/"
    path = referer.path
    if not path.startswith("/") or path.startswith("//"):
        return "/"
    return path


def conflict_page(request: Request, config: Config, exc: Exception) -> Response:
    """A job or a draft refused because of another, said as a page wherever it is met.

    Five forms of the same refusal - bare text, a page, a redirect with a
    query, a form drawn again, JSON - became one (review 26-10-24, 07-02).
    The routes that do something of their own first, such as answering a
    second click with the job the first one queued, still catch it.
    """

    stale = isinstance(exc, db.DraftConflict)
    message = str(exc) if stale else CONFLICT_SENTENCES[type(exc)]
    if not _from_a_browser(request):
        return PlainTextResponse(message, status_code=409)
    return refusal_page(
        request,
        config,
        message,
        back=_page_it_came_from(request),
        stale=stale,
        status_code=409,
    )


def not_found_page(request: Request, config: Config) -> Response | None:
    """A page that is not there, inside the interface; None where the framework answers.

    A bookmarked page behind a feature turned off answered `{"detail":
    "Not found"}` (review 26-10-24, 07-02). Only for somebody signed in: the
    pages say nothing to anybody else.
    """

    if not _from_a_browser(request):
        return None
    session = current_session(request)
    if session is None:
        return None
    token = request.cookies.get(auth.SESSION_COOKIE, "")
    return TEMPLATES.TemplateResponse(
        request,
        "not-found.html",
        {
            "username": session.username,
            "role": session.role,
            "management_writes": config.management_writes,
            "csrf_token": auth.csrf_token(token),
            "section": "",
            "demo_fixture": config.demo_fixture,
        },
        status_code=404,
    )


def database_unavailable(request: Request, exc: Exception) -> Response:
    """A request the database could not answer, said as a page (review 2026-10-20, U2).

    It was a bare 500 with no way on. The page reads nothing: the session, the
    switches and the header's clusters are all database reads, and the
    database is what failed. A query the server's `statement_timeout` stopped
    says so, since a narrower filter is then the way on. The error itself goes
    to the log, never to the page.
    """

    slow = isinstance(exc, psycopg.errors.QueryCanceled)
    logger.warning("%s %s: the database did not answer: %s", request.method, request.url.path, exc)
    posted = request.method != "GET"
    return TEMPLATES.TemplateResponse(
        request,
        "unavailable.html",
        {"slow": slow, "posted": posted, "again": "/" if posted else str(request.url)},
        status_code=503,
    )


def form_refusal(request: Request, config: Config, errors: Sequence[Any]) -> Response:
    """A form the framework could not read, said as a page rather than as JSON (CR-06).

    A field longer than its limit - three hundred server lines - answered with
    pydantic's error object and no way back. What was typed is not repeated: the
    page names the field and the limit, and the browser's back button returns to
    the form as it was.

    No `maxlength` on the form instead: a browser cuts pasted text at it without
    a word, and a server list cut mid-line can end in an address that is valid
    and wrong.
    """

    sentences: list[str] = []
    for error in errors:
        location = error.get("loc", ()) if isinstance(error, Mapping) else ()
        field = str(location[-1]) if location else "a field"
        label = field.replace("_", " ").capitalize()
        context = error.get("ctx") or {}
        if error.get("type") == "string_too_long" and "max_length" in context:
            sentences.append(f"{label} is longer than {context['max_length']:,} characters.")
        else:
            sentences.append(f"{label} could not be read.")
    message = " ".join(dict.fromkeys(sentences)) + " Nothing was saved; go back to correct it."
    return refusal_page(request, config, message, back=request.url.path)
