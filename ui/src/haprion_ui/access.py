"""Who is asking and what they may do: the session, the write gate and the refusal (K01, review 2026-10-28).

Every signed-in page starts with `current_session`; every page that queues a
change passes `admin_write_gate` - signed in, writes on, an admin - and an
account whose role may not do something is answered with `forbidden_page`.

* **The client address comes from a header nginx overwrites**, never from one a
  client can contribute to. The site config sets `X-Forwarded-For` to the peer
  address rather than appending to it, so what arrives here is one address that
  a request cannot lie about. If it is missing or unparseable, the peer address
  is used and the request is still served - the throttle must not be the reason
  the interface stops working.
* **Every state-changing request carries a CSRF token**, including logout. A
  forced logout is a small attack, but an exception in the rule is how the rule
  stops being checkable.
* **The session cookie is set with every flag stated** rather than defaulted.
"""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime, timedelta

from fastapi import HTTPException, Request, Response
from fastapi.responses import (
    PlainTextResponse,
    RedirectResponse,
)

from haprion_ui import (
    auth,
    cluster_identity,
    db,
    features,
    metrics,
    oidc_web,
    update_check,
)
from haprion_ui.config import Config
from haprion_ui.db import AuthenticatedSession
from haprion_ui.reading import (
    listed_clusters,
)
from haprion_ui.templates import INSTALLED_VERSION, TEMPLATES, ZONE_COOKIE

#
# How stale the inactivity clock is allowed to get before it is written again.
# Without this every authenticated request would be a write, which turns a
# read-only page view into database traffic and contention on one row. A minute
# of imprecision against a ten-hour timeout is not a meaningful difference.
#
# Never more than half the inactivity timeout, though. The configuration allows
# a one-minute timeout, and with a one-minute touch the clock was written only
# after the session had already expired, so an active session was signed out
# (review 2026-09-28 F08).
#
TOUCH_AFTER = timedelta(minutes=1)


def touch_after(inactivity_minutes: int) -> timedelta:
    return min(TOUCH_AFTER, timedelta(minutes=inactivity_minutes) / 2)


def client_address(request: Request) -> str:
    """The address to hold responsible for this request.

    Taken from the forwarded header because the only thing that can connect to
    this process is nginx: it listens on a socket only root and nginx's workers
    may open (haprion-web.socket, review 2026-10-22, 5-8), and nginx overwrites
    the header. A socket has no peer address, and the one before it was
    `127.0.0.1` for every caller, which would put the entire internet in one
    throttle bucket.

    Validated as an address rather than trusted as a string. The column is
    `inet`, and a header that is not an address is a bug in whatever wrote it -
    it must not become its own quietly-unthrottled bucket.
    """

    forwarded = request.headers.get("x-forwarded-for", "")
    candidate = forwarded.split(",")[0].strip()
    if not candidate and request.client is not None:
        candidate = request.client.host
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return "127.0.0.1"


def set_session_cookie(
    response: Response, config: Config, token: str, expires_at: datetime
) -> None:
    """Set the session cookie, with every flag stated rather than defaulted.

    `SameSite=Lax` rather than `Strict`: Strict would drop the cookie when
    arriving from a link in a mail or a monitoring dashboard, which is a normal
    way to reach an operations interface, and Lax already withholds it from
    cross-site form posts - the case that matters.
    """

    response.set_cookie(
        auth.SESSION_COOKIE,
        token,
        max_age=int((expires_at - datetime.now(UTC)).total_seconds()),
        httponly=True,
        secure=config.session.cookie_secure,
        samesite="lax",
        path="/",
    )


def current_session(request: Request) -> AuthenticatedSession | None:
    """Who is calling, if anyone. Reads; decides nothing.

    Returns None for every failure - absent, unknown, expired, revoked, disabled
    - because from a handler's point of view those are one state: not signed in.
    The distinction is kept where it is useful, in the audit trail.
    """

    #
    # The reader's clock is set here because this is the one call every signed-in
    # page makes before it formats a time: the browser's own zone, which zone.js
    # keeps in a cookie (B190), and the host's until it has.
    #
    metrics.read_in(request.cookies.get(ZONE_COOKIE))
    token = request.cookies.get(auth.SESSION_COOKIE)
    if not token:
        return None
    config: Config = request.app.state.config
    digest = auth.token_hash(token)

    with request.app.state.pool.connection() as connection:
        session = db.session_by_hash(connection, digest)
        verdict = auth.evaluate_session(session, config.session)
        if not verdict.usable or session is None:
            return None
        oidc_web.note_session(session.source)
        #
        # The inactivity clock is moved forward in its own transaction, after
        # the read, and only when it has actually gone stale.
        #
        if datetime.now(UTC) - session.last_seen_at > touch_after(
            config.session.inactivity_minutes
        ):
            db.touch_session(connection, digest)
            connection.commit()
        #
        # What this installation has turned off, for the menu and the pages
        # alike (B193). Beside the clock for the same reason: every signed-in
        # page passes through here before it draws anything.
        #
        features.read_in(db.feature_switches(connection))
        #
        # A newer release for the header (B342), read only while the check is
        # on: off, it costs the page nothing.
        #
        update_check.read_in(
            db.update_check(connection) if features.is_on(features.UPDATE_CHECK) else None,
            on=features.is_on(features.UPDATE_CHECK),
            installed=INSTALLED_VERSION,
        )
    #
    # The clusters' colours follow the order they are listed in, and go when
    # the switch is off or there are more than the colours (B204).
    #
    cluster_identity.read_in(
        listed_clusters(request, config), on=features.is_on(features.CLUSTER_COLOURS)
    )
    return session


def hidden_by_a_switch(request: Request) -> None:
    """Answer 404 for a page a switched-off feature hides (B193).

    A dependency of the whole router, so no handler under a hidden path can be
    reached by a URL somebody kept - not the page, not a form's POST. The
    switches are read only for those paths; every other request costs nothing.
    """

    path = request.url.path
    if not any(
        path == prefix or path.startswith(f"{prefix}/") for prefix, _ in features.HIDDEN_PATHS
    ):
        return
    with request.app.state.pool.connection() as connection:
        features.read_in(db.feature_switches(connection))
    if features.hiding(path):
        raise HTTPException(status_code=404, detail="Not found")


def admin_write_gate(config: Config, request: Request) -> AuthenticatedSession | Response:
    """Signed in, writes on, and an admin - every page that queues a change.

    Named for certificate deletion once, its first user; the backup and
    restore pages were gated by a name that said otherwise.
    """

    session = current_session(request)
    if session is None:
        return RedirectResponse("/login", status_code=303)
    if not config.management_writes:
        return PlainTextResponse("Not found", status_code=404)
    if session.role != "admin":
        return forbidden_page(request, config)
    return session


def forbidden_page(request: Request, config: Config) -> Response:
    """What this account's role may not open or do, as a page with the menu (review 26-10-22, 2-8).

    A page for what a browser sends - a page asked for, a form posted - and the
    plain answer it had before for anything else, by the rule the framework's
    own refusals follow (CR-06): a script reading JSON is not given HTML.
    """

    kind = request.headers.get("content-type", "")
    if request.method != "GET" and not kind.startswith(
        ("application/x-www-form-urlencoded", "multipart/form-data")
    ):
        return PlainTextResponse("Refused", status_code=403)
    session = current_session(request)
    if session is None:
        return RedirectResponse("/login", status_code=303)
    token = request.cookies.get(auth.SESSION_COOKIE, "")
    return TEMPLATES.TemplateResponse(
        request,
        "forbidden.html",
        {
            "username": session.username,
            "role": session.role,
            "management_writes": config.management_writes,
            "csrf_token": auth.csrf_token(token),
            "section": "",
            "demo_fixture": config.demo_fixture,
        },
        status_code=403,
    )
