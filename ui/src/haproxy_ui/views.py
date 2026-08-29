"""The request-facing half of authentication: cookies, forms and redirects.

The rules that shape every handler below:

* **The client address comes from a header nginx overwrites**, never from one a
  client can contribute to. The site config sets `X-Forwarded-For` to the peer
  address rather than appending to it, so what arrives here is one address that
  a request cannot lie about. If it is missing or unparseable, the peer address
  is used and the request is still served - the throttle must not be the reason
  the interface stops working.
* **Failures say one thing.** Unknown account, wrong password, disabled account
  and a throttled address all render the same sentence. Anything else turns the
  form into a way to learn which usernames exist and which are locked.
* **Every state-changing request carries a CSRF token**, including logout. A
  forced logout is a small attack, but an exception in the rule is how the rule
  stops being checkable.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from haproxy_ui import activity, auth, dashboard, db, demo, history, proxies, snapshot
from haproxy_ui.config import Config
from haproxy_ui.db import AuthenticatedSession

TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

#
# How stale the inactivity clock is allowed to get before it is written again.
# Without this every authenticated request would be a write, which turns a
# read-only page view into database traffic and contention on one row. A minute
# of imprecision against a ten-hour timeout is not a meaningful difference.
#
TOUCH_AFTER = timedelta(minutes=1)

SIGN_IN_FAILED = "Sign-in failed. Check the username and password and try again."


@dataclass(frozen=True, slots=True)
class Source:
    """Where one kind of cached reading comes from, in each of the three modes.

    A page must never choose its own source: development can be showing the
    synthetic fixture or an operator-made production snapshot, and a view that
    reached the database directly would quietly show real rows on a page
    labelled as fixture data. Stated once, per kind of reading, so a new page
    picks a source rather than inventing one.
    """

    demo_rows: Callable[[], Iterable[Any]]
    snapshot_rows: Callable[[snapshot.ProductionSnapshot], Iterable[Any]]
    cached_rows: Callable[[Any], Iterable[Any]]


#
# The cached readers are wrapped rather than referenced, so the lookup happens
# when the page is rendered. Binding `db.cluster_statuses` here would capture the
# function at import and quietly ignore a test that replaces it.
#
STATUS_SOURCE = Source(
    demo.status_rows,
    lambda taken: taken.status_rows,
    lambda connection: db.cluster_statuses(connection),
)
INVENTORY_SOURCE = Source(
    demo.inventory_rows,
    lambda taken: taken.inventory_rows,
    lambda connection: db.cluster_inventories(connection),
)
HISTORY_SOURCE = Source(
    demo.history_rows,
    lambda taken: taken.history_rows,
    lambda connection: db.cluster_histories(connection),
)


def read_source(
    request: Request, config: Config, source: Source
) -> tuple[tuple[str, ...], Iterable[Any]]:
    """The clusters to render and their newest readings, from the active mode."""

    if config.demo_fixture:
        return demo.CLUSTERS, source.demo_rows()
    if config.production_snapshot:
        captured = snapshot.load_production_snapshot(
            snapshot.path_for_config(request.app.state.config_path)
        )
        return captured.clusters, source.snapshot_rows(captured)
    with request.app.state.pool.connection() as connection:
        return config.clusters, source.cached_rows(connection)


def client_address(request: Request) -> str:
    """The address to hold responsible for this request.

    Taken from the forwarded header because the only thing that connects to this
    process is nginx on loopback; the peer address would otherwise be
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


def _cookie(response: Response, config: Config, token: str, expires_at: datetime) -> None:
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
        #
        # The inactivity clock is moved forward in its own transaction, after
        # the read, and only when it has actually gone stale.
        #
        if datetime.now(UTC) - session.last_seen_at > TOUCH_AFTER:
            db.touch_session(connection, digest)
            connection.commit()
    return session


def require_session(request: Request) -> AuthenticatedSession:
    """A dependency for anything that must not be reachable while signed out.

    Raised rather than returned, because a dependency cannot redirect: a 303
    with a Location header is how a browser gets sent to the form, and how an
    HTMX request gets an answer it can follow rather than a page fragment where
    content was expected.
    """

    session = current_session(request)
    if session is None:
        raise HTTPException(status_code=303, headers={"Location": "/login"})
    return session


def build_router(config: Config) -> APIRouter:
    router = APIRouter()

    @router.get("/", response_class=HTMLResponse)
    def index(request: Request) -> Response:
        session = current_session(request)
        if session is None:
            return RedirectResponse("/login", status_code=303)
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        clusters, status_rows = read_source(request, config, STATUS_SOURCE)
        dashboard_view = dashboard.build_dashboard(
            clusters,
            status_rows,
            stale_after=timedelta(seconds=config.poller.interval_seconds * 2),
        )
        return TEMPLATES.TemplateResponse(
            request,
            "index.html",
            {
                "username": session.username,
                "role": session.role,
                "management_writes": config.management_writes,
                "csrf_token": auth.csrf_token(token),
                "dashboard": dashboard_view,
                "section": "dashboard",
                "demo_fixture": config.demo_fixture,
                "production_snapshot": config.production_snapshot,
            },
        )

    @router.get("/proxies", response_class=HTMLResponse)
    def proxy_overview(request: Request) -> Response:
        session = current_session(request)
        if session is None:
            return RedirectResponse("/login", status_code=303)
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        clusters, inventory_rows = read_source(request, config, INVENTORY_SOURCE)
        overview = proxies.build_proxy_overview(
            clusters,
            inventory_rows,
            stale_after=timedelta(seconds=config.poller.interval_seconds * 2),
        )
        return TEMPLATES.TemplateResponse(
            request,
            "proxies.html",
            {
                "username": session.username,
                "role": session.role,
                "csrf_token": auth.csrf_token(token),
                "proxies": overview,
                "section": "proxies",
                "demo_fixture": config.demo_fixture,
                "production_snapshot": config.production_snapshot,
            },
        )

    @router.get("/history", response_class=HTMLResponse)
    def version_history(request: Request) -> Response:
        session = current_session(request)
        if session is None:
            return RedirectResponse("/login", status_code=303)
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        clusters, history_rows = read_source(request, config, HISTORY_SOURCE)
        overview = history.build_history_overview(
            clusters,
            history_rows,
            stale_after=timedelta(seconds=config.poller.interval_seconds * 2),
        )
        return TEMPLATES.TemplateResponse(
            request,
            "history.html",
            {
                "username": session.username,
                "role": session.role,
                "csrf_token": auth.csrf_token(token),
                "history": overview,
                "section": "history",
                "demo_fixture": config.demo_fixture,
                "production_snapshot": config.production_snapshot,
            },
        )

    @router.get("/activity", response_class=HTMLResponse)
    def latest_activity(request: Request) -> Response:
        session = current_session(request)
        if session is None:
            return RedirectResponse("/login", status_code=303)
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        clusters, status_rows = read_source(request, config, STATUS_SOURCE)
        current = dashboard.build_dashboard(
            clusters,
            status_rows,
            stale_after=timedelta(seconds=config.poller.interval_seconds * 2),
        )
        return TEMPLATES.TemplateResponse(
            request,
            "activity.html",
            {
                "username": session.username,
                "role": session.role,
                "csrf_token": auth.csrf_token(token),
                "activity": activity.build_activity(current),
                "section": "activity",
                "demo_fixture": config.demo_fixture,
                "production_snapshot": config.production_snapshot,
            },
        )

    @router.get("/login", response_class=HTMLResponse)
    def login_form(request: Request) -> Response:
        if current_session(request) is not None:
            return RedirectResponse("/", status_code=303)
        #
        # A token is needed to protect the login post itself, and there is no
        # session to derive one from yet. A short-lived cookie carries one, set
        # here and replaced by the real session cookie on success.
        #
        pre_token = auth.new_session_token()
        response: Response = TEMPLATES.TemplateResponse(
            request,
            "login.html",
            {"error": None, "csrf_token": auth.csrf_token(pre_token)},
        )
        response.set_cookie(
            auth.PRE_SESSION_COOKIE,
            pre_token,
            max_age=600,
            httponly=True,
            secure=config.session.cookie_secure,
            samesite="lax",
            path="/login",
        )
        return response

    @router.post("/login", response_class=HTMLResponse)
    def login(
        request: Request,
        username: str = Form(default="", max_length=64),
        password: str = Form(default="", max_length=auth.MAX_PASSWORD_BYTES),
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        pre_token = request.cookies.get(auth.PRE_SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(pre_token, csrf_token):
            #
            # Not an error page. A stale form is the ordinary cause - the tab was
            # open longer than the pre-session cookie lived - and the useful
            # answer is a fresh form, not a diagnosis.
            #
            return _login_again(request, config)

        address = client_address(request)
        with request.app.state.pool.connection() as connection:
            failures = db.failures_since_last_success(
                connection,
                username=username,
                client_ip=address,
                window_minutes=config.throttle.window_minutes,
            )
            throttled = failures >= config.throttle.max_failures

            account = None if throttled else db.account_by_username(connection, username)
            if account is None or account.disabled:
                #
                # The same time is spent whether the account is missing,
                # disabled or throttled, so the three cannot be told apart from
                # outside.
                #
                auth.burn_absent_user_time(password)
                accepted = False
            else:
                accepted = auth.verify_password(account.password_hash, password)

            db.record_login_attempt(
                connection, username=username or "?", client_ip=address, succeeded=accepted
            )
            if not accepted:
                db.record_audit_event(
                    connection,
                    actor=username or None,
                    action="login_failed",
                    detail={
                        "client_ip": address,
                        "reason": "throttled" if throttled else "rejected",
                    },
                )
                connection.commit()
                return _login_again(request, config, error=SIGN_IN_FAILED)

            assert account is not None  # noqa: S101 - accepted implies an account was found
            #
            # A new token on every login, which is what makes the rotation
            # requirement real: nothing a browser held before signing in is
            # still valid afterwards.
            #
            token = auth.new_session_token()
            expires_at = auth.absolute_expiry(config.session)
            db.create_session(
                connection,
                token_hash=auth.token_hash(token),
                user_id=account.id,
                expires_at=expires_at,
            )
            db.record_audit_event(
                connection,
                actor=account.username,
                action="login",
                detail={"client_ip": address, "role": account.role},
            )
            connection.commit()

        response = RedirectResponse("/", status_code=303)
        _cookie(response, config, token, expires_at)
        response.delete_cookie(auth.PRE_SESSION_COOKIE, path="/login")
        return response

    @router.post("/logout")
    def logout(
        request: Request,
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        response = RedirectResponse("/login", status_code=303)
        if not token or not auth.csrf_token_is_valid(token, csrf_token):
            return response

        with request.app.state.pool.connection() as connection:
            digest = auth.token_hash(token)
            session = db.session_by_hash(connection, digest)
            db.revoke_session(connection, digest)
            db.record_audit_event(
                connection,
                actor=session.username if session else None,
                action="logout",
                detail={"client_ip": client_address(request)},
            )
            connection.commit()
        response.delete_cookie(auth.SESSION_COOKIE, path="/")
        return response

    return router


def _login_again(request: Request, config: Config, *, error: str | None = None) -> Response:
    """Render a fresh login form, with a fresh token to post it with."""

    pre_token = auth.new_session_token()
    response: Response = TEMPLATES.TemplateResponse(
        request,
        "login.html",
        {"error": error, "csrf_token": auth.csrf_token(pre_token)},
        status_code=401 if error else 200,
    )
    response.set_cookie(
        auth.PRE_SESSION_COOKIE,
        pre_token,
        max_age=600,
        httponly=True,
        secure=config.session.cookie_secure,
        samesite="lax",
        path="/login",
    )
    return response
