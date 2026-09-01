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

import hashlib
import ipaddress
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from fastapi import APIRouter, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from haproxy_ui import (
    activity,
    auth,
    backups,
    certificates,
    dashboard,
    db,
    demo,
    history,
    jobs,
    operations,
    proxies,
    snapshot,
)
from haproxy_ui import preview as preview_module
from haproxy_ui.config import Config
from haproxy_ui.db import AuthenticatedSession

TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

#
# A multi-select arrives as repeated fields, so its default has to be a list -
# and a list built in an argument default would be one list shared by every
# request. Named here so there is exactly one, and it is never mutated.
#
NETWORK_SELECTION = Form(default=[])

STATIC_DIRECTORY = Path(__file__).parent / "static"


def asset_token(directory: Path = STATIC_DIRECTORY) -> str:
    """A short token that changes whenever a local asset does.

    Without it a stylesheet change is invisible until every reader empties a
    cache they have no reason to suspect - and worse, it is invisible
    *selectively*: the new markup arrives with the old CSS, which looks like a
    layout bug in the new page rather than like a stale file. That happened
    once; this is the fix that keeps it from happening again.

    Computed from size and modification time rather than from file contents:
    a release is a fresh directory of files, so the two move together, and this
    reads no bytes on a path that runs at startup.
    """

    digest = hashlib.sha256()
    try:
        for path in sorted(directory.iterdir()):
            if path.is_file():
                stat = path.stat()
                digest.update(f"{path.name}:{stat.st_size}:{stat.st_mtime_ns}".encode())
    except OSError:
        # A missing static directory is a deployment fault that the mount will
        # report; it must not stop a page from rendering its own diagnosis.
        return "0"
    return digest.hexdigest()[:12]


#
# Resolved once, at import. The files cannot change under a running release -
# a release directory is read-only and a new one is a new process.
#
TEMPLATES.env.globals["asset_token"] = asset_token()
TEMPLATES.env.globals["new_request_key"] = lambda: str(uuid4())

#
# The theme is rendered into the document by the server, from a cookie the
# browser maintains. It has to be known before the first byte: a theme applied
# by script is applied after the first paint at the earliest, and between two
# documents the browser paints its own light canvas - a flash on every
# navigation, and every tab here is a full page load.
#
THEME_COOKIE = "haproxy_ui_theme"
THEMES = ("light", "dark")


def selected_theme(request: Request) -> str:
    """Return the requested theme, or the default for anything else.

    The value is written by client-side script and is therefore attacker
    controlled. It reaches an HTML attribute, so it is matched against the
    themes that exist rather than escaped and passed through.
    """
    theme = request.cookies.get(THEME_COOKIE, "")
    return theme if theme in THEMES else THEMES[0]


TEMPLATES.env.filters["selected_theme"] = selected_theme


def snapshot_age(captured_at: datetime | None) -> str:
    """How old the snapshot is, or empty for a mode that has no snapshot.

    Stated once, next to the badge that already says the page is showing one.
    Per-cluster freshness is measured against the capture, so this is the only
    place the wall clock appears in snapshot mode - and it is the only place it
    means anything, because it is the only number the operator can act on.
    """

    if captured_at is None:
        return ""
    return dashboard.relative_age(captured_at, datetime.now(UTC))


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
BACKUP_SOURCE = Source(
    demo.backup_rows,
    lambda taken: taken.backup_rows,
    lambda connection: db.cluster_backups(connection),
)
CERTIFICATE_SOURCE = Source(
    demo.certificate_rows,
    lambda taken: taken.certificate_rows,
    lambda connection: db.cluster_certificates(connection),
)


def read_source(
    request: Request, config: Config, source: Source
) -> tuple[tuple[str, ...], Iterable[Any], datetime | None]:
    """The clusters to render, their newest readings, and the clock to judge them by.

    The third value is the moment the readings describe, and it is set only for
    a snapshot. A snapshot is deliberately static, so measured against the wall
    clock every reading in it goes stale two poll intervals after it was taken,
    on every page, forever. That is formally true and useless: a badge that is
    always lit teaches the reader to stop seeing it, and it would be lit for the
    one thing the reader cannot act on - dev cannot poll production.

    Measured against the capture instead, the badge says what it says everywhere
    else: whether production's own readings were current when they were taken.
    The age of the snapshot is a separate fact, and the page states it beside
    the mode badge rather than smearing it across every cluster.
    """

    if config.demo_fixture:
        # The fixture times its readings from the moment it is read, so it needs
        # no clock of its own; it is never stale.
        return demo.CLUSTERS, source.demo_rows(), None
    if config.production_snapshot:
        captured = snapshot.load_production_snapshot(
            snapshot.path_for_config(request.app.state.config_path)
        )
        return captured.clusters, source.snapshot_rows(captured), captured.captured_at
    with request.app.state.pool.connection() as connection:
        return config.clusters, source.cached_rows(connection), None


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
        clusters, status_rows, captured_at = read_source(request, config, STATUS_SOURCE)
        dashboard_view = dashboard.build_dashboard(
            clusters,
            status_rows,
            now=captured_at,
            stale_after=timedelta(seconds=config.poller.interval_seconds * 2),
            #
            # The snapshot's readings describe the instant it was taken, so
            # the freshness line says that rather than claiming the wall
            # clock. Staleness is still judged the same way.
            #
            captured=captured_at is not None,
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
                "snapshot_age": snapshot_age(captured_at),
            },
        )

    @router.get("/proxies", response_class=HTMLResponse)
    def proxy_overview(request: Request) -> Response:
        session = current_session(request)
        if session is None:
            return RedirectResponse("/login", status_code=303)
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        clusters, inventory_rows, captured_at = read_source(request, config, INVENTORY_SOURCE)
        overview = proxies.build_proxy_overview(
            clusters,
            inventory_rows,
            now=captured_at,
            stale_after=timedelta(seconds=config.poller.interval_seconds * 2),
            #
            # The snapshot's readings describe the instant it was taken, so
            # the freshness line says that rather than claiming the wall
            # clock. Staleness is still judged the same way.
            #
            captured=captured_at is not None,
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
                "management_writes": config.management_writes,
                "demo_fixture": config.demo_fixture,
                "production_snapshot": config.production_snapshot,
                "snapshot_age": snapshot_age(captured_at),
            },
        )

    @router.get("/proxies/preview", response_class=HTMLResponse)
    def proxy_preview_form(request: Request) -> Response:
        return _preview_page(request, config, dict(preview_module.DEFAULTS))

    @router.post("/proxies/preview", response_class=HTMLResponse)
    def proxy_preview_submit(
        request: Request,
        name: str = Form(default="", max_length=64),
        hostnames: str = Form(default="", max_length=2048),
        protocol: str = Form(default="http", max_length=8),
        vip: str = Form(default="", max_length=64),
        source: str = Form(default="", max_length=64),
        certificate: str = Form(default="", max_length=255),
        redirect_http: str = Form(default=""),
        hsts: str = Form(default=""),
        hsts_max_age: str = Form(default="", max_length=16),
        hsts_subdomains: str = Form(default=""),
        balance: str = Form(default="roundrobin", max_length=16),
        balance_key: str = Form(default="", max_length=64),
        cookie: str = Form(default="", max_length=32),
        servers: str = Form(default="", max_length=4096),
        health_type: str = Form(default="disabled", max_length=16),
        health_path: str = Form(default="", max_length=1024),
        health_host: str = Form(default="", max_length=255),
        health_port: str = Form(default="", max_length=8),
        allow_ranges: str = Form(default="", max_length=2048),
        backend_tls: str = Form(default="", max_length=16),
        allow_from: list[str] = NETWORK_SELECTION,
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        """Show what this object would generate. Write nothing, anywhere.

        A CSRF token is still required even though the page changes no state.
        The form is only reachable with a session, and a page that accepted
        posts from anywhere would be one more thing to reason about for no gain.
        """

        session = current_session(request)
        if session is None:
            return RedirectResponse("/login", status_code=303)
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return PlainTextResponse("Refused", status_code=403)

        return _preview_page(
            request,
            config,
            {
                "name": name,
                "hostnames": hostnames,
                "protocol": protocol,
                "vip": vip,
                "source": source,
                "certificate": certificate,
                "redirect_http": redirect_http == "on",
                "hsts": hsts == "on",
                "hsts_max_age": hsts_max_age,
                "hsts_subdomains": hsts_subdomains == "on",
                "balance": balance,
                "balance_key": balance_key,
                "cookie": cookie,
                "servers": servers,
                "health_type": health_type,
                "health_path": health_path,
                "health_host": health_host,
                "health_port": health_port,
                "allow_ranges": allow_ranges,
                "backend_tls": backend_tls,
                "allow_from": tuple(allow_from),
            },
            submitted=True,
        )

    @router.get("/certificates", response_class=HTMLResponse)
    def certificate_overview(request: Request) -> Response:
        session = current_session(request)
        if session is None:
            return RedirectResponse("/login", status_code=303)
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        clusters, certificate_rows, captured_at = read_source(request, config, CERTIFICATE_SOURCE)
        overview = certificates.build_certificate_overview(
            clusters,
            certificate_rows,
            now=captured_at,
            stale_after=timedelta(seconds=config.poller.interval_seconds * 2),
            #
            # The snapshot's readings describe the instant it was taken, so
            # the freshness line says that rather than claiming the wall
            # clock. Staleness is still judged the same way.
            #
            captured=captured_at is not None,
        )
        return TEMPLATES.TemplateResponse(
            request,
            "certificates.html",
            {
                "username": session.username,
                "role": session.role,
                "csrf_token": auth.csrf_token(token),
                "certificates": overview,
                "management_writes": config.management_writes,
                "section": "certificates",
                "demo_fixture": config.demo_fixture,
                "production_snapshot": config.production_snapshot,
                "snapshot_age": snapshot_age(captured_at),
            },
        )

    @router.get("/backups", response_class=HTMLResponse)
    def backup_overview(request: Request) -> Response:
        session = current_session(request)
        if session is None:
            return RedirectResponse("/login", status_code=303)
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        clusters, backup_rows, captured_at = read_source(request, config, BACKUP_SOURCE)
        overview = backups.build_backup_overview(
            clusters,
            backup_rows,
            now=captured_at,
            stale_after=timedelta(seconds=config.poller.interval_seconds * 2),
            #
            # The snapshot's readings describe the instant it was taken, so
            # the freshness line says that rather than claiming the wall
            # clock. Staleness is still judged the same way.
            #
            captured=captured_at is not None,
        )
        return TEMPLATES.TemplateResponse(
            request,
            "backups.html",
            {
                "username": session.username,
                "role": session.role,
                "csrf_token": auth.csrf_token(token),
                "backups": overview,
                "section": "backups",
                "management_writes": config.management_writes,
                "demo_fixture": config.demo_fixture,
                "production_snapshot": config.production_snapshot,
                "snapshot_age": snapshot_age(captured_at),
            },
        )

    @router.get("/history", response_class=HTMLResponse)
    def version_history(request: Request) -> Response:
        session = current_session(request)
        if session is None:
            return RedirectResponse("/login", status_code=303)
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        clusters, history_rows, captured_at = read_source(request, config, HISTORY_SOURCE)
        overview = history.build_history_overview(
            clusters,
            history_rows,
            now=captured_at,
            stale_after=timedelta(seconds=config.poller.interval_seconds * 2),
            #
            # The snapshot's readings describe the instant it was taken, so
            # the freshness line says that rather than claiming the wall
            # clock. Staleness is still judged the same way.
            #
            captured=captured_at is not None,
        )
        return TEMPLATES.TemplateResponse(
            request,
            "history.html",
            {
                "username": session.username,
                "role": session.role,
                "csrf_token": auth.csrf_token(token),
                "history": overview,
                "management_writes": config.management_writes,
                "section": "history",
                "demo_fixture": config.demo_fixture,
                "production_snapshot": config.production_snapshot,
                "snapshot_age": snapshot_age(captured_at),
            },
        )

    @router.get("/activity", response_class=HTMLResponse)
    def latest_activity(request: Request) -> Response:
        session = current_session(request)
        if session is None:
            return RedirectResponse("/login", status_code=303)
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        clusters, status_rows, captured_at = read_source(request, config, STATUS_SOURCE)
        current = dashboard.build_dashboard(
            clusters,
            status_rows,
            now=captured_at,
            stale_after=timedelta(seconds=config.poller.interval_seconds * 2),
            #
            # The snapshot's readings describe the instant it was taken, so
            # the freshness line says that rather than claiming the wall
            # clock. Staleness is still judged the same way.
            #
            captured=captured_at is not None,
        )
        entries = activity.build_activity(current)
        return TEMPLATES.TemplateResponse(
            request,
            "activity.html",
            {
                "username": session.username,
                "role": session.role,
                "csrf_token": auth.csrf_token(token),
                "activity": entries,
                "summary": activity.summarise_activity(entries),
                "section": "activity",
                "management_writes": config.management_writes,
                "demo_fixture": config.demo_fixture,
                "production_snapshot": config.production_snapshot,
                "snapshot_age": snapshot_age(captured_at),
            },
        )

    @router.get("/jobs", response_class=HTMLResponse)
    def latest_jobs(request: Request) -> Response:
        """Show the bounded, reader-safe history of management requests."""

        session = current_session(request)
        if session is None:
            return RedirectResponse("/login", status_code=303)
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        with request.app.state.pool.connection() as connection:
            #
            # The cluster readings decide whether a job's follow-up line is
            # still true, so they are read here rather than the job rows being
            # trusted to describe the present on their own.
            #
            overview = jobs.build_job_overview(
                db.recent_jobs(connection),
                awaiting=jobs.awaiting_deployment(db.cluster_statuses(connection)),
                #
                # The contract withholds raw stderr from a reader role, and only
                # from a reader role. Deciding it here rather than in the
                # template means the projection an unentitled session receives
                # never contains the diagnostics at all. See B44.
                #
                diagnostics=session.role == "admin",
            )
        return TEMPLATES.TemplateResponse(
            request,
            "jobs.html",
            {
                "username": session.username,
                "role": session.role,
                "csrf_token": auth.csrf_token(token),
                "jobs": overview,
                "management_writes": config.management_writes,
                "section": "jobs",
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

    @router.post("/operations")
    def queue_operation(
        request: Request,
        operation: str = Form(default="", max_length=32),
        cluster: str = Form(default="", max_length=32),
        idempotency_key: str = Form(default="", max_length=64),
        version: str = Form(default="", max_length=16),
        expected_commit: str = Form(default="", max_length=64),
        allow_vip_unknown: str = Form(default=""),
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        """Ask for an operation. Say nothing about what happened to it.

        Four refusals before anything is written, in this order, because each one
        answers a different question and collapsing them would make an incident
        harder to read: is the installation allowed to write at all, is this a
        session, is it allowed to ask, and is the request itself well formed.

        The reader role is refused here as well as in the template that does not
        draw the button. The template is a courtesy; this is the control.
        """

        if not config.management_writes:
            #
            # The documented rollback for the whole write path is turning this
            # off, so the route has to be dead when it is off - not merely
            # unlinked. 404 rather than 403: an installation that does not do
            # management writes has no such endpoint, and saying "forbidden"
            # would tell an intruder that one exists to be enabled.
            #
            return PlainTextResponse("Not found", status_code=404)

        session = current_session(request)
        if session is None:
            return RedirectResponse("/login", status_code=303)
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return PlainTextResponse("Refused", status_code=403)
        if session.role != "admin":
            return PlainTextResponse("Refused", status_code=403)

        payload: dict[str, Any] = {}
        if operation in {"deploy", "cert_deploy"}:
            payload["allow_vip_unknown"] = allow_vip_unknown == "on"
        elif operation == "revert":
            if not version.isdigit():
                return PlainTextResponse("A version is required", status_code=400)
            payload = {"version": int(version), "expected_commit": expected_commit}

        try:
            key = UUID(idempotency_key)
        except ValueError:
            #
            # Generated by the form, not here. A key made up at this point would
            # be new on every submission, which is the same as having none: the
            # second click would queue a second operation.
            #
            return PlainTextResponse("A request key is required", status_code=400)

        try:
            #
            # Prepared and then thrown away. Building the command is how the
            # payload is validated, and doing it before the insert means an
            # operation nobody can run never becomes a row - and never takes the
            # cluster's one active slot to say so.
            #
            operations.prepare(
                operation=operation, cluster=cluster, request_id=uuid4(), payload=payload
            )
        except operations.UnknownOperation:
            return PlainTextResponse("Unknown operation", status_code=400)
        except operations.BadPayload:
            # Validation detail can contain request-derived values. It belongs
            # in neither a client response nor CodeQL's stack-trace surface;
            # the form already names the fields it accepts.
            return PlainTextResponse("Invalid operation parameters", status_code=400)

        with request.app.state.pool.connection() as connection:
            try:
                job = db.queue_job(
                    connection,
                    operation=operation,
                    cluster=cluster,
                    payload=payload,
                    idempotency_key=key,
                )
            except db.ClusterBusy:
                connection.rollback()
                return PlainTextResponse("A job is already running for this cluster", 409)
            except db.RequestConflict:
                connection.rollback()
                return PlainTextResponse("That request key asked for something else", 409)
            db.record_audit_event(
                connection,
                actor=session.username,
                action="queue_job",
                cluster=cluster,
                request_id=job.request_id,
                detail={"operation": operation, "job": job.id},
            )
            connection.commit()

        #
        # 303 and not a rendered page: a queued job is a thing that happened, and
        # a refresh of this response must not queue another. The idempotency key
        # would catch that anyway; not relying on it is cheaper than explaining
        # why it did.
        #
        return RedirectResponse("/jobs", status_code=303)

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


def _preview_page(
    request: Request,
    config: Config,
    form: dict[str, Any],
    *,
    submitted: bool = False,
) -> Response:
    session = current_session(request)
    if session is None:
        return RedirectResponse("/login", status_code=303)
    token = request.cookies.get(auth.SESSION_COOKIE, "")
    cluster = preview_module.PREVIEW_CLUSTER
    result = preview_module.preview(form, cluster) if submitted else preview_module.Preview()
    return TEMPLATES.TemplateResponse(
        request,
        "preview.html",
        {
            "username": session.username,
            "role": session.role,
            "csrf_token": auth.csrf_token(token),
            "section": "preview",
            "form": form,
            "choices": preview_module.choices(cluster),
            "suggested_cookie": preview_module.suggested_cookie(
                str(form.get("name", "") or "").strip()
            ),
            "result": result,
            "submitted": submitted,
            "management_writes": config.management_writes,
            "demo_fixture": config.demo_fixture,
            "production_snapshot": config.production_snapshot,
            "snapshot_age": None,
        },
    )


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
