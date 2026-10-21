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

import contextlib
import hashlib
import importlib.metadata
import io
import ipaddress
import json
import logging
import re
import secrets
import sys
import zipfile
from collections.abc import Callable, Collection, Iterable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import urlencode
from uuid import UUID, uuid4, uuid5

import anyio
import psycopg
from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, Response, UploadFile
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
)
from fastapi.templating import Jinja2Templates
from haprion import (
    cert_export_socket,
    cert_receiver,
    crs,
    dnsdist_config,
    proxy_model,
    resolve_socket,
    server_names,
    server_state,
    status_collect,
)
from haprion import cluster_settings as cluster_settings_module
from haprion.cert_export import FORMATS as EXPORT_FORMATS
from haprion.cert_export import Export, ExportError
from haprion.certificates import CERTIFICATE_OPENING
from haprion.cli import changes_publish
from haprion.config import CERTIFICATE_ID, DEFAULT_ABUSE_WINDOW, ConfigError
from haprion.digits import is_digits
from haprion.dns_profile_keys import DnsProfilePublicKey, KeyFileError, read_public_key
from haprion.managed_network import load_document as load_network_document
from haprion.managed_network import location as network_location
from haprion.objects import objects_result
from haprion.proxy_model import (
    DEFAULT_DNS_FALL,
    DEFAULT_DNS_INTERVAL,
    DEFAULT_DNS_RISE,
    DEFAULT_DOWN_INTERVAL,
    DEFAULT_FALL,
    DEFAULT_FAST_INTERVAL,
    DEFAULT_INTERVAL,
    DEFAULT_RISE,
    SENDERS_ADDRESS,
    ModelError,
    load_proxy,
)
from starlette.datastructures import FormData
from starlette.templating import _TemplateResponse

from haprion_ui import (
    advanced_dialog,
    attention,
    audit,
    auth,
    backups,
    blocked,
    certificate_activity,
    certificate_delete,
    certificate_form,
    certificate_import_form,
    certificate_receivers,
    certificate_renew,
    certificate_retarget,
    certificates,
    cluster_identity,
    cluster_nodes,
    cluster_settings_page,
    dashboard,
    db,
    demo,
    dns_profile_form,
    feature_switch,
    features,
    first_cluster,
    getting_started,
    health,
    held_servers,
    history,
    jobs,
    location_data,
    metrics,
    ndes_profile_form,
    network,
    node_events,
    objects,
    oidc_web,
    operations,
    proxies,
    search_index,
    server_card,
    sorting,
    timing,
    traffic_log_table,
    traffic_logs,
    traffic_summary,
    update_check,
    users,
    waf,
)
from haprion_ui import editor as editor_module
from haprion_ui import preview as preview_module
from haprion_ui import probe as probe_module
from haprion_ui import version_changes as version_changes_view
from haprion_ui.cluster_identity import accent_index
from haprion_ui.config import CLUSTER_ID, Config
from haprion_ui.db import AuthenticatedSession
from haprion_ui.form_groups import form_groups, waf_exception_count
from haprion_ui.health_rows import health_rows


class _TimedTemplates(Jinja2Templates):
    """Every page's template time counted as such (`timing`)."""

    def TemplateResponse(self, *args: Any, **kwargs: Any) -> _TemplateResponse:  # noqa: N802
        def render() -> _TemplateResponse:
            response: _TemplateResponse = Jinja2Templates.TemplateResponse(self, *args, **kwargs)
            return response

        return timing.rendered(render)


#
# A commit as a form carries it, checked before it reaches a column that
# would refuse it with a database error instead of a sentence.
#
COMMIT_ID = re.compile(r"[0-9a-f]{40}")

TEMPLATES = _TimedTemplates(directory=str(Path(__file__).parent / "templates"))
logger = logging.getLogger("haprion_ui")

#
# A multi-select arrives as repeated fields, so its default has to be a list -
# and a list built in an argument default would be one list shared by every
# request. Named here so there is exactly one, and it is never mutated.
#
NETWORK_SELECTION = Form(default=[])
#
# The one file input the interface has (B165): optional at the parameter so a
# submission without a file is the form's refusal, not a 422 from the
# framework. Named here for the reason the multi-select is.
#
UPLOADED_FILE = File(default=None)

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


def release_label(prefix: str | None = None) -> tuple[str, str]:
    """The version beside the name in the header, and the release it runs from.

    The release is the directory the environment lives in,
    `/opt/haprion-ui/releases/<id>/venv`, reached through `current`; anywhere
    else - a checkout, the tests - there is no release, and the version says it.
    """

    version = f"v{importlib.metadata.version('haprion-ui')}"
    release = Path(prefix or sys.prefix).resolve().parent
    return version, release.name if release.parent.name == "releases" else version


#
# Resolved once, at import. The files cannot change under a running release -
# a release directory is read-only and a new one is a new process.
#
TEMPLATES.env.globals["asset_token"] = asset_token()
TEMPLATES.env.globals["release_version"], TEMPLATES.env.globals["release_id"] = release_label()
INSTALLED_VERSION = importlib.metadata.version("haprion-ui")
TEMPLATES.env.globals["update_available"] = update_check.header
TEMPLATES.env.globals["new_request_key"] = lambda: str(uuid4())
#
# HAProxy's check codes as sentences. A global rather than a field on the row:
# the rows come from the engine's own dataclass, which the CLI shares, and how
# a web page words something is not the engine's business.
#
TEMPLATES.env.globals["check_phrase"] = health.check_phrase
TEMPLATES.env.globals["form_groups"] = form_groups
TEMPLATES.env.globals["waf_exception_count"] = waf_exception_count
TEMPLATES.env.globals["waf_where"] = waf.where
TEMPLATES.env.globals["health_rows"] = health_rows
TEMPLATES.env.globals["feature_on"] = features.is_on
TEMPLATES.env.filters["accent_class"] = cluster_identity.accent_class
TEMPLATES.env.filters["cluster_accent"] = lambda cluster: cluster_identity.accent_class(
    cluster_identity.accent_index(cluster)
)
TEMPLATES.env.globals["through_provider"] = oidc_web.through_provider

#
# The theme is rendered into the document by the server, from a cookie the
# browser maintains. It has to be known before the first byte: a theme applied
# by script is applied after the first paint at the earliest, and between two
# documents the browser paints its own light canvas - a flash on every
# navigation, and every tab here is a full page load.
#
THEME_COOKIE = "haprion_ui_theme"
# The browser's IANA zone, written by zone.js; read, never set, by the server.
ZONE_COOKIE = "haprion_ui_zone"
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


def shown_at(moment: datetime) -> str:
    """One stored moment, in the clock the person reading it is holding.

    Times are stored and reasoned about in UTC everywhere, and the traffic card
    already prints them in the host's zone for the reason written beside
    `metrics.shown`: a page whose times cannot be lined up against `journalctl`
    or a deploy sends people to the wrong minute. The traffic log is the page
    most likely to be read beside a journal, so it uses the same clock and the
    same format rather than a second one.
    """

    return metrics.shown(moment).strftime(metrics.TIMESTAMP)


TEMPLATES.env.filters["shown_at"] = shown_at
TEMPLATES.env.filters["groupby_object"] = waf.by_object
TEMPLATES.env.filters["shown"] = metrics.shown
TEMPLATES.env.filters["certificate_order"] = lambda rows, sort: certificates.TABLE.ordered(
    rows, sort
)
TEMPLATES.env.filters["proxy_order"] = lambda rows, sort, lamps: proxies.TABLE.ordered(
    rows, sort, lamps
)
TEMPLATES.env.filters["proxy_page_link"] = proxies.page_link
TEMPLATES.env.globals["proxy_page_size"] = proxies.PAGE_SIZE


def _freshness_warnings(reading: traffic_logs.Reading, now: datetime) -> tuple[Any, ...]:
    """(node, seconds since success, seconds since attempt) for each node the log warning names."""

    freshness = tuple(
        (node, node.stale_seconds(now=now), node.attempt_seconds(now=now)) for node in reading.nodes
    )
    return tuple(
        item
        for item in freshness
        if item[0].latest_attempt_failed()
        or item[0].catching_up()
        or item[1] is None
        or item[1] > 300
    )


def _log_time_filter(
    value: str,
    *,
    earliest: datetime,
    latest: datetime,
    end_of_minute: bool = False,
    outside: str = "Choose a date and time within the available 14 days.",
) -> datetime | None:
    """Turn a date and time in the reader's clock into the UTC used by log records."""

    if not value:
        return None
    if len(value) != 14:
        raise ValueError(outside)
    try:
        local = datetime.strptime(value, "%y-%m-%d %H:%M")
    except ValueError as exc:
        raise ValueError("Choose a valid date and time.") from exc
    if local.tzinfo is not None:
        raise ValueError("Choose a local date and time.")
    result = metrics.wall(local).astimezone(UTC)
    if result < earliest or result > latest:
        raise ValueError(outside)
    if end_of_minute:
        result = min(result + timedelta(minutes=1, microseconds=-1), latest)
    return result


#
# How many of a traffic page's readings run at once, each on its own pooled
# connection. Every card asks two questions - its line and its figures - and
# the answers are independent, so asking them one after another only added
# their times up. Measured 2026-10-01 against a copy at production density
# (two clusters, a week of raw samples every 20 s, the hourly rollup behind
# it) with PostgreSQL held to two CPUs, the size this installation is built
# for: the 7- and 30-day windows took 1.28 s in sequence, 0.85 s two at a
# time, and four bought nothing more on two cores - it only took them from the
# poller and the worker.
#
TRAFFIC_READERS = 2


def _read_concurrently[T](pool: Any, reads: Sequence[Callable[[Any], T]]) -> list[T]:
    """Each read on a connection of its own, at most `TRAFFIC_READERS` at once.

    The answers come back in the order asked. A read that fails fails the page,
    as it did when they ran one by one.
    """

    def run(read: Callable[[Any], T]) -> T:
        with pool.connection() as connection:
            return read(connection)

    if len(reads) <= 1:
        return [run(read) for read in reads]
    #
    # A thread does not inherit the request's context. Each read runs in a copy
    # of it, so its queries are counted with the page that asked (`timing`).
    #
    context = copy_context()
    with ThreadPoolExecutor(max_workers=TRAFFIC_READERS) as readers:
        return list(readers.map(lambda read: context.copy().run(run, read), reads))


def _traffic_marks(request: Request, marked: metrics.Selection) -> dict[str, object]:
    """What a card needs to draw and extend the reader's marked range.

    The link is handed over as a callable rather than one link per bucket:
    every page draws between sixty and a hundred and eighty buckets per card
    and several cards, and building all of them for the one the reader will
    click is a page assembled for the click that did not happen yet.

    The rest of the query string is carried through it, so a range marked on
    the 7-day view stays on the 7-day view - and so does anything else the
    address is carrying that this function has never heard of.
    """

    base = {name: value for name, value in request.query_params.items()}
    return {
        "traffic_marked": marked,
        "traffic_range": metrics.range_label(marked),
        "traffic_link": lambda stamp: metrics.link_to(base, marked, stamp),
        #
        # Where "clear the marks" leads, for the reader who wants out without
        # hunting for the third click.
        #
        "traffic_clear": metrics.link_clear(base) if marked.since is not None else "",
    }


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


# How long saving a DNS profile waits for its apply job before the list is
# drawn. The job is one root helper call; when the queue is idle it is done
# within a second, and the page should say so rather than send the operator
# to the Jobs page for a one-second job. In seconds.
#
DNS_PROFILE_APPLY_WAIT = 6.0

#
# The figures an object's traffic card draws, by what serves it: dnsdist counts
# a dns pool's queries (Fas 19a B4), IPVS a syslog pool's messages (19b B3),
# HAProxy everything else.
#
OBJECT_FIGURES = {"dns": metrics.DNS_FIGURES, "syslog": metrics.SYSLOG_FIGURES}

SIGN_IN_FAILED = "Sign-in failed. Check the username and password and try again."
SIGN_IN_BUSY = "Too many sign-ins at once. Try again in a moment."
UNAVAILABLE_PROVIDER = "Sign-in through the provider is not available"
EXPIRED = (
    "This run has expired: it was prepared more than an hour ago. Start a new restore from the "
    "backup page."
)


@dataclass(frozen=True, slots=True)
class Source:
    """Where one kind of cached reading comes from, in each of the two modes.

    A page must never choose its own source: an interface can be showing the
    synthetic fixture, and a view that reached the database directly would
    quietly show real rows on a page labelled as fixture data. Stated once, per kind of reading, so a new page
    picks a source rather than inventing one.
    """

    demo_rows: Callable[[], Iterable[Any]]
    cached_rows: Callable[[Any], Iterable[Any]]
    scoped_rows: Callable[[Any, str], Iterable[Any]] | None = None


#
# The cached readers are wrapped rather than referenced, so the lookup happens
# when the page is rendered. Binding `db.cluster_statuses` here would capture the
# function at import and quietly ignore a test that replaces it.
#
STATUS_SOURCE = Source(
    demo.status_rows,
    lambda connection: db.cluster_statuses(connection),
)
INVENTORY_SOURCE = Source(
    demo.inventory_rows,
    lambda connection: db.cluster_inventories(connection),
)
HISTORY_SOURCE = Source(
    demo.history_rows,
    lambda connection: db.cluster_histories(connection),
    lambda connection, cluster: db.cluster_histories(connection, cluster=cluster),
)
BACKUP_SOURCE = Source(
    demo.backup_rows,
    lambda connection: db.cluster_backups(connection),
)
CERTIFICATE_SOURCE = Source(
    demo.certificate_rows,
    lambda connection: db.cluster_certificates(connection),
    lambda connection, cluster: db.cluster_certificates(connection, cluster=cluster),
)
NETWORK_SOURCE = Source(
    demo.network_rows,
    lambda connection: db.cluster_networks(connection),
    lambda connection, cluster: db.cluster_networks(connection, cluster=cluster),
)
#
# The cluster's own settings (Fas 15).
#
SETTINGS_SOURCE = Source(
    demo.settings_rows,
    lambda connection: db.cluster_settings(connection),
)
OBJECTS_SOURCE = Source(
    demo.object_rows,
    lambda connection: db.cluster_objects(connection),
    lambda connection, cluster: db.cluster_objects(connection, cluster=cluster),
)


#
# The readings the header's search covers, by the operation that wrote them
# (B222). The cluster list is the fifth, and is not a reading.
#
SEARCHED_SOURCES = (
    ("objects", OBJECTS_SOURCE),
    ("network", NETWORK_SOURCE),
    ("cert_list", CERTIFICATE_SOURCE),
    ("status", STATUS_SOURCE),
)
#
# A page number past this is not one anybody reached by clicking Next.
#
MAX_SEARCH_PAGE = 10000


def listed_clusters(request: Request, config: Config) -> tuple[str, ...]:
    """The clusters this interface shows, in the order it shows them."""

    if config.demo_fixture:
        return demo.CLUSTERS
    #
    # The clusters the poller last read from the cluster file (B206), so one
    # created or removed from Settings is on the pages at the next pass.
    # `ui.toml`'s list only until the poller has written one.
    #
    return _cluster_list(request, config)[0]


def _creations(request: Request, recent: list[Any]) -> list[cluster_nodes.Creating]:
    """Clusters being created that the list does not show yet (finding 51)."""

    config = request.app.state.config
    return cluster_nodes.creations(
        recent,
        listed_clusters(request, config),
        now=datetime.now(UTC),
        settle=timedelta(seconds=config.poller.interval_seconds * 2),
    )


def _cluster_list(request: Request, config: Config) -> tuple[tuple[str, ...], bool]:
    """The live list and whether it came from the cluster file rather than `ui.toml`."""

    with request.app.state.pool.connection() as connection:
        listed = db.cluster_list(connection)
    # Empty is an answer (B302): no cluster yet, or the last one removed.
    return (listed, True) if listed is not None else (config.clusters, False)


def read_source(
    request: Request,
    config: Config,
    source: Source,
    *,
    cluster: str | None = None,
    clusters: tuple[str, ...] | None = None,
) -> tuple[tuple[str, ...], Iterable[Any]]:
    """The clusters to render and their newest readings."""

    if config.demo_fixture:
        # The fixture times its readings from the moment it is read, so it needs
        # no clock of its own; it is never stale.
        return (
            demo.CLUSTERS,
            [
                row
                for row in source.demo_rows()
                if cluster is None or getattr(row, "cluster", None) == cluster
            ],
        )
    listed, from_file = _cluster_list(request, config) if clusters is None else (clusters, True)
    if cluster is not None and cluster not in listed:
        return listed, ()
    with request.app.state.pool.connection() as connection:
        rows = (
            source.scoped_rows(connection, cluster)
            if cluster is not None and source.scoped_rows is not None
            else source.cached_rows(connection)
        )
    if cluster is not None:
        rows = [row for row in rows if getattr(row, "cluster", None) == cluster]
    #
    # A cluster the cluster file no longer names has been removed (Settings or
    # `haprion-cluster remove`), and its last cached readings are never deleted:
    # the poller has no delete privilege. Drawn, it stayed on every page as "Not
    # configured" for good (review 2026-09-30 F1). With the list from `ui.toml`
    # the old card stays, because there a removal is a hand edit worth seeing.
    #
    if from_file:
        rows = [row for row in rows if getattr(row, "cluster", None) in listed]
    return listed, rows


def read_manager_certificates(request: Request, config: Config) -> db.ManagerCertificates | None:
    """What the manager holds - the registry, what the interface is served
    with - read whether or not a cluster exists (B304)."""

    if config.demo_fixture:
        return demo.manager_certificates()
    with request.app.state.pool.connection() as connection:
        return db.manager_certificates(connection)


def read_certificate_takeouts(request: Request, config: Config) -> dict[str, db.TakenOut] | None:
    """The newest download per external certificate (26-10-18); None in the demo,
    which has no audit trail and keeps the rows it always had."""

    if config.demo_fixture:
        return None
    with request.app.state.pool.connection() as connection:
        return db.certificate_takeouts(connection)


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


#
# Why the Servers card's buttons did nothing, by `?servers=` (B263). A queued
# job needs no sentence: the buttons give way to its spinner.
#
SERVER_NOTICES = {
    "none": "Tick the servers first.",
    "busy": "A job is already running for this cluster. Try again when it has finished.",
}
BLOCKED_NOTICES = {
    "none": "Tick the addresses first.",
    "busy": SERVER_NOTICES["busy"],
}


#
# What Settings says after a switch has been flipped, by `?switched=`.
#
SWITCHED = {
    "cert_receivers-off": "External certificates turned off. Registered receivers still get new certificates.",
    "cert_receivers-on": "External certificates turned on.",
    "node_backups-off": "Node backups turned off. The clusters' schedules are being stopped; see Jobs.",
    "node_backups-on": "Node backups turned on. The schedules that were stopped are being started again.",
    "cluster_colours-off": "Cluster colours turned off.",
    "cluster_colours-on": "Cluster colours turned on.",
    "advanced_config-off": "Advanced config turned off. Objects keep their text and it is still published.",
    "advanced_config-on": "Advanced config turned on.",
    "update_check-off": "Update check turned off. GitHub is not asked again.",
    "update_check-on": "Update check turned on. The poller asks GitHub within a minute.",
}


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


#
# Every handler is a plain `def`, which FastAPI runs in its thread pool. They
# all read the database - the session check alone does - with the synchronous
# pool, and an `async def` doing that waited on the event loop: while it waited
# for a connection, no other request of anybody's was answered (review
# 26-10-13, K1). What is asynchronous in a request - its form, an upload - is
# read from the thread through the loop instead.
#
async def _read_form(request: Request) -> FormData:
    return await request.form()


def _posted(request: Request) -> FormData:
    """The request's form, read from a handler running in the thread pool."""

    return anyio.from_thread.run(_read_form, request)


def _earlier_names(
    name: str,
    targets: Mapping[str, metrics.BackendTarget],
    aliases: Mapping[str, Sequence[db.EarlierName]],
) -> list[db.EarlierName]:
    """A backend's earlier names: recorded renames, and the generator's older form of each."""

    found = list(aliases.get(name, ()))
    found += [
        db.EarlierName(older)
        for older, target in targets.items()
        if target.current == name and older != name
    ]
    return found


def _admin_write_gate(config: Config, request: Request) -> AuthenticatedSession | Response:
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
        return PlainTextResponse("Refused", status_code=403)
    return session


def _registry_overview(config: Config, request: Request) -> certificates.RegistryView | None:
    clusters, certificate_rows = read_source(request, config, CERTIFICATE_SOURCE)
    overview = certificates.build_certificate_overview(
        clusters,
        certificate_rows,
        manager=read_manager_certificates(request, config),
        stale_after=timedelta(seconds=config.poller.interval_seconds * 2),
    )
    return overview.registry


def _page_context(
    config: Config, request: Request, session: AuthenticatedSession
) -> tuple[str, certificates.RegistryView | None, dict[str, Any]]:
    token = request.cookies.get(auth.SESSION_COOKIE, "")
    registry = _registry_overview(config, request)
    with request.app.state.pool.connection() as connection:
        recent = db.recent_jobs(connection)
    return (
        token,
        registry,
        {
            "username": session.username,
            "role": session.role,
            "csrf_token": auth.csrf_token(token),
            "registry_present": registry is not None,
            "certificate_job": jobs.certificate_in_flight(recent),
            "section": "certificates",
            "management_writes": config.management_writes,
            "demo_fixture": config.demo_fixture,
        },
    )


def _backup_overview(config: Config, request: Request) -> Any:
    clusters, backup_rows = read_source(request, config, BACKUP_SOURCE)
    return backups.build_backup_overview(
        clusters,
        backup_rows,
        stale_after=timedelta(seconds=config.poller.interval_seconds * 2),
    )


def _account_rows(config: Config, request: Request) -> list[db.AccountRow]:
    with request.app.state.pool.connection() as connection:
        return db.account_rows(
            connection,
            window_minutes=config.throttle.window_minutes,
            max_failures=config.throttle.max_failures,
        )


def _status_row(config: Config, request: Request, cluster: str) -> Any | None:
    clusters, rows = read_source(request, config, STATUS_SOURCE)
    if cluster not in clusters:
        return None
    return next((row for row in rows if row.cluster == cluster), None)


def _queue_node_job(
    config: Config,
    request: Request,
    gate: AuthenticatedSession,
    cluster: str,
    payload: Mapping[str, Any],
    key: UUID,
    node: str | None,
    again: Callable[[str], Response],
    *,
    operation: str = "cluster_node",
    back: str | None = None,
) -> Response:
    #
    # Who asked, for the version a node change publishes (B335): the helper
    # records it only because the worker is the one who sends it.
    #
    payload = {**payload, "requested_by": gate.username}
    try:
        operations.prepare(
            operation=operation, cluster=cluster, request_id=uuid4(), payload=payload
        )
    except operations.BadPayload as refused:
        return again(str(refused))
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
            return again(
                "A job is already running for this cluster. Try again when it has finished."
            )
        except db.RequestConflict:
            connection.rollback()
            return PlainTextResponse("That request key asked for something else", 409)
        #
        # The audit row names the node and the action, never the block: the
        # block holds public keys, and the audit log is not where a reader
        # looks for one.
        #
        detail: dict[str, Any] = {
            "operation": operation,
            "job": job.id,
            "action": payload["action"],
        }
        if node is not None:
            detail["node"] = node
        db.record_audit_event(
            connection,
            actor=gate.username,
            action="queue_job",
            cluster=cluster,
            request_id=job.request_id,
            detail=detail,
        )
        connection.commit()
    if back is not None:
        return RedirectResponse(back, status_code=303)
    #
    # Back to the cluster's page, named from the configured list rather
    # than from the request: the callers already refused a cluster not on
    # it, and the address is then never built from what the browser sent.
    #
    listed = next(name for name in listed_clusters(request, config) if name == cluster)
    return RedirectResponse(f"/settings/nodes/{listed}", status_code=303)


def _first_cluster(
    config: Config,
    request: Request,
    session: AuthenticatedSession,
    *,
    recent: list[Any],
    busy: Mapping[str, str],
    status_rows: Iterable[Any],
    views: Iterable[Any],
) -> first_cluster.Guide | None:
    """The guide's step for an admin who may write, or None (B315)."""

    if session.role != "admin" or not config.management_writes:
        return None
    listed = listed_clusters(request, config)
    cluster = listed[0] if len(listed) == 1 else ""
    reading = next((row for row in status_rows if row.cluster == cluster), None)
    vip = next((view.vip for view in views if view.cluster == cluster), "")
    return first_cluster.guide(
        clusters=listed,
        reading=reading,
        creations=_creations(request, recent),
        busy=busy,
        vip=vip if vip and vip != "Unknown" else "",
        phase=request.query_params.get("first-cluster", ""),
        deployed_recently=first_cluster.deployed_recently(recent, cluster),
        failure=first_cluster.failure(recent, cluster) if cluster else None,
    )


def _oidc_page(
    config: Config,
    request: Request,
    session: AuthenticatedSession,
    provider: db.OidcProvider,
    *,
    form: Mapping[str, Any] | None = None,
    problem: str = "",
    done: str = "",
    checks: list[dict[str, Any]] | None = None,
    status_code: int = 200,
) -> Response:
    token = request.cookies.get(auth.SESSION_COOKIE, "")
    values: dict[str, Any] = {
        name: getattr(provider, name) for name in db.OIDC_SETTINGS if name != "client_secret_sealed"
    }
    values.update(form or {})
    return TEMPLATES.TemplateResponse(
        request,
        "settings-oidc.html",
        {
            "username": session.username,
            "role": session.role,
            "csrf_token": auth.csrf_token(token),
            "section": "settings",
            "management_writes": config.management_writes,
            "provider": provider,
            "values": values,
            "secret_set": provider.client_secret_sealed is not None,
            "installed": config.oidc_public_key is not None,
            "redirect_uri": oidc_web.redirect_uri(str(request.base_url)),
            "auth_methods": oidc_web.AUTH_METHODS,
            "logout_modes": oidc_web.LOGOUT_MODES,
            "local_logins": oidc_web.LOCAL_LOGINS,
            "checks": checks,
            "problem": problem,
            "done": done,
        },
        status_code=status_code,
    )


def _oidc_provider(request: Request) -> db.OidcProvider | None:
    with request.app.state.pool.connection() as connection:
        return db.oidc_provider(connection)


def _dns_public_key(config: Config) -> DnsProfilePublicKey | None:
    """The key the web seals against, read fresh: a rotation is a file swap."""

    if config.dns_profiles_public_key is None:
        return None
    try:
        return read_public_key(config.dns_profiles_public_key)
    except KeyFileError as exc:
        logger.error("dns_profiles.public_key cannot be read: %s", exc)
        return None


def _oidc_redirect(request: Request) -> str:
    return oidc_web.redirect_uri(str(request.base_url))


def _start_oidc(
    request: Request,
    provider: db.OidcProvider,
    *,
    mode: str,
    bound_to: str,
) -> Response:
    """Record a sign-in in progress and answer where the browser goes (O5).

    `bound_to` is the cookie the answer must come back with: the
    pre-sign-in cookie for a sign-in, the session for Test sign-in. Its
    hash is kept, never the token. A provider that cannot be reached is
    the caller's to say, as `oidc_web.OidcProblem`.
    """

    tokens = oidc_web.new_login_tokens()
    redirect = _oidc_redirect(request)
    found = oidc_web.ask("discover", provider, redirect=redirect)
    with request.app.state.pool.connection() as connection:
        db.start_oidc_login(
            connection,
            state=tokens.state,
            nonce=tokens.nonce,
            verifier=tokens.verifier,
            mode=mode,
            pre_session_hash=auth.token_hash(bound_to),
        )
        connection.commit()
    return RedirectResponse(
        oidc_web.authorization_url(provider, found, tokens, redirect=redirect), status_code=303
    )


def build_router(config: Config) -> APIRouter:
    router = APIRouter(dependencies=[Depends(hidden_by_a_switch)])

    @router.get("/", response_class=HTMLResponse)
    def index(request: Request) -> Response:
        session = current_session(request)
        if session is None:
            return RedirectResponse("/login", status_code=303)
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        clusters, status_rows = read_source(request, config, STATUS_SOURCE)
        _, network_rows = read_source(request, config, NETWORK_SOURCE)
        dashboard_view = dashboard.build_dashboard(
            clusters,
            status_rows,
            stale_after=timedelta(seconds=config.poller.interval_seconds * 2),
            network_readings=network_rows,
        )
        moment = datetime.now(UTC)
        with request.app.state.pool.connection() as connection:
            recent = db.recent_jobs(connection)
            #
            # Per cluster, for its own header (B220, moved off a row of tiles
            # on 2026-10-01: traffic is a fact about a cluster's VIPs).
            #
            recent_since = moment - traffic_summary.recent_window(config.poller.interval_seconds)
            traffic_clusters = listed_clusters(request, config)
            day_traffic = db.read_traffic_summaries(
                connection,
                clusters=traffic_clusters,
                since=moment - traffic_summary.DAY,
                until=moment,
            )
            recent_traffic = db.read_traffic_summaries(
                connection, clusters=traffic_clusters, since=recent_since, until=moment
            )
            response_times = (
                db.read_response_times_by_cluster(
                    connection,
                    clusters=traffic_clusters,
                    since=moment - traffic_summary.RESPONSE_WINDOW,
                    until=moment,
                )
                if config.traffic_logs.enabled
                else None
            )
            traffic = {
                name: traffic_summary.row(
                    day_traffic[name],
                    recent_traffic[name],
                    response_times[name] if response_times is not None else None,
                )
                for name in traffic_clusters
            }
        running = jobs.in_flight(recent)
        #
        # The first cluster's guide (B315) is the getting started list's first
        # row while it has a step to show, never the dashboard in its place
        # (B328, 26-10-18): a guide in the dashboard's place had no way out.
        #
        first = _first_cluster(
            config,
            request,
            session,
            recent=recent,
            busy=running,
            status_rows=status_rows,
            views=dashboard_view.clusters,
        )
        #
        # What is saved and not published, per cluster (B257): where there is
        # any, the card's deploy becomes Publish & deploy, a dialog that lists
        # what goes out and takes the comment. The count is asked first and the
        # package built only where there is one - it reads the cluster's
        # objects, which a card without saved changes has no use for.
        #
        pending = (
            {
                cluster: _package(request, config, cluster)
                for cluster in listed_clusters(request, config)
                if _pending_count(request, config, cluster)
            }
            if config.management_writes and session.role == "admin"
            else {}
        )
        #
        # Not with writes off: every row leads to a setting that cannot be made
        # then, and the list could not be hidden either (review 2026-10-18, U2).
        #
        checklist = (
            _getting_started(request, dashboard_view, network_rows, first)
            if session.role == "admin" and config.management_writes
            else None
        )
        return TEMPLATES.TemplateResponse(
            request,
            "index.html",
            {
                #
                # What needs doing, under the four cards (B274).
                #
                "attention": _attention(request, config),
                "getting_started": checklist,
                "show_getting_started": checklist is None
                and session.role == "admin"
                and config.management_writes
                and _getting_started_offered_again(request),
                "pending": pending,
                "traffic": traffic,
                "username": session.username,
                "role": session.role,
                "management_writes": config.management_writes,
                "csrf_token": auth.csrf_token(token),
                "dashboard": dashboard_view,
                #
                # What each cluster is busy with. The buttons below it are
                # replaced by this while a job runs, rather than left drawn to
                # offer an action the queue would refuse with a 409.
                #
                "in_flight": running,
                #
                # Clusters whose last deploy was refused for a certificate a
                # node lacks. The card then offers the certificate deploy the
                # engine asked for, beside the deploy button.
                #
                "certificate_blocks": jobs.certificate_blocks(recent),
                #
                # Addresses dynamic blocking holds, per cluster and object
                # (B271): said on every card, the objects linked for an admin.
                #
                "blocked_counts": {
                    cluster: counted
                    for cluster in clusters
                    if (counted := blocked.cluster_counts(status_rows, cluster=cluster))
                },
                #
                # Servers somebody took out of service, per cluster and object
                # (26-10-10): said beside the blocks, linked for an admin.
                #
                "held_servers": _held_servers(request, config, clusters, status_rows),
                "section": "dashboard",
                "demo_fixture": config.demo_fixture,
                #
                # The page redraws itself once per poll (live.js), so the CPU,
                # memory and freshness on it move without a reload. Not for a
                # the demo data: nothing behind it changes.
                #
                #
                # Sooner when a block runs out before the next poll (B271), so
                # the card's warning goes when the block does; and timed from
                # the newest reading, so the next one is shown when it lands.
                #
                "live_seconds": (
                    None
                    if config.demo_fixture
                    else blocked.live_seconds(
                        config.poller.interval_seconds,
                        min(
                            (
                                change
                                for change in (
                                    blocked.next_change(status_rows, clusters),
                                    dashboard.next_reading(
                                        status_rows, config.poller.interval_seconds
                                    ),
                                )
                                if change is not None
                            ),
                            default=None,
                        ),
                    )
                ),
            },
        )

    def _nodes_reported(rows: Iterable[Any], cluster: str) -> bool:
        """Whether any node in this cluster answered with a server list at all.

        A cluster nobody has read is not a cluster serving nothing, and the two
        must not come out the same. Without this a poll that had never run made
        every object look undeployed.
        """

        reading = next((row for row in rows if getattr(row, "cluster", None) == cluster), None)
        result = getattr(reading, "result", None)
        nodes = result.get("nodes") if isinstance(result, Mapping) else None
        return any(
            isinstance(entry, Mapping)
            and isinstance(entry.get("status"), Mapping)
            and isinstance(entry["status"].get("servers"), list)
            for entry in (nodes if isinstance(nodes, Sequence) else ())
        )

    def _proxy_listing(request: Request, role: str) -> dict[str, Any]:
        """Everything the proxy table draws, for the page and for its refresh.

        Read once here rather than twice in two handlers. The refresh replaces
        the rows in place while something is on its way, and a second gathering
        of the same facts would be free to disagree with the first about what a
        row says - which is the disagreement nobody would see until a row
        changed shape halfway through a deploy.
        """

        clusters, inventory_rows = read_source(request, config, INVENTORY_SOURCE)
        overview = proxies.build_proxy_overview(
            clusters,
            inventory_rows,
            stale_after=timedelta(seconds=config.poller.interval_seconds * 2),
        )
        #
        # One cluster's objects using one VIP, source or group, from the
        # network page's *Used by* (26-10-11). Only that cluster is read at all.
        #
        used = proxies.used_asked(request.query_params, clusters)
        if used is not None:
            overview = proxies.ProxyOverview(
                clusters=tuple(view for view in overview.clusters if view.cluster == used.cluster)
            )
        #
        # The listing is built from published frontends, so an object that has
        # been committed but not deployed appears in none of them - which is
        # the object somebody is working on. Carried separately rather than
        # merged into the same table: they are a different state, and half a
        # table of empty ports and backend counts would say so badly.
        #
        _, object_rows = read_source(request, config, OBJECTS_SOURCE)
        rows = {reading.cluster: reading for reading in object_rows}
        #
        # Objects, not frontends. The generator names a frontend after the
        # address and protocol it binds, and every object on that address goes
        # through it - so a listing of frontends showed the implementation
        # rather than the work, and an https object that redirects plain HTTP
        # appeared twice under two names its author never chose.
        #
        #
        # Read before the listing, because the listing asks it what the nodes
        # are serving. The same reading the health lamp uses, and for the same
        # reason: it is measured on the node rather than derived from a release
        # the nodes may not have pulled yet.
        #
        _, health_rows = read_source(request, config, STATUS_SOURCE)
        #
        # Read from the same rows as the lamps. Publishing does not deploy, and
        # the listing was the one page that never said so for an object that
        # was changed rather than added or removed.
        #
        behind = health.clusters_behind(health_rows)
        listed = {}
        served: dict[str, frozenset[str]] = {}
        with request.app.state.pool.connection() as connection:
            #
            # Names a finished removal took away, asked about beside the ones
            # still in the repository. The nodes can only answer about a name
            # somebody names, and these are precisely the names the repository
            # no longer has.
            #
            recent = {
                view.cluster: db.recent_jobs(connection, cluster=view.cluster)
                for view in overview.clusters
            }
        gone = {cluster: objects.removed_names(jobs) for cluster, jobs in recent.items()}
        #
        # Each cluster's objects read out of the cache once per request, not
        # once per use: at ten thousand objects every pass over them cost a
        # sixth of a second (2026-10-01).
        #
        stored = {
            view.cluster: objects.cluster_object_views(rows.get(view.cluster))
            for view in overview.clusters
        }
        #
        # Whose each backend the nodes report is, by the objects' own account
        # and a removal's (B250): a pool's name no longer says.
        #
        owners = {
            view.cluster: health.backend_owners(
                stored[view.cluster], objects.removed_backends(recent[view.cluster])
            )
            for view in overview.clusters
        }
        for view in overview.clusters:
            names = [obj.name for obj in stored[view.cluster]]
            served[view.cluster] = health.served_objects(
                health_rows,
                cluster=view.cluster,
                names=[*names, *gone[view.cluster]],
                owners=owners[view.cluster],
            )
            listed[view.cluster] = objects.listed_objects(
                rows.get(view.cluster),
                view.proxies,
                #
                # `None` where no node said anything, so the hostname match
                # answers instead. Silence is not "nothing is served".
                #
                served=served[view.cluster] if _nodes_reported(health_rows, view.cluster) else None,
                views=stored[view.cluster],
            )
        #
        # What is left of the published inventory once the managed frontends are
        # accounted for above: configuration this platform does not own, where
        # the frontend really is the only thing there is to show.
        #
        unmanaged = {
            view.cluster: () if used else objects.unmanaged_only(view.proxies)
            for view in overview.clusters
        }
        #
        # The passive health answer, per object, for the lamp in the listing.
        # Not a probe: probing is an SSH operation against a node, and a page
        # that ran one per row on every load would turn opening a list into a
        # burst of connections nobody asked for. This is what HAProxy on the
        # nodes has already decided, read out of the same status reading the
        # dashboard draws.
        #
        #
        # Whether the object is checked and whether it leaves from a source
        # address come from the objects helper (B222), not from reading the
        # document here. The second decides which node may answer: only the
        # node holding the address can bind it, and the other reports the
        # backend down.
        #
        backend_lamps = {
            view.cluster: health.object_healths(
                health_rows,
                cluster=view.cluster,
                owners=owners[view.cluster],
                objects={
                    #
                    # Every listed name is a candidate owner, so a server is
                    # never lent to an object whose name is a prefix of another.
                    #
                    **{other.name: (True, False) for other in listed[view.cluster]},
                    **{obj.name: (obj.health_checked, obj.sourced) for obj in stored[view.cluster]},
                },
            )
            for view in overview.clusters
        }
        #
        # And a step earlier than that: a draft has not reached the cluster
        # repository at all, so it is in neither the inventory nor the objects
        # cache. It is listed for the same reason the waiting objects are - the
        # period when somebody needs to find their work is exactly the period
        # before it is anywhere else - and separately, because "saved here" and
        # "committed but not deployed" are different answers to "where is it".
        #
        with request.app.state.pool.connection() as connection:
            drafts = {
                #
                # One row per object, the one its editor opens: a draft over a
                # saved change (B257), each carrying its stage for the badge.
                #
                view.cluster: tuple(
                    _top_layers(
                        _settled_drafts(
                            connection,
                            view.cluster,
                            _objects_reading(
                                rows.get(view.cluster),
                                {listing.name for listing in listed[view.cluster]},
                            ),
                        )
                    )
                )
                for view in overview.clusters
            }
            #
            # Which of those drafts are already on their way. Publishing is a
            # job, so between the click and the row there is a stretch where
            # the work is neither a draft anybody is still editing nor a
            # published object - and a row that says "Draft" through all of it
            # reads as though the button did nothing.
            #
            #
            # One read per cluster, two questions. `publishing` is what is
            # still trying; `failed` is what stopped and changed nothing - and
            # until the second existed a refused publish said nothing anywhere
            # a person looks, which read as the object turning back into a
            # draft by itself.
            #
            recent = {
                view.cluster: db.recent_jobs(connection, cluster=view.cluster)
                for view in overview.clusters
            }
            publishing = {
                cluster: objects.names_being_published(rows) for cluster, rows in recent.items()
            }
            failed = {cluster: objects.publish_failures(rows) for cluster, rows in recent.items()}
            #
            # Per object, not per cluster. What the nodes are behind on is a
            # release, but which objects that release changed is not: a row that
            # wore the cluster's fact claimed every site had been reconfigured when
            # one had.
            #
            # Read from the status rather than from the jobs. The jobs knew only
            # what this application published recently enough to still be in the
            # listing, so an object changed from the command line, or changed
            # longer ago than the window reaches, wore no badge at all.
            #
            # The jobs are still asked where the releases cannot answer - the
            # nodes run a release built before manifests existed - and only for
            # what they say in the positive. A badge for "could not be
            # compared" was tried and reverted the same afternoon: it landed on
            # every object at once, which is the cluster-wide claim this badge
            # was made per object to avoid.
            #
            reconfigured = {
                view.cluster: objects.awaiting_deploy(
                    health.object_states(health_rows, cluster=view.cluster),
                    recent[view.cluster],
                )
                for view in overview.clusters
            }
            #
            # And what a finished removal took away that the nodes have not
            # stopped serving. A removal is a publish, so between it and the
            # deploy the object is gone from the repository while the site is
            # still answering - and until this the listing showed neither,
            # which is the one direction it must not fail in.
            #
            removed = {
                view.cluster: objects.removed_awaiting_deploy(
                    db.recent_jobs(connection, cluster=view.cluster),
                    listed[view.cluster],
                    served[view.cluster],
                )
                for view in overview.clusters
            }
        #
        # The three numbers above the table, counted from the table's own rows
        # rather than from published frontends. A frontend is not a proxy
        # anybody wrote - an https object that redirects plain HTTP is two of
        # them, and every object on one address shares one - so the old count
        # disagreed with the list underneath it in both directions.
        #
        #
        # Narrowed last, so the lamps and badges above were worked out against
        # every object, as they are on the whole listing.
        #
        if used is not None:
            chosen = used.names(network.usage(stored[used.cluster]))
            listed[used.cluster] = tuple(
                listing for listing in listed[used.cluster] if listing.name in chosen
            )
        counts = objects.counted(listed, unmanaged)
        return {
            "proxies": overview,
            "listed": listed,
            "counts": counts,
            "health": backend_lamps,
            "unmanaged": unmanaged,
            #
            # A reader has no drafts to see: a draft is somebody's unfinished
            # edit, and the row exists so its author can find it again.
            #
            #
            # Filtered, the table is what the objects say they use: a draft,
            # a publish on its way and a removal have no such answer yet.
            #
            "drafts": drafts if role == "admin" and used is None else {},
            "publishing": publishing if used is None else {},
            "behind": behind,
            "reconfigured": reconfigured,
            "unforwarded": {
                view.cluster: health.syslog_unforwarded(health_rows, cluster=view.cluster)
                for view in overview.clusters
            },
            "failed": failed,
            "removed": removed if used is None else {},
            "used": used,
        }

    #
    # What each cluster is busy with, as data. The pages that draw a spinner
    # instead of their buttons need to know when to stop, and they cannot ask
    # the rows endpoint - the answer they want is not a row.
    #
    # It returns the state rather than markup because the markup those pages
    # would need back is a form carrying a CSRF token and a fresh idempotency
    # key. A browser must not be the one to mint either, so when the answer
    # differs from what a page was drawn with, the page asks the server for
    # itself again.
    #
    @router.get("/clusters/busy")
    def clusters_busy(request: Request) -> Response:
        session = current_session(request)
        if session is None:
            return JSONResponse({"detail": "not signed in"}, status_code=401)
        with request.app.state.pool.connection() as connection:
            recent = db.recent_jobs(connection)
            busy = jobs.in_flight(recent)
            #
            # And which clusters the poller has not read through since their
            # last job ended (0068). A job finishing is not the same moment as
            # the poller seeing what it did; a page redrawn on the first showed
            # the spinner gone beside counts from before the job. Waited for at
            # most two intervals, the age at which a reading is called stale.
            #
            catching_up = db.clusters_catching_up(
                connection,
                listed_clusters(request, config),
                within=timedelta(seconds=config.poller.interval_seconds * 2),
            )
        #
        # A cluster being created is busy until the poller has read it, so a
        # page showing its spinner waits for the list rather than redrawing
        # without it (finding 51).
        #
        for entry in _creations(request, recent):
            if entry.running:
                busy.setdefault(entry.cluster, entry.running)
        return JSONResponse({"busy": busy, "catching_up": catching_up})

    @router.get("/proxies", response_class=HTMLResponse)
    def proxy_overview(request: Request) -> Response:
        session = current_session(request)
        if session is None:
            return RedirectResponse("/login", status_code=303)
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        listing = _proxy_listing(request, session.role)
        sort, asked = proxies.TABLE.chosen(request)
        response = TEMPLATES.TemplateResponse(
            request,
            "proxies.html",
            {
                "username": session.username,
                "role": session.role,
                "csrf_token": auth.csrf_token(token),
                **listing,
                "section": "proxies",
                "discarded": request.query_params.get("discarded", ""),
                "management_writes": config.management_writes,
                "demo_fixture": config.demo_fixture,
                "proxy_sort": sort,
                "proxy_sorts": proxies.TABLE.links(
                    sort, listing["used"].query() if listing["used"] else None
                ),
                "proxy_paging": proxies.pages_asked(request.query_params),
            },
        )
        if asked:
            proxies.TABLE.remember(response, sort, secure=config.session.cookie_secure)
        return response

    #
    # The rows on their own, so a listing can catch up without the page being
    # drawn again. A row moves for reasons that happen elsewhere - a publish
    # finishes, a deploy reaches the nodes - and until this existed the only
    # way to see it was to reload, which loses the scroll position and blinks
    # the whole page for one changed cell.
    #
    # Rendered from the same macro the page uses, and never from a second copy
    # of the markup. What comes back is markup for a `tbody` and the three
    # numbers above it; the browser puts each where it belongs.
    #
    @router.get("/proxies/rows")
    def proxy_rows(request: Request) -> Response:
        session = current_session(request)
        if session is None:
            return JSONResponse({"detail": "not signed in"}, status_code=401)
        listing = _proxy_listing(request, session.role)
        #
        # Fetched by name because a template module carries no type: the macro
        # is declared in the template and the checker cannot see it. The name
        # is bound to a test, which is what actually keeps the two in step.
        #
        template: Any = TEMPLATES.env.get_template("_proxy-rows.html").module
        macro = template.proxy_rows
        #
        # In the order the page was drawn in: the cookie the heading set comes
        # with this request too.
        #
        order, _asked = proxies.TABLE.chosen(request)
        clusters = {
            view.cluster: str(
                macro(
                    view.cluster,
                    session.role,
                    listing["drafts"].get(view.cluster, ()),
                    listing["publishing"].get(view.cluster, ()),
                    listing["listed"].get(view.cluster, ()),
                    listing["unmanaged"].get(view.cluster, ()),
                    listing["health"].get(view.cluster, {}),
                    listing["removed"].get(view.cluster, ()),
                    listing["failed"].get(view.cluster, {}),
                    listing["reconfigured"].get(view.cluster, frozenset())
                    if view.cluster in listing["behind"]
                    else frozenset(),
                    order,
                    proxies.pages_asked(request.query_params),
                    listing["unforwarded"].get(view.cluster, ()),
                    listing["used"],
                )
            )
            for view in listing["proxies"].clusters
        }
        counts = listing["counts"]
        return JSONResponse(
            {
                "clusters": clusters,
                "counts": {
                    "published": counts.published,
                    "managed": counts.managed,
                    "unmanaged": counts.unmanaged,
                },
            }
        )

    #
    # Declared above `/proxies/{cluster}/{name}`, and the order is the whole
    # reason it works: both are two segments, and the router takes the first
    # that matches, so a route declared after it would never be reached and
    # `new` would open the detail page for an object nobody has.
    #
    @router.get("/proxies/{cluster}/new", response_class=HTMLResponse)
    def new_object_form(request: Request, cluster: str) -> Response:
        return _editor_page(request, config, cluster, "", None)

    @router.post("/proxies/{cluster}/new", response_class=HTMLResponse)
    def new_object_submit(
        request: Request,
        cluster: str,
        form: Annotated[editor_module.ObjectForm, Form()],
    ) -> Response:
        return _editor_submit(request, config, cluster, "", form)

    @router.get("/proxies/{cluster}/{name}/edit", response_class=HTMLResponse)
    def edit_object_form(request: Request, cluster: str, name: str) -> Response:
        saved = request.query_params.get("saved") == "1"
        return _editor_page(
            request,
            config,
            cluster,
            name,
            None,
            open_group="waf" if request.query_params.get("open") == "waf" else "",
            #
            # The card under it says which: a draft or saved changes (B257).
            #
            notice=SAVED_NOTICE if saved else "",
        )

    @router.post("/proxies/{cluster}/{name}/edit", response_class=HTMLResponse)
    def edit_object_submit(
        request: Request,
        cluster: str,
        name: str,
        form: Annotated[editor_module.ObjectForm, Form()],
    ) -> Response:
        return _editor_submit(request, config, cluster, name, form)

    #
    # *Publish again* beside the warning that a dns server's name has moved
    # (B253): the stored object, published as the editor would publish it, so
    # the name is looked up again. Nothing here bypasses the editor's checks.
    #
    @router.post("/proxies/{cluster}/{name}/lookup", response_class=HTMLResponse)
    def lookup_object_again(
        request: Request,
        cluster: str,
        name: str,
        csrf_token: Annotated[str, Form()] = "",
    ) -> Response:
        return _lookup_again(request, config, cluster, name, csrf_token)

    #
    # Removing an object. Declared before `/proxies/{cluster}/{name}` for the
    # reason `new` is: the router takes the first route that matches, and both
    # are two segments.
    #
    # It is a page of its own rather than a fifth button in the editor. It is
    # the one action here that takes a site off the internet, going back cannot
    # undo it, and a confirmation inside a browser dialog is one people click
    # through without reading.
    #
    @router.get("/proxies/{cluster}/{name}/remove", response_class=HTMLResponse)
    def remove_object_form(request: Request, cluster: str, name: str) -> Response:
        session = current_session(request)
        if session is None:
            return RedirectResponse("/login", status_code=303)
        if not config.management_writes:
            #
            # 404 and not 403, for the reason `/operations` gives: an
            # installation that does not do management writes has no editor,
            # and saying "forbidden" would announce one waiting to be switched
            # on.
            #
            return PlainTextResponse("Not found", status_code=404)
        if session.role != "admin":
            return PlainTextResponse("Refused", status_code=403)
        state = _editor_state(request, config, cluster)
        stored = next((view for view in state.stored if view.name == name), None)
        if stored is None:
            return _refusal_page(
                request,
                config,
                "This cluster has no object of that name to remove.",
                back="/proxies",
            )
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        return TEMPLATES.TemplateResponse(
            request,
            "remove.html",
            {
                "username": session.username,
                "role": session.role,
                "csrf_token": auth.csrf_token(token),
                "cluster": cluster,
                "name": name,
                "hostnames": stored.hostnames,
                "section": "proxies",
                "management_writes": config.management_writes,
                "demo_fixture": config.demo_fixture,
            },
        )

    @router.post("/proxies/{cluster}/{name}/remove", response_class=HTMLResponse)
    def remove_object_submit(
        request: Request,
        cluster: str,
        name: str,
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        return _removal_submit(request, config, cluster, name, csrf_token)

    #
    # The advanced config dialog's *Check* and *Save* (Fas 17, B223). Answered
    # with the part of the dialog that changes, never with a page: the dialog
    # is the only way in (decided 2026-10-01), and a page of its own would be a
    # second editor for the same draft.
    #
    @router.post("/proxies/{cluster}/{name}/advanced", response_class=HTMLResponse)
    def advanced_config_submit(
        request: Request,
        cluster: str,
        name: str,
        action: Annotated[str, Form(max_length=16)] = "check",
        advanced: Annotated[str, Form()] = "",
        handwritten_pool: Annotated[bool, Form()] = False,
        expected_revision: Annotated[str, Form(max_length=16)] = "",
        object_fingerprint: Annotated[str, Form(max_length=64)] = "",
        csrf_token: Annotated[str, Form(max_length=128, alias=auth.CSRF_FIELD)] = "",
    ) -> Response:
        return _advanced_submit(
            request,
            config,
            cluster,
            name,
            action=action,
            text=advanced,
            handwritten=handwritten_pool,
            expected_revision=expected_revision,
            object_fingerprint=object_fingerprint,
            csrf_token=csrf_token,
        )

    @router.post("/proxies/{cluster}/{name}/servers")
    def proxy_servers(
        request: Request,
        cluster: str,
        name: str,
        csrf_token: Annotated[str, Form(max_length=128)],
        idempotency_key: Annotated[str, Form(max_length=64)],
        state: Annotated[str, Form(max_length=16)],
    ) -> Response:
        """Queue drain, maintenance or ready for the ticked servers (B263).

        The helper finds every server in the object's newest version again
        before a node is asked, so what is checked here is the shape only.
        """

        gate = _admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return PlainTextResponse("Refused", status_code=403)
        listed = next((one for one in listed_clusters(request, config) if one == cluster), None)
        if listed is None or not proxy_model.NAME.fullmatch(name):
            return PlainTextResponse("Not found", status_code=404)
        try:
            key = UUID(idempotency_key)
        except ValueError:
            return PlainTextResponse("A request key is required", status_code=400)
        back = f"/proxies/{listed}/{name}"
        posted = _posted(request)
        #
        # One past the bound, so the helper's own limit refuses a request
        # over it rather than this quietly sending part of one.
        #
        chosen = list(dict.fromkeys(str(entry)[:300] for entry in posted.getlist("server")))[
            : server_state.MAX_SERVERS + 1
        ]
        if not chosen:
            return RedirectResponse(f"{back}?servers=none", status_code=303)
        payload = {"object": name, "servers": chosen, "state": state}
        try:
            operations.prepare(
                operation=server_state.OPERATION,
                cluster=listed,
                request_id=uuid4(),
                payload=payload,
            )
        except operations.BadPayload:
            return PlainTextResponse("Invalid operation parameters", status_code=400)
        with request.app.state.pool.connection() as connection:
            try:
                job = db.queue_job(
                    connection,
                    operation=server_state.OPERATION,
                    cluster=listed,
                    payload=payload,
                    idempotency_key=key,
                )
            except db.ClusterBusy:
                connection.rollback()
                return RedirectResponse(f"{back}?servers=busy", status_code=303)
            except db.RequestConflict:
                connection.rollback()
                return PlainTextResponse("That request key asked for something else", 409)
            db.record_audit_event(
                connection,
                actor=gate.username,
                action="queue_job",
                cluster=listed,
                request_id=job.request_id,
                detail={
                    "operation": server_state.OPERATION,
                    "job": job.id,
                    "object": name,
                    "state": state,
                    "servers": chosen,
                },
            )
            connection.commit()
        return RedirectResponse(back, status_code=303)

    @router.post("/proxies/{cluster}/{name}/unblock")
    def proxy_unblock(
        request: Request,
        cluster: str,
        name: str,
        csrf_token: Annotated[str, Form(max_length=128)],
        idempotency_key: Annotated[str, Form(max_length=64)],
    ) -> Response:
        """Queue lifting the object's dynamic block on the ticked addresses (B271).

        The helper reads each address and the object's newest version again
        before a node is asked; what is checked here is the shape only.
        """

        gate = _admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return PlainTextResponse("Refused", status_code=403)
        listed = next((one for one in listed_clusters(request, config) if one == cluster), None)
        if listed is None or not proxy_model.NAME.fullmatch(name):
            return PlainTextResponse("Not found", status_code=404)
        try:
            key = UUID(idempotency_key)
        except ValueError:
            return PlainTextResponse("A request key is required", status_code=400)
        back = f"/proxies/{listed}/{name}"
        posted = _posted(request)
        #
        # One past the bound, so the helper's own limit refuses a request over
        # it rather than this quietly sending part of one.
        #
        chosen = list(dict.fromkeys(str(entry)[:64] for entry in posted.getlist("address")))[
            : server_state.MAX_ADDRESSES + 1
        ]
        if not chosen:
            return RedirectResponse(f"{back}?blocked=none", status_code=303)
        payload = {"object": name, "addresses": chosen}
        try:
            operations.prepare(
                operation=server_state.UNBLOCK_OPERATION,
                cluster=listed,
                request_id=uuid4(),
                payload=payload,
            )
        except operations.BadPayload:
            return PlainTextResponse("Invalid operation parameters", status_code=400)
        with request.app.state.pool.connection() as connection:
            try:
                job = db.queue_job(
                    connection,
                    operation=server_state.UNBLOCK_OPERATION,
                    cluster=listed,
                    payload=payload,
                    idempotency_key=key,
                )
            except db.ClusterBusy:
                connection.rollback()
                return RedirectResponse(f"{back}?blocked=busy", status_code=303)
            except db.RequestConflict:
                connection.rollback()
                return PlainTextResponse("That request key asked for something else", 409)
            db.record_audit_event(
                connection,
                actor=gate.username,
                action="queue_job",
                cluster=listed,
                request_id=job.request_id,
                detail={
                    "operation": server_state.UNBLOCK_OPERATION,
                    "job": job.id,
                    "object": name,
                    "addresses": chosen,
                },
            )
            connection.commit()
        return RedirectResponse(back, status_code=303)

    @router.get("/proxies/{cluster}/{name}", response_class=HTMLResponse)
    def proxy_object(request: Request, cluster: str, name: str) -> Response:
        """One proxy as it is written, beside the row the nodes are serving.

        Admin only, for the reason B68 gives about the preview: the stored
        document names certificates and every backend address behind a site,
        and the overview this is reached from deliberately shows neither.
        """

        session = current_session(request)
        if session is None:
            return RedirectResponse("/login", status_code=303)
        if session.role != "admin":
            return PlainTextResponse("Refused", status_code=403)
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        clusters, object_rows = read_source(request, config, OBJECTS_SOURCE)
        if cluster not in clusters:
            raise HTTPException(status_code=404)
        _, inventory_rows = read_source(request, config, INVENTORY_SOURCE)
        overview = proxies.build_proxy_overview(
            clusters,
            inventory_rows,
            stale_after=timedelta(seconds=config.poller.interval_seconds * 2),
        )
        published = tuple(
            proxy for view in overview.clusters if view.cluster == cluster for proxy in view.proxies
        )
        _, history_rows = read_source(request, config, HISTORY_SOURCE)
        listing = history.build_history_overview(
            clusters,
            history_rows,
            stale_after=timedelta(seconds=config.poller.interval_seconds * 2),
        )
        versions = tuple(
            version
            for view in listing.clusters
            if view.cluster == cluster
            for version in view.versions
        )
        #
        # Released is not serving, so the deploy state is read too. Reporting a
        # release as live while every node still pulls the previous one is the
        # one thing this card must not do.
        #
        _, status_rows = read_source(request, config, STATUS_SOURCE)
        board = dashboard.build_dashboard(
            clusters,
            status_rows,
            stale_after=timedelta(seconds=config.poller.interval_seconds * 2),
        )
        serving = next((view for view in board.clusters if view.cluster == cluster), None)
        #
        # What the nodes report, not the target they were given. The cluster
        # view's `version` is the version they are meant to reach, so using it
        # here would have the page say "the nodes are on v29" at the exact
        # moment they are not.
        #
        running = sorted({node.version for node in serving.nodes}) if serving else []
        node_version = running[0] if len(running) == 1 else ", ".join(running)
        #
        # An object that names no VIP is served on the cluster's default, which
        # is why the address is read from the network description rather than
        # from the object.
        #
        # The object's own VIP where it names one (B221, 2026-10-01): until
        # then this said "default" for every object, including one served on
        # another address. The default below is for an object with no stored
        # document, served from configuration not written here.
        #
        _, network_rows = read_source(request, config, NETWORK_SOURCE)
        network_rows = tuple(network_rows)
        object_rows = tuple(object_rows)
        written = next(
            (
                view
                for row in object_rows
                if row.cluster == cluster
                for view in objects.cluster_object_views(row)
                if view.name == name
            ),
            None,
        )
        # As the objects helper reported it (B222).
        resolved = written.addresses if written is not None else None
        described = next(
            (
                view
                for view in network.build_network_overview(
                    clusters,
                    network_rows,
                    stale_after=timedelta(seconds=config.poller.interval_seconds * 2),
                )
                if view.cluster == cluster
            ),
            None,
        )
        vip = (
            next((item for item in described.vips if item.is_default), None) if described else None
        )
        #
        # Whether *this* object is one the pending deploy carries. The release
        # state is the cluster's, and wearing it here told somebody opening an
        # untouched site that it was waiting for a deploy - the same mistake
        # the listing rows made before they were given this per-object answer.
        #
        object_state = health.object_states(status_rows, cluster=cluster).get(name, objects.UNKNOWN)
        #
        # The same fallback the listing uses, so the two pages cannot say
        # different things about one object. Where the releases cannot be
        # compared, a publish job naming this object is still a fact about
        # something that happened - and it is asked only for that.
        #
        if object_state == objects.UNKNOWN:
            with request.app.state.pool.connection() as connection:
                carried = objects.carried_since_deploy(db.recent_jobs(connection, cluster=cluster))
            if name in carried:
                object_state = objects.CHANGED
        detail = objects.build_object_detail(
            cluster,
            name,
            object_rows,
            published,
            versions,
            release_state=serving.release_state if serving else "",
            node_version=node_version,
            object_state=object_state,
            vip=resolved.vip_name if resolved else (vip.name if vip else None),
            vip_address=(resolved.vip.address or None)
            if resolved
            else (vip.address if vip else None),
            vip_is_default=resolved.vip_is_default if resolved else vip is not None,
            stale_after=timedelta(seconds=config.poller.interval_seconds * 2),
        )
        #
        # A draft makes a name a page too. An object that has only ever been
        # written here is stored nowhere and served nowhere, and without this it
        # would be a 404 - which is what somebody would meet immediately after
        # saving their first draft of it.
        #
        with request.app.state.pool.connection() as connection:
            #
            # `detail.stored` is this cluster's own reading of the object, so a
            # draft whose publish has finished is kept until that reading shows
            # it. Otherwise the page loses both between the job and the poll.
            #
            draft = _settled_draft(
                connection,
                cluster,
                name,
                _objects_reading(
                    next((row for row in object_rows if row.cluster == cluster), None),
                    {name} if detail.stored else set(),
                ),
            )
        #
        # A name that is neither stored, nor served, nor drafted is not a page.
        # Rendering an empty detail for any string would make every typo look
        # like a proxy somebody had deleted.
        #
        if detail.stored is None and detail.published is None and detail.available and not draft:
            raise HTTPException(status_code=404)
        #
        # What the advanced config dialog opens with: the draft's text when there
        # is a draft, as the editor opens the draft (Fas 17). Read whatever the
        # switch says, because the page says an object carries text either way
        # (B224) - the switch only hides the button.
        #
        base = (
            draft.yaml
            if draft is not None and not draft.deleted
            else (detail.stored.document if detail.stored is not None else "")
        )
        advanced = advanced_dialog.opened(base) if base else None
        #
        # What has actually gone through this object's backends lately. Read from
        # the samples the poller stores rather than from the nodes, so opening
        # the page reaches nothing: it is history, and history is the one thing
        # a node cannot be asked for.
        #
        # Which backends this page can ask about, from both places a name can come
        # from - and it needs both.
        #
        # The inventory knows proxies by the name the runtime serves them under,
        # which for a managed object is the shared VIP frontend and never the
        # object. So `published` is None for every managed object, and keying
        # the card off it alone removed the card from exactly the pages it was
        # built for. It stays because it is the only name an *unmanaged* proxy
        # has: nobody wrote a document for it here.
        #
        # The stored document answers for the other half, through the same
        # naming rule the generator uses. Read with the engine's own reader, so
        # nothing here holds a second opinion about what the file says.
        #
        traffic: list[metrics.BackendTraffic] = []
        chosen = metrics.window(request.query_params.get("traffic"))
        #
        # One moment for every backend on the page, so the cards share an axis and
        # can be compared against each other rather than each against the
        # instant its own query ran. Taken before the marked range is read,
        # because a range only means anything inside the window it was marked
        # in and is checked against these two.
        #
        now = datetime.now(UTC)
        since = now - chosen.span
        marked = metrics.selection(
            request.query_params.get("from"),
            request.query_params.get("to"),
            start=since,
            end=now,
            bucket=chosen.bucket,
        )
        #
        # The figures answer for the marked range where there is one, while the
        # drawing keeps the whole window. That is the point of marking: the
        # shape says where to look and the numbers say what was there, and a
        # graph that redrew itself to the marks would throw away the context
        # that made them worth marking.
        #
        counted_since, counted_until = marked.counted(since, now)
        served: list[str] = list(detail.published.backends if detail.published else ())
        targets: dict[str, metrics.BackendTarget] = {}
        #
        # A dns object's pool is counted by dnsdist (Fas 19a B4) and drawn with
        # a resolver's figures rather than HAProxy's.
        #
        figures = metrics.HTTP_FIGURES
        servers: server_card.ServerCard | None = None
        server_set_by: dict[str, str] = {}
        server_shared: dict[str, tuple[search_index.Sharer, ...]] = {}
        proxy: proxy_model.Proxy | None = None
        if detail.stored is not None:
            try:
                proxy = load_proxy(name, detail.stored.document.encode())
            except ModelError:
                proxy = None
            if proxy is not None:
                figures = OBJECT_FIGURES.get(proxy.listen.protocol, metrics.HTTP_FIGURES)
                #
                # Drain, maintenance and ready (B263), under the stored object.
                #
                servers = server_card.build(
                    proxy,
                    status_rows,
                    cluster=cluster,
                    current=detail.publication is not None and detail.publication.tone == "healthy",
                    sourced=written is not None and written.sourced,
                )
                #
                # Who took a server out, and when (B275): the newest queue that
                # asked for the state it is in now.
                #
                held = [
                    (row.target, state)
                    for row in (servers.rows if servers is not None else ())
                    for state in ("drain", "maint")
                    if any(cell.label.startswith(state.upper()) for cell in row.cells)
                ]
                if held:
                    with request.app.state.pool.connection() as connection:
                        asked = audit.set_by(
                            db.server_state_events(connection, cluster=cluster, object_name=name)
                        )
                    for target, state in held:
                        found = asked.get((target, state))
                        if found is not None and target not in server_set_by:
                            server_set_by[target] = f"Set by {found.actor} · {found.shown_at}"
                #
                # The same server in other objects (26-10-18): a drain here
                # leaves them sending to it. From the search's rows, which the
                # demo fixture builds in memory as the search page does.
                #
                if servers is not None and servers.rows:
                    addresses = sorted({row.target.rsplit("/", 1)[1] for row in servers.rows})
                    if config.demo_fixture:
                        _, object_rows = read_source(request, config, OBJECTS_SOURCE)
                        backend_rows = search_index.backend_rows(
                            (
                                entry
                                for row in object_rows
                                if row.cluster == cluster
                                and row.outcome in ("done", "partial")
                                and isinstance(row.result, Mapping)
                                for entry in search_index.entries_for(
                                    "objects", row.cluster, row.result
                                )
                                or []
                            ),
                            cluster,
                        )
                    else:
                        with request.app.state.pool.connection() as connection:
                            backend_rows = db.backend_rows(
                                connection, cluster=cluster, addresses=addresses
                            )
                    shared = search_index.shared_servers(backend_rows, name, addresses)
                    server_shared = {
                        row.target: shared[row.target.rsplit("/", 1)[1]]
                        for row in servers.rows
                        if row.target.rsplit("/", 1)[1] in shared
                    }
            if proxy is not None:
                #
                # One card per backend the object has now, each reading the
                # names it had before as well: the generator's older form
                # (B250) and any rename recorded at a publish.
                #
                targets = metrics.backend_targets({name: proxy})
                served.extend(
                    dict.fromkeys(
                        target.current
                        for target in targets.values()
                        if target.current not in served
                    )
                )
        if served:
            with request.app.state.pool.connection() as connection:
                aliases = db.read_backend_aliases(connection, cluster=cluster)

            def samples(backend: str) -> Callable[[Any], list[metrics.Interval]]:
                return lambda connection: db.read_backend_series(
                    connection,
                    cluster=cluster,
                    backend=backend,
                    since=since,
                    until=now,
                    width=chosen.bucket,
                    earlier=_earlier_names(backend, targets, aliases),
                )

            def totals(backend: str) -> Callable[[Any], metrics.BackendMeasurement]:
                def read(connection: Any) -> metrics.BackendMeasurement:
                    found = db.read_backend_totals(
                        connection,
                        cluster=cluster,
                        backend=backend,
                        since=counted_since,
                        until=counted_until,
                        earlier=_earlier_names(backend, targets, aliases),
                        counters=metrics.summed(figures),
                    )
                    return metrics.measured(figures, found)

                return read

            reads: list[Callable[[Any], Any]] = [
                read for backend in served for read in (samples(backend), totals(backend))
            ]
            answers = _read_concurrently(request.app.state.pool, reads)
            traffic = [
                metrics.backend_traffic(
                    metrics.backend_label(backend, targets),
                    answers[index * 2],
                    tick_format=chosen.tick,
                    start=since,
                    end=now,
                    bucket=chosen.bucket,
                    chosen=marked,
                    measurement=answers[index * 2 + 1],
                    figures=figures,
                )
                for index, backend in enumerate(served)
            ]
        moved = moved_dns_servers(status_rows, cluster=cluster, pools=served)
        #
        # The card's buttons give way to whatever the cluster is busy with, as
        # on every page that queues a job; and the last drain or maintenance of
        # this object that not every node took is said until the next one.
        #
        servers_busy: str | None = None
        blocked_busy: str | None = None
        cluster_busy: str | None = None
        servers_missed = ""
        #
        # The addresses the object's dynamic blocking holds (B271), with the
        # last unblock that not every node took said until the next one.
        #
        blocked_card = blocked.object_card(status_rows, cluster=cluster, name=name)
        #
        # A block comes and goes on its own time, so a page that can show one
        # draws itself again once per poll; other objects' pages stay still,
        # since each drawing reads their traffic again.
        #
        blocking = blocked_card is not None or (
            proxy is not None and proxy.dynamic_block is not None
        )
        blocked_missed = ""
        if servers is not None or blocked_card is not None:
            with request.app.state.pool.connection() as connection:
                recent = db.recent_jobs(connection, cluster=cluster)
            cluster_busy = jobs.in_flight(recent).get(cluster)
            #
            # The queue takes one job per cluster, so while any runs both
            # cards lose their buttons; the spinner says what runs on the card
            # it belongs to, and a job for the whole cluster on both (26-10-10).
            #
            in_progress: str | None = next(
                (
                    job.operation
                    for job in recent
                    if job.cluster == cluster and job.state in {"pending", "running"}
                ),
                None,
            )
            servers_busy = cluster_busy if in_progress != server_state.UNBLOCK_OPERATION else None
            blocked_busy = cluster_busy if in_progress != server_state.OPERATION else None
            unblocked = next(
                (
                    job
                    for job in recent
                    if job.operation == server_state.UNBLOCK_OPERATION
                    and job.payload.get("object") == name
                ),
                None,
            )
            if unblocked is not None and unblocked.state not in {"pending", "running"}:
                if unblocked.outcome == "partial":
                    blocked_missed = "Not every node lifted the last unblock."
                elif unblocked.outcome != "done":
                    blocked_missed = "The last unblock was not made."
            last = next(
                (
                    job
                    for job in recent
                    if job.operation == server_state.OPERATION and job.payload.get("object") == name
                ),
                None,
            )
            #
            # What the last one did, in its own words (review 26-10-09, F7):
            # `partial` is a node that did not take it, anything else that is
            # not `done` is a change that was not made at all - a refusal before
            # any node was asked among them.
            #
            if last is not None and last.state not in {"pending", "running"}:
                if last.outcome == "partial":
                    servers_missed = "Not every node took the last change."
                elif last.outcome != "done":
                    servers_missed = "The last change was not made."
        return TEMPLATES.TemplateResponse(
            request,
            "object.html",
            {
                "dns_moved": moved,
                "servers": servers,
                "server_set_by": server_set_by,
                "server_shared": server_shared,
                "servers_notice": SERVER_NOTICES.get(request.query_params.get("servers", "")),
                "servers_busy": servers_busy,
                "blocked_busy": blocked_busy,
                "cluster_busy": cluster_busy,
                "servers_missed": servers_missed,
                "blocked": blocked_card,
                "blocked_notice": BLOCKED_NOTICES.get(request.query_params.get("blocked", "")),
                "blocked_missed": blocked_missed,
                "time_left": blocked.time_left,
                "live_seconds": (
                    blocked.live_seconds(
                        config.poller.interval_seconds,
                        blocked.next_change(status_rows, (cluster,)),
                    )
                    if blocking and not config.demo_fixture
                    else None
                ),
                "username": session.username,
                "role": session.role,
                "csrf_token": auth.csrf_token(token),
                "section": "proxies",
                "object": detail,
                #
                # The exact names other objects answer under this one's
                # subdomain (B278): theirs, wholly, and said here.
                #
                #
                # HTTP/3 is the VIP's (B280); an https object served on one that
                # has it says so, since nothing in the object does.
                #
                "http3_vip": next(
                    (
                        item.name
                        for item in (described.vips if described else ())
                        if item.http3
                        and item.name == detail.vip
                        and written is not None
                        and written.protocol == "https"
                    ),
                    None,
                ),
                "answered_elsewhere": objects.answered_elsewhere(
                    name,
                    detail.stored.hostnames if detail.stored is not None else (),
                    objects.cluster_object_views(
                        next((row for row in object_rows if row.cluster == cluster), None)
                    ),
                ),
                "draft": draft,
                "advanced": advanced,
                "object_fingerprint": editor_module.fingerprint(
                    detail.stored.document if detail.stored is not None else None
                ),
                "stored_advanced": bool(
                    detail.stored is not None
                    and advanced_dialog.opened(detail.stored.document).text
                ),
                "advanced_offered": (
                    config.management_writes
                    and advanced is not None
                    and features.is_on(features.ADVANCED_CONFIG)
                    and not (draft is not None and draft.deleted)
                ),
                #
                # What just happened, carried in the redirect. A 303 leaves
                # nothing behind, so without it a save that worked and a page
                # somebody merely opened look exactly alike.
                #
                "saved": request.query_params.get("saved") == "1",
                "discarded": request.query_params.get("discarded") == "1",
                "traffic": traffic,
                "traffic_window": chosen.label,
                "traffic_bucket": chosen.bucket_label,
                "traffic_rate_unit": chosen.rate_unit,
                "traffic_windows": metrics.WINDOWS,
                "traffic_chosen": chosen.key,
                **_traffic_marks(request, marked),
                #
                # The object's own traffic and WAF requests are one link away
                # (26-10-10), where there is a traffic log to open.
                #
                "traffic_logs_enabled": config.traffic_logs.enabled,
                #
                # More than one backend is the only case where naming them helps.
                # With one, the name is the object's own backend written twice
                # in a row and answers nothing the page has not said.
                #
                "traffic_named": len(traffic) > 1,
                "spark_width": metrics.SPARK_WIDTH,
                "spark_height": metrics.SPARK_HEIGHT,
                "management_writes": config.management_writes,
                "demo_fixture": config.demo_fixture,
            },
        )

    def _documents(readings: Iterable[Any], cluster: str) -> dict[str, Any]:
        """One cluster's stored objects, as the engine's own model reads them.

        Read with `load_proxy` rather than with a second parser here, so this
        page cannot hold an opinion about a document that differs from the one
        the generator acts on. An object this version cannot read is skipped:
        it is reported where it is opened, and a traffic card is not the place
        to raise it a second time.
        """

        by_cluster = {reading.cluster: reading for reading in readings}
        found: dict[str, Any] = {}
        for view in objects.cluster_object_views(by_cluster.get(cluster)):
            try:
                found[view.name] = load_proxy(view.name, view.document.encode())
            except ModelError:
                continue
        return found

    def _cluster_traffic(request: Request, config: Config, only: str | None) -> Response:
        """Traffic for every cluster, or for one of them.

        Cluster-level from end to end, which is why it is its own page rather
        than something reached from a proxy: a frontend belongs to the address
        and to the cluster and never to an object (B94), and "which backend
        carries this" cannot be asked from inside the backend somebody already
        picked.

        Admin only, for the same reason as the object page: naming every
        frontend and backend a cluster carries describes the shape of what is
        published, which the overview deliberately does not.
        """

        session = current_session(request)
        if session is None:
            return RedirectResponse("/login", status_code=303)
        if session.role != "admin":
            return PlainTextResponse("Refused", status_code=403)
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        clusters, _rows = read_source(request, config, STATUS_SOURCE)
        if only is not None and only not in clusters:
            raise HTTPException(status_code=404)
        wanted = [only] if only is not None else list(clusters)
        #
        # The stored documents, only so a generated redirect can be named by
        # what it does. Its configuration name is a digest of the route that
        # made it, which is right for counters that must survive an edit and
        # unreadable on a page.
        #
        _, object_rows = read_source(request, config, OBJECTS_SOURCE)

        chosen = metrics.window(request.query_params.get("traffic"))
        #
        # One moment for the whole page. Two queries taken a second apart would
        # give the sections axes that do not quite line up, and the only use of
        # this page is holding one against another.
        #
        now = datetime.now(UTC)
        since = now - chosen.span
        marked = metrics.selection(
            request.query_params.get("from"),
            request.query_params.get("to"),
            start=since,
            end=now,
            bucket=chosen.bucket,
        )
        #
        # One range across every card on the page. The sections already share
        # an axis, and the question this page exists to answer - which of these
        # carried the traffic - is asked of one stretch of time at a time.
        #
        counted_since, counted_until = marked.counted(since, now)

        pool = request.app.state.pool
        #
        # The names first, on one connection: they are cheap, and every card's
        # readings depend on them.
        #
        listed: list[tuple[str, list[str], list[tuple[str, bool]], dict[str, metrics.Figures]]] = []
        #
        # Each backend's earlier names, so a renamed one keeps its history
        # under the name it has now: the generator's own rename (B250) from the
        # objects, and a pool somebody renamed from the record of the publish.
        #
        targets_of = {
            cluster: metrics.backend_targets(_documents(object_rows, cluster)) for cluster in wanted
        }
        aliases: dict[str, dict[str, list[db.EarlierName]]] = {}
        with pool.connection() as connection:
            for cluster in wanted:
                aliases[cluster] = db.read_backend_aliases(connection, cluster=cluster)
                listed.append(
                    (
                        cluster,
                        [
                            backend
                            for backend in db.read_cluster_backends(
                                connection, cluster=cluster, since=since, until=now
                            )
                            if not metrics.is_engine(backend)
                        ],
                        #
                        # Name and ownership apart: an address nobody reported
                        # holding is still an address this cluster saw, and it
                        # says so on its own card rather than being left off
                        # the page.
                        #
                        [
                            seen
                            for seen in db.read_cluster_frontends(
                                connection, cluster=cluster, since=since, until=now
                            )
                            if not metrics.is_exporter(seen[0])
                        ],
                        #
                        # dnsdist's pools (Fas 19a B4) and IPVS's (19b B3),
                        # each with its own figures: queries and messages are
                        # not requests.
                        #
                        {
                            **dict.fromkeys(
                                db.read_cluster_backends(
                                    connection,
                                    cluster=cluster,
                                    since=since,
                                    until=now,
                                    kind="dns",
                                ),
                                metrics.DNS_FIGURES,
                            ),
                            **dict.fromkeys(
                                db.read_cluster_backends(
                                    connection,
                                    cluster=cluster,
                                    since=since,
                                    until=now,
                                    kind="syslog",
                                ),
                                metrics.SYSLOG_FIGURES,
                            ),
                        },
                    )
                )

        def frontend_reads(
            cluster: str, name: str
        ) -> tuple[Callable[[Any], list[metrics.Interval]], Callable[[Any], Any]]:
            def samples(connection: Any) -> list[metrics.Interval]:
                return db.read_frontend_series(
                    connection,
                    cluster=cluster,
                    frontend=name,
                    since=since,
                    until=now,
                    width=chosen.bucket,
                )

            def totals(connection: Any) -> metrics.BackendMeasurement:
                return db.read_frontend_totals(
                    connection,
                    cluster=cluster,
                    frontend=name,
                    since=counted_since,
                    until=counted_until,
                )

            return samples, totals

        def backend_reads(
            cluster: str, name: str
        ) -> tuple[Callable[[Any], list[metrics.Interval]], Callable[[Any], Any]]:
            earlier = _earlier_names(name, targets_of[cluster], aliases[cluster])

            def samples(connection: Any) -> list[metrics.Interval]:
                return db.read_backend_series(
                    connection,
                    cluster=cluster,
                    backend=name,
                    since=since,
                    until=now,
                    width=chosen.bucket,
                    earlier=earlier,
                )

            def totals(connection: Any) -> metrics.BackendMeasurement:
                return db.read_backend_totals(
                    connection,
                    cluster=cluster,
                    backend=name,
                    since=counted_since,
                    until=counted_until,
                    earlier=earlier,
                )

            return samples, totals

        def pool_reads(
            cluster: str, name: str, figures: metrics.Figures
        ) -> tuple[Callable[[Any], Any], ...]:
            """A dns or syslog pool's readings: the backend's line, its own figures."""

            earlier = _earlier_names(name, targets_of[cluster], aliases[cluster])
            samples, _totals = backend_reads(cluster, name)

            def totals(connection: Any) -> metrics.BackendMeasurement:
                return metrics.measured(
                    figures,
                    db.read_backend_totals(
                        connection,
                        cluster=cluster,
                        backend=name,
                        since=counted_since,
                        until=counted_until,
                        earlier=earlier,
                        counters=metrics.summed(figures),
                    ),
                )

            return samples, totals

        #
        # Every card's two readings, asked together, then handed back to the
        # section each card belongs to.
        #
        keys: list[tuple[str, str, str]] = []
        reads: list[Callable[[Any], Any]] = []
        spans: list[int] = []
        for cluster, backends, seen, pools in listed:
            for frontend, _owned in seen:
                keys.append((cluster, "frontend", frontend))
                reads.extend(frontend_reads(cluster, frontend))
                spans.append(2)
            for backend in backends:
                keys.append((cluster, "backend", backend))
                reads.extend(backend_reads(cluster, backend))
                spans.append(2)
            for pool_name, figures in pools.items():
                keys.append((cluster, "backend", pool_name))
                reads.extend(pool_reads(cluster, pool_name, figures))
                spans.append(2)
        answers = _read_concurrently(pool, reads)
        read_back: dict[tuple[str, str, str], tuple[Any, ...]] = {}
        at = 0
        for key, span in zip(keys, spans, strict=True):
            read_back[key] = tuple(answers[at : at + span])
            at += span

        def section(
            cluster: str,
            kind: str,
            named: Sequence[str],
            label: Callable[[str], str],
            kinds: Mapping[str, metrics.Figures] | None = None,
        ) -> list[metrics.BackendTraffic]:
            """One section: every series read, drawn against one scale.

            The ceiling has to be known before any card is drawn, so this is
            two passes over the same list rather than one - which is the price
            of the comparison the section exists to make.

            A dns pool sits among the backends (26-10-06) with a resolver's
            figures, its line counting queries where the others count
            requests, and a syslog pool (19b B3) counting messages - each a
            count per bucket, on the one scale.
            """

            def figures_of(name: str) -> metrics.Figures:
                return (kinds or {}).get(name, metrics.HTTP_FIGURES)

            found = [(name, read_back[(cluster, kind, name)]) for name in named]
            ceiling = max(
                (
                    metrics.shared_ceiling(
                        [answered[0]],
                        start=since,
                        end=now,
                        bucket=chosen.bucket,
                        figures=figures_of(name),
                    )
                    for name, answered in found
                ),
                default=0,
            )
            return [
                metrics.backend_traffic(
                    label(name),
                    answered[0],
                    tick_format=chosen.tick,
                    start=since,
                    end=now,
                    bucket=chosen.bucket,
                    measurement=answered[1],
                    ceiling=ceiling,
                    chosen=marked,
                    figures=figures_of(name),
                )
                for name, answered in found
            ]

        drawn = []
        for cluster, backends, seen, pools in listed:
            targets = targets_of[cluster]

            def label(name: str, targets: Mapping[str, metrics.BackendTarget] = targets) -> str:
                """The pool's own name or what it redirects; the stored name where nothing says.

                A page that invented a name would be worse than one showing
                an opaque name it could not resolve.
                """

                return metrics.backend_label(name, targets)

            served_pools, redirects = metrics.split_backends(backends, targets)

            frontends = [frontend for frontend, _owned in seen]
            drawn.append(
                {
                    "cluster": cluster,
                    "accent": accent_index(cluster),
                    "frontends": [
                        (
                            metrics.listening(name),
                            owned,
                            card,
                            metrics.listening(name).protocol == "http",
                        )
                        for (name, owned), card in zip(
                            seen,
                            section(
                                cluster,
                                "frontend",
                                frontends,
                                lambda name: metrics.listening(name).vip,
                            ),
                            strict=True,
                        )
                    ],
                    #
                    # Backends and redirect answers are drawn apart and scaled
                    # apart. A redirect has no servers and answers 3xx itself,
                    # so letting it into the comparison would size every real
                    # backend against traffic that never reached one.
                    #
                    "backends": section(
                        cluster,
                        "backend",
                        #
                        # By the name the card shows, as every list is
                        # alphabetical by what it reads.
                        #
                        sorted([*served_pools, *pools], key=label),
                        label,
                        kinds=pools,
                    ),
                    "redirects": section(cluster, "backend", redirects, label),
                }
            )

        return TEMPLATES.TemplateResponse(
            request,
            "cluster.html",
            {
                "username": session.username,
                "role": session.role,
                "csrf_token": auth.csrf_token(token),
                "section": "metrics",
                "clusters": drawn,
                #
                # Which object each backend card is generated for, by the name
                # the card shows, so it can link to that object's logs
                # (26-10-10); where there is a traffic log to open.
                #
                "backend_owners": {
                    cluster: {target.label: target.owner for target in targets.values()}
                    for cluster, targets in targets_of.items()
                },
                "traffic_logs_enabled": config.traffic_logs.enabled,
                "one_cluster": only,
                "traffic_window": chosen.label,
                "traffic_bucket": chosen.bucket_label,
                "traffic_rate_unit": chosen.rate_unit,
                "traffic_windows": metrics.WINDOWS,
                "traffic_chosen": chosen.key,
                **_traffic_marks(request, marked),
                #
                # Always named here, unlike the object page. Every card on this
                # page is one of several being compared, so which series a line
                # belongs to is the first thing a reader needs.
                #
                "traffic_named": True,
                "spark_width": metrics.SPARK_WIDTH,
                "spark_height": metrics.SPARK_HEIGHT,
                "management_writes": config.management_writes,
                "demo_fixture": config.demo_fixture,
            },
        )

    #
    # The header's search (B221). Every source it reads is a cached reading the
    # pages already draw, so a search asks no node anything; see `search`.
    #
    @router.get("/search", response_class=HTMLResponse)
    def search_page(request: Request) -> Response:
        session = current_session(request)
        if session is None:
            return RedirectResponse("/login", status_code=303)
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        query = search_index.normalise(request.query_params.get("q", ""))
        asked = request.query_params.get("page", "1")
        page = min(int(asked), MAX_SEARCH_PAGE) if is_digits(asked) and int(asked) > 0 else 1
        results = search_index.Results(query, (), 0, 1)
        if query and config.demo_fixture:
            #
            # Neither mode has rows in the database: the readings are a
            # fixture or a file. The same functions the poller uses build the
            # rows, and they are searched in memory.
            #
            clusters = listed_clusters(request, config)
            entries = search_index.cluster_entries(clusters)
            for operation, source in SEARCHED_SOURCES:
                _, rows = read_source(request, config, source)
                for row in rows:
                    if row.outcome in ("done", "partial") and isinstance(row.result, Mapping):
                        entries += (
                            search_index.entries_for(operation, row.cluster, row.result) or []
                        )
            results = search_index.matching(
                entries, query, role=session.role, clusters=clusters, page=page
            )
        elif query:
            clusters = listed_clusters(request, config)
            with request.app.state.pool.connection() as connection:
                results = db.search(
                    connection, query, role=session.role, clusters=clusters, page=page
                )
        return TEMPLATES.TemplateResponse(
            request,
            "search.html",
            {
                "username": session.username,
                "role": session.role,
                "csrf_token": auth.csrf_token(token),
                "section": "search",
                "search_query": query,
                "results": results,
                "management_writes": config.management_writes,
                "demo_fixture": config.demo_fixture,
            },
        )

    @router.get("/metrics", response_class=HTMLResponse)
    def all_traffic(request: Request) -> Response:
        return _cluster_traffic(request, config, None)

    @router.get("/clusters/{cluster}/metrics", response_class=HTMLResponse)
    def cluster_traffic(request: Request, cluster: str) -> Response:
        return _cluster_traffic(request, config, cluster)

    @router.get("/logs", response_class=HTMLResponse)
    def traffic_log_page(request: Request) -> Response:
        return _traffic_log_page(request, waf_page=False)

    #
    # The log warning alone (26-10-12). It was drawn once with the page, so a
    # node catching up said "9 s ago" and the same byte count for as long as
    # the page stayed open. The page asks for this every few seconds and swaps
    # it in; reading the collector's freshness files costs no query of the
    # log, and the table, filters and scroll position are left alone.
    #
    @router.get("/logs/warning", response_class=HTMLResponse)
    def traffic_log_warning(request: Request) -> Response:
        session = current_session(request)
        if session is None:
            return RedirectResponse("/login", status_code=303)
        listed = listed_clusters(request, config)
        selected = request.query_params.get("cluster", "")[:32]
        if not config.traffic_logs.enabled or (selected and selected not in listed):
            reading = traffic_logs.Reading((), (), 0, False)
        else:
            reading = traffic_logs.read_freshness(
                config.traffic_logs.directory, (selected,) if selected else tuple(listed)
            )
        return TEMPLATES.TemplateResponse(
            request,
            "_log-warning.html",
            {
                "enabled": config.traffic_logs.enabled,
                "reading": reading,
                "freshness_warnings": _freshness_warnings(reading, datetime.now(UTC)),
                "selected_cluster": selected,
            },
        )

    #
    # The same reading narrowed to the requests an access rule met (Fas 21,
    # B227): stored once, in the traffic log, and shown on a page of its own so
    # that what the rules see is not mixed into the ordinary traffic.
    #
    @router.get("/waf", response_class=HTMLResponse)
    def waf_page(request: Request) -> Response:
        #
        # A place to work (B234): what the engine found per object and rule,
        # the exceptions objects carry, and - as before - the requests a rule
        # met, which is the traffic log narrowed.
        #
        view = request.query_params.get("view", "")
        if view == "requests":
            return _traffic_log_page(request, waf_page=True)
        return _waf_work_page(request, config, "exceptions" if view == "exceptions" else "findings")

    @router.get("/waf/allow", response_class=HTMLResponse)
    def waf_allow_page(request: Request) -> Response:
        return _waf_allow(request, config, None)

    @router.post("/waf/allow", response_class=HTMLResponse)
    def waf_allow(request: Request) -> Response:
        return _waf_allow(request, config, _posted(request))

    @router.post("/waf/exceptions/remove", response_class=HTMLResponse)
    def waf_remove_exception(request: Request) -> Response:
        return _waf_remove(request, config, _posted(request))

    def _traffic_log_page(request: Request, *, waf_page: bool) -> Response:
        session = current_session(request)
        if session is None:
            return RedirectResponse("/login", status_code=303)
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        selected_cluster = request.query_params.get("cluster", "")[:32]
        selected_status = request.query_params.get("status", "")[:3]
        selected_query = request.query_params.get("q", "")[:200]
        selected_from = request.query_params.get("from", "")[:14]
        selected_to = request.query_params.get("to", "")[:14]
        selected_waf = "hits" if waf_page else request.query_params.get("waf", "")[:4]
        if selected_waf not in ("", "hits", "none"):
            selected_waf = ""
        #
        # One object (26-10-10), from its own page: only with its cluster, as a
        # name is an object only within one.
        #
        selected_object = request.query_params.get("object", "")[:40]
        if not selected_cluster or not proxy_model.NAME.fullmatch(selected_object):
            selected_object = ""
        owned: tuple[tuple[str, ...], tuple[str, ...]] | None = None
        now = datetime.now(UTC)
        local_now = metrics.shown(now)
        local_earliest = metrics.wall(
            datetime.combine(
                local_now.date() - timedelta(days=config.traffic_logs.retention_days - 1),
                datetime.min.time(),
            )
        )
        earliest = local_earliest.astimezone(UTC)
        time_filter_error: str | None
        try:
            from_at = _log_time_filter(selected_from, earliest=earliest, latest=now)
            to_at = _log_time_filter(selected_to, earliest=earliest, latest=now, end_of_minute=True)
            if from_at is not None and to_at is not None and from_at > to_at:
                raise ValueError("From must be earlier than To.")
        except ValueError as exc:
            from_at = None
            to_at = None
            time_filter_error = str(exc)
        else:
            time_filter_error = None
        #
        # HAProxy knows generated backend members only as s1, s2, ... . Resolve
        # those positions before filtering so the one shared search field can
        # find the configured destination as well as the hidden backend name.
        # This intentionally follows the current document: after a backend is
        # edited, old records follow the new ordering rather than pretending
        # the mirror preserved historical configuration that it never stored.
        #
        server_addresses: dict[tuple[str, str, str], str] = {}
        if config.traffic_logs.enabled:
            _, object_rows = read_source(request, config, OBJECTS_SOURCE)
            for object_row in object_rows:
                parsed = []
                if selected_object and object_row.cluster == selected_cluster:
                    #
                    # An object the cluster does not have matches nothing,
                    # rather than every request.
                    #
                    found = next(
                        (
                            view
                            for view in objects.cluster_object_views(object_row)
                            if view.name == selected_object
                        ),
                        None,
                    )
                    owned = (
                        (
                            tuple(found.runtime_backends or ()),
                            traffic_logs.owned_hosts(
                                found.hostnames,
                                (
                                    name
                                    for view in objects.cluster_object_views(object_row)
                                    if view.name != found.name
                                    for name in view.hostnames
                                ),
                            ),
                        )
                        if found is not None
                        else ((), ())
                    )
                for obj in objects.cluster_object_views(object_row):
                    if not obj.readable:
                        continue
                    try:
                        parsed.append(load_proxy(obj.name, obj.document.encode()))
                    except (ModelError, UnicodeError):
                        continue
                server_addresses.update(
                    traffic_logs.configured_server_addresses(object_row.cluster, parsed)
                )
        #
        # Reading files, never asking a node. The collector already fetched
        # these, so a node that is slow, unreachable or hostile cannot make this
        # request hang - it can only make its own mirror old, which is exactly
        # what the compact warning reports.
        #
        if config.traffic_logs.enabled:
            with request.app.state.pool.connection() as connection:
                reading = traffic_logs.read_database(
                    connection,
                    config.traffic_logs.directory,
                    listed_clusters(request, config),
                    limit=config.traffic_logs.max_lines,
                    cluster=selected_cluster,
                    status=selected_status,
                    substring=selected_query,
                    from_at=from_at,
                    to_at=to_at,
                    server_addresses=server_addresses,
                    waf=selected_waf,
                    owned=(owned or ((), ())) if selected_object else None,
                )
        else:
            reading = traffic_logs.Reading((), (), 0, False)
        if time_filter_error is not None:
            reading = replace(reading, entries=(), filter_error=time_filter_error)
        table = traffic_log_table.WAF_TABLE if waf_page else traffic_log_table.TABLE
        sort, asked = table.chosen(request)
        reading = replace(reading, entries=tuple(table.ordered(reading.entries, sort)))
        #
        # A heading keeps the filter: sorting reorders the matches the filter
        # found, it does not start a new reading.
        #
        filters = {
            name: value
            for name, value in (
                ("cluster", selected_cluster),
                ("status", selected_status),
                ("q", selected_query),
                ("from", selected_from),
                ("to", selected_to),
                ("waf", "" if waf_page else selected_waf),
                ("view", "requests" if waf_page else ""),
                ("object", selected_object),
            )
            if value
        }
        freshness_warnings = _freshness_warnings(reading, now)
        #
        # The WAF page's Requests tab carries the same three figures as its
        # other two (mock round 7), over the same clusters and days.
        #
        waf_tabs: dict[str, Any] = {}
        if waf_page:
            listed = listed_clusters(request, config)
            chosen = (selected_cluster,) if selected_cluster in listed else tuple(listed)
            waf_tabs = {"tab_counts": _waf_overview(request, config, chosen).tab_counts()}
        response = TEMPLATES.TemplateResponse(
            request,
            "logs.html",
            {
                **waf_tabs,
                "username": session.username,
                "role": session.role,
                "csrf_token": auth.csrf_token(token),
                "section": "waf" if waf_page else "logs",
                "waf_page": waf_page,
                "selected_waf": selected_waf,
                "selected_object": selected_object,
                "all_objects": ("/waf?" if waf_page else "/logs?")
                + urlencode({key: value for key, value in filters.items() if key != "object"}),
                "management_writes": config.management_writes,
                "enabled": config.traffic_logs.enabled,
                "reading": reading,
                "freshness_warnings": freshness_warnings,
                "clusters": listed_clusters(request, config),
                "selected_cluster": selected_cluster,
                "selected_status": selected_status,
                "selected_query": selected_query,
                "selected_from": selected_from,
                "selected_to": selected_to,
                "time_min": local_earliest.strftime("%y-%m-%d %H:%M"),
                "time_max": local_now.strftime("%y-%m-%d %H:%M"),
                "max_lines": config.traffic_logs.max_lines,
                "log_sorts": table.links(sort, filters),
            },
        )
        if asked:
            table.remember(response, sort, secure=config.session.cookie_secure)
        return response

    @router.get("/network", response_class=HTMLResponse)
    def network_overview(request: Request) -> Response:
        return _network_page(request, config)

    @router.get("/certificates", response_class=HTMLResponse)
    def certificate_overview(request: Request) -> Response:
        session = current_session(request)
        if session is None:
            return RedirectResponse("/login", status_code=303)
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        clusters, certificate_rows = read_source(request, config, CERTIFICATE_SOURCE)
        #
        # The node status too, for the one question the certificate listing
        # cannot answer: whether the nodes are carrying what was published. The
        # listing reads the manager's own directory, the nodes report their own
        # fingerprints, and the registry view needs both to say anything
        # truthful about a cluster target.
        #
        _, status_rows = read_source(request, config, STATUS_SOURCE)
        overview = certificates.build_certificate_overview(
            clusters,
            certificate_rows,
            manager=read_manager_certificates(request, config),
            status_readings=status_rows,
            stale_after=timedelta(seconds=config.poller.interval_seconds * 2),
            taken_out=read_certificate_takeouts(request, config),
        )
        with request.app.state.pool.connection() as connection:
            recent = db.recent_jobs(connection, limit=100)
        running = jobs.in_flight(recent)
        #
        # A row the queue is deleting says so in its State cell instead of
        # the page sending the person to the jobs list to watch; the page
        # refreshes itself while that is going on.
        #
        deleting = certificate_activity.deletion_states(recent)
        #
        # A cluster deploy asked for from a row is said on that row too, with
        # the page refreshing until it ends: the person who pressed Deploy to
        # nodes was looking at the row, not at the jobs page (2026-09-20).
        #
        if overview.registry is not None:
            for identifier, state in certificate_activity.deploy_states(
                overview.registry.certificates, recent
            ).items():
                deleting.setdefault(identifier, state)
        overview = certificates.with_deletion_states(overview, deleting)
        refresh = any(
            deleting[entry.identifier].active
            and entry.state_label == deleting[entry.identifier].label
            for entry in (overview.registry.certificates if overview.registry else ())
            if entry.identifier in deleting
        )
        #
        # Which view and which expanded row, in the query string rather than in
        # script: the page is read-only, the two views are two renderings of
        # cached readings, and a link is something an operator can send to
        # somebody else. The registry is the default since 2026-09-15: it is
        # the complete list, and the one the certificate actions return to.
        #
        chosen = "clusters" if request.query_params.get("view") == "clusters" else "registry"
        #
        # With receivers switched off the registry is the one view (B193): the
        # complete list, where every certificate action lives.
        #
        if not features.is_on(features.CERT_RECEIVERS):
            chosen = "registry"
        if overview.registry is None:
            chosen = "clusters"
        sort, asked = certificates.TABLE.chosen(request)
        response = TEMPLATES.TemplateResponse(
            request,
            "certificates.html",
            {
                "username": session.username,
                "role": session.role,
                "csrf_token": auth.csrf_token(token),
                "certificates": overview,
                "chosen_view": chosen,
                "refresh": refresh,
                "opened": request.query_params.get("open", ""),
                #
                # What this cluster is busy with, read the same way the
                # dashboard reads it. One job per cluster, so the buttons
                # below are replaced by it rather than left drawn to offer an
                # action the queue would refuse with a 409.
                #
                "in_flight": running,
                "management_writes": config.management_writes,
                "section": "certificates",
                "demo_fixture": config.demo_fixture,
                "certificate_sort": sort,
                "certificate_sorts": {
                    view: certificates.TABLE.links(sort, {"view": view})
                    for view in ("registry", "clusters")
                },
            },
        )
        if asked:
            certificates.TABLE.remember(response, sort, secure=config.session.cookie_secure)
        return response

    #
    # Phase 11's gate, as a page: a form, a button, a certificate. The page is
    # its own address rather than a panel on the listing for the reason the
    # object editor is - a refused submission has somewhere to be re-drawn
    # with what was typed still in place.
    #
    @router.get("/certificates/new", response_class=HTMLResponse)
    def new_certificate_form(request: Request) -> Response:
        if request.query_params.get("for") == "interface":
            #
            # The same form for the interface's own certificate (B188): the
            # name it is served on filled in, no targets.
            #
            manager = _certificate_choices(request, config).manager or ""
            return _certificate_form_page(
                request,
                config,
                replace(certificate_form.EMPTY_FORM, domain=manager, interface=True),
            )
        #
        # The kind switch carries what is already filled in (2026-10-06) -
        # the name, the CA and its profile - so changing kind does not empty
        # the form. Only drawn into the fields; the submission checks them
        # like any other.
        #
        query = request.query_params
        typed = replace(
            certificate_form.EMPTY_FORM,
            domain=query.get("domain", "")[:255],
            method=query.get("method") or certificate_form.EMPTY_FORM.method,
            dns_profile=query.get("dns_profile", "")[:255],
            ndes_profile=query.get("ndes_profile", "")[:255],
            key_type=query.get("key_type", "")[:255],
        )
        if request.query_params.get("for") == "external" and features.is_on(
            features.CERT_RECEIVERS
        ):
            #
            # A certificate to take out and install by hand (B255): one name,
            # no targets, its key downloaded from the row.
            #
            # No CSR here: the key must stay with the manager to be exported.
            method = certificate_form.EMPTY_FORM.method if typed.method == "csr" else typed.method
            return _certificate_form_page(
                request, config, replace(typed, method=method, key_type="", exportable=True)
            )
        return _certificate_form_page(request, config, typed)

    @router.post("/certificates/new", response_class=HTMLResponse)
    def new_certificate_submit(
        request: Request,
        domain: str = Form(default="", max_length=255),
        method: str = Form(default="", max_length=16),
        cluster: Sequence[str] = Form(default=()),
        receiver: Sequence[str] = Form(default=()),
        format: Sequence[str] = Form(default=()),
        dns_profile: str = Form(default="", max_length=32),
        ndes_profile: str = Form(default="", max_length=32),
        key_type: str = Form(default="", max_length=16),
        interface: str = Form(default="", max_length=1),
        exportable: str = Form(default="", max_length=1),
        idempotency_key: str = Form(default="", max_length=64),
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        """Queue one certificate job - issue, enrollment or signing request - or say why not.

        The same four refusals `/operations` makes, in the same order, and
        then the form's own. Not routed through `/operations`: that route
        answers a refusal with a bare 400, and the one page in the interface
        whose whole purpose is to be filled in deserves to be re-drawn with
        the sentence on it.
        """

        form = certificate_form.IssueForm(
            domain=domain,
            method=method,
            dns_profile=dns_profile,
            ndes_profile=ndes_profile,
            clusters=tuple(cluster),
            receivers=tuple(receiver),
            formats=tuple(format),
            key_type=key_type,
            interface=interface == "1",
            exportable=exportable == "1",
        )
        session = current_session(request)
        if session is None:
            return RedirectResponse("/login", status_code=303)
        if not config.management_writes:
            return PlainTextResponse("Not found", status_code=404)
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return PlainTextResponse("Refused", status_code=403)
        if session.role != "admin":
            return PlainTextResponse("Refused", status_code=403)
        try:
            key = UUID(idempotency_key)
        except ValueError:
            return PlainTextResponse("A request key is required", status_code=400)

        if form.exportable and not features.is_on(features.CERT_RECEIVERS):
            return PlainTextResponse("Not found", status_code=404)
        choices = _certificate_choices(request, config)
        try:
            payload = certificate_form.payload_from_form(form, choices)
        except certificate_form.FormProblem as problem:
            return _certificate_form_page(request, config, form, problem=str(problem))

        operation = certificate_form.operation_of(form)
        try:
            operations.prepare(
                operation=operation, cluster=None, request_id=uuid4(), payload=payload
            )
        except operations.BadPayload:
            return PlainTextResponse("Invalid operation parameters", status_code=400)

        with request.app.state.pool.connection() as connection:
            try:
                job = db.queue_job(
                    connection,
                    operation=operation,
                    cluster=None,
                    payload=payload,
                    idempotency_key=key,
                )
            except db.CertificateBusy:
                connection.rollback()
                return _certificate_form_page(
                    request,
                    config,
                    form,
                    problem="A certificate job is already running. Wait for it to "
                    "finish on the Jobs page, then ask again.",
                )
            except db.RequestConflict:
                connection.rollback()
                return PlainTextResponse("That request key asked for something else", 409)
            db.record_audit_event(
                connection,
                actor=session.username,
                action="queue_job",
                cluster=None,
                request_id=job.request_id,
                detail={"operation": operation, "job": job.id},
            )
            connection.commit()
        #
        # Back to the listing, where the request is the first row: it says
        # "Requesting" and refreshes until the CA has answered, and carries
        # the CA's own words if the answer is no. Not opened - the detail
        # under a row that has no material yet is empty. The jobs page keeps
        # the full record, but it is not where a person expects to land.
        # The interface's own certificate goes back to where it was asked for.
        #
        if form.interface:
            return RedirectResponse("/settings", status_code=303)
        return RedirectResponse("/certificates?view=registry", status_code=303)

    #
    # The signing request a waiting row exists to hand out (C9b). Served
    # from the same cached reading the page is drawn from, as a file the
    # browser saves: what a CA's form asks to be pasted or uploaded. The
    # CSR is public by construction - it holds the public key and the
    # names - and the row is on a page a viewer may read, so no role is
    # checked beyond the session.
    #
    @router.get("/certificates/{certificate_id}/csr")
    def certificate_signing_request(request: Request, certificate_id: str) -> Response:
        session = current_session(request)
        if session is None:
            return RedirectResponse("/login", status_code=303)
        if not CERTIFICATE_ID.fullmatch(certificate_id):
            return PlainTextResponse("Not found", status_code=404)
        row = _registry_views(request, config).get(certificate_id)
        if row is None or row.csr_pem is None:
            return PlainTextResponse("No signing request is waiting for this name", status_code=404)
        return PlainTextResponse(
            row.csr_pem,
            media_type="application/pkcs10",
            headers={"Content-Disposition": f'attachment; filename="{certificate_id}.csr"'},
        )

    #
    # An external certificate's public half (B255, as one zip 2026-10-07): the
    # chain as one file, the leaf alone and the issuers alone - the three a
    # device asks for. Drawn from the cached reading, as the CSR is. An admin
    # alone, like the key: a reader reads, and taking a certificate out to
    # install it somewhere is not reading (2026-10-07).
    #
    @router.post("/certificates/{certificate_id}/download")
    def certificate_download(
        request: Request,
        certificate_id: str,
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        gate = _external_certificate_gate(request, certificate_id, csrf_token)
        if not isinstance(gate, tuple):
            return gate
        session, row = gate
        #
        # Recorded like the export with its key (26-10-18): a renewed
        # certificate taken out without one still has its version taken out,
        # and the registry row reads which version that was.
        #
        with request.app.state.pool.connection() as connection:
            db.record_audit_event(
                connection,
                actor=session.username,
                action="certificate_download",
                cluster=None,
                request_id=uuid4(),
                detail={
                    "certificate": certificate_id,
                    "format": "zip",
                    "fingerprint_sha256": row.fingerprint,
                },
            )
            connection.commit()
        return _zip_response(
            _public_files(certificate_id, row.fullchain_pem or ""), f"{certificate_id}.zip"
        )

    #
    # The page behind *Export…* (B255): one external certificate, its public
    # files and its key, the way *Renew…* is one row and its renewal. The
    # export itself posts to the route below.
    #
    @router.post("/certificates/export", response_class=HTMLResponse)
    def certificate_export_review(
        request: Request,
        certificate: Sequence[str] = Form(default=()),
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        gate = _admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        if not features.is_on(features.CERT_RECEIVERS):
            return PlainTextResponse("Not found", status_code=404)
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return PlainTextResponse("Refused", status_code=403)
        chosen = tuple(certificate)
        row = _registry_views(request, config).get(chosen[0]) if len(chosen) == 1 else None
        problem = ""
        if len(chosen) != 1:
            problem = "Choose one certificate to export."
        elif row is None or not row.exportable:
            problem = f"{chosen[0]} is not an external certificate."
            row = None
        return TEMPLATES.TemplateResponse(
            request,
            "certificate-export.html",
            {
                "username": gate.username,
                "role": gate.role,
                "csrf_token": auth.csrf_token(token),
                "row": row,
                "back": f"/certificates?view=registry&open={row.identifier}"
                if row is not None
                else "/certificates?view=registry",
                "problem": problem,
                "section": "certificates",
                "management_writes": config.management_writes,
                "demo_fixture": config.demo_fixture,
            },
        )

    #
    # An external certificate with its key (B255, as one zip 2026-10-07): the
    # public files, the key as PEM, and both PKCS#12 forms under one password
    # the manager draws and puts beside them, the way a receiver gets a `.pfx`
    # and a `.password`. The password guards nothing the zip does not already
    # hold unencrypted - it is there because devices will not take a bundle
    # without one. The guard is the admin, the click and the audit row.
    #
    # Every form comes from the export helper, which gives out the key of an
    # exportable entry and of no other, and each must be the certificate the
    # page was drawn from: a renewal between the reading and the click would
    # otherwise put a new key beside an old chain. Served without a copy kept.
    #
    @router.post("/certificates/{certificate_id}/export")
    def certificate_export(
        request: Request,
        certificate_id: str,
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        gate = _external_certificate_gate(request, certificate_id, csrf_token)
        if not isinstance(gate, tuple):
            return gate
        session, row = gate
        back = f"/certificates?view=registry&open={certificate_id}"
        password = secrets.token_urlsafe(18)
        exported: dict[str, Export] = {}
        try:
            for form in EXPORT_FORMATS:
                exported[form] = cert_export_socket.ask(
                    certificate_id,
                    form,
                    None if form == "pem-key" else password,
                    requested_by=session.username,
                )
        except ExportError as refusal:
            return _refusal_page(request, config, f"{refusal} Nothing was exported.", back=back)
        if any(item.fingerprint != row.fingerprint for item in exported.values()):
            return _refusal_page(
                request,
                config,
                f"{certificate_id} changed since the page was read. Open it again; "
                "nothing was exported.",
                back=back,
            )
        with request.app.state.pool.connection() as connection:
            db.record_audit_event(
                connection,
                actor=session.username,
                action="certificate_export",
                cluster=None,
                request_id=uuid4(),
                detail={
                    "certificate": certificate_id,
                    "format": "zip",
                    "forms": list(EXPORT_FORMATS),
                    "fingerprint_sha256": row.fingerprint,
                },
            )
            connection.commit()
        #
        # Named here, from the ID this route checked, rather than taken from
        # the helper's answer into a header or a member name.
        #
        files = [
            *_public_files(certificate_id, row.fullchain_pem or ""),
            (f"{certificate_id}.key.pem", exported["pem-key"].content, True),
            (f"{certificate_id}.pfx", exported["pfx"].content, True),
            (f"{certificate_id}.compatible.pfx", exported["pfx-compatible"].content, True),
            (f"{certificate_id}.password", (password + "\n").encode("ascii"), True),
        ]
        return _zip_response(files, f"{certificate_id}.with-key.zip")

    #
    # What both routes above check before they give anything out: an admin
    # where management writes are on, the form's own CSRF token, and a row of
    # the registry marked external with its chain read. The admin and the
    # row, or the answer that refuses.
    #
    def _external_certificate_gate(
        request: Request, certificate_id: str, csrf_token: str
    ) -> tuple[AuthenticatedSession, certificates.RegistryCertificateView] | Response:
        session = _admin_write_gate(config, request)
        if not isinstance(session, AuthenticatedSession):
            return session
        if not features.is_on(features.CERT_RECEIVERS) or not CERTIFICATE_ID.fullmatch(
            certificate_id
        ):
            return PlainTextResponse("Not found", status_code=404)
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return PlainTextResponse("Refused", status_code=403)
        row = _registry_views(request, config).get(certificate_id)
        if row is None or not row.exportable or not row.fullchain_pem or not row.fingerprint:
            return _refusal_page(
                request,
                config,
                f"{certificate_id} is not an external certificate that can be read.",
                back="/certificates?view=registry",
            )
        return session, row

    #
    # A certificate somebody already has (C9, B165): a file, a name, the
    # targets. Its own page and its own button, because "import" and "new"
    # are different questions - one is a thing that exists, the other a
    # thing to be made - and the same page with a different middle.
    #
    @router.get("/certificates/import", response_class=HTMLResponse)
    def import_certificate_form(request: Request) -> Response:
        if request.query_params.get("for") == "interface":
            choices = _certificate_choices(request, config)
            name = (
                certificate_form.interface_id_for(choices.manager, choices.taken)
                if choices.manager
                else ""
            )
            return _certificate_import_page(
                request,
                config,
                replace(certificate_import_form.EMPTY_FORM, name=name, interface=True),
            )
        #
        # The name a switch between the two kinds carried over (B276).
        #
        carried = request.query_params.get("name", "")[:255]
        if request.query_params.get("kind") == "authority":
            return _certificate_import_page(
                request,
                config,
                replace(certificate_import_form.EMPTY_FORM, name=carried, kind="authority"),
            )
        return _certificate_import_page(
            request, config, replace(certificate_import_form.EMPTY_FORM, name=carried)
        )

    @router.post("/certificates/import", response_class=HTMLResponse)
    def import_certificate_submit(
        request: Request,
        name: str = Form(default="", max_length=255),
        password: str = Form(default="", max_length=256),
        cluster: Sequence[str] = Form(default=()),
        receiver: Sequence[str] = Form(default=()),
        format: Sequence[str] = Form(default=()),
        interface: str = Form(default="", max_length=1),
        kind: str = Form(default="certificate", max_length=16),
        source: str = Form(default="upload", max_length=16),
        idempotency_key: str = Form(default="", max_length=64),
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
        file: UploadFile | None = UPLOADED_FILE,
    ) -> Response:
        """Seal the file and queue one `cert_import` job, or draw the form again saying why not.

        The file is read once, bounded, into memory, sealed against the
        installation's public key, and dropped: the payload the job carries
        is the box. The same four refusals `/certificates/new` makes first.
        """

        data, filename = _uploaded_bytes(file)
        form = certificate_import_form.ImportForm(
            name=name,
            password=password,
            clusters=tuple(cluster),
            receivers=tuple(receiver),
            formats=tuple(format),
            filename=filename,
            data=data,
            interface=interface == "1",
            kind=kind,
            source=source,
        )
        session = current_session(request)
        if session is None:
            return RedirectResponse("/login", status_code=303)
        if not config.management_writes:
            return PlainTextResponse("Not found", status_code=404)
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return PlainTextResponse("Refused", status_code=403)
        if session.role != "admin":
            return PlainTextResponse("Refused", status_code=403)
        try:
            key = UUID(idempotency_key)
        except ValueError:
            return PlainTextResponse("A request key is required", status_code=400)

        public_key = _dns_public_key(config)
        choices = _certificate_choices(request, config)
        try:
            payload = certificate_import_form.payload_from_form(
                certificate_import_form.normalise(form),
                choices,
                public_key,
                replaceable=choices.imported,
            )
        except certificate_form.FormProblem as problem:
            return _certificate_import_page(request, config, form, problem=str(problem))
        return _queue_import(
            request, session, key, payload, form=form, after="/settings" if form.interface else ""
        )

    @router.post("/certificates/{certificate_id}/upload")
    def upload_certificate(
        request: Request,
        certificate_id: str,
        csrf_token: Annotated[str, Form(max_length=128)],
        idempotency_key: Annotated[str, Form(max_length=64)],
        file: UploadFile | None = UPLOADED_FILE,
    ) -> Response:
        """A certificate for a row whose key the manager holds: a renewal, or a CSR's answer.

        Only the file. The name is the row's and the targets stay as they
        are; a key in the file is refused here and pointed at the import
        page, where replacing the key is the stated intent.
        """

        data, _filename = _uploaded_bytes(file)
        session = current_session(request)
        if session is None:
            return RedirectResponse("/login", status_code=303)
        if not config.management_writes:
            return PlainTextResponse("Not found", status_code=404)
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token) or session.role != "admin":
            return PlainTextResponse("Refused", status_code=403)
        try:
            key = UUID(idempotency_key)
        except ValueError:
            return PlainTextResponse("A request key is required", status_code=400)

        row = _registry_views(request, config).get(certificate_id)
        if row is None or row.placeholder:
            return PlainTextResponse("Certificate is not in the registry", status_code=404)
        if row.source_kind != "import":
            return _refusal_page(
                request,
                config,
                f"{certificate_id} is not an imported certificate; its material is not "
                "replaced by an upload.",
                back=f"/certificates?view=registry&open={certificate_id}",
            )
        public_key = _dns_public_key(config)
        if public_key is None:
            return _refusal_page(
                request,
                config,
                "The installation's sealing key is not configured, so a file cannot be "
                "uploaded. Import it with haprion-cert-import on the manager.",
                back=f"/certificates?view=registry&open={certificate_id}",
            )
        back = (
            "/settings" if row.interface else f"/certificates?view=registry&open={certificate_id}"
        )
        try:
            certificate_import_form.check_file(data, key_allowed=False)
            payload = certificate_import_form.sealed_payload(
                public_key,
                certificate_id=certificate_id,
                data=data,
                clusters=[t.name for t in row.targets if t.kind == "cluster"],
                receivers=[t.name for t in row.targets if t.kind == "receiver"],
            )
        except certificate_form.FormProblem as problem:
            return _refusal_page(request, config, str(problem), back=back)
        if row.interface:
            #
            # The interface's own certificate (B188), or the answer to the
            # request made for it: no targets, the mark carried.
            #
            payload["interface"] = True
            return _queue_import(request, session, key, payload, after="/settings")
        return _queue_import(request, session, key, payload, open_row=certificate_id)

    def _uploaded_bytes(file: UploadFile | None) -> tuple[bytes, str]:
        """The file's bytes, read once and bounded one byte past the limit.

        One byte past, so the form can say "too large" rather than silently
        judging a truncated file. Reading stops there; the rest of a large
        upload is never held.
        """

        if file is None:
            return b"", ""
        data = anyio.from_thread.run(file.read, certificate_import_form.MAX_UPLOAD_BYTES + 1)
        anyio.from_thread.run(file.close)
        return data, file.filename or ""

    def _queue_import(
        request: Request,
        session: AuthenticatedSession,
        key: UUID,
        payload: dict[str, Any],
        *,
        form: certificate_import_form.ImportForm | None = None,
        open_row: str = "",
        after: str = "",
    ) -> Response:
        """Queue the sealed upload; the same refusals the issue form makes, said the same way."""

        try:
            operations.prepare(
                operation="cert_import", cluster=None, request_id=uuid4(), payload=payload
            )
        except operations.BadPayload:
            return PlainTextResponse("Invalid operation parameters", status_code=400)
        with request.app.state.pool.connection() as connection:
            try:
                job = db.queue_job(
                    connection,
                    operation="cert_import",
                    cluster=None,
                    payload=payload,
                    idempotency_key=key,
                )
            except db.CertificateBusy:
                connection.rollback()
                busy = (
                    "A certificate job is already running. Wait for it to finish, then try again."
                )
                if form is not None:
                    return _certificate_import_page(request, config, form, problem=busy)
                return PlainTextResponse(busy, status_code=409)
            except db.RequestConflict:
                connection.rollback()
                return PlainTextResponse("That request key asked for something else", 409)
            db.record_audit_event(
                connection,
                actor=session.username,
                action="queue_job",
                cluster=None,
                request_id=job.request_id,
                detail={"operation": "cert_import", "job": job.id, "certificate": payload["id"]},
            )
            connection.commit()
        if after:
            return RedirectResponse(after, status_code=303)
        if open_row:
            return RedirectResponse(f"/certificates?view=registry&open={open_row}", status_code=303)
        return RedirectResponse("/certificates?view=registry", status_code=303)

    def _certificate_import_page(
        request: Request,
        config: Config,
        form: certificate_import_form.ImportForm,
        *,
        problem: str = "",
    ) -> Response:
        session = current_session(request)
        if session is None:
            return RedirectResponse("/login", status_code=303)
        if not config.management_writes:
            return PlainTextResponse("Not found", status_code=404)
        if session.role != "admin":
            return PlainTextResponse("Refused", status_code=403)
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        choices = _certificate_choices(request, config)
        with request.app.state.pool.connection() as connection:
            recent = db.recent_jobs(connection)
        #
        # The file is never redrawn: a browser will not take a value for a
        # file input, and the bytes have no business in a page. The person
        # picks it again; everything typed is kept.
        #
        return TEMPLATES.TemplateResponse(
            request,
            "certificate-import.html",
            {
                "username": session.username,
                "role": session.role,
                "csrf_token": auth.csrf_token(token),
                "form": certificate_import_form.normalise(form),
                "choices": choices,
                "problem": problem,
                "accept": certificate_import_form.ACCEPT,
                "max_kb": certificate_import_form.MAX_UPLOAD_BYTES // 1024,
                "sealing_available": _dns_public_key(config) is not None,
                "certificate_job": jobs.certificate_in_flight(recent),
                "section": "certificates",
                "management_writes": config.management_writes,
                "demo_fixture": config.demo_fixture,
            },
        )

    @router.post("/certificates/{certificate_id}/resume")
    def resume_enrollment(
        request: Request,
        certificate_id: str,
        csrf_token: Annotated[str, Form(max_length=128)],
        idempotency_key: Annotated[str, Form(max_length=64)],
    ) -> Response:
        """Queue the resume of an NDES request the CA was still holding.

        The request's root-only record holds everything else - profile,
        names, targets - so the job carries only the ID (C6).
        """

        session = current_session(request)
        if session is None:
            return RedirectResponse("/login", status_code=303)
        if not config.management_writes:
            return PlainTextResponse("Not found", status_code=404)
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token) or session.role != "admin":
            return PlainTextResponse("Refused", status_code=403)
        try:
            key = UUID(idempotency_key)
        except ValueError:
            return PlainTextResponse("A request key is required", status_code=400)
        payload = {"id": certificate_id, "resume": True}
        try:
            operations.prepare(
                operation="cert_scep", cluster=None, request_id=uuid4(), payload=payload
            )
        except operations.BadPayload:
            return PlainTextResponse("Invalid operation parameters", status_code=400)
        with request.app.state.pool.connection() as connection:
            try:
                job = db.queue_job(
                    connection,
                    operation="cert_scep",
                    cluster=None,
                    payload=payload,
                    idempotency_key=key,
                )
            except db.CertificateBusy:
                connection.rollback()
                return PlainTextResponse(
                    "A certificate job is already running. Wait for it to finish, then try again.",
                    status_code=409,
                )
            except db.RequestConflict:
                connection.rollback()
                return PlainTextResponse("That request key asked for something else", 409)
            db.record_audit_event(
                connection,
                actor=session.username,
                action="queue_job",
                cluster=None,
                request_id=job.request_id,
                detail={"operation": "cert_scep", "job": job.id, "resume": certificate_id},
            )
            connection.commit()
        # A fixed address, with the row still open: the listing's State cell
        # follows the job from there, on the row the button was pressed on.
        return RedirectResponse(
            f"/certificates?view=registry&open={certificate_id}", status_code=303
        )

    @router.post("/certificates/{certificate_id}/publish")
    def publish_certificate(
        request: Request,
        certificate_id: str,
        csrf_token: Annotated[str, Form(max_length=128)],
        idempotency_key: Annotated[str, Form(max_length=64)],
    ) -> Response:
        """Publish one registered certificate to the targets it already has."""

        session = current_session(request)
        if session is None:
            return RedirectResponse("/login", status_code=303)
        if not config.management_writes:
            return PlainTextResponse("Not found", status_code=404)
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token) or session.role != "admin":
            return PlainTextResponse("Refused", status_code=403)
        try:
            key = UUID(idempotency_key)
        except ValueError:
            return PlainTextResponse("A request key is required", status_code=400)

        row = _registry_views(request, config).get(certificate_id)
        if row is None:
            return PlainTextResponse("Certificate is not in the registry", status_code=404)
        if not row.needs_publish:
            return PlainTextResponse("Certificate does not need publishing", status_code=409)

        payload = {"certificates": [certificate_id], "deploy": True}
        try:
            operations.prepare(
                operation="cert_publish", cluster=None, request_id=uuid4(), payload=payload
            )
        except operations.BadPayload:
            return PlainTextResponse("Invalid operation parameters", status_code=400)
        with request.app.state.pool.connection() as connection:
            try:
                job = db.queue_job(
                    connection,
                    operation="cert_publish",
                    cluster=None,
                    payload=payload,
                    idempotency_key=key,
                )
            except db.CertificateBusy:
                connection.rollback()
                return PlainTextResponse(
                    "A certificate job is already running. Wait for it to finish, then try again.",
                    status_code=409,
                )
            except db.RequestConflict:
                connection.rollback()
                return PlainTextResponse("That request key asked for something else", 409)
            db.record_audit_event(
                connection,
                actor=session.username,
                action="queue_job",
                cluster=None,
                request_id=job.request_id,
                detail={
                    "operation": "cert_publish",
                    "job": job.id,
                    "certificate": certificate_id,
                },
            )
            connection.commit()
        return RedirectResponse(
            f"/certificates?view=registry&open={certificate_id}", status_code=303
        )

    def _certificate_choices(request: Request, config: Config) -> certificate_form.IssueChoices:
        """The targets the form may offer, read the way the listing reads them."""

        clusters, certificate_rows = read_source(request, config, CERTIFICATE_SOURCE)
        overview = certificates.build_certificate_overview(
            clusters,
            certificate_rows,
            manager=read_manager_certificates(request, config),
            stale_after=timedelta(seconds=config.poller.interval_seconds * 2),
        )
        usable_profiles: tuple[str, ...] = ()
        profiles_required = config.dns_profiles_public_key is not None
        if profiles_required:
            with request.app.state.pool.connection() as connection:
                profile_rows = db.dns_profiles(connection)
                recent = db.profile_jobs(connection, "dns_profile_apply")
            usable_profiles = tuple(
                profile.id
                for profile in profile_rows
                if dns_profile_form.profile_status(profile.id, profile.revision, recent).usable
            )
        usable_ndes: tuple[str, ...] = ()
        if profiles_required:
            with request.app.state.pool.connection() as connection:
                ndes_rows = db.ndes_profiles(connection)
                recent = db.profile_jobs(connection, "ndes_profile_apply")
            usable_ndes = tuple(
                profile.id
                for profile in ndes_rows
                if ndes_profile_form.profile_status(profile.id, profile.revision, recent).usable
            )
        #
        # With receivers switched off (B193) no form offers one and every
        # form refuses one as not registered: the issue, import and upload
        # forms and Publish to... / Remove from... all read this.
        #
        offered = (
            overview.registry.receivers
            if overview.registry is not None and features.is_on(features.CERT_RECEIVERS)
            else ()
        )
        return certificate_form.IssueChoices(
            clusters=tuple(clusters),
            receivers=offered,
            dns_profiles=usable_profiles,
            profiles_required=profiles_required,
            ndes_profiles=usable_ndes,
            receiver_transports={
                row.identifier: row.transport_label for row in overview.registry.receiver_rows
            }
            if overview.registry
            else {},
            registered=tuple(
                entry.identifier
                for entry in (*overview.registry.certificates, overview.registry.interface)
                if entry is not None
            )
            if overview.registry
            else (),
            imported=tuple(
                entry.identifier
                for entry in overview.registry.certificates
                if entry.source_kind == "import" and not entry.placeholder
            )
            if overview.registry
            else (),
            authorities=tuple(
                entry.identifier
                for entry in overview.registry.certificates
                if entry.source_kind == "authority"
            )
            if overview.registry
            else (),
            waiting=tuple(
                entry.identifier for entry in overview.registry.certificates if entry.csr_pending
            )
            if overview.registry
            else (),
            manager=overview.registry.manager if overview.registry else None,
            interface_id=overview.registry.interface.identifier
            if overview.registry and overview.registry.interface
            else None,
            taken=tuple(
                view.identifier
                for view in (
                    *overview.registry.certificates,
                    overview.registry.interface,
                    overview.registry.interface_request,
                )
                if view is not None
            )
            if overview.registry
            else (),
        )

    def _certificate_form_page(
        request: Request,
        config: Config,
        form: certificate_form.IssueForm,
        *,
        problem: str = "",
    ) -> Response:
        session = current_session(request)
        if session is None:
            return RedirectResponse("/login", status_code=303)
        if not config.management_writes:
            #
            # 404 and not 403, for the reason `/operations` gives: an
            # installation that does not do management writes has no such
            # form, and saying "forbidden" would announce one waiting to be
            # switched on.
            #
            return PlainTextResponse("Not found", status_code=404)
        if session.role != "admin":
            return PlainTextResponse("Refused", status_code=403)
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        choices = _certificate_choices(request, config)
        with request.app.state.pool.connection() as connection:
            recent = db.recent_jobs(connection)
        return TEMPLATES.TemplateResponse(
            request,
            "certificate-new.html",
            {
                "username": session.username,
                "role": session.role,
                "csrf_token": auth.csrf_token(token),
                "form": certificate_form.normalise(form),
                "choices": choices,
                "key_types": certificate_form.KEY_TYPE_LABELS,
                "problem": problem,
                "certificate_job": jobs.certificate_in_flight(recent),
                "section": "certificates",
                "management_writes": config.management_writes,
                "demo_fixture": config.demo_fixture,
            },
        )

    # - Certificate cleanup (C5b, B139) ------------------------------------

    def _registry_views(
        request: Request, config: Config
    ) -> Mapping[str, certificates.RegistryCertificateView]:
        """The registry as the listing draws it, by ID, for the cleanup page."""

        clusters, certificate_rows = read_source(request, config, CERTIFICATE_SOURCE)
        overview = certificates.build_certificate_overview(
            clusters,
            certificate_rows,
            manager=read_manager_certificates(request, config),
            stale_after=timedelta(seconds=config.poller.interval_seconds * 2),
        )
        if overview.registry is None:
            return {}
        registry = overview.registry
        #
        # The interface's own entry and its waiting request are rows too, for
        # the routes that act on a row by ID - its CSR, its upload, its
        # renewal - though the listing draws them on the settings page.
        #
        extra = tuple(
            view for view in (registry.interface, registry.interface_request) if view is not None
        )
        return {view.identifier: view for view in (*registry.certificates, *extra)}

    def _certificate_delete_page(
        request: Request,
        session: AuthenticatedSession,
        *,
        chosen: Sequence[str],
        problem: str = "",
    ) -> Response:
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        registry = _registry_views(request, config)
        with request.app.state.pool.connection() as connection:
            drafts = db.live_drafts(connection)
            recent = db.recent_jobs(connection)
        picked: certificate_delete.Selection | None = None
        try:
            picked = certificate_delete.selection(chosen, registry, drafts)
        except certificate_delete.SelectionProblem as refused:
            problem = problem or str(refused)
        return TEMPLATES.TemplateResponse(
            request,
            "certificate-delete.html",
            {
                "username": session.username,
                "role": session.role,
                "csrf_token": auth.csrf_token(token),
                "selection": picked,
                "problem": problem,
                "certificate_job": jobs.certificate_in_flight(recent),
                "section": "certificates",
                "management_writes": config.management_writes,
                "demo_fixture": config.demo_fixture,
            },
        )

    # - Renew… (C9c) ------------------------------------------------------

    def _certificate_renew_page(
        request: Request,
        session: AuthenticatedSession,
        *,
        chosen: Sequence[str],
        problem: str = "",
    ) -> Response:
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        registry = _registry_views(request, config)
        with request.app.state.pool.connection() as connection:
            recent = db.recent_jobs(connection)
        renewal: certificate_renew.Renewal | None = None
        try:
            renewal = certificate_renew.selection(chosen, registry)
        except certificate_renew.SelectionProblem as refused:
            problem = problem or str(refused)
        return TEMPLATES.TemplateResponse(
            request,
            "certificate-renew.html",
            {
                "username": session.username,
                "role": session.role,
                "csrf_token": auth.csrf_token(token),
                "renewal": renewal,
                "back": "/settings"
                if renewal is not None and renewal.row.interface
                else f"/certificates?view=registry&open={renewal.identifier}"
                if renewal is not None
                else "/certificates?view=registry",
                "problem": problem,
                "certificate_job": jobs.certificate_in_flight(recent),
                "section": "settings"
                if renewal is not None and renewal.row.interface
                else "certificates",
                "management_writes": config.management_writes,
                "demo_fixture": config.demo_fixture,
            },
        )

    @router.post("/certificates/renew", response_class=HTMLResponse)
    def certificate_renew_review(
        request: Request,
        certificate: Sequence[str] = Form(default=()),
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        """The page behind *Renew…*: one row, renewed the way its source is made."""

        gate = _admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return PlainTextResponse("Refused", status_code=403)
        return _certificate_renew_page(request, gate, chosen=tuple(certificate))

    @router.post("/certificates/renew/confirm", response_class=HTMLResponse)
    def certificate_renew_confirm(
        request: Request,
        certificate: Sequence[str] = Form(default=()),
        idempotency_key: str = Form(default="", max_length=64),
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        """Queue the certbot or NDES renewal the page offered; a file goes to the upload route."""

        gate = _admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return PlainTextResponse("Refused", status_code=403)
        try:
            key = UUID(idempotency_key)
        except ValueError:
            return PlainTextResponse("A request key is required", status_code=400)
        registry = _registry_views(request, config)
        try:
            renewal = certificate_renew.selection(tuple(certificate), registry)
            operation, payload = certificate_renew.payload(renewal)
        except certificate_renew.SelectionProblem as refused:
            return _certificate_renew_page(
                request, gate, chosen=tuple(certificate), problem=str(refused)
            )
        try:
            operations.prepare(
                operation=operation, cluster=None, request_id=uuid4(), payload=payload
            )
        except operations.BadPayload:
            return PlainTextResponse("Invalid operation parameters", status_code=400)
        with request.app.state.pool.connection() as connection:
            try:
                job = db.queue_job(
                    connection,
                    operation=operation,
                    cluster=None,
                    payload=payload,
                    idempotency_key=key,
                )
            except db.CertificateBusy:
                connection.rollback()
                return _certificate_renew_page(
                    request,
                    gate,
                    chosen=tuple(certificate),
                    problem="A certificate job is already running. Wait for it to finish on "
                    "the Jobs page, then ask again.",
                )
            except db.RequestConflict:
                connection.rollback()
                return PlainTextResponse("That request key asked for something else", 409)
            db.record_audit_event(
                connection,
                actor=gate.username,
                action="queue_job",
                cluster=None,
                request_id=job.request_id,
                detail={
                    "operation": operation,
                    "job": job.id,
                    "certificate": renewal.identifier,
                    "renew": True,
                },
            )
            connection.commit()
        #
        # Back to the list, the row closed: its State cell says "Renewing"
        # from the table, and the detail was not asked for (2026-09-21).
        # The interface's own certificate is renewed from, and back to, Settings.
        #
        if renewal.row.interface:
            return RedirectResponse("/settings", status_code=303)
        return RedirectResponse("/certificates?view=registry", status_code=303)

    # - Publish to… / Remove from… (2026-09-15) ---------------------------

    def _certificate_retarget_page(
        request: Request,
        session: AuthenticatedSession,
        action: str,
        *,
        chosen: Sequence[str],
        problem: str = "",
    ) -> Response:
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        registry = _registry_views(request, config)
        choices = _certificate_choices(request, config)
        with request.app.state.pool.connection() as connection:
            drafts = db.live_drafts(connection)
            recent = db.recent_jobs(connection)
        picked: certificate_retarget.Selection | None = None
        try:
            picked = certificate_retarget.selection(
                action, chosen, registry, choices.clusters, choices.receivers, drafts
            )
        except certificate_retarget.SelectionProblem as refused:
            problem = problem or str(refused)
        return TEMPLATES.TemplateResponse(
            request,
            "certificate-retarget.html",
            {
                "receiver_transports": choices.receiver_transports,
                "username": session.username,
                "role": session.role,
                "csrf_token": auth.csrf_token(token),
                "selection": picked,
                "problem": problem,
                "certificate_job": jobs.certificate_in_flight(recent),
                "section": "certificates",
                "management_writes": config.management_writes,
                "demo_fixture": config.demo_fixture,
            },
        )

    @router.post("/certificates/targets/{action}", response_class=HTMLResponse)
    def certificate_retarget_review(
        request: Request,
        action: str,
        certificate: Sequence[str] = Form(default=()),
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        """The page that asks which targets: nothing is queued from here."""

        if action not in certificate_retarget.ACTIONS:
            return PlainTextResponse("Not found", status_code=404)
        gate = _admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return PlainTextResponse("Refused", status_code=403)
        return _certificate_retarget_page(request, gate, action, chosen=tuple(certificate))

    @router.post("/certificates/targets/{action}/confirm", response_class=HTMLResponse)
    def certificate_retarget_confirm(
        request: Request,
        action: str,
        certificate: Sequence[str] = Form(default=()),
        cluster: Sequence[str] = Form(default=()),
        receiver: Sequence[str] = Form(default=()),
        format: Sequence[str] = Form(default=()),
        idempotency_key: str = Form(default="", max_length=64),
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        """Queue one `cert_target` job for the selection and the ticked targets.

        The selection and the offered targets are evaluated again here, not
        trusted from the previous page; a target that stopped being offered
        in between is simply not in the job, and a draft written in between
        is a refusal now.
        """

        if action not in certificate_retarget.ACTIONS:
            return PlainTextResponse("Not found", status_code=404)
        gate = _admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return PlainTextResponse("Refused", status_code=403)
        try:
            key = UUID(idempotency_key)
        except ValueError:
            return PlainTextResponse("A request key is required", status_code=400)

        registry = _registry_views(request, config)
        choices = _certificate_choices(request, config)
        with request.app.state.pool.connection() as connection:
            drafts = db.live_drafts(connection)
        try:
            picked = certificate_retarget.selection(
                action, tuple(certificate), registry, choices.clusters, choices.receivers, drafts
            )
            payload = certificate_retarget.payload(
                picked, tuple(cluster), tuple(receiver), tuple(format)
            )
            operations.prepare(
                operation="cert_target",
                cluster=None,
                request_id=uuid4(),
                payload=payload,
                draft_references=lambda ids: certificate_delete.draft_references(drafts, ids),
            )
        except (certificate_retarget.SelectionProblem, operations.BadPayload) as refused:
            return _certificate_retarget_page(
                request, gate, action, chosen=tuple(certificate), problem=str(refused)
            )

        with request.app.state.pool.connection() as connection:
            try:
                job = db.queue_job(
                    connection,
                    operation="cert_target",
                    cluster=None,
                    payload=payload,
                    idempotency_key=key,
                )
            except db.CertificateBusy:
                connection.rollback()
                return _certificate_retarget_page(
                    request,
                    gate,
                    action,
                    chosen=tuple(certificate),
                    problem="A certificate job is already running. Wait for it to finish, "
                    "then ask again.",
                )
            except db.RequestConflict:
                connection.rollback()
                return PlainTextResponse("That request key asked for something else", 409)
            db.record_audit_event(
                connection,
                actor=gate.username,
                action="queue_job",
                cluster=None,
                request_id=job.request_id,
                detail={"operation": "cert_target", "job": job.id, **payload},
            )
            connection.commit()
        #
        # Back on the list as it was, also for one certificate: the change is
        # made from the selection, where no row was open, and the row's state
        # column follows the job (like a deletion or a renewal).
        #
        return RedirectResponse("/certificates?view=registry", status_code=303)

    # - Receivers (B142, 2026-09-18) ------------------------------------------

    def _receivers_page(
        request: Request,
        session: AuthenticatedSession,
        *,
        problem: str = "",
    ) -> Response:
        """The list: every receiver, its fetch commands, and the job on its row."""

        _token, registry, context = _page_context(config, request, session)
        rows = registry.receiver_rows if registry else ()
        manager = registry.manager if registry else None
        with request.app.state.pool.connection() as connection:
            own = db.operation_jobs(connection, "cert_receiver", limit=5)
        on_rows, ghosts = certificate_receivers.on_the_rows(
            rows, certificate_receivers.recent_activity(own)
        )
        return TEMPLATES.TemplateResponse(
            request,
            "certificate-receivers.html",
            {
                **context,
                "rows": tuple(
                    (row, certificate_receivers.fetch_steps(row, manager)) for row in rows
                ),
                "manager": manager,
                "on_rows": on_rows,
                "ghosts": ghosts,
                "problem": problem,
            },
        )

    def _receiver_password_page(
        request: Request, session: AuthenticatedSession, receiver: str, password: str
    ) -> Response:
        """An https receiver's new password, on the one answer that shows it (B306).

        It was made for this request, its hash went into the job, and nothing
        keeps it - not the database, not a cache.
        """

        _token, registry, context = _page_context(config, request, session)
        manager = registry.manager if registry else None
        return TEMPLATES.TemplateResponse(
            request,
            "certificate-receiver-password.html",
            {
                **context,
                "receiver": receiver,
                "step": certificate_receivers.password_step(
                    receiver, manager or "<manager>", password
                ),
            },
            headers={"Cache-Control": "no-store"},
        )

    def _receiver_form_page(
        request: Request,
        session: AuthenticatedSession,
        *,
        problem: str = "",
        form: Mapping[str, str] | None = None,
    ) -> Response:
        """The form: what is needed before the job, and nothing from after it."""

        _token, _registry, context = _page_context(config, request, session)
        entered = {"receiver": "", "transport": "sftp", "public_key": "", "allow": ""}
        if form:
            entered.update(form)
        return TEMPLATES.TemplateResponse(
            request,
            "certificate-receiver-new.html",
            {
                **context,
                "key_steps": certificate_receivers.key_steps(entered["receiver"]),
                "transports": certificate_receivers.TRANSPORT_HELP,
                "windows_transports": certificate_receivers.WINDOWS_TRANSPORTS,
                "windows": entered["transport"] in certificate_receivers.WINDOWS_TRANSPORTS,
                "form": entered,
                "problem": problem,
            },
        )

    #
    # Settings (Fas 13, B161): what belongs to the application itself rather
    # than to what it manages. First the interface's own certificate (B188):
    # what nginx serves, the registry entry that serves it, a request made
    # for it, and the ways to replace it - the certificate forms, in their
    # interface mode.
    #
    @router.get("/settings/status-access", response_class=HTMLResponse)
    def status_access_edit(request: Request) -> Response:
        gate = _admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        return _status_access_page(request, gate)

    def _status_access_page(
        request: Request,
        gate: AuthenticatedSession,
        *,
        problem: str = "",
        entered: str | None = None,
        status_code: int = 200,
    ) -> Response:
        """The addresses that may ask /status/ (B274), on a page of its own (26-10-12)."""

        token = request.cookies.get(auth.SESSION_COOKIE, "")
        with request.app.state.pool.connection() as connection:
            entries = db.status_access(connection)
        return TEMPLATES.TemplateResponse(
            request,
            "settings-status-access.html",
            {
                "username": gate.username,
                "role": gate.role,
                "csrf_token": auth.csrf_token(token),
                "section": "settings",
                "management_writes": config.management_writes,
                "entries": entries,
                "networks": entered
                if entered is not None
                else "".join(f"{entry.network}\n" for entry in entries),
                "problem": problem,
            },
            status_code=status_code,
        )

    @router.post("/getting-started/hide")
    def hide_getting_started(
        request: Request, csrf_token: Annotated[str, Form(max_length=128)]
    ) -> Response:
        """Hide the getting started list for the whole installation (B316)."""

        gate = _admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return PlainTextResponse("Refused", status_code=403)
        with request.app.state.pool.connection() as connection:
            if db.hide_getting_started(connection, actor=gate.username):
                db.record_audit_event(
                    connection, actor=gate.username, action="getting_started_hidden", detail={}
                )
            connection.commit()
        return RedirectResponse("/", status_code=303)

    @router.post("/getting-started/show")
    def show_getting_started(
        request: Request, csrf_token: Annotated[str, Form(max_length=128)]
    ) -> Response:
        """Show a hidden getting started list again (0076)."""

        gate = _admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return PlainTextResponse("Refused", status_code=403)
        with request.app.state.pool.connection() as connection:
            if db.show_getting_started(connection):
                db.record_audit_event(
                    connection, actor=gate.username, action="getting_started_shown", detail={}
                )
            connection.commit()
        return RedirectResponse("/", status_code=303)

    def _getting_started_offered_again(request: Request) -> bool:
        """A hidden list's way back, for a week after it was hidden."""

        with request.app.state.pool.connection() as connection:
            hidden_at = db.getting_started_hidden_at(connection)
        return hidden_at is not None and getting_started.offered_again(hidden_at, datetime.now(UTC))

    def _getting_started(
        request: Request,
        dashboard_view: dashboard.DashboardView,
        network_rows: Any,
        guide: first_cluster.Guide | None = None,
    ) -> getting_started.Checklist | None:
        """The list for an admin, until it is hidden (B316); every tick read, none stored."""

        with request.app.state.pool.connection() as connection:
            if db.getting_started_hidden_at(connection) is not None:
                return None
            provider = db.oidc_provider(connection)
            switches = db.feature_switches(connection)
            access = db.status_access(connection)
        networks = {
            view.cluster: view
            for view in network.build_network_overview(
                listed_clusters(request, config),
                network_rows,
                stale_after=timedelta(seconds=config.poller.interval_seconds * 2),
            )
        }
        settings_views = {
            view.cluster: view
            for view in cluster_settings_page.card_views(
                *read_source(request, config, SETTINGS_SOURCE), waiting=frozenset(), running={}
            )
        }
        backups_on = features.NODE_BACKUPS in switches and switches[features.NODE_BACKUPS].enabled
        scheduled = (
            {
                view.cluster
                for view in _backup_overview(config, request).clusters
                if view.schedule is not None and view.schedule.enabled
            }
            if backups_on
            else set()
        )
        registry = _registry_overview(config, request)
        interface = registry.interface.identifier if registry and registry.interface else None
        served = certificates.interface_served(read_manager_certificates(request, config))
        facts = getting_started.Facts(
            clusters=tuple(
                getting_started.ClusterFacts(
                    name=view.cluster,
                    nodes=tuple(node.name for node in view.nodes),
                    owner=next((node.name for node in view.nodes if node.vip == "Owner"), None),
                    vips=tuple(
                        getting_started.Vip(vip.address, vip.tls_policy, vip.source)
                        for vip in getattr(networks.get(view.cluster), "vips", ())
                    ),
                    logs_forwarded=getattr(settings_views.get(view.cluster), "logs_set", False),
                    backups_scheduled=view.cluster in scheduled,
                    target_version=view.target_version,
                )
                for view in dashboard_view.clusters
                if view.configured
            ),
            interface_self_signed=served.self_signed if served is not None else None,
            accounts=len(_account_rows(config, request)),
            sso=provider is not None and provider.enabled,
            site_certificates=sum(
                entry.source_label in {"Certbot", "NDES"} and entry.identifier != interface
                for entry in (registry.certificates if registry else ())
            ),
            node_backups_on=backups_on,
            status_access=bool(access),
            features_changed=any(switch.updated_by for switch in switches.values()),
            guide=guide.current if guide is not None else None,
        )
        return getting_started.checklist(facts)

    @router.post("/attention/acknowledge")
    def acknowledge_attention(
        request: Request,
        csrf_token: Annotated[str, Form(max_length=128)],
        kind: Annotated[str, Form(max_length=32)],
        subject: Annotated[str, Form(max_length=256)],
        cluster: Annotated[str, Form(max_length=64)] = "",
    ) -> Response:
        """Leave one row of *Needs attention* out until it has gone (B299)."""

        gate = _admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return PlainTextResponse("Refused", status_code=403)
        #
        # Only a row the list shows now: a key made up, or one that has gone
        # since the page was drawn, is acknowledged by nothing.
        #
        shown = next(
            (
                item
                for item in _attention(request, config).items
                if item.key == (kind, cluster, subject)
            ),
            None,
        )
        if shown is not None:
            with request.app.state.pool.connection() as connection:
                if db.acknowledge_attention(connection, shown.key, actor=gate.username):
                    db.record_audit_event(
                        connection,
                        actor=gate.username,
                        action="attention_acknowledged",
                        detail={
                            "kind": kind,
                            "cluster": cluster or None,
                            "subject": subject,
                            "message": shown.message,
                        },
                    )
                connection.commit()
        return RedirectResponse("/", status_code=303)

    @router.post("/settings/status-access")
    def save_status_access(
        request: Request,
        csrf_token: Annotated[str, Form(max_length=128)],
        networks: Annotated[str, Form(max_length=4096)] = "",
    ) -> Response:
        """Replace the list of addresses that may ask /status/ (B274); empty switches it off."""

        gate = _admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return PlainTextResponse("Refused", status_code=403)
        try:
            checked = attention.access_list(networks)
        except ValueError as problem:
            return _status_access_page(
                request, gate, problem=str(problem), entered=networks, status_code=400
            )
        with request.app.state.pool.connection() as connection:
            db.set_status_access(connection, networks=checked, actor=gate.username)
            db.record_audit_event(
                connection,
                actor=gate.username,
                action="status_access_changed",
                detail={"networks": list(checked)},
            )
            connection.commit()
        return RedirectResponse("/settings#external-monitoring", status_code=303)

    @router.get("/settings", response_class=HTMLResponse)
    def settings_page(request: Request) -> Response:
        gate = _admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        switched = request.query_params.get("switched", "")[:32]
        return _settings_page(request, gate, done=SWITCHED.get(switched, ""))

    def _locked(request: Request, name: str) -> bool:
        """Whether a switch cannot be on here: cluster colours past six clusters."""

        return feature_switch.locked(name, listed_clusters(request, config))

    def _settings_page(
        request: Request,
        gate: AuthenticatedSession,
        *,
        problem: str = "",
        done: str = "",
        status_code: int = 200,
    ) -> Response:
        _token, registry, context = _page_context(config, request, gate)
        entry = registry.interface if registry else None
        served = certificates.interface_served(read_manager_certificates(request, config))
        sort, asked = users.TABLE.chosen(request)
        with request.app.state.pool.connection() as connection:
            switches = db.feature_switches(connection)
            provider = db.oidc_provider(connection)
            recent = db.recent_jobs(connection)
            status_access = db.status_access(connection)
            update_row = db.update_check(connection)
        creation_rows = _creations(request, recent)
        response = TEMPLATES.TemplateResponse(
            request,
            "settings.html",
            {
                **context,
                "section": "settings",
                #
                # Who may ask /status/ what needs doing (B274).
                #
                "status_access": status_access,
                "served": served,
                "entry": entry,
                "waiting": registry.interface_request if registry else None,
                "manager": registry.manager if registry else None,
                #
                # The registry marks one certificate and nginx serves another:
                # an install that has not happened yet, or a pair replaced by
                # hand with haprion-tls. Said, not resolved here.
                #
                "mismatch": entry is not None
                and served is not None
                and entry.readable
                and bool(entry.fingerprint)
                and entry.fingerprint != served.fingerprint,
                "users": users.user_views(
                    _account_rows(config, request), signed_in_as=gate.username, sort=sort
                ),
                "user_sorts": users.TABLE.links(sort),
                # Which provider sign-in goes through, said where accounts are
                # (B197): a change to it is a change to who can be admin.
                "sso": oidc_web.summary(provider),
                "sso_on": provider is not None and provider.enabled,
                "cluster_settings": cluster_settings_page.card_views(
                    *read_source(request, config, SETTINGS_SOURCE),
                    waiting=network.awaiting_deploy(recent, part="settings"),
                    running=jobs.in_flight(recent, cluster_settings_page.SETTINGS_OPERATIONS),
                ),
                "cluster_nodes": cluster_nodes.card_rows(
                    *read_source(request, config, STATUS_SOURCE), creation_rows
                ),
                "location_data": location_data.card(
                    read_source(request, config, OBJECTS_SOURCE)[1]
                ),
                #
                # Whether a switch is locked is asked of every switch, on or
                # off: asked only of those that were on, an off switch read the
                # previous one's answer, or none at all when it came first.
                #
                #
                # What a switch's row says beside its name: for the WAF engine,
                # whether the machines can do what the switch offers (B231).
                #
                "feature_details": {
                    features.WAF_ENGINE: waf.engine(
                        read_source(request, config, OBJECTS_SOURCE)[1],
                        read_source(request, config, STATUS_SOURCE)[1],
                    ).summary(),
                    #
                    # When GitHub last answered, or since when it has not (B342).
                    #
                    features.UPDATE_CHECK: update_check.detail(
                        update_row,
                        on=switches[features.UPDATE_CHECK].enabled
                        if features.UPDATE_CHECK in switches
                        else False,
                        shown=lambda at: metrics.shown(at).strftime("%y-%m-%d %H:%M"),
                    ),
                },
                "features": [
                    (feature, switches[feature.name].enabled and not locked, locked)
                    for feature in features.FEATURES
                    if feature.name in switches
                    for locked in (_locked(request, feature.name),)
                ],
                "problem": problem,
                "done": done,
            },
            status_code=status_code,
        )
        if asked:
            users.TABLE.remember(response, sort, secure=config.session.cookie_secure)
        return response

    # - Settings -> Features (§16.5, B193) ---------------------------------
    #
    # Two switches. Receivers off hides them; node backups off also stops
    # every cluster's backup timer with the schedule job the backup page
    # queues, remembers what it stopped, and on starts exactly that again.
    # The flip and its jobs are one transaction: a busy cluster refuses all of
    # it, so a switch never reads off while a timer it meant to stop still runs.
    #

    def _restore_waiting(request: Request) -> bool:
        with request.app.state.pool.connection() as connection:
            return feature_switch.restore_waiting(connection)

    @router.get("/settings/features/{name}", response_class=HTMLResponse)
    def feature_page(request: Request, name: str) -> Response:
        """The question before turning a feature off, when off does more than hide."""

        gate = _admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        feature = features.BY_NAME.get(name)
        if feature is None:
            return PlainTextResponse("Not found", status_code=404)
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        return TEMPLATES.TemplateResponse(
            request,
            "settings-feature.html",
            {
                "username": gate.username,
                "role": gate.role,
                "csrf_token": auth.csrf_token(token),
                "section": "settings",
                "management_writes": config.management_writes,
                "feature": feature,
            },
        )

    @router.post("/settings/features/{name}", response_class=HTMLResponse)
    def switch_feature(
        request: Request,
        name: str,
        enabled: str = Form(default="", max_length=3),
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        gate = _admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return PlainTextResponse("Refused", status_code=403)
        feature = features.BY_NAME.get(name)
        if feature is None or enabled not in ("on", "off"):
            return PlainTextResponse("Not found", status_code=404)
        want = enabled == "on"
        readings = feature_switch.Readings(
            clusters=lambda: listed_clusters(request, config),
            backup_overview=lambda: _backup_overview(config, request),
            objects=lambda: read_source(request, config, OBJECTS_SOURCE)[1],
            restore_waiting=lambda: _restore_waiting(request),
        )
        with request.app.state.pool.connection() as connection:
            try:
                feature_switch.switch(
                    connection,
                    name=name,
                    want=want,
                    actor=gate.username,
                    via="web",
                    readings=readings,
                )
            except feature_switch.UnknownFeature:
                connection.rollback()
                return PlainTextResponse("Not found", status_code=404)
            except features.SwitchRefused as problem:
                connection.rollback()
                return _settings_page(request, gate, problem=str(problem), status_code=409)
            connection.commit()
        return RedirectResponse(f"/settings?switched={name}-{enabled}", status_code=303)

    # - Settings -> Users (§16.4 U4, B189) ----------------------------------
    #
    # Admin only, behind the same gate as the tab and the form's CSRF token.
    # The signed-in session is the proof: no second password (decided
    # 2026-09-27, reverses that part of B187). Refuses the admin's own
    # account - that is the account menu's - and leaves the last active admin
    # to the database, which refuses under a lock whichever path asks. The
    # verbs and audit names are `haprion-user`'s, with `via: web`.
    #

    def _account_row(request: Request, username: str) -> db.AccountRow | None:
        with request.app.state.pool.connection() as connection:
            return db.account_row(
                connection,
                username,
                window_minutes=config.throttle.window_minutes,
                max_failures=config.throttle.max_failures,
            )

    def _users_context(request: Request, session: AuthenticatedSession) -> dict[str, Any]:
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        return {
            "username": session.username,
            "role": session.role,
            "csrf_token": auth.csrf_token(token),
            "section": "settings",
            "management_writes": config.management_writes,
            "minimum_length": auth.MINIMUM_PASSWORD_LENGTH,
            "roles": users.ROLES,
        }

    def _user_page(
        request: Request,
        session: AuthenticatedSession,
        row: db.AccountRow,
        *,
        problem: str = "",
        done: str = "",
        status_code: int = 200,
    ) -> Response:
        return TEMPLATES.TemplateResponse(
            request,
            "settings-user.html",
            {
                **_users_context(request, session),
                "account": users.user_view(row, signed_in_as=session.username),
                "problem": problem,
                "done": users.DONE.get(done, ""),
            },
            status_code=status_code,
        )

    def _new_user_page(
        request: Request,
        session: AuthenticatedSession,
        *,
        problem: str = "",
        form: Mapping[str, str] | None = None,
        status_code: int = 200,
    ) -> Response:
        return TEMPLATES.TemplateResponse(
            request,
            "settings-user-new.html",
            {
                **_users_context(request, session),
                "problem": problem,
                "form": {"username": "", "role": "reader", **(form or {})},
            },
            status_code=status_code,
        )

    # - Settings -> Logs & metrics (Fas 15, B209) ---------------------------

    def _cluster_settings_page(
        request: Request,
        session: AuthenticatedSession,
        cluster: str,
        *,
        head: str,
        form: cluster_settings_page.SettingsForm,
        saved: db.ClusterChange | None = None,
        problem: str = "",
        status_code: int = 200,
    ) -> Response:
        #
        # How each node's rsyslog is getting on with the receivers above,
        # where the attention list's forwarding rows lead (26-10-12).
        #
        _, status_rows = read_source(request, config, STATUS_SOURCE)
        status = next((row for row in status_rows if row.cluster == cluster), None)
        return TEMPLATES.TemplateResponse(
            request,
            "settings-cluster.html",
            {
                **_users_context(request, session),
                "delivery": cluster_settings_page.delivery(
                    status.result if status is not None else None, now=datetime.now(UTC)
                ),
                "cluster": cluster,
                "accent": cluster_identity.accent_index(cluster),
                "head": head,
                "form": form,
                "saved": saved,
                "problem": problem,
            },
            status_code=status_code,
        )

    def _saved_settings(request: Request, cluster: str, row: Any) -> db.ClusterChange | None:
        with request.app.state.pool.connection() as connection:
            return _settled_changes(connection, cluster, {"settings": _reading_head(row)}).get(
                "settings"
            )

    def _settings_reading(request: Request, cluster: str) -> Any:
        """This cluster's cached reading, or None when it is not listed or not read."""

        clusters, rows = read_source(request, config, SETTINGS_SOURCE)
        if cluster not in clusters:
            return None
        return next((row for row in rows if row.cluster == cluster and row.outcome == "done"), None)

    @router.get("/settings/clusters/{cluster}", response_class=HTMLResponse)
    def cluster_settings_edit(request: Request, cluster: str) -> Response:
        gate = _admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        row = _settings_reading(request, cluster)
        if row is None:
            return PlainTextResponse("Not found", status_code=404)
        #
        # Saved settings are what the form shows and what the next publish
        # carries (B257); the published ones when there are none, or when the
        # saved document no longer parses.
        #
        saved = _saved_settings(request, cluster, row)
        result = row.result
        if saved is not None:
            with contextlib.suppress(ConfigError):
                result = {
                    **row.result,
                    **cluster_settings_module.document_result(
                        cluster_settings_module.load_document(saved.document.encode("utf-8"))
                    ),
                }
        return _cluster_settings_page(
            request,
            gate,
            cluster,
            head=str(row.result.get("head", "")),
            form=cluster_settings_page.form_from_result(result),
            saved=saved,
        )

    @router.post("/settings/clusters/{cluster}", response_class=HTMLResponse)
    def cluster_settings_save(
        request: Request,
        cluster: str,
        target_name: Sequence[str] = Form(default=()),
        target_address: Sequence[str] = Form(default=()),
        target_port: Sequence[str] = Form(default=()),
        target_disk: Sequence[str] = Form(default=()),
        target_tls: Sequence[str] = Form(default=()),
        not_logged_from: str = Form(default="", max_length=2048),
        metrics_on: str = Form(default="", max_length=4),
        metrics_port: str = Form(default="", max_length=8),
        metrics_sources: str = Form(default="", max_length=2048),
        peers_on: str = Form(default="", max_length=4),
        peers_port: str = Form(default="", max_length=8),
        expected_head: str = Form(default="", max_length=40),
        #
        # Save, or discard what was saved (B257); published from Versions.
        #
        settings_action: str = Form(default="save", max_length=8),
        saved_revision: str = Form(default="", max_length=16),
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        gate = _admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return PlainTextResponse("Refused", status_code=403)
        if _settings_reading(request, cluster) is None:
            return PlainTextResponse("Not found", status_code=404)
        revision = int(saved_revision) if is_digits(saved_revision) else None
        page = f"/settings/clusters/{cluster}"
        if settings_action == "discard":
            if revision is None:
                return PlainTextResponse("There is nothing to discard", status_code=400)
            with request.app.state.pool.connection() as connection:
                try:
                    db.discard_cluster_change(
                        connection, cluster=cluster, kind="settings", expected_revision=revision
                    )
                except db.DraftConflict:
                    connection.rollback()
                    return PlainTextResponse(
                        "The saved settings changed since they were read; reload and try again",
                        status_code=409,
                    )
                db.record_audit_event(
                    connection,
                    actor=gate.username,
                    action="discard_change",
                    cluster=cluster,
                    request_id=uuid4(),
                    detail={"kind": "settings"},
                )
                connection.commit()
            return RedirectResponse(page, status_code=303)
        if settings_action != "save":
            return PlainTextResponse("Unknown action", status_code=400)
        if not COMMIT_ID.fullmatch(expected_head):
            return PlainTextResponse("Invalid operation parameters", status_code=400)
        rows = max(len(target_name), len(target_address), len(target_port))
        if rows > cluster_settings_page.MAX_TARGETS:
            return PlainTextResponse("Too many log targets", status_code=400)

        def field(values: Sequence[str], index: int) -> str:
            # Bounded here rather than by the form parser, which cannot bound
            # the members of a repeated field.
            return values[index][:64] if index < len(values) else ""

        form = cluster_settings_page.SettingsForm(
            targets=tuple(
                cluster_settings_page.TargetRow(
                    name=field(target_name, index),
                    address=field(target_address, index),
                    port=field(target_port, index),
                    disk_mib=field(target_disk, index),
                    tls=field(target_tls, index) == "yes",
                )
                for index in range(cluster_settings_page.MAX_TARGETS)
            ),
            not_logged_from=not_logged_from,
            metrics_on=metrics_on == "on",
            metrics_port=metrics_port,
            metrics_sources=metrics_sources,
            peers_on=peers_on == "on",
            peers_port=peers_port,
        )
        try:
            settings = cluster_settings_page.settings_from_form(form)
        except cluster_settings_page.FormProblem as problem:
            return _cluster_settings_page(
                request,
                gate,
                cluster,
                head=expected_head,
                form=form,
                problem=str(problem),
                status_code=400,
            )
        #
        # The document is built here, from named fields, and in the engine's
        # canonical form; the helper parses it again and is the authority.
        #
        document = cluster_settings_module.dump_document(settings).decode("utf-8")
        #
        # Saved, and published with the next publish from Versions (B257).
        #
        with request.app.state.pool.connection() as connection:
            try:
                change = db.save_cluster_change(
                    connection,
                    cluster=cluster,
                    kind="settings",
                    document=document,
                    base_hash=expected_head,
                    updated_by=gate.username,
                    expected_revision=revision,
                )
            except db.DraftConflict as conflict:
                connection.rollback()
                return _cluster_settings_page(
                    request,
                    gate,
                    cluster,
                    head=expected_head,
                    form=form,
                    problem=str(conflict),
                    status_code=409,
                )
            db.record_audit_event(
                connection,
                actor=gate.username,
                action="save_change",
                cluster=cluster,
                request_id=uuid4(),
                detail={"kind": "settings", "revision": change.revision},
            )
            connection.commit()
        return RedirectResponse(page, status_code=303)

    # - Settings -> Nodes (Fas 16, B211) ------------------------------------
    #
    # Which nodes each cluster has, and adding or removing one. The list is the
    # poller's status reading; a change is a `cluster_node` job for the root
    # helper, confirmed with the node's name, because both directions change
    # who can fetch the cluster's configuration and certificates.
    #

    def _nodes_page(
        request: Request,
        gate: AuthenticatedSession,
        cluster: str,
        *,
        addition: cluster_nodes.Addition | None = None,
        removal: str = "",
        moving: str = "",
        cluster_removal: bool = False,
        block: str = "",
        host: str = "",
        problem: str = "",
        joined: bool = False,
        status_code: int = 200,
    ) -> Response:
        _token, _registry, context = _page_context(config, request, gate)
        with request.app.state.pool.connection() as connection:
            recent = db.recent_jobs(connection)
            hidden_at = db.getting_started_hidden_at(connection)
        listed = listed_clusters(request, config)
        status = _status_row(config, request, cluster)
        rows = cluster_nodes.node_rows(status)
        return TEMPLATES.TemplateResponse(
            request,
            "settings-nodes.html",
            {
                **context,
                # Arrived from Create cluster: what was joined (finding 57).
                "joined": [row.name for row in rows] if joined else [],
                #
                # Nothing deployed yet: where to go next is the Dashboard, and
                # Getting started there when an admin still has it (finding 69).
                #
                "undeployed": dashboard.not_deployed(status),
                "getting_started_listed": gate.role == "admin" and hidden_at is None,
                "section": "settings",
                "cluster": cluster,
                "accent": cluster_identity.accent_index(cluster),
                "nodes": rows,
                #
                # The button follows the rule the removal is checked with, so
                # the two cannot disagree (Fas 18, 26-10-15: a count of two left
                # from before B302 hid it on every two-node cluster).
                #
                "removable_nodes": {
                    row.name for row in rows if cluster_nodes.removable(rows, row.name) is None
                },
                "running": jobs.in_flight(recent).get(cluster),
                "addition": addition,
                "removal": removal,
                "moving": moving,
                "cluster_removal": cluster_removal,
                "cluster_removable": cluster_nodes.cluster_removable(listed, cluster) is None,
                "block": block,
                "host": host,
                "problem": problem,
            },
            status_code=status_code,
        )

    @router.get("/settings/nodes/{cluster}", response_class=HTMLResponse)
    def cluster_nodes_page(request: Request, cluster: str) -> Response:
        gate = _admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        if cluster not in listed_clusters(request, config):
            return PlainTextResponse("Not found", status_code=404)
        return _nodes_page(request, gate, cluster, joined=request.query_params.get("joined") == "1")

    @router.post("/settings/nodes/{cluster}/add", response_class=HTMLResponse)
    def cluster_node_add(
        request: Request,
        cluster: str,
        block: str = Form(default="", max_length=8192),
        host: str = Form(default="", max_length=253),
        confirm: str = Form(default="", max_length=64),
        idempotency_key: str = Form(default="", max_length=64),
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        """Read the block and show what it says; with the node's name typed, queue it."""

        gate = _admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return PlainTextResponse("Refused", status_code=403)
        if cluster not in listed_clusters(request, config):
            return PlainTextResponse("Not found", status_code=404)
        try:
            addition = cluster_nodes.read_addition(
                block,
                cluster=cluster,
                host=host,
                count=len(cluster_nodes.node_rows(_status_row(config, request, cluster))),
            )
        except cluster_nodes.FormProblem as problem:
            return _nodes_page(
                request,
                gate,
                cluster,
                block=block,
                host=host,
                problem=str(problem),
                status_code=400,
            )
        if not confirm:
            return _nodes_page(request, gate, cluster, addition=addition)
        if confirm.strip() != addition.name:
            return _nodes_page(
                request,
                gate,
                cluster,
                addition=addition,
                problem=f"Type {addition.name} to add it.",
                status_code=400,
            )
        try:
            key = UUID(idempotency_key)
        except ValueError:
            return PlainTextResponse("A request key is required", status_code=400)
        try:
            stored, join_key = cluster_nodes.sealed_block(
                addition.block, cluster=cluster, public_key=_dns_public_key(config)
            )
        except cluster_nodes.FormProblem as problem:
            return _nodes_page(
                request, gate, cluster, addition=addition, problem=str(problem), status_code=400
            )
        payload: dict[str, Any] = {
            "action": "add",
            "block": stored,
            "host": addition.host,
            "deploy": True,
        }
        if join_key is not None:
            payload["join_key"] = join_key
        return _queue_node_job(
            config,
            request,
            gate,
            cluster,
            payload,
            key,
            addition.name,
            lambda problem: _nodes_page(
                request, gate, cluster, addition=addition, problem=problem, status_code=409
            ),
        )

    @router.post("/settings/nodes/{cluster}/remove", response_class=HTMLResponse)
    def cluster_node_remove(
        request: Request,
        cluster: str,
        node: str = Form(default="", max_length=64),
        confirm: str = Form(default="", max_length=64),
        idempotency_key: str = Form(default="", max_length=64),
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        """Ask first; with the node's name typed, queue the removal."""

        gate = _admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return PlainTextResponse("Refused", status_code=403)
        if cluster not in listed_clusters(request, config):
            return PlainTextResponse("Not found", status_code=404)
        refused = cluster_nodes.removable(
            cluster_nodes.node_rows(_status_row(config, request, cluster)), node
        )
        if refused is not None:
            return _nodes_page(request, gate, cluster, problem=refused, status_code=400)
        if not confirm:
            return _nodes_page(request, gate, cluster, removal=node)
        if confirm.strip() != node:
            return _nodes_page(
                request,
                gate,
                cluster,
                removal=node,
                problem=f"Type {node} to remove it.",
                status_code=400,
            )
        try:
            key = UUID(idempotency_key)
        except ValueError:
            return PlainTextResponse("A request key is required", status_code=400)
        return _queue_node_job(
            config,
            request,
            gate,
            cluster,
            {"action": "remove", "node": node, "deploy": True},
            key,
            node,
            lambda problem: _nodes_page(
                request, gate, cluster, removal=node, problem=problem, status_code=409
            ),
        )

    @router.post("/settings/nodes/{cluster}/host", response_class=HTMLResponse)
    def cluster_node_host(
        request: Request,
        cluster: str,
        node: str = Form(default="", max_length=64),
        host: str = Form(default="", max_length=253),
        idempotency_key: str = Form(default="", max_length=64),
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        """The same node at another name (B295): ask for the host, then queue the change."""

        gate = _admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return PlainTextResponse("Refused", status_code=403)
        if cluster not in listed_clusters(request, config):
            return PlainTextResponse("Not found", status_code=404)
        rows = cluster_nodes.node_rows(_status_row(config, request, cluster))
        if not any(row.name == node for row in rows):
            return PlainTextResponse("Not found", status_code=404)
        if not idempotency_key:
            current = next(row.host for row in rows if row.name == node)
            return _nodes_page(request, gate, cluster, moving=node, host=current)
        try:
            new_host = cluster_nodes.read_host_change(rows, node, host)
            key = UUID(idempotency_key)
        except cluster_nodes.FormProblem as problem:
            return _nodes_page(
                request,
                gate,
                cluster,
                moving=node,
                host=host,
                problem=str(problem),
                status_code=400,
            )
        except ValueError:
            return PlainTextResponse("A request key is required", status_code=400)
        return _queue_node_job(
            config,
            request,
            gate,
            cluster,
            {"action": "host", "node": node, "host": new_host},
            key,
            node,
            lambda problem: _nodes_page(
                request,
                gate,
                cluster,
                moving=node,
                host=host,
                problem=problem,
                status_code=409,
            ),
        )

    @router.post("/settings/nodes/{cluster}/remove-cluster", response_class=HTMLResponse)
    def cluster_remove(
        request: Request,
        cluster: str,
        confirm: str = Form(default="", max_length=64),
        idempotency_key: str = Form(default="", max_length=64),
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        """Ask first; with the cluster's ID typed, queue its removal (B211)."""

        gate = _admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return PlainTextResponse("Refused", status_code=403)
        listed = listed_clusters(request, config)
        if cluster not in listed:
            return PlainTextResponse("Not found", status_code=404)
        refused = cluster_nodes.cluster_removable(listed, cluster)
        if refused is not None:
            return _nodes_page(request, gate, cluster, problem=refused, status_code=400)
        if not confirm:
            return _nodes_page(request, gate, cluster, cluster_removal=True)
        if confirm.strip() != cluster:
            return _nodes_page(
                request,
                gate,
                cluster,
                cluster_removal=True,
                problem=f"Type {cluster} to remove it.",
                status_code=400,
            )
        try:
            key = UUID(idempotency_key)
        except ValueError:
            return PlainTextResponse("A request key is required", status_code=400)
        return _queue_node_job(
            config,
            request,
            gate,
            cluster,
            {"action": "remove"},
            key,
            None,
            lambda problem: _nodes_page(
                request, gate, cluster, cluster_removal=True, problem=problem, status_code=409
            ),
            operation="cluster_define",
            back="/settings#nodes",
        )

    def _new_cluster_page(
        request: Request,
        gate: AuthenticatedSession,
        *,
        form: Mapping[str, str] | None = None,
        creation: cluster_nodes.Creation | None = None,
        creating: cluster_nodes.Creating | None = None,
        problem: str = "",
        status_code: int = 200,
    ) -> Response:
        _token, registry, context = _page_context(config, request, gate)
        return TEMPLATES.TemplateResponse(
            request,
            "settings-cluster-new.html",
            {
                **context,
                "creating": creating,
                "section": "settings",
                "form": {field: "" for field in cluster_nodes.CREATION_FIELDS} | dict(form or {}),
                "certificates": sorted(
                    entry.identifier for entry in (registry.certificates if registry else ())
                ),
                "creation": creation,
                "problem": problem,
            },
            status_code=status_code,
        )

    @router.get("/settings/new-cluster", response_class=HTMLResponse)
    def new_cluster_page(request: Request) -> Response:
        gate = _admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        #
        # Create cluster stays here while the cluster is made, as the guide's
        # first-node step does (Fas 18, finding 57), and goes on to the
        # cluster's own page once the list has it, where the next node is
        # added. A redraw that comes back redirected is reloaded, which
        # follows it.
        #
        creating = request.query_params.get("creating", "")
        if CLUSTER_ID.fullmatch(creating):
            if creating in listed_clusters(request, config):
                return RedirectResponse(f"/settings/nodes/{creating}?joined=1", status_code=303)
            with request.app.state.pool.connection() as connection:
                recent = db.recent_jobs(connection)
            shown = next(
                (row for row in _creations(request, recent) if row.cluster == creating), None
            )
            if shown is not None:
                return _new_cluster_page(request, gate, creating=shown)
        return _new_cluster_page(request, gate)

    @router.post("/settings/new-cluster", response_class=HTMLResponse)
    def cluster_create(
        request: Request,
        cluster: str = Form(default="", max_length=64),
        display_name: str = Form(default="", max_length=64),
        vip: str = Form(default="", max_length=64),
        address_prefix: str = Form(default="", max_length=4),
        address_interface: str = Form(default="", max_length=64),
        node_path: str = Form(default="", max_length=64),
        default_certificate: str = Form(default="", max_length=253),
        block_1: str = Form(default="", max_length=8192),
        host_1: str = Form(default="", max_length=253),
        block_2: str = Form(default="", max_length=8192),
        host_2: str = Form(default="", max_length=253),
        confirm: str = Form(default="", max_length=64),
        idempotency_key: str = Form(default="", max_length=64),
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        """Read the form and both blocks and show them; with the ID typed, queue it (B211)."""

        gate = _admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return PlainTextResponse("Refused", status_code=403)
        form = {
            "cluster": cluster,
            "display_name": display_name,
            "vip": vip,
            "address_prefix": address_prefix,
            "address_interface": address_interface,
            "node_path": node_path,
            "default_certificate": default_certificate,
            "block_1": block_1,
            "host_1": host_1,
            "block_2": block_2,
            "host_2": host_2,
        }
        registry = _registry_overview(config, request)
        try:
            creation = cluster_nodes.read_creation(
                form,
                listed=listed_clusters(request, config),
                certificates=(
                    entry.identifier for entry in (registry.certificates if registry else ())
                ),
            )
        except cluster_nodes.FormProblem as problem:
            return _new_cluster_page(
                request, gate, form=form, problem=str(problem), status_code=400
            )
        if not confirm:
            return _new_cluster_page(request, gate, form=form, creation=creation)
        if confirm.strip() != creation.cluster:
            return _new_cluster_page(
                request,
                gate,
                form=form,
                creation=creation,
                problem=f"Type {creation.cluster} to create it.",
                status_code=400,
            )
        try:
            key = UUID(idempotency_key)
        except ValueError:
            return PlainTextResponse("A request key is required", status_code=400)
        try:
            creation_payload = creation.payload(_dns_public_key(config))
        except cluster_nodes.FormProblem as problem:
            return _new_cluster_page(
                request, gate, form=form, creation=creation, problem=str(problem), status_code=400
            )
        return _queue_node_job(
            config,
            request,
            gate,
            creation.cluster,
            creation_payload,
            key,
            None,
            lambda problem: _new_cluster_page(
                request, gate, form=form, creation=creation, problem=problem, status_code=409
            ),
            operation="cluster_define",
            #
            # Back to this page, which shows the cluster being made until the
            # poller has read it and then goes on to the cluster's page; a
            # creation that failed says so here (review 2026-09-30 F3, Fas 18
            # findings 51 and 57).
            #
            back=f"/settings/new-cluster?creating={creation.cluster}",
        )

    @router.get("/settings/new-user", response_class=HTMLResponse)
    def new_user_page(request: Request) -> Response:
        gate = _admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        return _new_user_page(request, gate)

    @router.post("/settings/new-user", response_class=HTMLResponse)
    def create_user(
        request: Request,
        username: str = Form(default="", max_length=64),
        role: str = Form(default="", max_length=16),
        new_password: str = Form(default="", max_length=auth.MAX_PASSWORD_BYTES),
        repeat_password: str = Form(default="", max_length=auth.MAX_PASSWORD_BYTES),
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        gate = _admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return PlainTextResponse("Refused", status_code=403)
        form = {"username": username, "role": role}
        if not username:
            problem = "Name the account."
        elif users.name_problem(username) is not None:
            problem = users.NAME_PROBLEM
        elif role not in users.ROLES:
            problem = "Choose a role."
        else:
            problem = _new_password_problem(new_password, repeat_password)
        if problem:
            return _new_user_page(request, gate, problem=problem, form=form, status_code=400)

        with request.app.state.pool.connection() as connection:
            if not db.create_account(
                connection,
                username=username,
                password_hash=auth.hash_password(new_password),
                role=role,
            ):
                connection.rollback()
                return _new_user_page(
                    request,
                    gate,
                    problem="An account with that name already exists.",
                    form=form,
                    status_code=409,
                )
            db.record_audit_event(
                connection,
                actor=gate.username,
                action="account_created",
                detail={"account": username, "role": role, "via": "web"},
            )
            connection.commit()
        # Back to the list the account now stands in, not to the account itself.
        return RedirectResponse("/settings#users", status_code=303)

    @router.get("/settings/users/{name}", response_class=HTMLResponse)
    def user_page(request: Request, name: str) -> Response:
        gate = _admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        row = _account_row(request, name)
        if row is None:
            return PlainTextResponse("Not found", status_code=404)
        return _user_page(request, gate, row, done=request.query_params.get("done", "")[:16])

    @router.post("/settings/users/{name}", response_class=HTMLResponse)
    def change_user(
        request: Request,
        name: str,
        action: str = Form(default="", max_length=16),
        role: str = Form(default="", max_length=16),
        new_password: str = Form(default="", max_length=auth.MAX_PASSWORD_BYTES),
        repeat_password: str = Form(default="", max_length=auth.MAX_PASSWORD_BYTES),
        break_glass: str = Form(default="", max_length=8),
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        gate = _admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return PlainTextResponse("Refused", status_code=403)
        if action not in users.ACTIONS:
            return PlainTextResponse("Unknown action", status_code=400)
        row = _account_row(request, name)
        if row is None:
            return PlainTextResponse("Not found", status_code=404)

        def again(problem: str, status_code: int = 400) -> Response:
            return _user_page(request, gate, row, problem=problem, status_code=status_code)

        if row.username.lower() == gate.username.lower():
            return again("This is your own account. Change your password from the account menu.")
        provider = row.source == "oidc"
        if action == "save" and provider:
            return again("The provider sets this account's role, and it has no password here.")
        #
        # Save writes what differs from the account: the role when another
        # is chosen, the password when one is typed, the break-glass mark when
        # it is changed. All in one transaction, so a refused role leaves the
        # rest as it was too.
        #
        new_role = action == "save" and role != row.role
        new_secret = action == "save" and bool(new_password or repeat_password)
        new_break_glass = action == "save" and (break_glass == "on") != row.break_glass
        if action == "save" and role not in users.ROLES:
            return again("Choose a role.")
        if action == "save" and not (new_role or new_secret or new_break_glass):
            return again("Nothing to save: change the role, the password or break-glass.")
        if new_secret:
            problem = _new_password_problem(new_password, repeat_password)
            if problem:
                return again(problem)
        if action == "disable" and row.disabled:
            return again("The account is already disabled.")
        if action == "enable" and not row.disabled:
            return again("The account is already enabled.")

        with request.app.state.pool.connection() as connection:
            changes: list[tuple[str, dict[str, object]]] = []

            def detail(**fields: object) -> dict[str, object]:
                return {"account": row.username, "via": "web", **fields}

            try:
                if new_role:
                    db.set_role(connection, user_id=row.id, role=role)
                    changes.append(("role_changed", detail(role=role, previous=row.role)))
                if new_secret:
                    ended = db.reset_password(
                        connection, user_id=row.id, password_hash=auth.hash_password(new_password)
                    )
                    changes.append(("password_reset", detail(sessions_revoked=ended)))
                if new_break_glass:
                    db.set_break_glass(connection, user_id=row.id, break_glass=not row.break_glass)
                    changes.append(("break_glass_changed", detail(break_glass=not row.break_glass)))
                if action == "delete":
                    if db.delete_account(connection, user_id=row.id):
                        changes.append(
                            ("account_deleted", detail(role=row.role, source=row.source))
                        )
                elif action == "disable":
                    ended = db.set_disabled(connection, user_id=row.id, disabled=True)
                    changes.append(("account_disabled", detail(sessions_revoked=ended)))
                elif action == "enable":
                    db.set_disabled(connection, user_id=row.id, disabled=False)
                    changes.append(("account_enabled", detail()))
                elif action == "revoke":
                    ended = db.revoke_sessions_for_user(connection, row.id)
                    changes.append(("sessions_revoked", detail(sessions_revoked=ended)))
                elif action == "unlock":
                    db.unlock_account(connection, username=row.username, actor=gate.username)
                    changes.append(("throttle_cleared", detail()))
            except db.NoBreakGlass:
                connection.rollback()
                return again(
                    "Sign-in through the provider is on and needs an active break-glass admin.",
                    409,
                )
            except db.LastAdmin:
                connection.rollback()
                return again("The last active admin cannot be demoted, disabled or deleted.", 409)
            for audit_action, audit_detail in changes:
                db.record_audit_event(
                    connection, actor=gate.username, action=audit_action, detail=audit_detail
                )
            connection.commit()
        if action == "delete":
            # The account's page is gone; back to the list it no longer stands in.
            return RedirectResponse("/settings#users", status_code=303)
        if action == "save":
            made = [new_role, new_secret, new_break_glass].count(True)
            if made > 1:
                done = "saved_password" if new_secret else "saved"
            else:
                done = "role" if new_role else "password" if new_secret else "break_glass"
        else:
            done = action
        return RedirectResponse(f"{users.href(row.username)}?done={done}", status_code=303)

    @router.get("/settings/oidc", response_class=HTMLResponse)
    def oidc_settings_page(request: Request) -> Response:
        """Settings -> Users -> OIDC configuration (B197)."""

        gate = _admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        provider = _oidc_provider(request)
        if provider is None:
            return PlainTextResponse("Not found", status_code=404)
        done = {
            "saved": "Saved.",
            "on": "Sign-in through the provider is on.",
            "off": "Sign-in through the provider is off.",
        }
        return _oidc_page(
            config, request, gate, provider, done=done.get(request.query_params.get("done", ""), "")
        )

    @router.post("/settings/oidc", response_class=HTMLResponse)
    def change_oidc_settings(request: Request) -> Response:
        """Save, Verify, and turn on or off. Each is audited; the secret never is."""

        gate = _admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        posted = _posted(request)
        form = {key: value for key, value in posted.items() if isinstance(value, str)}
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, form.get(auth.CSRF_FIELD, "")):
            return PlainTextResponse("Refused", status_code=403)
        provider = _oidc_provider(request)
        if provider is None:
            return PlainTextResponse("Not found", status_code=404)
        action = form.get("action", "")
        redirect = oidc_web.redirect_uri(str(request.base_url))

        def again(
            problem: str,
            *,
            shown: Mapping[str, Any] | None = None,
            checks: list[dict[str, Any]] | None = None,
            status_code: int = 400,
        ) -> Response:
            return _oidc_page(
                config,
                request,
                gate,
                provider,
                form=shown,
                problem=problem,
                checks=checks,
                status_code=status_code,
            )

        def verify(candidate: db.OidcProvider) -> tuple[bool, list[dict[str, Any]], str]:
            try:
                result = oidc_web.ask("verify", candidate, redirect=redirect)
            except oidc_web.OidcUnavailable as error:
                return False, [], str(error)
            except oidc_web.OidcRefused as error:
                return False, [], str(error)
            checks = [check for check in result.get("checks", []) if isinstance(check, dict)]
            return result.get("ok") is True, checks, ""

        if action == "save":
            shown = {
                key: (form.get(key) == "on" if key == "prompt_login" else form.get(key, ""))
                for key in db.OIDC_SETTINGS
                if key not in ("client_secret_sealed", "key_id")
            }
            parsed = oidc_web.parse(form, provider, public_key=config.oidc_public_key)
            if parsed.problem:
                return again(parsed.problem, shown=shown)
            #
            # Said here rather than left to the row: the trigger raises the
            # revision only when a setting changes, so an unchanged save while
            # on would be refused as unverified settings - which they are not.
            #
            if all(getattr(provider, name) == value for name, value in parsed.settings.items()):
                return again("Nothing to save: no setting was changed.", shown=shown)
            verified = False
            if provider.enabled:
                #
                # On, the row accepts only verified settings: these are
                # verified first, and saved as verified in one statement.
                #
                candidate = replace(provider, **parsed.settings)
                verified, checks, trouble = verify(candidate)
                if not verified:
                    return again(
                        trouble
                        or "Sign-in through the provider is on, and these settings did not pass Verify. Nothing was saved.",
                        shown=shown,
                        checks=checks,
                    )
            with request.app.state.pool.connection() as connection:
                try:
                    db.save_oidc_provider(
                        connection, settings=parsed.settings, actor=gate.username, verified=verified
                    )
                except db.ProviderRefused as error:
                    connection.rollback()
                    return again(str(error), shown=shown, status_code=409)
                db.record_audit_event(
                    connection,
                    actor=gate.username,
                    action="oidc_configured",
                    detail={
                        "issuer": parsed.settings["issuer"],
                        "client_id": parsed.settings["client_id"],
                        "secret_replaced": "client_secret_sealed" in parsed.settings,
                        "via": "web",
                    },
                )
                connection.commit()
            return RedirectResponse("/settings/oidc?done=saved", status_code=303)

        if action == "verify":
            ok, checks, trouble = verify(provider)
            if trouble:
                return again(trouble, status_code=409)
            with request.app.state.pool.connection() as connection:
                recorded = ok and db.record_oidc_verified(connection, revision=provider.revision)
                db.record_audit_event(
                    connection,
                    actor=gate.username,
                    action="oidc_verified",
                    detail={
                        "issuer": provider.issuer,
                        "ok": ok,
                        "revision": provider.revision,
                        "via": "web",
                    },
                )
                connection.commit()
            refreshed = _oidc_provider(request) or provider
            return _oidc_page(
                config,
                request,
                gate,
                refreshed,
                checks=checks,
                done="Verified." if recorded else "",
                problem="" if ok else "Verify found a problem.",
                status_code=200 if ok else 409,
            )

        if action == "test":
            #
            # A sign-in that creates no session and shows what came back,
            # bound to this admin's session rather than a pre-sign-in cookie.
            #
            try:
                return _start_oidc(request, provider, mode="test", bound_to=token)
            except oidc_web.OidcProblem as error:
                return again(f"{UNAVAILABLE_PROVIDER}: {error}", status_code=409)

        if action in ("on", "off"):
            with request.app.state.pool.connection() as connection:
                try:
                    db.set_oidc_enabled(connection, enabled=action == "on", actor=gate.username)
                except db.ProviderRefused as error:
                    connection.rollback()
                    return again(str(error), status_code=409)
                db.record_audit_event(
                    connection,
                    actor=gate.username,
                    action="oidc_enabled" if action == "on" else "oidc_disabled",
                    detail={"issuer": provider.issuer, "via": "web"},
                )
                connection.commit()
            return RedirectResponse(f"/settings/oidc?done={action}", status_code=303)

        return PlainTextResponse("Unknown action", status_code=400)

    @router.get("/settings/users/{name}/delete", response_class=HTMLResponse)
    def delete_user_page(request: Request, name: str) -> Response:
        """The question before an account is removed for good (B197)."""

        gate = _admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        row = _account_row(request, name)
        if row is None:
            return PlainTextResponse("Not found", status_code=404)
        if row.username.lower() == gate.username.lower():
            return RedirectResponse(users.href(row.username), status_code=303)
        return TEMPLATES.TemplateResponse(
            request,
            "settings-user-delete.html",
            {
                **_users_context(request, gate),
                "account": users.user_view(row, signed_in_as=gate.username),
            },
        )

    @router.get("/certificates/receivers", response_class=HTMLResponse)
    def certificate_receivers_page(request: Request) -> Response:
        """Who fetches from this manager, and what each host runs to do it."""

        gate = _admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        return _receivers_page(request, gate)

    @router.get("/certificates/receivers/new", response_class=HTMLResponse)
    def certificate_receiver_form(request: Request) -> Response:
        """Register a receiver: its own page, like a new certificate is."""

        gate = _admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        if _registry_overview(config, request) is None:
            return RedirectResponse("/certificates/receivers", status_code=303)
        return _receiver_form_page(request, gate)

    def _queue_receiver_job(
        request: Request,
        session: AuthenticatedSession,
        payload: Mapping[str, Any],
        key: UUID,
        *,
        form: Mapping[str, str] | None,
        password: str | None = None,
    ) -> Response:
        def again(problem: str) -> Response:
            if form is None:
                return _receivers_page(request, session, problem=problem)
            return _receiver_form_page(request, session, problem=problem, form=form)

        try:
            operations.prepare(
                operation="cert_receiver", cluster=None, request_id=uuid4(), payload=payload
            )
        except operations.BadPayload as refused:
            return again(str(refused))
        with request.app.state.pool.connection() as connection:
            try:
                job = db.queue_job(
                    connection,
                    operation="cert_receiver",
                    cluster=None,
                    payload=payload,
                    idempotency_key=key,
                )
            except db.CertificateBusy:
                connection.rollback()
                return again(
                    "A certificate job is already running. Wait for it to finish, then ask again."
                )
            except db.RequestConflict:
                connection.rollback()
                return PlainTextResponse("That request key asked for something else", 409)
            #
            # The audit row names the receiver and the action, never the key:
            # a public key is not a secret, but the audit log is not where a
            # reader looks for one either.
            #
            db.record_audit_event(
                connection,
                actor=session.username,
                action="queue_job",
                cluster=None,
                request_id=job.request_id,
                detail={
                    "operation": "cert_receiver",
                    "job": job.id,
                    "receiver": payload["receiver"],
                    "action": payload["action"],
                },
            )
            connection.commit()
        if password is not None:
            #
            # Drawn here rather than after a redirect: a redirect's next page
            # would need the password from somewhere, and nothing holds it.
            #
            return _receiver_password_page(request, session, payload["receiver"], password)
        return RedirectResponse("/certificates/receivers", status_code=303)

    @router.post("/certificates/receivers/new", response_class=HTMLResponse)
    def certificate_receiver_add(
        request: Request,
        receiver: str = Form(default="", max_length=128),
        transport: str = Form(default="", max_length=16),
        public_key: str = Form(default="", max_length=8192),
        allow: str = Form(default="", max_length=2048),
        idempotency_key: str = Form(default="", max_length=64),
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        """Queue one `cert_receiver` add job, or draw the form again saying why not."""

        gate = _admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return PlainTextResponse("Refused", status_code=403)
        try:
            key = UUID(idempotency_key)
        except ValueError:
            return PlainTextResponse("A request key is required", status_code=400)
        entered = {
            "receiver": receiver,
            "transport": transport,
            "public_key": public_key,
            "allow": allow,
        }
        registry = _registry_overview(config, request)
        try:
            payload = certificate_receivers.payload(
                receiver, transport, public_key, allow, registry.receiver_rows if registry else ()
            )
        except certificate_receivers.ReceiverProblem as refused:
            return _receiver_form_page(request, gate, problem=str(refused), form=entered)
        password = None
        if payload.get("transport") == "https":
            password = cert_receiver.new_secret()
            payload = {**payload, "secret_hash": cert_receiver.secret_hash(password)}
        return _queue_receiver_job(request, gate, payload, key, form=entered, password=password)

    @router.post("/certificates/receivers/secret", response_class=HTMLResponse)
    def certificate_receiver_secret(
        request: Request,
        receiver: str = Form(default="", max_length=128),
        idempotency_key: str = Form(default="", max_length=64),
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        """Queue a new secret for an https receiver, and show its password once."""

        gate = _admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return PlainTextResponse("Refused", status_code=403)
        try:
            key = UUID(idempotency_key)
        except ValueError:
            return PlainTextResponse("A request key is required", status_code=400)
        registry = _registry_overview(config, request)
        rows = registry.receiver_rows if registry else ()
        if not any(row.identifier == receiver and row.transport == "https" for row in rows):
            return _receivers_page(request, gate, problem=f"{receiver} is not an https receiver.")
        password = cert_receiver.new_secret()
        payload = {
            "receiver": receiver,
            "action": "secret",
            "secret_hash": cert_receiver.secret_hash(password),
        }
        return _queue_receiver_job(request, gate, payload, key, form=None, password=password)

    #
    # A new public key for an rsync or sftp receiver (26-10-18): a host
    # installed again keeps its name, directory and certificates and has a new
    # key pair. Its own page, as registering is, for the key steps and the paste.
    #
    def _receiver_key_page(
        request: Request,
        session: AuthenticatedSession,
        receiver: str,
        transport: str,
        *,
        public_key: str = "",
        problem: str = "",
    ) -> Response:
        _token, _registry, context = _page_context(config, request, session)
        return TEMPLATES.TemplateResponse(
            request,
            "certificate-receiver-key.html",
            {
                **context,
                "receiver": receiver,
                "key_steps": certificate_receivers.key_steps(receiver),
                "windows": transport in certificate_receivers.WINDOWS_TRANSPORTS,
                "public_key": public_key,
                "problem": problem,
            },
        )

    def _ssh_transport(request: Request, receiver: str) -> str | None:
        """The receiver's transport when it fetches over ssh, else None."""

        registry = _registry_overview(config, request)
        rows = registry.receiver_rows if registry else ()
        return next(
            (
                row.transport
                for row in rows
                if row.identifier == receiver and row.transport != "https"
            ),
            None,
        )

    @router.get("/certificates/receivers/key", response_class=HTMLResponse)
    def certificate_receiver_key_form(request: Request) -> Response:
        gate = _admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        receiver = request.query_params.get("receiver", "")
        transport = _ssh_transport(request, receiver)
        if transport is None:
            return _receivers_page(request, gate, problem=f"{receiver} has no SSH key to replace.")
        return _receiver_key_page(request, gate, receiver, transport)

    @router.post("/certificates/receivers/key", response_class=HTMLResponse)
    def certificate_receiver_key(
        request: Request,
        receiver: str = Form(default="", max_length=128),
        public_key: str = Form(default="", max_length=8192),
        idempotency_key: str = Form(default="", max_length=64),
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        """Queue a new key for an ssh receiver; its lock, directory and certificates stay."""

        gate = _admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return PlainTextResponse("Refused", status_code=403)
        try:
            key = UUID(idempotency_key)
        except ValueError:
            return PlainTextResponse("A request key is required", status_code=400)
        transport = _ssh_transport(request, receiver)
        if transport is None:
            return _receivers_page(request, gate, problem=f"{receiver} has no SSH key to replace.")
        #
        # The helper's own shape check, here first, so a wrong paste is said
        # beside the field rather than as a failed job.
        #
        try:
            cert_receiver.parse_public_key(public_key, "The pasted text")
        except cert_receiver.ReceiverError as refused:
            return _receiver_key_page(
                request, gate, receiver, transport, public_key=public_key, problem=str(refused)
            )
        payload = {"receiver": receiver, "action": "key", "public_key": public_key}
        return _queue_receiver_job(request, gate, payload, key, form=None)

    @router.post("/certificates/receivers/remove", response_class=HTMLResponse)
    def certificate_receiver_remove(
        request: Request,
        receiver: str = Form(default="", max_length=128),
        idempotency_key: str = Form(default="", max_length=64),
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        """Queue one `cert_receiver` remove job for a receiver nothing publishes to."""

        gate = _admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return PlainTextResponse("Refused", status_code=403)
        try:
            key = UUID(idempotency_key)
        except ValueError:
            return PlainTextResponse("A request key is required", status_code=400)
        registry = _registry_overview(config, request)
        try:
            payload = certificate_receivers.removal(
                receiver, registry.receiver_rows if registry else ()
            )
        except certificate_receivers.ReceiverProblem as refused:
            return _receivers_page(request, gate, problem=str(refused))
        return _queue_receiver_job(request, gate, payload, key, form=None)

    @router.post("/certificates/delete", response_class=HTMLResponse)
    def certificate_delete_review(
        request: Request,
        certificate: Sequence[str] = Form(default=()),
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        """The confirmation page for a selection: nothing is queued from here.

        A POST rather than a GET with the IDs in the address, because the
        selection can be long and because the page it draws is a question
        about a change, not a view somebody should bookmark.
        """

        gate = _admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return PlainTextResponse("Refused", status_code=403)
        return _certificate_delete_page(request, gate, chosen=tuple(certificate))

    @router.post("/certificates/delete/confirm", response_class=HTMLResponse)
    def certificate_delete_confirm(
        request: Request,
        certificate: Sequence[str] = Form(default=()),
        idempotency_key: str = Form(default="", max_length=64),
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        """Queue one `cert_delete` job for what the confirmation page offered.

        The selection is evaluated again here, not trusted from the previous
        page: a draft written in between is a refusal now, and the question
        is asked again with it on the row rather than the job quietly
        carrying less than was confirmed. The helper's own refusals arrive
        on the job's rows.
        """

        gate = _admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return PlainTextResponse("Refused", status_code=403)
        try:
            key = UUID(idempotency_key)
        except ValueError:
            return PlainTextResponse("A request key is required", status_code=400)

        registry = _registry_views(request, config)
        with request.app.state.pool.connection() as connection:
            drafts = db.live_drafts(connection)
        try:
            picked = certificate_delete.selection(tuple(certificate), registry, drafts)
        except certificate_delete.SelectionProblem as refused:
            return _certificate_delete_page(
                request, gate, chosen=tuple(certificate), problem=str(refused)
            )
        if not picked.deletable:
            return _certificate_delete_page(
                request,
                gate,
                chosen=tuple(certificate),
                problem="Nothing in the selection can be deleted from here.",
            )
        if picked.refused:
            return _certificate_delete_page(
                request,
                gate,
                chosen=tuple(certificate),
                problem="Since you were asked, something changed for "
                + ", ".join(row.identifier for row in picked.refused)
                + "; nothing was queued. Read the rows and confirm again.",
            )
        payload = {"certificates": list(picked.deletable)}
        try:
            operations.prepare(
                operation="cert_delete",
                cluster=None,
                request_id=uuid4(),
                payload=payload,
                draft_references=lambda ids: certificate_delete.draft_references(drafts, ids),
            )
        except operations.BadPayload as refused:
            return _certificate_delete_page(
                request, gate, chosen=tuple(certificate), problem=str(refused)
            )

        with request.app.state.pool.connection() as connection:
            try:
                job = db.queue_job(
                    connection,
                    operation="cert_delete",
                    cluster=None,
                    payload=payload,
                    idempotency_key=key,
                )
            except db.CertificateBusy:
                connection.rollback()
                return _certificate_delete_page(
                    request,
                    gate,
                    chosen=tuple(certificate),
                    problem="A certificate job is already running. Wait for it to finish on "
                    "the Jobs page, then ask again.",
                )
            except db.RequestConflict:
                connection.rollback()
                return PlainTextResponse("That request key asked for something else", 409)
            db.record_audit_event(
                connection,
                actor=gate.username,
                action="queue_job",
                cluster=None,
                request_id=job.request_id,
                detail={
                    "operation": "cert_delete",
                    "job": job.id,
                    "certificates": list(picked.deletable),
                },
            )
            connection.commit()
        return RedirectResponse("/certificates?view=registry", status_code=303)

    # - DNS provider profiles (P4) -----------------------------------------

    # - Node restore (§15.2, B175) -----------------------------------------

    @router.get("/history/{cluster}/versions/{commit}", response_class=HTMLResponse)
    def version_changes(request: Request, cluster: str, commit: str) -> Response:
        """What one version changed, as the poller fetched it (B220, 2026-10-01).

        A page of its own, so the button is a plain link that works without
        script; the Versions page opens the same section in a dialog.
        """

        session = current_session(request)
        if session is None:
            return RedirectResponse("/login", status_code=303)
        clusters, history_rows = read_source(request, config, HISTORY_SOURCE)
        if cluster not in clusters:
            return HTMLResponse("Not found", status_code=404)
        overview = history.build_history_overview(
            clusters,
            history_rows,
            stale_after=timedelta(seconds=config.poller.interval_seconds * 2),
        )
        shown = next(
            (
                (view, version)
                for view in overview.clusters
                if view.cluster == cluster
                for version in view.versions
                if version.expected_commit == commit
            ),
            None,
        )
        if shown is None:
            return HTMLResponse("Not found", status_code=404)
        with request.app.state.pool.connection() as connection:
            found = db.read_version_diff(connection, cluster=cluster, commit=commit)
        return TEMPLATES.TemplateResponse(
            request,
            "version-changes.html",
            {
                "username": session.username,
                "role": session.role,
                "csrf_token": auth.csrf_token(request.cookies.get(auth.SESSION_COOKIE, "")),
                "section": "history",
                "cluster": shown[0],
                "version": shown[1],
                "changes": version_changes_view.build(found),
                "demo_fixture": config.demo_fixture,
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
        with request.app.state.pool.connection() as connection:
            running = jobs.in_flight(db.recent_jobs(connection))
        #
        # What is saved and not yet published, per cluster (B257): the one
        # place a publish is made. Only where a publish could be.
        #
        pending = (
            {
                view.cluster: _package(request, config, view.cluster)
                for view in overview.clusters
                if view.configured
            }
            if config.management_writes and session.role == "admin"
            else {}
        )
        return TEMPLATES.TemplateResponse(
            request,
            "history.html",
            {
                "pending": pending,
                "published": request.query_params.get("published", "")[:40],
                "username": session.username,
                "role": session.role,
                "csrf_token": auth.csrf_token(token),
                "history": overview,
                "versions_per_page": history.VERSIONS_PER_PAGE,
                #
                # What this cluster is busy with, read the same way the
                # dashboard reads it. One job per cluster, so the buttons
                # below are replaced by it rather than left drawn to offer an
                # action the queue would refuse with a 409.
                #
                "in_flight": running,
                "management_writes": config.management_writes,
                "section": "history",
                "demo_fixture": config.demo_fixture,
            },
        )

    @router.post("/history/{cluster}/publish", response_class=HTMLResponse)
    def publish_changes(
        request: Request,
        cluster: str,
        comment: str = Form(default="", max_length=4096),
        expected_head: str = Form(default="", max_length=64),
        shown: str = Form(default="", alias="package", max_length=64),
        then: str = Form(default="", max_length=8),
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        """Publish everything saved for one cluster as one version (B257).

        `then=deploy` is Publish & deploy, asked from the dashboard's dialog:
        the worker deploys the version it has just recorded, in the same job,
        and the answer goes back to the dashboard, where the job is shown.

        The package is built again here rather than carried by the form, and
        the form carries back what it was shown: `expected_head`, the version
        the page was drawn at, and `package`, the list itself (R1). Either one
        moved means the list the person read is not the list that would go,
        and the page is shown again instead.
        """

        gate = _admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return PlainTextResponse("Refused", status_code=403)
        if cluster not in listed_clusters(request, config):
            return PlainTextResponse("Not found", status_code=404)
        deploy = then == "deploy"
        back = "/" if deploy else "/history"
        package = _package(request, config, cluster)
        if package.problem:
            return _refusal_page(request, config, package.problem, back=back)
        if not package.rows:
            return _refusal_page(request, config, "Nothing is saved to publish.", back=back)
        if expected_head != package.head:
            return _refusal_page(
                request,
                config,
                "A newer version was recorded after this page was opened. Read the list again "
                "before publishing.",
                back=back,
            )
        if shown != package.identity:
            #
            # Saved again, added or taken away in another tab since the list
            # was drawn (R1): what would go is not what was confirmed.
            #
            return _refusal_page(
                request,
                config,
                "The saved changes changed after this page was opened. Read the list again "
                "before publishing.",
                back=back,
            )
        if not comment.strip():
            return _refusal_page(
                request, config, "A comment is needed: it is the version's.", back=back
            )
        payload = {
            **package.payload,
            "comment": comment.strip(),
            "requested_by": gate.username,
            **({"deploy": True} if deploy else {}),
        }
        key = _publish_key(cluster, "changes_publish", payload)
        try:
            operations.prepare(
                operation="changes_publish", cluster=cluster, request_id=uuid4(), payload=payload
            )
        except operations.BadPayload:
            return _refusal_page(
                request,
                config,
                "This interface could not build a publish from what is saved.",
                back=back,
            )
        with request.app.state.pool.connection() as connection:
            try:
                job = db.queue_job(
                    connection,
                    operation="changes_publish",
                    cluster=cluster,
                    payload=payload,
                    idempotency_key=key,
                )
            except db.ClusterBusy:
                connection.rollback()
                return _refusal_page(
                    request,
                    config,
                    "This cluster is already running a job. Publish when it has finished.",
                    back=back,
                )
            except db.RequestConflict:
                connection.rollback()
                return _refusal_page(
                    request,
                    config,
                    "That publish was already asked for with different content.",
                    back=back,
                )
            db.record_audit_event(
                connection,
                actor=gate.username,
                action="queue_job",
                cluster=cluster,
                request_id=job.request_id,
                detail={
                    "operation": "changes_publish",
                    "job": job.id,
                    "changes": [row.name for row in package.rows],
                },
            )
            connection.commit()
        if deploy:
            return RedirectResponse("/", status_code=303)
        return RedirectResponse(f"/history?published={cluster}", status_code=303)

    def _status_allowed(request: Request) -> bool:
        """Whether the asking address is on Settings' list for `/status/` (B274)."""

        with request.app.state.pool.connection() as connection:
            allowed = db.status_access(connection)
        if not allowed:
            return False
        address = ipaddress.ip_address(client_address(request))
        return any(
            address in ipaddress.ip_network(entry.network, strict=False) for entry in allowed
        )

    #
    # What needs doing, for a monitor (B274): no sign-in, and only for the
    # addresses an admin listed. Anybody else - and everybody while the list
    # is empty - is told there is nothing here.
    #
    @router.get("/status/attention.json")
    def status_attention(request: Request) -> Response:
        if not _status_allowed(request):
            return PlainTextResponse("Not found", status_code=404)
        return Response(
            _attention(request, config).as_json(),
            media_type="application/json",
            headers={"Cache-Control": "no-store"},
        )

    @router.get("/status/metrics")
    def status_metrics(request: Request) -> Response:
        if not _status_allowed(request):
            return PlainTextResponse("Not found", status_code=404)
        return Response(
            _attention(request, config).as_metrics(),
            media_type="text/plain; version=0.0.4",
            headers={"Cache-Control": "no-store"},
        )

    @router.post("/jobs/{job_id}/held")
    def decide_held_job(
        request: Request,
        job_id: int,
        csrf_token: Annotated[str, Form(max_length=128)],
        decision: Annotated[str, Form(max_length=16)],
    ) -> Response:
        """Run or discard a job held since the manager last started (0082, review 2026-10-20 R1)."""

        gate = _admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return PlainTextResponse("Refused", status_code=403)
        if decision not in {"run", "discard"}:
            return PlainTextResponse("Refused", status_code=400)
        with request.app.state.pool.connection() as connection:
            if db.decide_held_job(
                connection, job_id=job_id, decision=decision, actor=gate.username
            ):
                db.record_audit_event(
                    connection,
                    actor=gate.username,
                    action="held_job_decided",
                    detail={"job": job_id, "decision": decision},
                )
            connection.commit()
        return RedirectResponse("/jobs", status_code=303)

    @router.get("/jobs", response_class=HTMLResponse)
    def latest_jobs(request: Request) -> Response:
        """Show the bounded, reader-safe history of management requests."""

        session = current_session(request)
        if session is None:
            return RedirectResponse("/login", status_code=303)
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        #
        # *Events* (B275): the jobs, and for an admin the rest of the record.
        #
        if request.query_params.get("view") == "audit" and session.role == "admin":
            return _audit_page(request, session, token)
        if request.query_params.get("view") == "nodes":
            return _node_events_page(request, session, token)
        with request.app.state.pool.connection() as connection:
            listed = db.recent_jobs(connection)
            queued_by = db.requested_by(connection, [row.request_id for row in listed])
            #
            # The cluster readings decide whether a job's follow-up line is
            # still true, so they are read here rather than the job rows being
            # trusted to describe the present on their own.
            #
            overview = jobs.build_job_overview(
                listed,
                awaiting=jobs.awaiting_deployment(db.cluster_statuses(connection)),
                #
                # The contract withholds raw stderr from a reader role, and only
                # from a reader role. Deciding it here rather than in the
                # template means the projection an unentitled session receives
                # never contains the diagnostics at all. See B44.
                #
                diagnostics=session.role == "admin",
            )
        by_job = {row.id: queued_by.get(row.request_id, "") for row in listed}
        overview = replace(
            overview, jobs=tuple(replace(job, by=by_job.get(job.id, "")) for job in overview.jobs)
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
                "view": "jobs",
            },
        )

    def _audit_page(request: Request, session: AuthenticatedSession, token: str) -> Response:
        """The record, newest first, a page at a time as the traffic log pages (B275, 26-10-11)."""

        query = request.query_params
        actor = query.get("who", "")[:255]
        cluster = query.get("cluster", "")[:32]
        search = query.get("q", "")[:200]
        selected_from = query.get("from", "")[:14]
        selected_to = query.get("to", "")[:14]
        size_raw = query.get("size", "")
        size = int(size_raw) if size_raw in ("25", "50", "100") else AUDIT_PAGE
        page_raw = query.get("page", "")
        page = int(page_raw) if is_digits(page_raw) and 0 < int(page_raw) < 100000 else 1
        opened_raw = query.get("open", "")
        opened = int(opened_raw) if is_digits(opened_raw) else None
        now = datetime.now(UTC)
        local_now = metrics.shown(now)
        local_earliest = metrics.wall(
            datetime.combine(
                local_now.date() - timedelta(days=AUDIT_KEEP_DAYS - 1), datetime.min.time()
            )
        )
        outside = "Choose a date and time within the two years the record keeps."
        time_error: str | None = None
        try:
            since = _log_time_filter(
                selected_from, earliest=local_earliest.astimezone(UTC), latest=now, outside=outside
            )
            until = _log_time_filter(
                selected_to,
                earliest=local_earliest.astimezone(UTC),
                latest=now,
                end_of_minute=True,
                outside=outside,
            )
            if since is not None and until is not None and since > until:
                raise ValueError("From must be earlier than To.")
        except ValueError as exc:
            since = until = None
            time_error = str(exc)
        sort, asked = AUDIT_TABLE.chosen(request)
        with request.app.state.pool.connection() as connection:
            total = db.audit_count(
                connection, actor=actor, cluster=cluster, search=search, since=since, until=until
            )
            pages = max(1, -(-total // size))
            page = min(page, pages)
            events = db.audit_events(
                connection,
                order=sort.lstrip("-"),
                descending=AUDIT_TABLE.descending(sort),
                offset=(page - 1) * size,
                limit=size,
                actor=actor,
                cluster=cluster,
                search=search,
                since=since,
                until=until,
            )
            accounts = db.account_names(connection)
            recent = {job.id for job in db.recent_jobs(connection, limit=200)}
        shown = audit.rows(events, accounts)
        kept = {
            "view": "audit",
            "cluster": cluster,
            "who": actor,
            "q": search,
            "from": selected_from,
            "to": selected_to,
            "size": str(size),
        }
        response = TEMPLATES.TemplateResponse(
            request,
            "jobs.html",
            {
                "username": session.username,
                "role": session.role,
                "csrf_token": auth.csrf_token(token),
                "management_writes": config.management_writes,
                "section": "jobs",
                "view": "audit",
                "events": shown,
                "recent_jobs": recent,
                "opened": opened,
                "filters": {
                    "who": actor,
                    "cluster": cluster,
                    "q": search,
                    "from": selected_from,
                    "to": selected_to,
                },
                "time_error": time_error,
                "kept": kept,
                "paging": {
                    "page": page,
                    "pages": pages,
                    "size": size,
                    "total": total,
                    "first": (page - 1) * size + 1 if total else 0,
                    "last": min(page * size, total),
                },
                "time_min": local_earliest.strftime("%y-%m-%d %H:%M"),
                "time_max": local_now.strftime("%y-%m-%d %H:%M"),
                "time_today": local_now.strftime("%y-%m-%d 00:00"),
                "clusters": listed_clusters(request, config),
                "audit_sorts": AUDIT_TABLE.links(sort, kept),
            },
        )
        if asked:
            AUDIT_TABLE.remember(response, sort, secure=config.session.cookie_secure)
        return response

    def _node_events_page(request: Request, session: AuthenticatedSession, token: str) -> Response:
        """What the nodes did on their own, a page at a time as *Audit* pages (26-10-12)."""

        query = request.query_params
        cluster = query.get("cluster", "")[:32]
        search = query.get("q", "")[:200]
        selected_from = query.get("from", "")[:14]
        selected_to = query.get("to", "")[:14]
        size_raw = query.get("size", "")
        size = int(size_raw) if size_raw in ("25", "50", "100") else AUDIT_PAGE
        page_raw = query.get("page", "")
        page = int(page_raw) if is_digits(page_raw) and 0 < int(page_raw) < 100000 else 1
        now = datetime.now(UTC)
        local_now = metrics.shown(now)
        local_earliest = metrics.wall(
            datetime.combine(
                local_now.date() - timedelta(days=NODE_EVENT_KEEP_DAYS - 1), datetime.min.time()
            )
        )
        outside = "Choose a date and time within the 90 days the log keeps."
        time_error: str | None = None
        try:
            since = _log_time_filter(
                selected_from, earliest=local_earliest.astimezone(UTC), latest=now, outside=outside
            )
            until = _log_time_filter(
                selected_to,
                earliest=local_earliest.astimezone(UTC),
                latest=now,
                end_of_minute=True,
                outside=outside,
            )
            if since is not None and until is not None and since > until:
                raise ValueError("From must be earlier than To.")
        except ValueError as exc:
            since = until = None
            time_error = str(exc)
        sort, asked = NODE_EVENT_TABLE.chosen(request)
        with request.app.state.pool.connection() as connection:
            total = db.node_event_count(
                connection, cluster=cluster, search=search, since=since, until=until
            )
            pages = max(1, -(-total // size))
            page = min(page, pages)
            events = db.node_event_page(
                connection,
                order=sort.lstrip("-"),
                descending=NODE_EVENT_TABLE.descending(sort),
                offset=(page - 1) * size,
                limit=size,
                cluster=cluster,
                search=search,
                since=since,
                until=until,
            )
        _, object_rows = read_source(request, config, OBJECTS_SOURCE)
        owners = {
            reading.cluster: health.backend_owners(objects.cluster_object_views(reading))
            for reading in object_rows
        }
        kept = {
            "view": "nodes",
            "cluster": cluster,
            "q": search,
            "from": selected_from,
            "to": selected_to,
            "size": str(size),
        }
        response = TEMPLATES.TemplateResponse(
            request,
            "jobs.html",
            {
                "username": session.username,
                "role": session.role,
                "csrf_token": auth.csrf_token(token),
                "management_writes": config.management_writes,
                "section": "jobs",
                "view": "nodes",
                "node_events": node_events.rows(events, owners),
                "filters": {
                    "cluster": cluster,
                    "q": search,
                    "from": selected_from,
                    "to": selected_to,
                },
                "time_error": time_error,
                "kept": kept,
                "paging": {
                    "page": page,
                    "pages": pages,
                    "size": size,
                    "total": total,
                    "first": (page - 1) * size + 1 if total else 0,
                    "last": min(page * size, total),
                },
                "time_min": local_earliest.strftime("%y-%m-%d %H:%M"),
                "time_max": local_now.strftime("%y-%m-%d %H:%M"),
                "time_today": local_now.strftime("%y-%m-%d 00:00"),
                "clusters": listed_clusters(request, config),
                "node_sorts": NODE_EVENT_TABLE.links(sort, kept),
            },
        )
        if asked:
            NODE_EVENT_TABLE.remember(response, sort, secure=config.session.cookie_secure)
        return response

    #
    # A refused form is answered in the interface rather than as a bare line of
    # text on a white page. The message is the same; what it now carries is
    # where it came from, that nothing was written, and that the browser's back
    # button still holds what was typed. Only the refusals a person meets while
    # filling in a form come here - a bad CSRF token or a role that may not ask
    # is not a mistake to explain, and those stay plain.
    #
    def _refusal(
        request: Request, session: Any, token: str, message: str, *, back: str
    ) -> Response:
        return _refusal_page(request, config, message, back=back)

    @router.post("/operations")
    def queue_operation(
        request: Request,
        operation: str = Form(default="", max_length=32),
        cluster: str = Form(default="", max_length=32),
        idempotency_key: str = Form(default="", max_length=64),
        version: str = Form(default="", max_length=16),
        expected_commit: str = Form(default="", max_length=64),
        allow_vip_unknown: str = Form(default=""),
        expected_version: str = Form(default="", max_length=12),
        backup_hour: str = Form(default="", max_length=2),
        backup_minute: str = Form(default="", max_length=2),
        backup_frequency: str = Form(default="daily", max_length=8),
        backup_weekday: Sequence[str] = Form(default=()),
        backup_day_of_month: str = Form(default="", max_length=2),
        backup_retention: str = Form(default="", max_length=3),
        backup_enabled: str = Form(default=""),
        vip_name: Sequence[str] = Form(default=()),
        vip_address: Sequence[str] = Form(default=()),
        vip_source: Sequence[str] = Form(default=()),
        vip_tls: Sequence[str] = Form(default=()),
        vip_http3: Sequence[str] = Form(default=()),
        default_vip_row: str = Form(default="", max_length=8),
        source_name: Sequence[str] = Form(default=()),
        source_address: Sequence[str] = Form(default=()),
        group_name: Sequence[str] = Form(default=()),
        group_members: Sequence[str] = Form(default=()),
        vip_remove: Sequence[str] = Form(default=()),
        source_remove: Sequence[str] = Form(default=()),
        group_remove: Sequence[str] = Form(default=()),
        expected_head: str = Form(default="", max_length=64),
        comment: str = Form(default="", max_length=4096),
        default_vip_confirmation: str = Form(default=""),
        #
        # The network form's two buttons (B257): save the description, or
        # discard what was saved. It is published from Versions.
        #
        network_action: str = Form(default="save", max_length=8),
        saved_revision: str = Form(default="", max_length=16),
        return_to: str = Form(default="", max_length=64),
        return_open: str = Form(default="", max_length=255),
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
        #
        # A switched-off feature has no operations either (B193), for the
        # reason `management_writes` gives above: no such endpoint.
        #
        owner = features.HIDDEN_OPERATIONS.get(operation)
        if owner is not None and not features.is_on(owner):
            return PlainTextResponse("Not found", status_code=404)

        payload: dict[str, Any] = {}
        if operation in {"deploy", "cert_deploy"}:
            payload["allow_vip_unknown"] = allow_vip_unknown == "on"
        if operation == "deploy" and expected_version:
            #
            # Text that is not a number goes on as it came, so `prepare`
            # refuses it the way it refuses any other bad value.
            #
            payload["expected_version"] = (
                int(expected_version) if is_digits(expected_version) else expected_version
            )
        elif operation == "backup_run":
            payload = {}
        elif operation == "backup_schedule":
            #
            # Numbers arrive as the form's text and go on as numbers; text that
            # is not a number goes on as it came, so that `prepare` refuses it
            # the way it refuses any other bad value, rather than this turning
            # it into a guess.
            #
            payload = {
                "time": f"{backup_hour}:{backup_minute}",
                "frequency": backup_frequency,
                "weekdays": list(backup_weekday),
                "day_of_month": int(backup_day_of_month)
                if is_digits(backup_day_of_month)
                else backup_day_of_month,
                "retention": int(backup_retention)
                if is_digits(backup_retention)
                else backup_retention,
                "enabled": backup_enabled == "on",
            }
        elif operation == "revert":
            if not is_digits(version):
                return PlainTextResponse("A version is required", status_code=400)
            payload = {
                "version": int(version),
                "expected_commit": expected_commit,
                "requested_by": session.username,
                #
                # The newest version the page listed (CR-09): a revert is a
                # decision about that history, not about one recorded since.
                #
                **({"expected_head": expected_head} if expected_head else {}),
            }
        elif operation == "network_publish":
            revision = int(saved_revision) if is_digits(saved_revision) else None
            if network_action == "discard":
                if revision is None:
                    return _refusal(
                        request, session, token, "There is nothing to discard.", back="/network"
                    )
                with request.app.state.pool.connection() as connection:
                    try:
                        db.discard_cluster_change(
                            connection, cluster=cluster, kind="network", expected_revision=revision
                        )
                    except db.DraftConflict as conflict:
                        connection.rollback()
                        return _refusal(request, session, token, str(conflict), back="/network")
                    db.record_audit_event(
                        connection,
                        actor=session.username,
                        action="discard_change",
                        cluster=cluster,
                        request_id=uuid4(),
                        detail={"kind": "network"},
                    )
                    connection.commit()
                return RedirectResponse("/network", status_code=303)
            if network_action != "save":
                return PlainTextResponse("Unknown action", status_code=400)
            # A changed default silently moves every object that did not name a
            # VIP.  The cached page states that count next to this confirmation;
            # the helper remains the authority for the document itself. Asked
            # when the description is saved (B257), since that is where the
            # decision is made.
            if default_vip_confirmation != "on":
                return _refusal(
                    request,
                    session,
                    token,
                    "Confirm the default VIP impact before saving.",
                    back="/network",
                )
            try:
                #
                # The rows become a document here rather than in the browser.
                # A person edits named addresses; the one shape the engine
                # parses is assembled from them in one place, so a hand-written
                # document can never reach the helper from this route.
                #
                document = network.document_from_form(
                    network.NetworkForm(
                        vip_names=tuple(vip_name),
                        vip_addresses=tuple(vip_address),
                        vip_sources=tuple(vip_source),
                        vip_tls=tuple(vip_tls),
                        default_vip_row=default_vip_row,
                        source_names=tuple(source_name),
                        source_addresses=tuple(source_address),
                        group_names=tuple(group_name),
                        group_members=tuple(group_members),
                        removed_vip_rows=network.row_numbers(vip_remove),
                        http3_vip_rows=network.row_numbers(vip_http3),
                        removed_source_rows=network.row_numbers(source_remove),
                        removed_group_rows=network.row_numbers(group_remove),
                    )
                )
            except network.FormProblem as problem:
                # Safe to show: these messages name a row's position, never
                # anything that was typed into it.
                return _refusal(request, session, token, str(problem), back="/network")
            if not COMMIT_ID.fullmatch(expected_head):
                return PlainTextResponse("Invalid operation parameters", status_code=400)
            #
            # Saved, and published with the next publish from Versions (B257).
            #
            with request.app.state.pool.connection() as connection:
                try:
                    change = db.save_cluster_change(
                        connection,
                        cluster=cluster,
                        kind="network",
                        document=document,
                        base_hash=expected_head,
                        updated_by=session.username,
                        expected_revision=revision,
                    )
                except db.DraftConflict as conflict:
                    connection.rollback()
                    return _refusal(request, session, token, str(conflict), back="/network")
                db.record_audit_event(
                    connection,
                    actor=session.username,
                    action="save_change",
                    cluster=cluster,
                    request_id=uuid4(),
                    detail={"kind": "network", "revision": change.revision},
                )
                connection.commit()
            return RedirectResponse("/network", status_code=303)

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
        # Back where it was asked for, when the form said where that was. Being
        # moved to the jobs page was the same failure the publish badge had: the
        # page somebody acted on could not show that the action was running, so
        # the interface moved them to one that could. The page says it now, so
        # it can keep them.
        #
        return RedirectResponse(_return_path(return_to, open=return_open), status_code=303)

    return router


@dataclass(frozen=True, slots=True)
class EditorState:
    """Everything the editor reads about one cluster before it draws anything.

    Gathered in one place because the page needs four of the poller's sources
    to answer one question, and a route that fetched them inline would read as
    plumbing with a form somewhere inside it. The four are not
    interchangeable: the objects say what is stored, the network and the
    certificates say what may be chosen, and the history says which version an
    edit is being made against.
    """

    cluster: str
    #
    # The commit the stored objects were read at. A draft records it, and a
    # publish refuses if the tree has moved since - so an edit is always made
    # against a base somebody can name.
    #
    commit: str | None
    base_version: int | None
    stored: tuple[objects.ObjectView, ...]
    choices: editor_module.EditorCluster
    available: bool


def _editor_state(request: Request, config: Config, cluster: str) -> EditorState:
    clusters, object_rows = read_source(request, config, OBJECTS_SOURCE, cluster=cluster)
    if cluster not in clusters:
        raise HTTPException(status_code=404)
    stale_after = timedelta(seconds=config.poller.interval_seconds * 2)
    reading = next((row for row in object_rows if row.cluster == cluster), None)
    result = reading.result if reading is not None and isinstance(reading.result, dict) else {}
    commit = result.get("commit")

    _, network_rows = read_source(
        request, config, NETWORK_SOURCE, cluster=cluster, clusters=clusters
    )
    #
    # Checked against the saved network when there is one (B257): an object
    # saved for a VIP the same publish adds would otherwise be refused for it.
    #
    with request.app.state.pool.connection() as connection:
        network_rows, _saved = _saved_network_rows(connection, list(network_rows))
    described = next(
        (
            view
            for view in network.build_network_overview(
                (cluster,),
                network_rows,
                stale_after=stale_after,
            )
            if view.cluster == cluster
        ),
        None,
    )
    _, certificate_rows = read_source(
        request, config, CERTIFICATE_SOURCE, cluster=cluster, clusters=clusters
    )
    held = next(
        (
            view
            for view in certificates.build_certificate_overview(
                (cluster,),
                certificate_rows,
                stale_after=stale_after,
            ).clusters
            if view.cluster == cluster
        ),
        None,
    )
    _, history_rows = read_source(
        request, config, HISTORY_SOURCE, cluster=cluster, clusters=clusters
    )
    released = next(
        (
            version
            for view in history.build_history_overview(
                (cluster,),
                history_rows,
                stale_after=stale_after,
            ).clusters
            if view.cluster == cluster
            for version in view.versions
            if version.published
        ),
        None,
    )
    return EditorState(
        cluster=cluster,
        commit=commit if isinstance(commit, str) and commit else None,
        base_version=released.number if released else None,
        stored=objects.cluster_object_views(reading),
        choices=editor_module.editor_cluster(cluster, described, held),
        available=reading is not None and reading.outcome == "done" and not reading.poll_error,
    )


def _state_reading(state: EditorState) -> ObjectsReading:
    """The editor state's objects cache, as `_reflects` reads it."""

    return ObjectsReading({view.name for view in state.stored}, state.commit)


def _unresolved_servers(name: str, document: str) -> list[str]:
    """The pool members' names the manager cannot resolve, as warnings (finding 72).

    Never a refusal: the nodes may resolve what the manager does not, and their
    own check before a release is switched to stays the gate. An object the
    model does not read yet, and a lookup service that cannot be asked, say
    nothing here - the first is said by the check, the second is the
    installation's.
    """

    try:
        proxy = load_proxy(name or "editor", document.encode())
    except proxy_model.ModelError:
        return []
    missing = resolve_socket.unresolved(server_names.names([proxy])) or []
    return [server_names.warning(host) for host in missing]


#
# What the editor says after a save when there is no card to say it (B330).
#
SAVED_NOTICE = "Saved."


def _editor_page(
    request: Request,
    config: Config,
    cluster: str,
    name: str,
    form: editor_module.ObjectForm | None,
    *,
    action: str = "check",
    draft_revision: str = "",
    notice: str = "",
    probe_asked: bool = False,
    open_group: str = "",
    answered: bool = True,
    object_fingerprint: str | None = None,
) -> Response:
    """Draw the editor, whether it was reached by a link or by a submission.

    One function for both because the page is the same page: a form, what it
    produces, and what is wrong with it. Splitting it would give a submission
    a second chance to disagree with the link about which cluster values it
    was judged against.
    """

    session = current_session(request)
    if session is None:
        return RedirectResponse("/login", status_code=303)
    if not config.management_writes:
        #
        # 404 and not 403, for the reason `/operations` gives: an installation
        # that does not do management writes has no editor, and saying
        # "forbidden" would announce one waiting to be switched on.
        #
        return PlainTextResponse("Not found", status_code=404)
    if session.role != "admin":
        return PlainTextResponse("Refused", status_code=403)
    token = request.cookies.get(auth.SESSION_COOKIE, "")
    state = _editor_state(request, config, cluster)

    with request.app.state.pool.connection() as connection:
        work = (
            _settled_work(connection, cluster, name, _state_reading(state))
            if name
            else ObjectWork()
        )
    draft = work.top

    stored = next((view for view in state.stored if view.name == name), None)
    unexpressible = ""
    #
    # Whether this page is an answer to a question about the object. Read
    # before `form` is replaced below, because from there on the two are
    # indistinguishable.
    #
    # "Test health" is a submission too, and it is not that question: it asks
    # the nodes about the backend, and a page that answered it with a verdict on
    # the document would be reporting on work the person did not ask about.
    #
    submitted = form is not None and form.action != "recheck" and answered
    if form is None:
        #
        # Opened rather than submitted. A draft is what the person was last
        # working on, so it wins over the stored document - and its absence is
        # what makes an untouched object open as it is written.
        #
        source = draft.yaml if draft is not None and not draft.deleted else None
        source = source or (stored.document if stored is not None else "")
        if not source:
            fields = dict(preview_module.DEFAULTS, name=name)
        else:
            try:
                fields = preview_module.form_from_document(source, networks=state.choices.networks)
            except preview_module.Unexpressible as exc:
                fields = dict(preview_module.DEFAULTS, name=name)
                unexpressible = str(exc)
        form = editor_module.ObjectForm(
            **_form_defaults(fields),
            saved_revision=str(work.saved.revision) if work.saved is not None else "",
            object_fingerprint=editor_module.fingerprint(stored.document if stored else None),
        )
        draft_revision = str(work.draft.revision) if work.draft is not None else ""

    fields = form.fields()
    #
    # What the nodes say about this object's backend right now. Read for the page
    # rather than for the check: it is an observation, not a verdict on the
    # document, and an object that has never been deployed simply has none.
    #
    _, status_rows = read_source(request, config, STATUS_SOURCE)
    backend = health.backend_health(
        status_rows,
        cluster=cluster,
        obj=str(fields.get("name", "")).strip() or name,
        backend=str(fields.get("backend", "")).strip()
        or str(fields.get("name", "")).strip()
        or name,
        #
        # The same address the probe binds, and read the same way. With one set,
        # only the node that carries it can answer for this backend - the other
        # runs the same check against an address it does not have.
        #
        source=probe_module.source_address(fields, editor_module.choices(state.choices)),
        #
        # As written in the form, so the card can say `198.51.100.10:8080`
        # instead of `s1`. The runtime name stays beside it: it is what appears
        # in the logs somebody will read next.
        #
        addresses=str(fields.get("servers", "")).splitlines(),
        held_only=fields.get("protocol") in SENDERS_ADDRESS,
    )
    #
    # Only when somebody pressed the button. A page that probed on every open
    # would have every visit reach out to two nodes and to whatever they can
    # connect to, which is a lot of traffic for a page somebody is reading.
    #
    report = (
        probe_module.run(cluster, fields, editor_module.choices(state.choices))
        if probe_asked
        else None
    )
    #
    # A syslog check is tried from every node's own address, as keepalived
    # runs it, and shown for the node holding the VIP, as the rows above it
    # are (Fas 19b B5).
    #
    if report is not None and fields.get("protocol") in SENDERS_ADDRESS and backend.held_by:
        report = replace(
            report, nodes=tuple(node for node in report.nodes if node.node in backend.held_by)
        )
    result = editor_module.check(
        fields,
        state.choices,
        others=tuple((view.name, view.document) for view in state.stored),
    )
    dns_form = fields.get("protocol") == "dns"
    #
    # What a publish changed in this object after the work on it was written
    # (0080): shown above the form, and Save says it writes over it.
    #
    moved_under = (
        editor_module.moved(
            draft.base_document,
            _published_document(state, draft.replaces or name),
            networks=state.choices.networks,
        )
        if draft is not None and _object_moved(state, draft) and draft.base_document is not None
        else ()
    )
    held = blocked.object_card(status_rows, cluster=cluster, name=name) if name else None
    unresolved = (
        _unresolved_servers(str(fields.get("name", "") or name), result.document)
        if result.document and not dns_form
        else []
    )
    return TEMPLATES.TemplateResponse(
        request,
        "editor.html",
        {
            "blocked_here": held.count if held is not None else 0,
            "username": session.username,
            "role": session.role,
            "csrf_token": auth.csrf_token(token),
            "section": "proxies",
            "cluster": cluster,
            #
            # The same colour this cluster carries on every other page. The
            # editor is the one place a person writes rather than reads, and it
            # was the one page that did not say which cluster they are writing
            # to in the way the rest of the interface says it.
            #
            "accent": accent_index(cluster),
            "name": name,
            "existing": stored is not None,
            "form": fields,
            "choices": editor_module.choices(state.choices),
            "complete": state.choices.complete,
            "available": state.available,
            "suggested_cookie": preview_module.suggested_cookie(
                str(fields.get("name", "")).strip()
            ),
            #
            # Read from the model rather than written into the template. The
            # form has no field for the check interval, so every object it
            # writes carries the default - and a hint that names it has to name
            # the value the engine will actually use.
            #
            #
            # A dns check's are dnsdist's (Fas 19a B5), which the engine writes
            # for one when the document says nothing.
            #
            "check_interval": DEFAULT_DNS_INTERVAL if dns_form else DEFAULT_INTERVAL,
            "rate_window": DEFAULT_ABUSE_WINDOW,
            "check_fast_interval": DEFAULT_FAST_INTERVAL,
            "check_down_interval": DEFAULT_DOWN_INTERVAL,
            "check_rise": DEFAULT_DNS_RISE if dns_form else DEFAULT_RISE,
            "check_fall": DEFAULT_DNS_FALL if dns_form else DEFAULT_FALL,
            #
            # DNS is offered once every node of the cluster runs dnsdist (Fas 19a
            # B5): a release with a listener is refused by a node without it.
            #
            "dns_offered": health.dns_everywhere(status_rows, cluster=cluster),
            #
            # Syslog once every node's keepalived reads the file its virtual
            # servers are written to (Fas 19b B4); until then a node installs
            # the file and forwards nothing.
            #
            "syslog_offered": health.syslog_everywhere(status_rows, cluster=cluster),
            "check_protocols": preview_module.CHECK_PROTOCOLS,
            "unresolved_servers": unresolved,
            "result": result,
            "draft": draft,
            "moved_under": moved_under,
            "current_version": state.base_version,
            "work": work,
            "draft_revision": draft_revision,
            "saved_revision": form.saved_revision,
            #
            # Carried from the page that was opened, not read again here: a
            # submission redrawn with the current object's would quietly accept
            # the change it is there to notice. Only the refusal hands over the
            # new one (CR-01).
            #
            "object_fingerprint": (
                form.object_fingerprint if object_fingerprint is None else object_fingerprint
            ),
            "unexpressible": unexpressible,
            "submitted": submitted,
            "waf_offered": features.is_on(features.WAF_ENGINE),
            "waf_unavailable": waf.engine(
                read_source(request, config, OBJECTS_SOURCE)[1], status_rows
            ).unavailable(cluster),
            "backend_health": backend,
            "open_group": open_group,
            "waf_exceptions": waf.form_exceptions(
                cluster,
                name,
                str(fields.get("waf_exceptions", "") or ""),
                stored.document if stored is not None else "",
                crs.installed_catalog() if fields.get("waf_exceptions") else {},
            ),
            "probe": report,
            #
            # Saved changes have their card, which says it (B330): the notice
            # would be the same thing said twice.
            #
            "notice": ""
            if notice == SAVED_NOTICE and getattr(draft, "stage", None) == "saved"
            else notice,
            "action": action,
            "unchanged": editor_module.unchanged(
                result.document, stored.document if stored else None
            ),
            "management_writes": config.management_writes,
            "demo_fixture": config.demo_fixture,
        },
    )


def _lookup_again(
    request: Request, config: Config, cluster: str, name: str, csrf_token: str
) -> Response:
    """The stored object saved with its dns server names looked up again (B252, B261)."""

    session = current_session(request)
    if session is None:
        return RedirectResponse("/login", status_code=303)
    if not config.management_writes:
        return PlainTextResponse("Not found", status_code=404)
    if session.role != "admin":
        return PlainTextResponse("Refused", status_code=403)
    token = request.cookies.get(auth.SESSION_COOKIE, "")
    if not auth.csrf_token_is_valid(token, csrf_token):
        return PlainTextResponse("Refused", status_code=403)
    state = _editor_state(request, config, cluster)
    stored = next((view for view in state.stored if view.name == name), None)
    if stored is None:
        return _refusal_page(
            request, config, "This cluster has no object of that name.", back="/proxies"
        )
    with request.app.state.pool.connection() as connection:
        draft = _settled_draft(connection, cluster, name, _state_reading(state))
    if draft is not None:
        #
        # Saving the stored object would throw the draft's work away. Saving
        # the draft looks the names up as well.
        #
        return _refusal_page(
            request,
            config,
            f"{name} has unsaved or unpublished changes. Save them in the editor; that looks "
            "the names up too.",
            back=_proxy_path(cluster, name, "edit"),
        )
    #
    # The names are looked up here, as every save of a dns object does (B261),
    # and the object saved with the addresses they give now. The publish is
    # Versions', with whatever else is saved, and the version says what moved.
    #
    try:
        document = dnsdist_config.with_addresses(
            stored.name, stored.document, resolve_socket.lookup
        )
    except (ValueError, ModelError) as refusal:
        return _refusal_page(request, config, str(refusal), back=_proxy_path(cluster, name))
    with request.app.state.pool.connection() as connection:
        try:
            saved = db.save_change(
                connection,
                cluster=cluster,
                object_id=stored.name,
                base_document=_published_document(state, stored.name),
                yaml=document,
                base_version=state.base_version,
                base_hash=state.commit or "",
                updated_by=session.username,
                saved_revision=None,
                draft_revision=None,
            )
        except db.DraftConflict as conflict:
            connection.rollback()
            return _refusal_page(request, config, str(conflict), back=_proxy_path(cluster, name))
        db.record_audit_event(
            connection,
            actor=session.username,
            action="save_change",
            cluster=cluster,
            request_id=uuid4(),
            detail={"object": stored.name, "revision": saved.revision, "lookup": True},
        )
        connection.commit()
    return RedirectResponse("/proxies", status_code=303)


def _moved_servers(
    request: Request, config: Config, cluster: str, stored: objects.ObjectView
) -> list[str]:
    """The status's word that one of this object's dns servers moved (B253)."""

    _, rows = read_source(request, config, STATUS_SOURCE)
    return moved_dns_servers(rows, cluster=cluster, pools=stored.runtime_backends or ())


def moved_dns_servers(rows: Iterable[Any], *, cluster: str, pools: Collection[str]) -> list[str]:
    """The status's word that a pool's server name moved since publishing (B252).

    The status names the pool; the page of the object owning it repeats the
    sentence, since publishing the object again is the answer.
    """

    return [
        str(warning.get("message", ""))
        for row in rows
        if getattr(row, "cluster", None) == cluster
        for warning in (getattr(row, "warnings", None) or ())
        if isinstance(warning, Mapping)
        and warning.get("code") == status_collect.DNS_SERVER_MOVED
        and status_collect.moved_pool(str(warning.get("message", ""))) in pools
    ]


def _form_defaults(fields: dict[str, Any]) -> dict[str, Any]:
    """The form model's own view of a field mapping.

    `allow_from` is the only one that needs saying: the model holds a list and
    the mapping carries a tuple, and pydantic will not take the tuple for a
    field it was told is a list.
    """

    values = dict(fields)
    values["allow_from"] = list(values.get("allow_from") or ())
    values["deny_from"] = list(values.get("deny_from") or ())
    values["block_exempt_from"] = list(values.get("block_exempt_from") or ())
    return values


#
# Every address these pages send a browser to is built here, from segments that
# have been checked against the rules that define them: the engine's own object
# name rule, and the cluster id the configuration is read with.
#
# What keeps such a redirect on this site is the leading "/proxies" - a
# reference that begins with a single slash takes its host from the page it was
# served from, and no number of ".." segments can put an authority back. The
# checking is what makes that argument unnecessary rather than merely true: the
# only thing that can reach a `Location` header from here is forty characters of
# lowercase letters, digits, hyphens and underscores. A caller that gets this
# far with anything else has a bug, so it is a 404 and not a page - the readable
# refusal belongs where the name was typed, and is done there.
#
def _published_document(state: Any, name: str | None) -> str:
    """The object `name` as the reading has it published; empty where nothing of that name is.

    What a draft keeps as its base (0080): the version it was written against
    moves with every publish of anything, and this moves only with the object.
    """

    stored = next((view for view in state.stored if view.name == name), None) if name else None
    return stored.document if stored is not None else ""


def _object_moved(state: Any, row: db.ProxyDraft) -> bool:
    """Whether the object this row changes was published differently after the row was written.

    Unknown - False - on a row from before 0080, which `base_hash` judges.
    """

    if row.base_document is None:
        return False
    now = _published_document(state, row.replaces or row.object_id)
    return now.strip() != row.base_document.strip()


def _carried_base(state: Any, name: str | None, *rows: db.ProxyDraft | None) -> str | None:
    """The base a write on top of somebody's work keeps: that work's, not the object's now.

    Only a save from the whole form, where the page has shown what moved
    underneath, takes the object as it is published now. A draft saved again,
    an exception or a line of advanced config added to a saved change is
    written over the same base as the work it changes - taking the new one
    would call the work current without anybody having seen what moved. A row
    from before 0080 carries None, as it was.
    """

    for row in rows:
        if row is not None:
            return row.base_document
    return _published_document(state, name)


def _proxy_path(cluster: str, *segments: str) -> str:
    """The URL of a page under `/proxies`, from segments that may be used as one."""

    if not CLUSTER_ID.fullmatch(cluster):
        raise HTTPException(status_code=404)
    for segment in segments:
        if not proxy_model.NAME.fullmatch(segment):
            raise HTTPException(status_code=404)
    return "/proxies/" + "/".join((cluster, *segments))


def _editor_submit(
    request: Request,
    config: Config,
    cluster: str,
    name: str,
    form: editor_module.ObjectForm,
) -> Response:
    """Check the object, save the draft, or throw the draft away.

    Saving is refused for a document the engine cannot read as an object at
    all. Whether it *fits the cluster* is a different question and does not
    block a draft: a hostname another object claims is answered at publish
    time, and a person who cannot save until every neighbour agrees cannot work
    incrementally.
    """

    session = current_session(request)
    if session is None:
        return RedirectResponse("/login", status_code=303)
    if not config.management_writes:
        return PlainTextResponse("Not found", status_code=404)
    token = request.cookies.get(auth.SESSION_COOKIE, "")
    if not auth.csrf_token_is_valid(token, form.csrf_token):
        return PlainTextResponse("Refused", status_code=403)
    if session.role != "admin":
        return PlainTextResponse("Refused", status_code=403)

    if is_digits(form.drop_exception):
        form = form.model_copy(
            update={
                "waf_exceptions": waf.without_form_exception(
                    form.waf_exceptions, int(form.drop_exception)
                ),
                "drop_exception": "",
            }
        )
        return _editor_page(
            request,
            config,
            cluster,
            name,
            form,
            draft_revision=form.expected_revision,
            open_group="waf",
            #
            # A change to the form, not a question about the object: the page
            # answers nothing, so it shows no verdict and no stored object.
            #
            answered=False,
        )

    if form.action == "check":
        return _editor_page(
            request, config, cluster, name, form, draft_revision=form.expected_revision
        )

    #
    # Asking the nodes to try the check the form describes, right now, against
    # the object as it is written on screen - published or not. The poller is
    # woken as well, because what it reports about a deployed backend is the other
    # half of the same question and it costs one notification.
    #
    if form.action == "recheck":
        with request.app.state.pool.connection() as connection:
            db.wake_poller(connection)
        return _editor_page(
            request,
            config,
            cluster,
            name,
            form,
            draft_revision=form.expected_revision,
            probe_asked=True,
        )

    state = _editor_state(request, config, cluster)
    typed = str(form.name or "").strip()
    object_id = name or typed
    if not object_id:
        return _refusal_page(
            request, config, "An object needs a name before it can be saved.", back="/proxies"
        )
    #
    # Checked where the person typed it, and not only where it is used. The rule
    # is the engine's own, so a name refused here is one the publish would refuse
    # anyway - the difference is a page that says which character was the problem
    # rather than a job that fails an hour later. Everything after this point,
    # the draft's key and every link back to it, may treat the name as a name.
    #
    if not proxy_model.NAME.fullmatch(object_id):
        return _refusal_page(
            request,
            config,
            f"{object_id} is not a usable object name - {proxy_model.name_refusal(object_id)}; "
            f"use {proxy_model.NAME_RULE}.",
            back="/proxies",
        )
    #
    # Renaming a *published* object really is a new object and a removal. The
    # name is not a label on the document: the generated file is named after it
    # and `guid` derives every section name in it, so no rename leaves the
    # HAProxy configuration untouched. What can be arranged is that the two
    # halves are one act - the publish below carries the new document and the
    # old name's removal in a single set, so the candidate `haproxy -c`
    # validates is the state afterwards and never the moment in between.
    #
    # This used to be refused, and the refusal sent people down a path that
    # does not work: publishing the new name first is refused for claiming a
    # hostname the old object still holds, and removing the old one first takes
    # the site down until the new one is published.
    #
    # A draft that has never been published needs no removal - nothing outside
    # the draft table carries its name yet - so it is only the key that moves,
    # handled below where the draft is written.
    #
    renaming = bool(name) and bool(typed) and typed != name
    published = any(view.name == name for view in state.stored)
    if renaming and not proxy_model.NAME.fullmatch(typed):
        return _refusal_page(
            request,
            config,
            f"{typed} is not a usable object name - {proxy_model.name_refusal(typed)}; "
            f"use {proxy_model.NAME_RULE}.",
            back=_proxy_path(cluster, name, "edit"),
        )

    draft_revision = int(form.expected_revision) if is_digits(form.expected_revision) else None
    saved_revision = int(form.saved_revision) if is_digits(form.saved_revision) else None
    #
    # A new object has no draft to be a revision of, so the fields are ignored
    # here rather than trusted. They are hidden inputs, and a browser restores
    # hidden inputs when somebody navigates back into a form - so a revision
    # from the object saved a moment ago survived into the new-object form and
    # turned the next save into an update of a row that had never existed. The
    # answer was "the draft changed since it was read", about a draft nobody
    # had ever made, and the work was refused with nowhere obvious to go.
    #
    if not name:
        draft_revision = saved_revision = None

    if form.action == "discard":
        #
        # The top of the work, which is what the page shows: the draft, or the
        # saved change when there is no draft over it (B257).
        #
        if draft_revision is not None:
            stage, discarded_revision = db.DRAFT, draft_revision
        elif saved_revision is not None:
            stage, discarded_revision = db.SAVED, saved_revision
        else:
            return _refusal_page(
                request,
                config,
                "There is nothing to discard.",
                back=_proxy_path(cluster, name, "edit"),
            )
        with request.app.state.pool.connection() as connection:
            try:
                db.discard_draft(
                    connection,
                    cluster=cluster,
                    object_id=object_id,
                    expected_revision=discarded_revision,
                    stage=stage,
                )
            except db.DraftConflict as conflict:
                connection.rollback()
                return _refusal_page(
                    request,
                    config,
                    str(conflict),
                    back=_proxy_path(cluster, object_id, "edit"),
                    stale=True,
                )
            db.record_audit_event(
                connection,
                actor=session.username,
                action="discard_draft",
                cluster=cluster,
                request_id=uuid4(),
                detail={"object": object_id, "stage": stage},
            )
            connection.commit()
        #
        # The object's own page, but only while it still is one. A name that is
        # neither stored, served nor drafted is a 404 by design - and after
        # discarding the only draft of an object that was never published, that
        # is exactly what the name has become. Sending somebody to it made the
        # last step of a perfectly ordinary act answer "Not Found".
        #
        # The listing instead, which is where the object no longer is. The name
        # travels in the query so the page can say which one, and it has passed
        # the engine's name rule above, so it is a name and not a fragment of
        # something else.
        #
        if any(view.name == object_id for view in state.stored) or (
            stage == db.DRAFT and saved_revision is not None
        ):
            return RedirectResponse(
                _proxy_path(cluster, object_id) + "?discarded=1", status_code=303
            )
        return RedirectResponse(f"/proxies?discarded={object_id}", status_code=303)

    #
    # No publish here (B257): saved changes are published together, from
    # Versions. A request asking this page to publish is a stale page or a
    # hand-made one, and nothing is written for it.
    #
    if form.action not in ("draft", "save"):
        return PlainTextResponse("Unknown action", status_code=400)

    if state.commit is None:
        return _refusal_page(
            request,
            config,
            "The stored objects have not been read yet, so there is no base to edit against.",
            back=_proxy_path(cluster, object_id, "edit"),
        )
    if not name and any(view.name == object_id for view in state.stored):
        return _refusal_page(
            request,
            config,
            "An object of that name already exists in this cluster.",
            back=_proxy_path(cluster, "new"),
        )
    #
    # The stored object has to be the one the page showed (CR-01). The draft's
    # revision only guards the draft, and with none the save and the publish
    # were made against whatever the cache held now - so a tab opened before
    # somebody else's publish wrote their change away with its old fields.
    # Answered with the form as submitted, and with the object as it now is, so
    # pressing save again is a decision rather than the same accident.
    #
    shown = next((view for view in state.stored if view.name == name), None) if name else None
    current = editor_module.fingerprint(shown.document if shown else None)
    if form.object_fingerprint != current:
        return _editor_page(
            request,
            config,
            cluster,
            name,
            form,
            draft_revision=form.expected_revision,
            notice=(
                f"{name} was changed by a publish after this page was opened, so nothing "
                "was saved. Saving this form now replaces that change; to keep it, open the "
                "object again."
            ),
            answered=False,
            object_fingerprint=current,
        )

    with request.app.state.pool.connection() as connection:
        work = (
            _settled_work(connection, cluster, name, _state_reading(state))
            if name
            else ObjectWork()
        )
    #
    # The published name this work takes the place of. A rename of a published
    # object records it on the row (B257), so the publish that eventually
    # carries the row removes the old name too - worked out at the moment of
    # publishing, as it was, a rename saved first and published later lost it
    # and the publish added the new object beside the old one.
    #
    # A name that has been renamed before keeps the first published name: the
    # names in between were never anywhere but here. Renamed back to that name,
    # it is an edit of the published object and replaces nothing.
    #
    replaces = next(
        (row.replaces for row in (work.draft, work.saved) if row is not None and row.replaces),
        None,
    )
    if renaming:
        if work.saved is not None and form.action == "draft":
            #
            # The two rows of one object carry one name. A draft that renamed
            # the object while its saved change kept the old name would make
            # them two objects, and saving the draft later would leave the
            # first in the next publish beside the second.
            #
            return _refusal_page(
                request,
                config,
                f"{name} has saved changes, so its name can only change with Save.",
                back=_proxy_path(cluster, name, "edit"),
            )
        with request.app.state.pool.connection() as connection:
            taken = _settled_draft(connection, cluster, typed, _state_reading(state))
        stored_elsewhere = any(view.name == typed for view in state.stored) and typed != replaces
        if stored_elsewhere or taken is not None:
            return _refusal_page(
                request,
                config,
                f"{typed} is already taken in this cluster, as an object or as a draft.",
                back=_proxy_path(cluster, name, "edit"),
            )
        if published and replaces is None:
            replaces = name
        object_id = typed
    if replaces == object_id:
        replaces = None

    #
    # A draft must be an object. Whether it fits beside its neighbours is a
    # publish question, and refusing to save until every clash is resolved
    # would stop somebody from working towards resolving them.
    #
    result = editor_module.check(form.fields(), state.choices)
    if result.about_the_object:
        return _editor_page(
            request, config, cluster, name, form, draft_revision=form.expected_revision
        )

    key = name or object_id
    with request.app.state.pool.connection() as connection:
        try:
            if form.action != "draft":
                #
                # Save: the saved change is written and the draft it was
                # finished from goes, in one transaction (B257). A rename
                # moves the saved row's key.
                #
                saved = db.save_change(
                    connection,
                    cluster=cluster,
                    object_id=key,
                    new_object_id=object_id if object_id != key else None,
                    yaml=result.document,
                    base_version=state.base_version,
                    base_hash=state.commit,
                    updated_by=session.username,
                    #
                    # From the whole form, with what moved shown above it:
                    # the one write that takes the object as it is now.
                    #
                    base_document=_published_document(state, replaces or key),
                    replaces=replaces,
                    saved_revision=saved_revision,
                    draft_revision=draft_revision,
                )
            elif object_id != key and draft_revision is not None:
                #
                # One statement, not a write and then a delete. `save_draft`
                # commits a transaction of its own, so a two-step rename left
                # the new row standing when the second step was refused - two
                # drafts where somebody had made one. The key moves or it does
                # not.
                #
                saved = db.rename_draft(
                    connection,
                    cluster=cluster,
                    object_id=key,
                    new_object_id=object_id,
                    yaml=result.document,
                    base_version=state.base_version,
                    base_hash=state.commit,
                    updated_by=session.username,
                    base_document=_carried_base(state, replaces or key, work.draft),
                    replaces=replaces,
                    expected_revision=draft_revision,
                )
            else:
                saved = db.save_draft(
                    connection,
                    cluster=cluster,
                    object_id=object_id,
                    yaml=result.document,
                    base_version=state.base_version,
                    base_hash=state.commit,
                    updated_by=session.username,
                    base_document=_carried_base(state, replaces or key, work.draft, work.saved),
                    replaces=replaces,
                    expected_revision=draft_revision if object_id == key else None,
                )
        except db.DraftConflict as conflict:
            connection.rollback()
            return _refusal_page(
                request,
                config,
                str(conflict),
                back=_proxy_path(cluster, object_id, "edit"),
                stale=True,
            )
        detail: dict[str, Any] = {
            "object": object_id,
            "revision": saved.revision,
            "stage": saved.stage,
        }
        if object_id != key:
            detail["renamed_from"] = key
        db.record_audit_event(
            connection,
            actor=session.username,
            action="save_draft" if form.action == "draft" else "save_change",
            cluster=cluster,
            request_id=uuid4(),
            detail=detail,
        )
        connection.commit()
    #
    # 303 rather than a rendered page, as everywhere else that writes: a
    # refresh of this response must not save a second time under a revision
    # that has since moved.
    #
    # A draft is unfinished work, so it goes back to the editor, under the
    # name it was saved as - a new object lands on the object it just created
    # rather than back on the empty form. A save is finished: back to the list,
    # as *Save and publish* went before B257, where the row says it is waiting.
    #
    #
    # Unless a server's name does not resolve from the manager (finding 72):
    # then back to the editor, which says so, rather than to a list that does
    # not - found before the deploy that a node would stop.
    #
    if form.action == "draft" or (
        result.document
        and form.fields().get("protocol") != "dns"
        and _unresolved_servers(key, result.document)
    ):
        return RedirectResponse(
            _proxy_path(cluster, object_id, "edit") + "?saved=1", status_code=303
        )
    return RedirectResponse("/proxies", status_code=303)


def _removal_bookkeeping(
    stored: Sequence[objects.ObjectView], published: Mapping[str, str | None]
) -> dict[str, dict[str, list[str]]]:
    """`removed_backends` for a publish that removes objects, or nothing (B250).

    A pool is named by itself, so once an object's document is gone the nodes'
    report of its backends says nothing about whose they were - and between the
    publish and the deploy the listing has to say the nodes still serve it.
    Written down here, from the objects helper's own account, as the interface's
    bookkeeping beside `draft`: checked by `operations.prepare` and never passed
    to the helper.
    """

    views = {view.name: view for view in stored}
    written = {
        name: list(view.runtime_backends)
        for name, document in published.items()
        if document is None
        and (view := views.get(name)) is not None
        and view.runtime_backends is not None
    }
    return {"removed_backends": written} if written else {}


#
# How many rows *Audit* shows to a page unless the reader chooses 25 or 100,
# as the traffic log does (B275, 26-10-11).
#
AUDIT_PAGE = 50

#
# How far back the record reaches: haprion-retention's AUDIT_KEEP_DAYS, which
# removes what is older. The From and To fields are bounded by it.
#
AUDIT_KEEP_DAYS = 730

#
# Audit's headings, sorted as every sortable table is (THEME.md) but in the
# database: the page holds one page of the record, and ordering only that
# would be a lie about the rest. The keys are unused for the same reason.
#
#
# How far back *Events → Nodes* reaches: haprion-retention's NODE_EVENT_KEEP_DAYS.
#
NODE_EVENT_KEEP_DAYS = 90

NODE_EVENT_TABLE = sorting.Table(
    columns=(
        sorting.Column("time", lambda _row, _: None, descending_first=True),
        sorting.Column("node", lambda _row, _: None),
        sorting.Column("what", lambda _row, _: None),
        sorting.Column("where", lambda _row, _: None),
    ),
    cookie="haprion_ui_node_event_sort",
    path="/jobs",
)

AUDIT_TABLE = sorting.Table(
    columns=(
        sorting.Column("time", lambda _row, _: None, descending_first=True),
        sorting.Column("who", lambda _row, _: None),
        sorting.Column("what", lambda _row, _: None),
        sorting.Column("where", lambda _row, _: None),
    ),
    cookie="haprion_ui_audit_sort",
    path="/jobs",
)


@dataclass(frozen=True, slots=True)
class PendingRow:
    """One saved change waiting for the next publish, as the Versions page lists it."""

    kind: str
    name: str
    what: str
    updated_by: str
    updated_at: datetime
    link: str
    #
    # Published as it is, it could put back what a newer version changed, so
    # the package is refused until it is saved again over what is there now
    # (B257). Since 0080 that is a row whose object was changed after it was
    # written (`moved`); a row from before can only say it was saved against
    # a version that is no longer the newest.
    #
    stale: bool
    moved: bool = False
    #
    # What a saved network description changes and who it reaches (B277):
    # one line per VIP, source or group, under the row.
    #
    details: tuple[network.NetworkChange, ...] = ()


@dataclass(frozen=True, slots=True)
class Package:
    """A cluster's saved changes, and the publish that would carry them (B257)."""

    cluster: str
    head: str | None
    rows: tuple[PendingRow, ...]
    payload: dict[str, Any]
    problem: str

    @property
    def identity(self) -> str:
        """The list as it was shown, as one value the publish form carries back (R1, 2026-10-08).

        The version it was saved against, and every saved row and document by
        its identity and revision: a row saved in another tab, saved again or
        removed since the page was drawn gives another value, while the head
        alone stays the same until something is published. Revisions and not
        content, as the clearing reads them, so the value says nothing a
        reader of the page could not already see.
        """

        def carried(key: str) -> list[list[Any]]:
            entries = self.payload.get(key) or []
            return sorted([entry["id"], entry["revision"]] for entry in entries)

        shown = {
            "cluster": self.cluster,
            "head": self.head,
            "drafts": carried("drafts"),
            "changes": carried("changes"),
        }
        encoded = json.dumps(shown, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


def _held_servers(
    request: Request, config: Config, clusters: Iterable[str], status_rows: Iterable[Any]
) -> dict[str, held_servers.HeldServers]:
    """Each cluster's servers in drain or maintenance, by object.

    The objects are read only for a cluster where a node holds a server: telling
    a pool's owner needs them, and at ten thousand objects that read is the
    cost of the whole dashboard (2026-10-01) for a line that is usually absent.
    """

    rows = list(status_rows)
    held = {
        cluster: found
        for cluster in clusters
        if (found := held_servers.held_backends(rows, cluster=cluster))
    }
    if not held:
        return {}
    _, object_rows = read_source(request, config, OBJECTS_SOURCE)
    stored = {reading.cluster: reading for reading in object_rows}
    counted = {
        cluster: held_servers.by_object(
            found, health.backend_owners(objects.cluster_object_views(stored.get(cluster)))
        )
        for cluster, found in held.items()
    }
    return {cluster: found for cluster, found in counted.items() if found is not None}


def _pending_count(request: Request, config: Config, cluster: str) -> int:
    """How many saved changes one cluster has, each cleared once its publish is read (B257)."""

    _, object_rows = read_source(request, config, OBJECTS_SOURCE, cluster=cluster)
    objects_row = next((row for row in object_rows if row.cluster == cluster), None)
    heads = _reading_heads(request, config, cluster)
    with request.app.state.pool.connection() as connection:
        saved = [
            row
            for row in _settled_drafts(connection, cluster, _objects_reading(objects_row))
            if row.stage == db.SAVED
        ]
        changes = _settled_changes(connection, cluster, heads)
    return len(saved) + len(changes)


def _package(request: Request, config: Config, cluster: str) -> Package:
    """Everything saved for one cluster, as rows and as one `changes_publish` payload.

    Drafts are not part of it: they are unfinished. A saved row whose base is
    not the newest version makes the whole package wait, and says which; the
    objects' bookkeeping (removed backends, renamed pools) is what one
    object's publish carried, for every object at once.
    """

    state = _editor_state(request, config, cluster)
    head = state.commit
    heads = _reading_heads(request, config, cluster)
    with request.app.state.pool.connection() as connection:
        saved = [
            row
            for row in _settled_drafts(connection, cluster, _state_reading(state))
            if row.stage == db.SAVED
        ]
        changes = _settled_changes(connection, cluster, heads)
    rows: list[PendingRow] = []
    objects: dict[str, str | None] = {}
    published = {view.name for view in state.stored}
    for row in saved:
        moved = _object_moved(state, row)
        objects[row.object_id] = None if row.deleted else row.yaml
        if row.replaces and not row.deleted:
            objects.setdefault(row.replaces, None)
        rows.append(
            PendingRow(
                kind="object",
                name=row.object_id,
                what=(
                    "Removal"
                    if row.deleted
                    else f"Renamed from {row.replaces}"
                    if row.replaces
                    else "Changed"
                    if row.object_id in published
                    else "New"
                ),
                updated_by=row.updated_by,
                updated_at=row.updated_at,
                link=_proxy_path(cluster, row.object_id, "edit"),
                stale=moved or (row.base_document is None and row.base_hash != head),
                moved=moved,
            )
        )
    #
    # A network description or settings saved over its own page's reading,
    # which another helper run makes than the objects' (review 26-10-08, F3).
    # While that reading stands at another version than the objects', the save
    # cannot be told stale from current, and the package waits for it rather
    # than send somebody to save again over the same lagging page.
    #
    lagging: list[str] = []
    for kind, label, link in (
        ("network", "Network description", "/network"),
        ("settings", "Logs & metrics", f"/settings/clusters/{cluster}"),
    ):
        change = changes.get(kind)
        if change is not None:
            if heads.get(kind) != head:
                lagging.append(label)
            rows.append(
                PendingRow(
                    kind=kind,
                    name=label,
                    #
                    # Every object's lines are the cluster's settings; said,
                    # since the row names no object (B277).
                    #
                    what=(
                        "Changed · applies to every object on the cluster"
                        if kind == "settings"
                        else "Changed"
                    ),
                    updated_by=change.updated_by,
                    updated_at=change.updated_at,
                    link=link,
                    stale=heads.get(kind) == head and change.base_hash != head,
                    details=(
                        _network_changes(request, config, cluster, change.document, state, saved)
                        if kind == "network"
                        else ()
                    ),
                )
            )
    payload: dict[str, Any] = {"expected_head": head or ""}
    if objects:
        payload["objects"] = objects
        payload["drafts"] = [{"id": str(row.id), "revision": row.revision} for row in saved]
        payload.update(_removal_bookkeeping(state.stored, objects))
        renamed: dict[str, str] = {}
        introduced: list[str] = []
        for row in saved:
            if row.deleted:
                continue
            more, new = _backend_renames(
                state.stored, row.object_id, row.yaml, row.replaces or row.object_id
            )
            renamed.update(more)
            introduced.extend(name for name in new if name not in introduced)
        if renamed or introduced:
            payload["backend_renames"] = {"renamed": renamed, "introduced": introduced}
    for kind in ("network", "settings"):
        if kind in changes:
            payload[kind] = changes[kind].document
    if changes:
        payload["changes"] = [
            {"id": str(change.id), "revision": change.revision}
            for change in sorted(changes.values(), key=lambda change: change.kind)
        ]
    stale = [row.name for row in rows if row.stale and not row.moved]
    changed = [row.name for row in rows if row.moved]
    problem = (
        "The stored objects have not been read yet."
        if head is None
        else f"{', '.join(changed)} {'was' if len(changed) == 1 else 'were'} changed by a "
        f"publish after the changes were saved. Open {'it' if len(changed) == 1 else 'each'} "
        "to save over that or discard the changes."
        if changed
        else f"{', '.join(stale)} {'was' if len(stale) == 1 else 'were'} saved against an "
        "older version. Open and save again before publishing."
        if stale
        else f"{' and '.join(lagging)} {'is' if len(lagging) == 1 else 'are'} still being read "
        "at the newest version. Publish again in a minute."
        if lagging
        else f"{len(objects)} objects; at most {changes_publish.MAX_OBJECTS} go in one publish."
        if len(objects) > changes_publish.MAX_OBJECTS
        else ""
    )
    return Package(cluster=cluster, head=head, rows=tuple(rows), payload=payload, problem=problem)


def _network_changes(
    request: Request,
    config: Config,
    cluster: str,
    document: str,
    state: EditorState,
    saved_objects: Sequence[Any],
) -> tuple[network.NetworkChange, ...]:
    """What the saved network description changes against the published one (B277).

    Read against the cluster's own reading, which is the published
    description. Its users are the objects as this publish leaves them: the
    published ones with the saved ones in their place, read by the engine's
    own object listing against the saved description - so an object moved off
    a removed VIP in the same publish is not said to block it (26-10-11).
    Nothing when either cannot be read: a line that guessed would be worse
    than none.
    """

    _, rows = read_source(request, config, NETWORK_SOURCE, cluster=cluster)
    reading = next((row for row in rows if row.cluster == cluster), None)
    if reading is None or reading.outcome != "done" or not isinstance(reading.result, Mapping):
        return ()
    saved = network.result_from_document(document, reading.result)
    if saved is None:
        return ()
    documents = {view.name: view.document for view in state.stored}
    for row in saved_objects:
        if row.replaces and row.replaces != row.object_id:
            documents.pop(row.replaces, None)
        if row.deleted:
            documents.pop(row.object_id, None)
        else:
            documents[row.object_id] = row.yaml
    ownership = reading.result.get("ownership_vip")
    try:
        parsed = load_network_document(
            document.encode("utf-8"),
            ownership_vip=str(ownership) if ownership else "",
            location=network_location(),
        )
    except ConfigError:
        return ()
    listed: Any = objects_result(
        {f"managed/proxies/{name}.yaml": text.encode("utf-8") for name, text in documents.items()},
        None if not documents else "0" * 40,
        network=parsed,
    )["objects"]
    after = [view for view in map(objects.object_view, listed) if view is not None]
    return network.changes(reading.result, saved, network.usage(after))


def _backend_renames(
    stored: Sequence[objects.ObjectView], name: str, document: str, before_name: str
) -> tuple[dict[str, str], list[str]]:
    """What a publish renames, and what names it brings into use (`metrics.renamed_backends`).

    Nothing without the stored objects to compare with: every name would look
    new, and closing them all would cut the history of backends that were
    never renamed.
    """

    if not stored:
        return {}, []
    views = {view.name: view for view in stored}
    try:
        after = load_proxy(name, document.encode())
    except ModelError:
        return {}, []
    previous = views.get(before_name)
    before = None
    if previous is not None:
        try:
            before = load_proxy(before_name, previous.document.encode())
        except ModelError:
            before = None
    return metrics.renamed_backends(before, after)


def _removal_submit(
    request: Request, config: Config, cluster: str, name: str, csrf_token: str
) -> Response:
    """Save the removal of one object, for the next publish (B257).

    A removal is a saved change like any other: the object leaves the
    repository with the publish that carries it, and the configuration
    generated from it leaves with it. `deleted` is what the row says: not
    that somebody abandoned an edit, but that they decided the object should
    go.
    """

    session = current_session(request)
    if session is None:
        return RedirectResponse("/login", status_code=303)
    if not config.management_writes:
        return PlainTextResponse("Not found", status_code=404)
    if session.role != "admin":
        return PlainTextResponse("Refused", status_code=403)
    token = request.cookies.get(auth.SESSION_COOKIE, "")
    if not token or not auth.csrf_token_is_valid(token, csrf_token):
        return _refusal_page(
            request, config, "That form had expired. Open the page again.", back="/proxies"
        )

    state = _editor_state(request, config, cluster)
    if state.commit is None:
        return _refusal_page(
            request,
            config,
            "The stored objects have not been read yet, so there is no base to remove from.",
            back="/proxies",
        )
    stored = next((view for view in state.stored if view.name == name), None)
    if stored is None:
        return _refusal_page(
            request, config, "This cluster has no object of that name to remove.", back="/proxies"
        )

    with request.app.state.pool.connection() as connection:
        existing = _settled_work(connection, cluster, name, _state_reading(state))
        try:
            #
            # A removal is finished work, so it is a saved change (B257). A
            # draft over the object goes with it, as the removal replaced the
            # draft before there were two: there is nothing left to finish.
            #
            saved = db.save_change(
                connection,
                cluster=cluster,
                object_id=name,
                #
                # The stored document, kept as the draft's text. The publish
                # sends `null` and never this - it is here so the row says what
                # is being removed rather than being empty, and so a removal
                # that is refused leaves the object's own text to look at.
                #
                yaml=stored.document,
                base_version=state.base_version,
                base_hash=state.commit,
                updated_by=session.username,
                base_document=stored.document,
                deleted=True,
                saved_revision=existing.saved.revision if existing.saved else None,
                draft_revision=existing.draft.revision if existing.draft else None,
            )
        except db.DraftConflict as conflict:
            connection.rollback()
            return _refusal_page(
                request, config, str(conflict), back=_proxy_path(cluster, name), stale=True
            )
        db.record_audit_event(
            connection,
            actor=session.username,
            action="save_change",
            cluster=cluster,
            request_id=uuid4(),
            detail={"object": name, "revision": saved.revision, "removed": True},
        )
        connection.commit()
    #
    # Saved, not published (B257): the removal goes out with the next publish,
    # and the listing says so on the object's row until then. Back to the list,
    # as every finished save is.
    #
    return RedirectResponse("/proxies", status_code=303)


#
# Fixed, and never regenerated. It turns a publish's identity - the cluster, the
# object and the draft revision being published - into the idempotency key the
# job table compares against, so a double-click or a refresh is the same request
# rather than a second publish of the same work.
#
PUBLISH_NAMESPACE = UUID("6f1d5f8e-1a2b-4c3d-8e9f-0a1b2c3d4e5f")


def _publish_key(cluster: str, operation: str, payload: Mapping[str, Any]) -> UUID:
    """The idempotency key one request is asked under: a digest of the request.

    Derived from everything the job will carry, and that is the whole point.
    The queue treats a repeated key as a retry only when the payload hashes the
    same, so a key covering less than the payload can be handed two different
    requests - and it answers the second with "already asked for with different
    content", permanently, for a publish somebody is looking at.

    That is what happened. The key was derived from cluster, object and
    document while the payload also carried `expected_head`, so the same
    document published again after the tree had moved was one key with two
    contents and could never be published again.

    Deriving it from the payload makes the two agree by construction rather
    than by remembering to add each new field here. A double-click is the same
    request because it is the same bytes; anything else is another request.
    """

    #
    # Sorted keys, because a mapping's order is not part of what was asked and
    # two orderings of one request must not be two requests.
    #
    body = json.dumps(
        {"cluster": cluster, "operation": operation, "payload": payload},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return uuid5(PUBLISH_NAMESPACE, sha256(body.encode("utf-8")).hexdigest())


@dataclass(frozen=True, slots=True)
class ObjectsReading:
    """What the objects cache holds for one cluster: the names, and the commit read."""

    names: Collection[str]
    commit: str | None = None


def _objects_reading(row: Any, names: Collection[str] | None = None) -> ObjectsReading:
    """One cluster's objects cache row as `_reflects` reads it; `names` overrides the row's."""

    result = getattr(row, "result", None)
    commit = result.get("commit") if isinstance(result, Mapping) else None
    if names is None:
        names = {view.name for view in objects.cluster_object_views(row)} if row else set()
    return ObjectsReading(names, commit if isinstance(commit, str) and commit else None)


@dataclass(frozen=True, slots=True)
class DraftPublish:
    """A finished publish of one draft revision: the commit it was made against, and
    whether it changed anything."""

    base: str
    changed: bool | None


def _published_drafts(
    connection: Any, cluster: str, drafts: Iterable[db.ProxyDraft]
) -> dict[tuple[str, int], DraftPublish]:
    """Which draft revisions a finished publish has already carried away.

    Named by identity - the draft's own id and the revision that was published -
    and never by what the document says. Content matched a draft that had been
    edited back to a text published earlier, which is somebody deliberately
    reverting, and it deleted their work as though it were finished.

    Asked about these drafts and no others (CR-04): the newest twenty jobs were
    the evidence until 2026-10-06, and twenty later jobs made published work look
    unpublished.
    """

    ids = {str(draft.id) for draft in drafts if draft.id is not None}
    settled: dict[tuple[str, int], DraftPublish] = {}
    for job in db.draft_publishes(connection, cluster=cluster, draft_ids=ids):
        payload = job.payload if isinstance(job.payload, Mapping) else {}
        base = payload.get("expected_head")
        #
        # Every publish is queued with the commit it was made against; a job
        # without one is no evidence, and its row stays for the operator.
        #
        if not isinstance(base, str) or not base:
            continue
        changed = _publish_changed(job.result)
        for identity, revision in _carried(payload, "draft", "drafts"):
            settled.setdefault(
                (identity, revision),
                DraftPublish(base, changed if isinstance(changed, bool) else None),
            )
    return settled


def _publish_changed(result: Any) -> bool | None:
    """Whether a finished publish recorded a new version: the helper's `result.changed`.

    Read from inside the envelope, where the helper writes it. It was read from
    the envelope's top level until 2026-10-08, where it never is - so a publish
    that changed nothing kept its draft until some later commit moved the
    cache, and the tests built their jobs in the same wrong shape. A publish
    followed by a deploy in one job (B257) keeps its own answer under `publish`.
    """

    if not isinstance(result, Mapping):
        return None
    embedded = result.get("publish")
    envelope: Mapping[str, Any] = embedded if isinstance(embedded, Mapping) else result
    body = envelope.get("result")
    changed = body.get("changed") if isinstance(body, Mapping) else None
    return changed if isinstance(changed, bool) else None


def _carried(payload: Mapping[str, Any], one: str, many: str) -> list[tuple[str, int]]:
    """The saved rows a publish carried: one object's `draft`, or a package's `drafts` (B257)."""

    entries = [payload.get(one)]
    listed = payload.get(many)
    if isinstance(listed, list):
        entries.extend(listed)
    return [
        (entry["id"], entry["revision"])
        for entry in entries
        if isinstance(entry, Mapping)
        and isinstance(entry.get("id"), str)
        and isinstance(entry.get("revision"), int)
    ]


def _reflects(draft: db.ProxyDraft, publish: DraftPublish, reading: ObjectsReading) -> bool:
    """Whether the objects cache has caught up with what this draft published.

    A publish finishes before the poller reads the repository again, so between
    the two there is a stretch where the job is done and the cache still shows
    the object as it was. Clearing the draft on the job alone made the row
    vanish for that stretch, and in the editor it opened the old document in
    place of the published one (review 2026-10-04, CR-03).

    Decided by the commit. The publish was made against the commit the cache
    showed when it was queued, and the repository only moves forward, so a
    cache that has read any other commit has read this publish or a later one.
    A cache still at that commit has not - unless the publish changed nothing,
    and then presence is all there is to wait for: a new object, or a removal.
    """

    if reading.commit is None:
        return False
    if reading.commit != publish.base:
        return True
    if publish.changed is not False:
        return False
    return (
        (draft.object_id not in reading.names)
        if draft.deleted
        else (draft.object_id in reading.names)
    )


@dataclass(frozen=True, slots=True)
class ObjectWork:
    """What one object has besides its stored document (B257).

    A draft is unfinished and never published; a saved change goes out with
    the next publish. Both may exist - a draft started on top of a saved
    change - and what the editor opens is the top one.
    """

    draft: db.ProxyDraft | None = None
    saved: db.ProxyDraft | None = None

    @property
    def top(self) -> db.ProxyDraft | None:
        return self.draft or self.saved


def _settled_row(
    connection: Any, cluster: str, row: db.ProxyDraft, reading: ObjectsReading
) -> db.ProxyDraft | None:
    """One row, cleared away if its own publish has finished and can be read."""

    if not _shown_rows(connection, cluster, (row,), reading):
        #
        # Unpublished, or published and the cache has not caught up. The row
        # is the only thing that can carry the object until it does.
        #
        return row
    if not _discard_shown(connection, cluster, row):
        return db.read_draft(connection, cluster, row.object_id, row.stage)
    connection.commit()
    return None


def _shown_rows(
    connection: Any, cluster: str, rows: Sequence[db.ProxyDraft], reading: ObjectsReading
) -> set[tuple[str, str]]:
    """The rows - by object and stage - whose own publish is done and the reading shows.

    The one rule for clearing an object's draft or saved change, asked of one
    row by the editor and of a cluster's rows by the listings (review 26-10-08,
    F5): written twice, a fix to one copy left the other behind.
    """

    settled = _published_drafts(connection, cluster, rows)
    return {
        (row.object_id, row.stage)
        for row in rows
        if (publish := settled.get((str(row.id), row.revision))) is not None
        and _reflects(row, publish, reading)
    }


def _discard_shown(connection: Any, cluster: str, row: db.ProxyDraft) -> bool:
    """Delete one row its publish has carried; False when it was saved again since it was read.

    That row is the newer one and stays. The conflict is not caught by
    rolling back: it is a delete that matched no row, not a failed statement,
    so the transaction is still good - and a rollback would throw away the
    deletes a caller clearing several rows has already made. Uncaught, it took
    the whole listing down with it, a 500 for a tidying step that was allowed
    to change nothing.
    """

    try:
        db.discard_draft(
            connection,
            cluster=cluster,
            object_id=row.object_id,
            expected_revision=row.revision,
            stage=row.stage,
        )
    except db.DraftConflict:
        return False
    return True


def _settled_work(
    connection: Any, cluster: str, object_id: str, reading: ObjectsReading
) -> ObjectWork:
    """One object's draft and saved change, each cleared away once its publish can be read.

    The editor reads this rather than the rows directly, and that is the case
    that matters most: the editor opens the top row in preference to the
    stored object, so a stale one would hand somebody their pre-publish copy
    of a document they have already published - and the next save would write
    it back.
    """

    rows = {
        stage: row
        for stage in (db.DRAFT, db.SAVED)
        if (row := db.read_draft(connection, cluster, object_id, stage)) is not None
    }
    settled = {
        stage: _settled_row(connection, cluster, row, reading) for stage, row in rows.items()
    }
    return ObjectWork(draft=settled.get(db.DRAFT), saved=settled.get(db.SAVED))


def _settled_draft(
    connection: Any, cluster: str, object_id: str, reading: ObjectsReading
) -> db.ProxyDraft | None:
    """The top of one object's work: its draft, else its saved change, else None."""

    return _settled_work(connection, cluster, object_id, reading).top


def _top_layers(rows: Iterable[db.ProxyDraft]) -> list[db.ProxyDraft]:
    """One row per object, the one the editor would open: the draft over a saved change."""

    top: dict[str, db.ProxyDraft] = {}
    for row in rows:
        if row.object_id not in top or row.stage == db.DRAFT:
            top[row.object_id] = row
    return [top[name] for name in sorted(top)]


def _settled_changes(
    connection: Any, cluster: str, heads: Mapping[str, str | None]
) -> dict[str, db.ClusterChange]:
    """This cluster's saved network and settings, each cleared once its own reading shows it (B257).

    `heads` holds the commit each kind's reading stands at - the network page's
    and the settings page's, the readings the document is drawn over. A kind
    not named there is kept as it is. Shown means the reading stands at the
    commit the publish recorded, or at a later version by the cached listing.
    Not "at another commit than the publish's base": the network, the settings
    and the objects are read by separate helper runs, and a reading that lags
    stands at an older commit than the base the package was published against
    (review 26-10-08, F3). A publish that changed nothing recorded the commit
    that was already there, so a reading at it has shown it.
    """

    changes = db.cluster_changes(connection, cluster)
    if not changes:
        return changes
    recorded: dict[tuple[str, int], tuple[str, int | None]] = {}
    ids = {str(change.id) for change in changes.values()}
    for job in db.change_publishes(connection, cluster=cluster, change_ids=ids):
        payload = job.payload if isinstance(job.payload, Mapping) else {}
        answer = _publish_recorded(job.result)
        if answer is None:
            continue
        for identity, revision in _carried(payload, "change", "changes"):
            recorded.setdefault((identity, revision), answer)
    versions: dict[str, int] | None = None
    kept = dict(changes)
    for kind, change in changes.items():
        answer = recorded.get((str(change.id), change.revision))
        head = heads.get(kind)
        if answer is None or head is None:
            continue
        commit, version = answer
        if head != commit:
            if versions is None:
                versions = _listed_versions(connection, cluster)
            shown = versions.get(head)
            if shown is None or version is None or shown <= version:
                continue
        try:
            db.discard_cluster_change(
                connection, cluster=cluster, kind=kind, expected_revision=change.revision
            )
        except db.DraftConflict:
            #
            # Saved again between the read and the delete: that one is newer
            # and stays. No rollback, for the reason `_discard_shown` gives.
            #
            continue
        del kept[kind]
    connection.commit()
    return kept


def _publish_recorded(result: Any) -> tuple[str, int | None] | None:
    """The commit and version a finished publish recorded, from inside its envelope."""

    if not isinstance(result, Mapping):
        return None
    embedded = result.get("publish")
    envelope: Mapping[str, Any] = embedded if isinstance(embedded, Mapping) else result
    body = envelope.get("result")
    if not isinstance(body, Mapping):
        return None
    commit, version = body.get("hash"), body.get("version")
    if not isinstance(commit, str) or not COMMIT_ID.fullmatch(commit):
        return None
    return commit, version if isinstance(version, int) and not isinstance(version, bool) else None


def _listed_versions(connection: Any, cluster: str) -> dict[str, int]:
    """Commit to version number, from the cluster's cached version listing."""

    history = db.cluster_history(connection, cluster)
    entries = history.result.get("versions") if history is not None else None
    numbers: dict[str, int] = {}
    for entry in entries if isinstance(entries, list) else ():
        if not isinstance(entry, Mapping):
            continue
        commit, number = entry.get("hash"), entry.get("version")
        if isinstance(commit, str) and isinstance(number, int) and not isinstance(number, bool):
            numbers[commit] = number
    return numbers


def _reading_heads(request: Request, config: Config, cluster: str) -> dict[str, str | None]:
    """The commit the network and the settings readings of one cluster stand at."""

    _, network_rows = read_source(request, config, NETWORK_SOURCE, cluster=cluster)
    _, settings_rows = read_source(request, config, SETTINGS_SOURCE)
    return {
        "network": _reading_head(next((r for r in network_rows if r.cluster == cluster), None)),
        "settings": _reading_head(
            next((r for r in settings_rows if r.cluster == cluster and r.outcome == "done"), None)
        ),
    }


def _reading_head(row: Any) -> str | None:
    result = getattr(row, "result", None)
    head = result.get("head") if isinstance(result, Mapping) else None
    return head if isinstance(head, str) and head else None


def _saved_network_rows(
    connection: Any, rows: Sequence[db.ClusterNetwork]
) -> tuple[list[db.ClusterNetwork], dict[str, db.ClusterChange]]:
    """The network readings with each cluster's saved description over them, and those saves."""

    saved: dict[str, db.ClusterChange] = {}
    for row in rows:
        change = _settled_changes(connection, row.cluster, {"network": _reading_head(row)}).get(
            "network"
        )
        if change is not None:
            saved[row.cluster] = change
    return (
        network.with_saved(rows, {cluster: change.document for cluster, change in saved.items()}),
        saved,
    )


def _settled_drafts(connection: Any, cluster: str, reading: ObjectsReading) -> list[db.ProxyDraft]:
    """This cluster's drafts, with the ones already published cleared away.

    Published work is not a draft any more. Left behind it is worse than untidy:
    the editor opens the draft in preference to the stored object, so a stale
    row would hand somebody yesterday's copy of a document they published.

    Done here and not in the worker because only the web role may touch this
    table - the privilege split keeps the worker out of it on purpose, and it
    publishes from the job payload rather than from the row. So the clearing
    happens the next time the interface reads, which is a write during a read
    and deliberately a narrow one: it deletes nothing but a draft whose own
    publish is recorded as done.
    """

    drafts = db.cluster_drafts(connection, cluster)
    published = _shown_rows(connection, cluster, drafts, reading)
    if not published:
        return drafts
    #
    # Counted rather than assumed, because the rows returned below have to
    # match what the table now holds.
    #
    kept = {
        (draft.object_id, draft.stage)
        for draft in drafts
        if (draft.object_id, draft.stage) in published
        and not _discard_shown(connection, cluster, draft)
    }
    connection.commit()
    return [
        draft
        for draft in drafts
        if (key := (draft.object_id, draft.stage)) not in published or key in kept
    ]


#
# Where an operation may send somebody afterwards. A closed set and not the
# submitted string: this value arrives in a form, and a redirect that trusts one
# is how a page is turned into a way of sending somebody somewhere else.
#
RETURN_PATHS = {
    "dashboard": "/",
    "first-cluster": "/first-cluster?first-cluster=deploying",
    "proxies": "/proxies",
    "certificates": "/certificates?view=registry",
    "history": "/history",
    "backups": "/backups",
    "network": "/network",
    "jobs": "/jobs",
}


def _return_path(name: str, *, open: str = "") -> str:
    """The page an operation returns to, or the jobs page.

    The jobs page is the fallback rather than the default, so a form that has
    not been told where it lives still lands somewhere that shows what happened.
    `open` names the registry row the button was on, so the person lands on
    it still unfolded; only a certificate ID is accepted, and only for the
    registry, since that is the one page with rows to unfold.
    """

    path = RETURN_PATHS.get(name, "/jobs")
    if name == "certificates" and open and CERTIFICATE_ID.fullmatch(open):
        return f"{path}&open={open}"
    return path


def _new_password_problem(new_password: str, repeat_password: str) -> str:
    """The sentence a new password is refused with, or ''. The CLI's same rules."""

    if len(new_password) < auth.MINIMUM_PASSWORD_LENGTH:
        return f"The new password must be at least {auth.MINIMUM_PASSWORD_LENGTH} characters."
    if len(new_password.encode("utf-8")) > auth.MAX_PASSWORD_BYTES:
        return f"The new password must be under {auth.MAX_PASSWORD_BYTES} bytes."
    if new_password != repeat_password:
        return "The two new passwords do not match."
    return ""


def _prove_password(
    connection: Any,
    config: Config,
    session: AuthenticatedSession,
    password: str,
    *,
    address: str,
    failed_action: str,
    wrong: str,
    detail: Mapping[str, object] | None = None,
) -> str:
    """'' when `password` is the signed-in account's own; else why not, recorded.

    A wrong one is a failed sign-in for this name and address - the same row
    the sign-in writes and the same throttle it reads - so a session somebody
    else is holding cannot be used to guess the password behind it. Throttled,
    the password is not even tried. The caller commits either way.
    """

    failures = db.failures_since_last_success(
        connection,
        username=session.username,
        client_ip=address,
        window_minutes=config.throttle.window_minutes,
    )
    throttled = failures >= config.throttle.max_failures
    account = None if throttled else db.account_by_username(connection, session.username)
    if account is None or account.disabled or account.password_hash is None:
        auth.burn_absent_user_time(password)
        accepted = False
    else:
        accepted = auth.verify_password(account.password_hash, password)
    if accepted:
        return ""
    db.record_login_attempt(
        connection, username=session.username, client_ip=address, succeeded=False
    )
    db.record_audit_event(
        connection,
        actor=session.username,
        action=failed_action,
        detail={
            **(detail or {}),
            "client_ip": address,
            "reason": "throttled" if throttled else "rejected",
            "via": "web",
        },
    )
    return "Too many failed attempts. Try again later." if throttled else wrong


def _password_page(
    request: Request,
    config: Config,
    session: AuthenticatedSession,
    *,
    problem: str = "",
    changed: bool = False,
    status_code: int = 200,
) -> Response:
    """The own-password form. Never echoes a password, not even a wrong one."""

    token = request.cookies.get(auth.SESSION_COOKIE, "")
    return TEMPLATES.TemplateResponse(
        request,
        "account-password.html",
        {
            "username": session.username,
            "role": session.role,
            "management_writes": config.management_writes,
            "csrf_token": auth.csrf_token(token),
            "problem": problem,
            "changed": changed,
            "minimum_length": auth.MINIMUM_PASSWORD_LENGTH,
        },
        status_code=status_code,
    )


def _public_files(certificate_id: str, fullchain_pem: str) -> list[tuple[str, bytes, bool]]:
    """An external certificate's public files: the chain whole, the leaf, the issuers.

    The three a device asks for (B255), named after the certificate, and
    marked not secret for the zip's permission bits.
    """

    blocks = [CERTIFICATE_OPENING + block for block in fullchain_pem.split(CERTIFICATE_OPENING)[1:]]
    files = [
        (f"{certificate_id}.fullchain.pem", "".join(blocks)),
        (f"{certificate_id}.crt.pem", "".join(blocks[:1])),
        (f"{certificate_id}.chain.pem", "".join(blocks[1:])),
    ]
    return [(name, text.encode("ascii"), False) for name, text in files if text]


def _zip_response(files: Sequence[tuple[str, bytes, bool]], filename: str) -> Response:
    """Files as one zip, built in memory and served without a copy kept (2026-10-07).

    A secret member is marked owner-only, so an unzip that honours the bits
    leaves the key as a key file would be left; the rest are world-readable.
    """

    stamp = datetime.now(UTC).timetuple()[:6]
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content, secret in files:
            member = zipfile.ZipInfo(name, date_time=stamp)
            member.compress_type = zipfile.ZIP_DEFLATED
            member.external_attr = (0o100600 if secret else 0o100644) << 16
            archive.writestr(member, content)
    return Response(
        buffer.getvalue(),
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
        },
    )


def _refusal_page(
    request: Request,
    config: Config,
    message: str,
    *,
    back: str,
    stale: bool = False,
    saved: bool = False,
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
            "back_label": back.lstrip("/") or "the dashboard",
            "section": back.lstrip("/").split("/")[0],
            "demo_fixture": config.demo_fixture,
        },
        status_code=400,
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
    return _refusal_page(request, config, message, back=request.url.path)


def _network_page(request: Request, config: Config) -> Response:
    """Each cluster's addresses, as the poller last read them.

    The page reads the cache like every other page rather than reaching a
    helper while somebody is looking at a screen. What it adds to the reading
    is one judgement: whether the description came from the cluster repository,
    because only then can it be changed from here.
    """

    session = current_session(request)
    if session is None:
        return RedirectResponse("/login", status_code=303)
    token = request.cookies.get(auth.SESSION_COOKIE, "")
    clusters, network_rows = read_source(request, config, NETWORK_SOURCE)
    #
    # A saved description is what the form shows and what the next publish
    # carries (B257), so it is drawn in place of the published one and said so.
    #
    with request.app.state.pool.connection() as connection:
        network_rows, saved_network = _saved_network_rows(connection, list(network_rows))
    overview = network.build_network_overview(
        clusters,
        network_rows,
        stale_after=timedelta(seconds=config.poller.interval_seconds * 2),
    )
    #
    # Published is not deployed, and this page had no way to say so: publishing
    # here moved somebody to the jobs page, which was the only place that knew.
    # The two facts it needs to keep them are the same two the dashboard uses -
    # what is still owed, and what is running - so the state is stated where the
    # change was made rather than on a page they were sent to.
    #
    with request.app.state.pool.connection() as connection:
        recent = db.recent_jobs(connection)
    #
    # Where the configuration has got to, as one badge per cluster. Three of
    # the four states come from the machine - which is what lets the page
    # correct itself when somebody deploys from the command line, and why it
    # needs no memory of what was pressed here.
    #
    _, status_rows = read_source(request, config, STATUS_SOURCE)
    board = dashboard.build_dashboard(
        clusters,
        status_rows,
        stale_after=timedelta(seconds=config.poller.interval_seconds * 2),
    )
    serving = {view.cluster: view for view in board.clusters}
    #
    # Which objects use each VIP, source and group (26-10-10), from the stored
    # objects as the helper read them. A cluster whose objects could not be
    # read says nothing rather than "not used".
    #
    _, object_rows = read_source(request, config, OBJECTS_SOURCE)
    used = {
        reading.cluster: network.usage(objects.cluster_object_views(reading))
        for reading in object_rows
        if reading.outcome == "done" and not reading.poll_error
    }
    awaiting = network.awaiting_deploy(recent)
    busy = jobs.in_flight(recent)
    failures = jobs.last_failure(recent)
    state = {
        view.cluster: network.deployment(
            running=busy.get(view.cluster),
            failure=failures.get(view.cluster),
            awaiting=view.cluster in awaiting,
            release_state=serving[view.cluster].release_state if view.cluster in serving else "",
            version=serving[view.cluster].version if view.cluster in serving else "",
        )
        for view in overview
    }
    return TEMPLATES.TemplateResponse(
        request,
        "network.html",
        {
            "username": session.username,
            "role": session.role,
            "csrf_token": auth.csrf_token(token),
            "section": "network",
            "clusters": overview,
            "usage": used,
            "saved_network": saved_network,
            "awaiting_deploy": awaiting,
            "deployment": state,
            "targets": {name: view.target_version for name, view in serving.items()},
            "management_writes": config.management_writes,
            "demo_fixture": config.demo_fixture,
        },
    )


def _sso_button(request: Request) -> str | None:
    """The provider button's text while sign-in goes through one, else None."""

    with request.app.state.pool.connection() as connection:
        provider = db.oidc_provider(connection)
    return provider.button_text if provider is not None and provider.enabled else None


def _oidc_account_refusal(
    connection: Any,
    *,
    issuer: str,
    subject: str,
    username: str,
) -> tuple[str, str] | None:
    """Why a sign-in as this identity stops at the account step, or None. Reads only.

    One answer for the sign-in and for Test sign-in, which must not promise what
    the sign-in refuses: a Test sign-in as a name a local account holds said
    "would sign in as admin" (2026-09-28). An account is made at the first
    sign-in, with the role the groups give (B297); an account of the same name
    is never taken over (B196).
    """

    account = db.account_by_oidc(connection, issuer=issuer, subject=subject)
    if account is None:
        named = db.account_by_username(connection, username)
        if named is not None:
            #
            # Bound to another issuer: the provider was changed, or its
            # application renamed, since this account first signed in. Said
            # as that, since "already exists" sends everyone looking for a
            # local account (review 2026-09-28 F5).
            #
            if named.source == "oidc" and named.oidc_issuer not in (None, issuer):
                return (
                    f"The account {username} here belongs to another provider's sign-in. "
                    "An admin can remove it so that it is made again.",
                    "other_issuer",
                )
            return f"An account named {username} already exists here.", "name_taken"
        if users.name_problem(username) is not None:
            #
            # A version records the name as who published it (B207); one that
            # cannot stand there never becomes an account (review 2026-09-29 F1).
            #
            return "The name the provider sent cannot be an account name here.", "unfit_name"
    if account is not None and account.disabled:
        return "That account is disabled here.", "disabled"
    return None


def _login_again(request: Request, config: Config, *, error: str | None = None) -> Response:
    """Render a fresh login form, with a fresh token to post it with."""

    pre_token = auth.new_session_token()
    response: Response = TEMPLATES.TemplateResponse(
        request,
        "login.html",
        {"error": error, "csrf_token": auth.csrf_token(pre_token), "sso": _sso_button(request)},
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


def _advanced_submit(
    request: Request,
    config: Config,
    cluster: str,
    name: str,
    *,
    action: str,
    text: str,
    handwritten: bool,
    expected_revision: str,
    csrf_token: str,
    object_fingerprint: str = "",
) -> Response:
    """Check the dialog's text, or save it into the object's draft (Fas 17, B223, B225).

    The draft is the editor's draft: the same row, the same revision check and
    the same refusal of a document that is not an object. What is saved is the
    draft's document - or the stored one when there is no draft - with only the
    text and the pool choice changed.
    """

    session = current_session(request)
    if session is None:
        return RedirectResponse("/login", status_code=303)
    if not config.management_writes or not features.is_on(features.ADVANCED_CONFIG):
        return PlainTextResponse("Not found", status_code=404)
    token = request.cookies.get(auth.SESSION_COOKIE, "")
    if not auth.csrf_token_is_valid(token, csrf_token):
        return PlainTextResponse("Refused", status_code=403)
    if session.role != "admin":
        return PlainTextResponse("Refused", status_code=403)
    #
    # Check and save; publishing is Versions' (B257).
    #
    if action not in ("check", "save") or not proxy_model.NAME.fullmatch(name):
        return PlainTextResponse("Unknown action", status_code=400)

    def answer(result: advanced_dialog.Answer, *, saved: str = "") -> Response:
        return TEMPLATES.TemplateResponse(
            request,
            "_advanced-answer.html",
            {"answer": result, "saved": saved},
        )

    if len(text) > advanced_dialog.MAX_TEXT:
        return answer(
            advanced_dialog.Answer(
                problem=f"The text is {len(text):,} characters; it may be at most "
                f"{advanced_dialog.MAX_TEXT:,}. Nothing was saved."
            )
        )

    state = _editor_state(request, config, cluster)
    stored = next((view for view in state.stored if view.name == name), None)
    with request.app.state.pool.connection() as connection:
        work = _settled_work(connection, cluster, name, _state_reading(state))
    #
    # The dialog saves finished work (B257), so it starts from the saved change
    # or the stored object - never from a draft somebody has not finished,
    # which would go out with the next publish half-done.
    #
    if work.draft is not None:
        return answer(
            advanced_dialog.Answer(
                problem=f"{name} has a draft. Save or discard it in the editor first."
            )
        )
    draft = work.saved
    if draft is not None and draft.deleted:
        return answer(advanced_dialog.Answer(problem="The saved changes remove this object."))
    base = draft.yaml if draft is not None else (stored.document if stored is not None else "")
    if not base or state.commit is None:
        return answer(advanced_dialog.Answer(problem="The stored objects have not been read yet."))
    try:
        document = advanced_dialog.apply(name, base, text, handwritten=handwritten)
    except (ValueError, ModelError) as exc:
        return answer(advanced_dialog.Answer(problem=str(exc)))
    result = advanced_dialog.check(name, document)
    if action == "check":
        return answer(result)
    if result.problem:
        return answer(result)
    #
    # The object the page showed, as the editor checks it (CR-01).
    #
    if object_fingerprint != editor_module.fingerprint(stored.document if stored else None):
        return answer(
            replace(
                result,
                problem=f"{name} was changed by a publish after this page was opened, so "
                "nothing was saved. Reload the page to see it as it is now.",
            )
        )
    #
    # Saving what is already there is nothing.
    #
    if editor_module.unchanged(document, base):
        return answer(replace(result, problem="Nothing changed."))

    revision = int(expected_revision) if is_digits(expected_revision) else None
    with request.app.state.pool.connection() as connection:
        try:
            saved = db.save_change(
                connection,
                cluster=cluster,
                object_id=name,
                yaml=document,
                base_version=state.base_version,
                base_hash=state.commit,
                updated_by=session.username,
                base_document=_carried_base(state, name, draft),
                replaces=draft.replaces if draft is not None else None,
                saved_revision=revision,
                draft_revision=None,
            )
        except db.DraftConflict as conflict:
            connection.rollback()
            return answer(
                replace(
                    result, problem=f"{conflict}. Reload the page to see the draft as it is now."
                )
            )
        db.record_audit_event(
            connection,
            actor=session.username,
            action="save_change",
            cluster=cluster,
            request_id=uuid4(),
            detail={"object": name, "revision": saved.revision, "advanced": True},
        )
        connection.commit()
    return answer(result, saved=_proxy_path(cluster, name) + "?saved=1")


# - WAF page (Fas 21 del B, B234) ------------------------------------------
#
# What the engine found per object and rule, and the exceptions objects carry.
# A finding is let through with an exception that is saved into the object's
# draft, as the editor saves one: the same row, the same revision check, the
# same refusal of a document the engine will not take. Publishing it is the
# object's own publish.
#
WAF_DAYS = 7


def _waf_documents(
    request: Request, config: Config, connection: Any, clusters: Sequence[str]
) -> tuple[dict[tuple[str, str], str], dict[tuple[str, str], str]]:
    """Each object's stored document, and its draft's where it has one (not a removal)."""

    _, object_rows = read_source(request, config, OBJECTS_SOURCE)
    stored: dict[tuple[str, str], str] = {}
    readings: dict[str, Any] = {}
    for row in object_rows:
        if row.cluster not in clusters:
            continue
        readings[row.cluster] = row
        for view in objects.cluster_object_views(row):
            if view.readable:
                stored[(row.cluster, view.name)] = view.document
    drafted: dict[tuple[str, str], str] = {}
    for cluster in clusters:
        names = {name for owner, name in stored if owner == cluster}
        for draft in _top_layers(
            _settled_drafts(connection, cluster, _objects_reading(readings.get(cluster), names))
        ):
            if not draft.deleted:
                drafted[(cluster, draft.object_id)] = draft.yaml
    return stored, drafted


@dataclass(frozen=True, slots=True)
class WafOverview:
    """What the WAF page's three tabs show, and the figure on each (mock round 7)."""

    days: int
    findings: list[Any]
    exceptions: list[Any]
    request_count: int

    def tab_counts(self) -> dict[str, int]:
        return {
            "findings": sum(len(card.findings) for card in self.findings),
            "exceptions": len(self.exceptions),
            "requests": self.request_count,
        }


def _waf_not_working(
    request: Request, config: Config, connection: Any, chosen: Sequence[str]
) -> set[tuple[str, str, Any]]:
    """The published exceptions the WAF page marks *Not working*, for the attention list."""

    days = min(WAF_DAYS, config.traffic_logs.retention_days)
    since = datetime.now(UTC) - timedelta(days=days)
    stored, _drafted = _waf_documents(request, config, connection, chosen)
    rows = db.waf_findings(connection, clusters=chosen, since=since)
    reached = {
        (cluster, moment): done
        for cluster, moments in waf.exception_moments(rows, stored).items()
        for moment, done in db.deploys_carrying(
            connection, cluster=cluster, moments=sorted(moments)
        ).items()
    }
    return waf.ineffective_exceptions(rows, stored, reached)


def _service_lamps(
    request: Request, config: Config, clusters: Iterable[Any], status_rows: Sequence[Any]
) -> dict[str, dict[str, health.ObjectHealth]]:
    """Each object's *Proxies* lamp, for the clusters whose reading is current.

    The same call the listing makes, on the same objects cache and status
    reading. A cluster read too long ago is its own row already, and a lamp
    from that reading would be a guess about now.
    """

    current = [
        cluster.cluster
        for cluster in clusters
        if getattr(cluster, "configured", True) and not cluster.stale
    ]
    if not current:
        return {}
    _, object_rows = read_source(request, config, OBJECTS_SOURCE)
    rows = {reading.cluster: reading for reading in object_rows}
    lamps: dict[str, dict[str, health.ObjectHealth]] = {}
    for cluster in current:
        stored = objects.cluster_object_views(rows.get(cluster))
        lamps[cluster] = health.object_healths(
            status_rows,
            cluster=cluster,
            owners=health.backend_owners(stored),
            objects={obj.name: (obj.health_checked, obj.sourced) for obj in stored},
        )
    return lamps


def _attention(request: Request, config: Config) -> attention.Attention:
    """What needs doing, worked out from the pages' own builders (B274)."""

    stale_after = timedelta(seconds=config.poller.interval_seconds * 2)
    now = datetime.now(UTC)
    clusters, status_rows = read_source(request, config, STATUS_SOURCE)
    status_rows = tuple(status_rows)
    _, network_rows = read_source(request, config, NETWORK_SOURCE)
    board = dashboard.build_dashboard(
        clusters, status_rows, stale_after=stale_after, network_readings=network_rows
    )
    certificate_clusters, certificate_rows = read_source(request, config, CERTIFICATE_SOURCE)
    certificate_view = certificates.build_certificate_overview(
        certificate_clusters,
        certificate_rows,
        manager=read_manager_certificates(request, config),
        stale_after=stale_after,
        status_readings=status_rows,
        taken_out=read_certificate_takeouts(request, config),
    )
    items: list[attention.Item] = []
    with request.app.state.pool.connection() as connection:
        features.read_in(db.feature_switches(connection))
        recent = db.recent_jobs(connection, limit=200)
        items += attention.from_jobs(recent)
        items += attention.from_manager(
            cluster_list_at=db.cluster_list_observed(connection),
            poller_silent_after=max(stale_after, timedelta(minutes=5)),
            rows=recent,
            writes=config.management_writes,
            horizons=db.partition_horizons(connection, attention.MAINTENANCE_AHEAD),
            now=now,
        )
        if config.traffic_logs.enabled:
            items += attention.from_waf(
                _waf_not_working(request, config, connection, clusters),
                describe=waf.where,
            )
    if config.traffic_logs.enabled:
        items += attention.from_traffic_logs(
            traffic_logs.read_freshness(config.traffic_logs.directory, tuple(clusters)).nodes,
            now=now,
        )
    items += attention.from_log_forwarding(status_rows, now=now)
    items += attention.from_dashboard(board.clusters, drift_label=dashboard.VERSION_DRIFT)
    items += attention.from_services(
        _service_lamps(request, config, board.clusters, status_rows),
        held_label=health.HELD_LABEL,
    )
    items += attention.from_certificates(certificate_view.registry, certificate_view.clusters)
    if features.is_on(features.NODE_BACKUPS):
        backup_clusters, backup_rows = read_source(request, config, BACKUP_SOURCE)
        items += attention.from_backups(
            backups.build_backup_overview(
                backup_clusters, backup_rows, stale_after=stale_after
            ).clusters
        )
    status_age: dict[str, int | None] = {
        row.cluster: int((now - row.observed_at).total_seconds()) for row in status_rows
    }
    for cluster in clusters:
        status_age.setdefault(cluster, None)
    with request.app.state.pool.connection() as connection:
        items, gone = attention.unacknowledged(items, db.attention_acks(connection))
        if gone:
            db.forget_attention_acks(connection, gone)
            connection.commit()
    return attention.build_attention(
        items,
        status_age=status_age,
        stale_after_seconds=int(stale_after.total_seconds()),
        now=now,
    )


def _waf_overview(request: Request, config: Config, chosen: Sequence[str]) -> WafOverview:
    days = min(WAF_DAYS, config.traffic_logs.retention_days)
    since = datetime.now(UTC) - timedelta(days=days)
    rules = crs.installed_catalog()
    with request.app.state.pool.connection() as connection:
        stored, drafted = _waf_documents(request, config, connection, chosen)
        rows = db.waf_findings(connection, clusters=chosen, since=since)
        verdicts = db.waf_verdicts(connection, clusters=chosen, since=since)
        request_count = db.waf_request_count(connection, clusters=chosen, since=since)
        #
        # What each exception let through, as its counter counted it within
        # what the exception covers (B273, review 26-10-11).
        #
        counted = db.waf_counted(connection, scopes=waf.counter_scopes(stored, rules), since=since)
        #
        # When each published exception that covers a finding reached the
        # nodes: the first deploy after it was made (26-10-11). Matches after
        # that mean the exception is not working, which the page says rather
        # than hides.
        #
        reached = {
            (cluster, moment): done
            for cluster, moments in waf.exception_moments(rows, stored).items()
            for moment, done in db.deploys_carrying(
                connection, cluster=cluster, moments=sorted(moments)
            ).items()
        }
    return WafOverview(
        days=days,
        findings=waf.build_findings(rows, verdicts, stored, drafted, rules, reached),
        exceptions=waf.build_exceptions(
            stored, drafted, rules, waf.ineffective_exceptions(rows, stored, reached), counted
        ),
        request_count=request_count,
    )


def _waf_work_page(request: Request, config: Config, view: str, problem: str = "") -> Response:
    session = current_session(request)
    if session is None:
        return RedirectResponse("/login", status_code=303)
    token = request.cookies.get(auth.SESSION_COOKIE, "")
    clusters = listed_clusters(request, config)
    selected = request.query_params.get("cluster", "")[:32]
    chosen = (selected,) if selected in clusters else tuple(clusters)
    overview = _waf_overview(request, config, chosen)
    days, findings, exceptions = overview.days, overview.findings, overview.exceptions
    return TEMPLATES.TemplateResponse(
        request,
        "waf.html",
        {
            "username": session.username,
            "role": session.role,
            "csrf_token": auth.csrf_token(token),
            "section": "waf",
            "management_writes": config.management_writes,
            "view": view,
            "days": days,
            "clusters": clusters,
            "selected_cluster": selected if selected in clusters else "",
            "findings": findings,
            "tab_counts": overview.tab_counts(),
            "exceptions": exceptions,
            "where": waf.where,
            "saved": request.query_params.get("saved", "")[:40],
            "saved_in": request.query_params.get("in", "")[:32],
            "can_write": config.management_writes and session.role == "admin",
            "problem": problem,
        },
        status_code=409 if problem else 200,
    )


def _waf_write_gate(
    request: Request, config: Config, csrf: str | None
) -> AuthenticatedSession | Response:
    session = current_session(request)
    if session is None:
        return RedirectResponse("/login", status_code=303)
    if not config.management_writes:
        return PlainTextResponse("Not found", status_code=404)
    token = request.cookies.get(auth.SESSION_COOKIE, "")
    if csrf is not None and not auth.csrf_token_is_valid(token, csrf):
        return PlainTextResponse("Refused", status_code=403)
    if session.role != "admin":
        return PlainTextResponse("Refused", status_code=403)
    return session


def _waf_save(
    request: Request,
    config: Config,
    session: AuthenticatedSession,
    *,
    cluster: str,
    name: str,
    change: Callable[[str], str],
    detail: dict[str, Any],
) -> str | None:
    """Apply one change to the object's draft (or its stored document); the problem, or None."""

    state = _editor_state(request, config, cluster)
    stored = next((view for view in state.stored if view.name == name), None)
    with request.app.state.pool.connection() as connection:
        work = _settled_work(connection, cluster, name, _state_reading(state))
    #
    # An exception is finished work, so it is a saved change (B257), made on
    # the saved change or the stored object and never on a draft somebody has
    # not finished.
    #
    if work.draft is not None:
        return f"{name} has a draft. Save or discard it in the editor first."
    draft = work.saved
    if draft is not None and draft.deleted:
        return f"The saved changes remove {name}."
    base = draft.yaml if draft is not None else (stored.document if stored is not None else "")
    if not base or state.commit is None:
        return "The stored objects have not been read yet."
    try:
        document = change(base)
        load_proxy(name, document.encode())
    except (ValueError, ModelError) as exc:
        return str(exc)
    if editor_module.unchanged(document, base):
        return None
    with request.app.state.pool.connection() as connection:
        try:
            saved = db.save_change(
                connection,
                cluster=cluster,
                object_id=name,
                yaml=document,
                base_version=state.base_version,
                base_hash=state.commit,
                updated_by=session.username,
                base_document=_carried_base(state, name, draft),
                replaces=draft.replaces if draft is not None else None,
                saved_revision=draft.revision if draft is not None else None,
                draft_revision=None,
            )
        except db.DraftConflict as conflict:
            connection.rollback()
            return f"{conflict}. Reload the page and try again."
        db.record_audit_event(
            connection,
            actor=session.username,
            action="save_change",
            cluster=cluster,
            request_id=uuid4(),
            detail={"object": name, "revision": saved.revision, **detail},
        )
        connection.commit()
    return None


def _waf_target(request: Request, config: Config, cluster: str, name: str) -> bool:
    return cluster in listed_clusters(request, config) and bool(proxy_model.NAME.fullmatch(name))


def _waf_allow(request: Request, config: Config, form: Any) -> Response:
    """The Allow dialog (B234, B235): where to let a finding through, as narrow as it allows."""

    values = form if form is not None else request.query_params
    gate = _waf_write_gate(
        request, config, str(values.get("csrf_token", "")) if form is not None else None
    )
    if not isinstance(gate, AuthenticatedSession):
        return gate
    session = gate
    cluster = str(values.get("cluster", ""))[:32]
    name = str(values.get("object", ""))[:40]
    rule_text = str(values.get("rule", ""))[:6]
    field = str(values.get("field", ""))[:256]
    offered = [str(path)[:1024] for path in values.getlist("path")][:20]
    if not _waf_target(request, config, cluster, name) or not is_digits(rule_text):
        return PlainTextResponse("Not found", status_code=404)
    rule = int(rule_text)
    if field and not proxy_model.waf_field(field):
        field = ""
    #
    # A path the engine could not be told exactly - percent-encoded, with an
    # empty segment - is not offered; the object or the field still is.
    #
    paths = [path for path in dict.fromkeys(offered) if proxy_model.WAF_PATH.fullmatch(path)]
    #
    # Why, in one line (26-10-10): a pasted line break becomes a space, and
    # the engine refuses whatever else a note may not hold, in its own words.
    #
    reason = " ".join(str(values.get("reason", ""))[: proxy_model.MAX_NOTE].split())
    problem = ""
    if form is not None:
        chosen = str(values.get("scope", ""))
        at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            exception = waf.exception_for(
                chosen,
                rule=rule,
                field=field,
                paths=[path for path in values.getlist("chosen_path") if path in paths],
                by=session.username,
                at=at,
                reason=reason,
            )
        except ValueError as exc:
            problem = str(exc)
        else:
            problem = (
                _waf_save(
                    request,
                    config,
                    session,
                    cluster=cluster,
                    name=name,
                    change=lambda base: waf.with_exception(name, base, exception),
                    detail={"waf_exception": {k: v for k, v in exception.items() if k != "at"}},
                )
                or ""
            )
            if not problem:
                return RedirectResponse(
                    "/waf?" + urlencode({"saved": name, "in": cluster}), status_code=303
                )
    catalog = crs.installed_catalog().get(rule)
    kind, explanation = waf.kind(rule // 1000)
    token = request.cookies.get(auth.SESSION_COOKIE, "")
    return TEMPLATES.TemplateResponse(
        request,
        "waf-allow.html",
        {
            "username": session.username,
            "role": session.role,
            "csrf_token": auth.csrf_token(token),
            "section": "waf",
            "management_writes": config.management_writes,
            "cluster": cluster,
            "name": name,
            "rule": rule,
            "field": field,
            "shown_field": waf.shown_field(field) if field else "",
            "paths": paths,
            "kind": kind,
            "explanation": explanation,
            "message": catalog.message
            if catalog is not None and catalog.message
            else f"Rule {rule}",
            "severity": catalog.severity if catalog is not None else "",
            "matched": str(values.get("matched", ""))[:1024],
            "reason": reason,
            "scope": str(values.get("scope", ""))
            or (
                "field_paths"
                if field and paths
                else "field"
                if field
                else "paths"
                if paths
                else "object"
            ),
            "problem": problem,
        },
        status_code=409 if problem else 200,
    )


def _waf_remove(request: Request, config: Config, form: Any) -> Response:
    gate = _waf_write_gate(request, config, str(form.get("csrf_token", "")))
    if not isinstance(gate, AuthenticatedSession):
        return gate
    cluster = str(form.get("cluster", ""))[:32]
    name = str(form.get("object", ""))[:40]
    rule_text = str(form.get("rule", ""))[:6]
    if not _waf_target(request, config, cluster, name) or not is_digits(rule_text):
        return PlainTextResponse("Not found", status_code=404)
    field = str(form.get("field", ""))[:256]
    paths = [str(path)[:1024] for path in form.getlist("path")][:20]
    problem = _waf_save(
        request,
        config,
        gate,
        cluster=cluster,
        name=name,
        change=lambda base: waf.without_exception(
            name, base, rule=int(rule_text), field=field, paths=paths
        ),
        detail={"waf_exception_removed": {"rule": int(rule_text), "field": field, "paths": paths}},
    )
    if problem:
        return _waf_work_page(request, config, "exceptions", problem=problem)
    return RedirectResponse(
        "/waf?" + urlencode({"view": "exceptions", "saved": name, "in": cluster}), status_code=303
    )
