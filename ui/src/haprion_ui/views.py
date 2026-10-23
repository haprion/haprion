"""What every page shares: sessions, cookies, the poller's readings, templates and gates.

The pages themselves are in `haprion_ui.pages`, one module per area; they read
from here and this module reads nothing of theirs.

The rules that shape every handler:

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
import importlib.metadata
import io
import ipaddress
import json
import logging
import re
import sys
import zipfile
from collections.abc import Callable, Collection, Iterable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import Any
from urllib.parse import urlencode
from uuid import UUID, uuid4, uuid5

import anyio
import psycopg
from fastapi import File, Form, HTTPException, Request, Response
from fastapi.responses import (
    PlainTextResponse,
    RedirectResponse,
)
from fastapi.templating import Jinja2Templates
from haprion import (
    crs,
    dnsdist_config,
    proxy_model,
    resolve_socket,
    server_names,
    status_collect,
)
from haprion.certificates import CERTIFICATE_OPENING
from haprion.cli import changes_publish
from haprion.config import CERTIFICATE_ID, CLUSTER_ID, DEFAULT_ABUSE_WINDOW, ConfigError
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
    auth,
    backups,
    blocked,
    certificates,
    cluster_identity,
    cluster_nodes,
    dashboard,
    db,
    demo,
    features,
    first_cluster,
    health,
    held_servers,
    history,
    jobs,
    metrics,
    moments,
    network,
    objects,
    oidc_web,
    operations,
    proxies,
    sorting,
    timing,
    traffic_logs,
    update_check,
    users,
    waf,
)
from haprion_ui import editor as editor_module
from haprion_ui import preview as preview_module
from haprion_ui import probe as probe_module
from haprion_ui.cluster_identity import accent_index
from haprion_ui.config import Config
from haprion_ui.db import AuthenticatedSession
from haprion_ui.form_groups import form_groups, waf_exception_count
from haprion_ui.health_rows import health_rows


class _TimedTemplates(Jinja2Templates):
    """Every page's template time counted as such (`timing`)."""

    def TemplateResponse(self, *args: Any, **kwargs: Any) -> _TemplateResponse:
        def render() -> _TemplateResponse:
            response: _TemplateResponse = Jinja2Templates.TemplateResponse(self, *args, **kwargs)
            return response

        return timing.rendered(render)


#
# A commit as a form carries it, checked before it reaches a column that
# would refuse it with a database error instead of a sentence.
#
COMMIT_ID = re.compile(r"[0-9a-f]{40}")


def _layout_context(request: Request) -> dict[str, Any]:
    """What the layout reads on every page, from the application rather than the page.

    Each page passed `management_writes` itself, and one that forgot drew a
    menu without Settings (review 2026-10-22, 2-9).
    """

    config = getattr(request.app.state, "config", None)
    return {} if config is None else {"management_writes": config.management_writes}


TEMPLATES = _TimedTemplates(
    directory=str(Path(__file__).parent / "templates"), context_processors=[_layout_context]
)
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

    return moments.moment(moment)


TEMPLATES.env.filters["shown_at"] = shown_at
TEMPLATES.env.filters["shown_day"] = moments.day
TEMPLATES.env.filters["shown_time"] = moments.time_of_day
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
        local = datetime.strptime(value, moments.PICKED)
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
    "cert_receivers-off": "Certificates for other hosts turned off. Registered receivers still get new certificates.",
    "cert_receivers-on": "Certificates for other hosts turned on.",
    "node_backups-off": "Node backups turned off. The clusters' schedules are being stopped; see Jobs.",
    "node_backups-on": "Node backups turned on. The schedules that were stopped are being started again.",
    "cluster_colours-off": "Cluster colours turned off.",
    "cluster_colours-on": "Cluster colours turned on.",
    "advanced_config-off": "Advanced config turned off. Proxies keep their text and it is still published.",
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
        return forbidden_page(request, config)
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
    return RedirectResponse("/settings/nodes/" + listed, status_code=303)


def _first_cluster(
    config: Config,
    request: Request,
    session: AuthenticatedSession,
    *,
    recent: list[Any],
    busy: Mapping[str, str],
    status_rows: Iterable[Any],
    network_readings: Iterable[Any],
) -> first_cluster.Guide | None:
    """The guide's step for an admin who may write, or None (B315)."""

    if session.role != "admin" or not config.management_writes:
        return None
    listed = listed_clusters(request, config)
    cluster = listed[0] if len(listed) == 1 else ""
    reading = next((row for row in status_rows if row.cluster == cluster), None)
    #
    # The address from the network description, not the dashboard card's
    # `vip`, which says who holds it: the guide showed a node's name as the
    # address (R2 26-10-22, F1).
    #
    vip = network.default_vip_address(
        next((row for row in network_readings if row.cluster == cluster), None)
    )
    return first_cluster.guide(
        clusters=listed,
        reading=reading,
        creations=_creations(request, recent),
        busy=busy,
        vip=vip,
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
        return forbidden_page(request, config)
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
            fields = dict(preview_module.DEFAULTS, **preview_module.NEW_POOL_CHECK, name=name)
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
        return forbidden_page(request, config)
    token = request.cookies.get(auth.SESSION_COOKIE, "")
    if not auth.csrf_token_is_valid(token, csrf_token):
        return forbidden_page(request, config)
    state = _editor_state(request, config, cluster)
    stored = next((view for view in state.stored if view.name == name), None)
    if stored is None:
        return _refusal_page(
            request, config, "This cluster has no proxy of that name.", back="/proxies"
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
        return forbidden_page(request, config)
    if session.role != "admin":
        return forbidden_page(request, config)

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
            request, config, "A proxy needs a name before it can be saved.", back="/proxies"
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
            f"{object_id} is not a usable proxy name - {proxy_model.name_refusal(object_id)}; "
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
            f"{typed} is not a usable proxy name - {proxy_model.name_refusal(typed)}; "
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
        return RedirectResponse("/proxies?discarded=" + object_id, status_code=303)

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
            "The stored proxies have not been read yet, so there is no base to edit against.",
            back=_proxy_path(cluster, object_id, "edit"),
        )
    if not name and any(view.name == object_id for view in state.stored):
        return _refusal_page(
            request,
            config,
            "A proxy of that name already exists in this cluster.",
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
                "proxy again."
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
                f"{typed} is already taken in this cluster, as a proxy or as a draft.",
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
                        "Changed · applies to every proxy on the cluster"
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
        "The stored proxies have not been read yet."
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
        else f"{len(objects)} proxies; at most {changes_publish.MAX_OBJECTS} go in one publish."
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
        return forbidden_page(request, config)
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
            "The stored proxies have not been read yet, so there is no base to remove from.",
            back="/proxies",
        )
    stored = next((view for view in state.stored if view.name == name), None)
    if stored is None:
        return _refusal_page(
            request, config, "This cluster has no proxy of that name to remove.", back="/proxies"
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


def _publish_key(cluster: str, operation: str, payload: Mapping[str, Any], *, drawn: UUID) -> UUID:
    """The idempotency key one request is asked under: the form's key and a digest of the request.

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

    And `drawn`, the key the form was drawn with, as every other form carries.
    A publish that failed, or was blocked by a locked cluster, kept its job row
    and so its key: the same list and comment sent again - from a page drawn
    afresh, after the cause was fixed - was answered with the old job and
    "Publishing..." while nothing was queued (review 2026-10-22, 1B-1).
    """

    #
    # Sorted keys, because a mapping's order is not part of what was asked and
    # two orderings of one request must not be two requests.
    #
    body = json.dumps(
        {"cluster": cluster, "operation": operation, "payload": payload, "drawn": str(drawn)},
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
        return path + "&open=" + open
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
        return forbidden_page(request, config)
    if session.role != "admin":
        return forbidden_page(request, config)
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
        return answer(advanced_dialog.Answer(problem="The saved changes remove this proxy."))
    base = draft.yaml if draft is not None else (stored.document if stored is not None else "")
    if not base or state.commit is None:
        return answer(advanced_dialog.Answer(problem="The stored proxies have not been read yet."))
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
    items += attention.from_dashboard(
        board.clusters,
        drift_label=dashboard.VERSION_DRIFT,
        cluster_faults=dashboard.CLUSTER_FAULTS,
    )
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
        return forbidden_page(request, config)
    if session.role != "admin":
        return forbidden_page(request, config)
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
        return "The stored proxies have not been read yet."
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
