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
import json
from collections.abc import Callable, Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import quote
from uuid import UUID, uuid4, uuid5

from fastapi import APIRouter, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from haproxy_mgmt import proxy_model
from haproxy_mgmt.proxy_model import (
    DEFAULT_FALL,
    DEFAULT_INTERVAL,
    DEFAULT_RISE,
    ModelError,
    load_proxy,
)

from haproxy_ui import (
    activity,
    auth,
    backups,
    certificates,
    dashboard,
    db,
    demo,
    health,
    history,
    jobs,
    metrics,
    network,
    objects,
    operations,
    proxies,
    snapshot,
)
from haproxy_ui import editor as editor_module
from haproxy_ui import preview as preview_module
from haproxy_ui import probe as probe_module
from haproxy_ui.cluster_identity import accent_index
from haproxy_ui.config import CLUSTER_ID, Config
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
# HAProxy's check codes as sentences. A global rather than a field on the row:
# the rows come from the engine's own dataclass, which the CLI shares, and how
# a web page words something is not the engine's business.
#
TEMPLATES.env.globals["check_phrase"] = health.check_phrase

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
NETWORK_SOURCE = Source(
    demo.network_rows,
    lambda taken: taken.network_rows,
    lambda connection: db.cluster_networks(connection),
)
#
# A production snapshot carries no objects, and that is a decision rather than
# an omission. The snapshot is a file copied into the development platform,
# where more people can read it, so every other source in it is rebuilt field by
# field and bounded. A stored object is the one thing that cannot be reduced
# that way and still be worth reading - it is the document itself, carrying
# every backend address the cluster talks to, which no other source in the
# snapshot exposes. Dev exercises this page against the fixture instead.
#
OBJECTS_SOURCE = Source(
    demo.object_rows,
    lambda taken: (),
    lambda connection: db.cluster_objects(connection),
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
        with request.app.state.pool.connection() as connection:
            running = jobs.in_flight(db.recent_jobs(connection))
        return TEMPLATES.TemplateResponse(
            request,
            "index.html",
            {
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
                "section": "dashboard",
                "demo_fixture": config.demo_fixture,
                "production_snapshot": config.production_snapshot,
                "snapshot_age": snapshot_age(captured_at),
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

    def _network_result(reading: Any) -> Mapping[str, Any]:
        result = getattr(reading, "result", None)
        return result if isinstance(result, Mapping) else {}

    def _default_vip(reading: Any) -> str:
        return str(_network_result(reading).get("default_vip", "") or "")

    def _vip_sources(reading: Any) -> dict[str, str]:
        """Each VIP's own source address, by name, as the poller cached it.

        Read here rather than through the editor's state: the listing needs one
        fact about the cluster and not a form's worth of choices, and building
        the latter to get the former is how a page grows a second reason to
        fail.
        """

        entries = _network_result(reading).get("vips")
        return (
            {
                str(entry.get("name", "")): str(entry.get("source", "") or "")
                for entry in entries
                if isinstance(entry, Mapping) and entry.get("name")
            }
            if isinstance(entries, Sequence) and not isinstance(entries, (str, bytes))
            else {}
        )

    def _proxy_listing(request: Request, role: str) -> dict[str, Any]:
        """Everything the proxy table draws, for the page and for its refresh.

        Read once here rather than twice in two handlers. The refresh replaces
        the rows in place while something is on its way, and a second gathering
        of the same facts would be free to disagree with the first about what a
        row says - which is the disagreement nobody would see until a row
        changed shape halfway through a deploy.
        """

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
        #
        # The listing is built from published frontends, so an object that has
        # been committed but not deployed appears in none of them - which is
        # the object somebody is working on. Carried separately rather than
        # merged into the same table: they are a different state, and half a
        # table of empty ports and backend counts would say so badly.
        #
        _, object_rows, _ = read_source(request, config, OBJECTS_SOURCE)
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
        _, health_rows, _ = read_source(request, config, STATUS_SOURCE)
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
            gone = {
                view.cluster: objects.removed_names(
                    db.recent_jobs(connection, cluster=view.cluster)
                )
                for view in overview.clusters
            }
        for view in overview.clusters:
            names = [obj.name for obj in objects.cluster_object_views(rows.get(view.cluster))]
            served[view.cluster] = health.served_objects(
                health_rows, cluster=view.cluster, names=[*names, *gone[view.cluster]]
            )
            listed[view.cluster] = objects.listed_objects(
                rows.get(view.cluster),
                view.proxies,
                #
                # `None` where no node said anything, so the hostname match
                # answers instead. Silence is not "nothing is served".
                #
                served=served[view.cluster] if _nodes_reported(health_rows, view.cluster) else None,
            )
        #
        # What is left of the published inventory once the managed frontends are
        # accounted for above: configuration this platform does not own, where
        # the frontend really is the only thing there is to show.
        #
        unmanaged = {
            view.cluster: objects.unmanaged_only(view.proxies) for view in overview.clusters
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
        # And the cluster's addresses, because they decide which node may
        # answer. An object leaving from a source address is answerable only
        # from the node that carries it; the other binds an address it does not
        # have and reports the pool down.
        #
        _, network_rows, _ = read_source(request, config, NETWORK_SOURCE)
        networks = {reading.cluster: reading for reading in network_rows}
        pool_lamps = {
            view.cluster: {
                obj.name: health.object_health(
                    health_rows,
                    cluster=view.cluster,
                    obj=obj.name,
                    others=[other.name for other in listed[view.cluster]],
                    checked=health.has_health_check(obj.document),
                    sourced=health.leaves_from_source(
                        obj.document,
                        default_vip=_default_vip(networks.get(view.cluster)),
                        vip_sources=_vip_sources(networks.get(view.cluster)),
                    ),
                )
                for obj in objects.cluster_object_views(rows.get(view.cluster))
            }
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
                view.cluster: tuple(
                    _settled_drafts(
                        connection,
                        view.cluster,
                        {listing.name for listing in listed[view.cluster]},
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
        counts = objects.counted(listed, unmanaged)
        return {
            "proxies": overview,
            "listed": listed,
            "counts": counts,
            "health": pool_lamps,
            "unmanaged": unmanaged,
            #
            # A reader has no drafts to see: a draft is somebody's unfinished
            # edit, and the row exists so its author can find it again.
            #
            "drafts": drafts if role == "admin" else {},
            "publishing": publishing,
            "behind": behind,
            "reconfigured": reconfigured,
            "failed": failed,
            "removed": removed,
            "captured_at": captured_at,
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
            busy = jobs.in_flight(db.recent_jobs(connection))
            #
            # And when each cluster was last read. A job finishing is not the
            # same moment as the poller seeing what it did, so a page that
            # reloaded on the first still showed the reading from before the
            # deploy: the spinner gone, and every number beside it stale.
            #
            observed = {
                status.cluster: status.observed_at.isoformat()
                for status in db.cluster_statuses(connection)
                if status.observed_at is not None
            }
        return JSONResponse({"busy": busy, "observed": observed})

    @router.get("/proxies", response_class=HTMLResponse)
    def proxy_overview(request: Request) -> Response:
        session = current_session(request)
        if session is None:
            return RedirectResponse("/login", status_code=303)
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        listing = _proxy_listing(request, session.role)
        captured_at = listing.pop("captured_at")
        return TEMPLATES.TemplateResponse(
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
                "production_snapshot": config.production_snapshot,
                "snapshot_age": snapshot_age(captured_at),
            },
        )

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
            notice=(
                "Saved as a draft. It reaches no configuration until it is published."
                if saved
                else ""
            ),
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
                "production_snapshot": config.production_snapshot,
                "snapshot_age": "",
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
        clusters, object_rows, captured_at = read_source(request, config, OBJECTS_SOURCE)
        if cluster not in clusters:
            raise HTTPException(status_code=404)
        _, inventory_rows, _ = read_source(request, config, INVENTORY_SOURCE)
        overview = proxies.build_proxy_overview(
            clusters,
            inventory_rows,
            now=captured_at,
            stale_after=timedelta(seconds=config.poller.interval_seconds * 2),
            captured=captured_at is not None,
        )
        published = tuple(
            proxy for view in overview.clusters if view.cluster == cluster for proxy in view.proxies
        )
        _, history_rows, _ = read_source(request, config, HISTORY_SOURCE)
        listing = history.build_history_overview(
            clusters,
            history_rows,
            now=captured_at,
            stale_after=timedelta(seconds=config.poller.interval_seconds * 2),
            captured=captured_at is not None,
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
        _, status_rows, _ = read_source(request, config, STATUS_SOURCE)
        board = dashboard.build_dashboard(
            clusters,
            status_rows,
            now=captured_at,
            stale_after=timedelta(seconds=config.poller.interval_seconds * 2),
            captured=captured_at is not None,
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
        _, network_rows, _ = read_source(request, config, NETWORK_SOURCE)
        addresses = network.build_network_overview(
            clusters,
            network_rows,
            now=captured_at,
            stale_after=timedelta(seconds=config.poller.interval_seconds * 2),
            captured=captured_at is not None,
        )
        described = next((view for view in addresses if view.cluster == cluster), None)
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
            vip=vip.name if vip else None,
            vip_address=vip.address if vip else None,
            vip_is_default=vip is not None,
            now=captured_at,
            stale_after=timedelta(seconds=config.poller.interval_seconds * 2),
            captured=captured_at is not None,
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
            draft = _settled_draft(connection, cluster, name, {name} if detail.stored else set())
        #
        # A name that is neither stored, nor served, nor drafted is not a page.
        # Rendering an empty detail for any string would make every typo look
        # like a proxy somebody had deleted.
        #
        if detail.stored is None and detail.published is None and detail.available and not draft:
            raise HTTPException(status_code=404)
        #
        # What has actually gone through this object's pools lately. Read from
        # the samples the poller stores rather than from the nodes, so opening
        # the page reaches nothing: it is history, and history is the one thing
        # a node cannot be asked for.
        #
        # Which pools this page can ask about, from both places a name can come
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
        traffic: list[metrics.PoolTraffic] = []
        chosen = metrics.window(request.query_params.get("traffic"))
        served: list[str] = list(detail.published.backends if detail.published else ())
        if detail.stored is not None:
            try:
                proxy = load_proxy(name, detail.stored.document.encode())
            except ModelError:
                proxy = None
            if proxy is not None:
                served.extend(
                    health.backend_name(name, pool)
                    for pool in proxy.backends
                    if health.backend_name(name, pool) not in served
                )
        if served:
            #
            # One moment for every pool on the page, so the cards share an axis
            # and can be compared against each other rather than each against
            # the instant its own query ran.
            #
            now = datetime.now(UTC)
            since = now - chosen.span
            with request.app.state.pool.connection() as connection:
                traffic = [
                    metrics.pool_traffic(
                        backend,
                        db.read_pool_samples(
                            connection,
                            cluster=cluster,
                            backend=backend,
                            since=since,
                            until=now,
                            width=chosen.bucket,
                        ),
                        tick_format=chosen.tick,
                        start=since,
                        end=now,
                        bucket=chosen.bucket,
                        measurement=db.read_pool_totals(
                            connection,
                            cluster=cluster,
                            backend=backend,
                            since=since,
                            until=now,
                        ),
                    )
                    for backend in served
                ]
        return TEMPLATES.TemplateResponse(
            request,
            "object.html",
            {
                "username": session.username,
                "role": session.role,
                "csrf_token": auth.csrf_token(token),
                "section": "proxies",
                "object": detail,
                "draft": draft,
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
                "traffic_windows": metrics.WINDOWS,
                "traffic_chosen": chosen.key,
                #
                # Whether the window asks for more history than the raw samples
                # are kept for. The card says so rather than drawing a month
                # that is really a week, which would read as a month with very
                # little traffic in it.
                #
                "traffic_truncated": chosen.span > metrics.RAW_RETENTION,
                #
                # More than one pool is the only case where naming them helps.
                # With one, the name is the object's own backend written twice
                # in a row and answers nothing the page has not said.
                #
                "traffic_named": len(traffic) > 1,
                "spark_width": metrics.SPARK_WIDTH,
                "spark_height": metrics.SPARK_HEIGHT,
                "management_writes": config.management_writes,
                "demo_fixture": config.demo_fixture,
                "production_snapshot": config.production_snapshot,
                "snapshot_age": snapshot_age(captured_at),
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
        than something reached from a proxy: a listener belongs to the address
        and to the cluster and never to an object (B94), and "which pool
        carries this" cannot be asked from inside the pool somebody already
        picked.

        Admin only, for the same reason as the object page: naming every
        listener and pool a cluster carries describes the shape of what is
        published, which the overview deliberately does not.
        """

        session = current_session(request)
        if session is None:
            return RedirectResponse("/login", status_code=303)
        if session.role != "admin":
            return PlainTextResponse("Refused", status_code=403)
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        clusters, _rows, captured_at = read_source(request, config, STATUS_SOURCE)
        if only is not None and only not in clusters:
            raise HTTPException(status_code=404)
        wanted = [only] if only is not None else list(clusters)
        #
        # The stored documents, only so a generated redirect can be named by
        # what it does. Its configuration name is a digest of the route that
        # made it, which is right for counters that must survive an edit and
        # unreadable on a page.
        #
        _, object_rows, _ = read_source(request, config, OBJECTS_SOURCE)

        chosen = metrics.window(request.query_params.get("traffic"))
        #
        # One moment for the whole page. Two queries taken a second apart would
        # give the sections axes that do not quite line up, and the only use of
        # this page is holding one against another.
        #
        now = datetime.now(UTC)
        since = now - chosen.span

        def section(
            named: Sequence[str],
            read: Callable[[str], list[metrics.Sample]],
            total: Callable[[str], metrics.PoolMeasurement],
            label: Callable[[str], str],
        ) -> list[metrics.PoolTraffic]:
            """One section: read every series, then draw them against one scale.

            The ceiling has to be known before any card is drawn, so this is
            two passes over the same list rather than one - which is the price
            of the comparison the section exists to make.
            """

            found = [(name, read(name), total(name)) for name in named]
            ceiling = metrics.shared_ceiling(
                [metrics.intervals(samples) for _name, samples, _totals in found],
                start=since,
                end=now,
                bucket=chosen.bucket,
            )
            return [
                metrics.pool_traffic(
                    label(name),
                    samples,
                    tick_format=chosen.tick,
                    start=since,
                    end=now,
                    bucket=chosen.bucket,
                    measurement=totals,
                    ceiling=ceiling,
                )
                for name, samples, totals in found
            ]

        drawn = []
        with request.app.state.pool.connection() as connection:
            for cluster in wanted:
                #
                # Bound once per cluster and named, rather than written as
                # lambdas at each call. Four readers differing only in which
                # table they ask is exactly the shape that reads as noise
                # inline - and neither the type checker nor a person could
                # follow which cluster each one had closed over.
                #
                def listener_samples(name: str, cluster: str = cluster) -> list[metrics.Sample]:
                    return db.read_listener_samples(
                        connection,
                        cluster=cluster,
                        frontend=name,
                        since=since,
                        until=now,
                        width=chosen.bucket,
                    )

                def listener_totals(name: str, cluster: str = cluster) -> metrics.PoolMeasurement:
                    return db.read_listener_totals(
                        connection, cluster=cluster, frontend=name, since=since, until=now
                    )

                def pool_samples(name: str, cluster: str = cluster) -> list[metrics.Sample]:
                    return db.read_pool_samples(
                        connection,
                        cluster=cluster,
                        backend=name,
                        since=since,
                        until=now,
                        width=chosen.bucket,
                    )

                def pool_totals(name: str, cluster: str = cluster) -> metrics.PoolMeasurement:
                    return db.read_pool_totals(
                        connection, cluster=cluster, backend=name, since=since, until=now
                    )

                targets = metrics.redirect_targets(_documents(object_rows, cluster))

                def redirect_label(name: str, targets: Mapping[str, str] = targets) -> str:
                    """What it redirects, or the stored name where nothing says.

                    A page that invented a name would be worse than one showing
                    an opaque name it could not resolve.
                    """

                    return targets.get(name, metrics.without_prefix(name))

                backends = db.read_cluster_pools(
                    connection, cluster=cluster, since=since, until=now
                )
                listeners = db.read_cluster_listeners(
                    connection, cluster=cluster, since=since, until=now
                )
                drawn.append(
                    {
                        "cluster": cluster,
                        "accent": accent_index(cluster),
                        "listeners": list(
                            zip(
                                [metrics.listening(name) for name in listeners],
                                section(
                                    listeners,
                                    listener_samples,
                                    listener_totals,
                                    lambda name: metrics.listening(name).vip,
                                ),
                                strict=True,
                            )
                        ),
                        #
                        # Pools and redirect answers are drawn apart and scaled
                        # apart. A redirect has no servers and answers 301
                        # itself, so letting it into the comparison would size
                        # every real pool against traffic that never reached
                        # one.
                        #
                        "pools": section(
                            [name for name in backends if not metrics.is_redirect(name)],
                            pool_samples,
                            pool_totals,
                            metrics.without_prefix,
                        ),
                        "redirects": section(
                            [name for name in backends if metrics.is_redirect(name)],
                            pool_samples,
                            pool_totals,
                            redirect_label,
                        ),
                    }
                )

        return TEMPLATES.TemplateResponse(
            request,
            "cluster.html",
            {
                "username": session.username,
                "role": session.role,
                "csrf_token": auth.csrf_token(token),
                "section": "traffic",
                "clusters": drawn,
                "one_cluster": only,
                "traffic_window": chosen.label,
                "traffic_bucket": chosen.bucket_label,
                "traffic_windows": metrics.WINDOWS,
                "traffic_chosen": chosen.key,
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
                "production_snapshot": config.production_snapshot,
                "snapshot_age": snapshot_age(captured_at),
            },
        )

    @router.get("/traffic", response_class=HTMLResponse)
    def all_traffic(request: Request) -> Response:
        return _cluster_traffic(request, config, None)

    @router.get("/clusters/{cluster}/traffic", response_class=HTMLResponse)
    def cluster_traffic(request: Request, cluster: str) -> Response:
        return _cluster_traffic(request, config, cluster)

    @router.get("/network", response_class=HTMLResponse)
    def network_overview(request: Request) -> Response:
        return _network_page(request, config)

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
        with request.app.state.pool.connection() as connection:
            running = jobs.in_flight(db.recent_jobs(connection))
        return TEMPLATES.TemplateResponse(
            request,
            "certificates.html",
            {
                "username": session.username,
                "role": session.role,
                "csrf_token": auth.csrf_token(token),
                "certificates": overview,
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
        with request.app.state.pool.connection() as connection:
            running = jobs.in_flight(db.recent_jobs(connection))
        return TEMPLATES.TemplateResponse(
            request,
            "history.html",
            {
                "username": session.username,
                "role": session.role,
                "csrf_token": auth.csrf_token(token),
                "history": overview,
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
        vip_name: Sequence[str] = Form(default=()),
        vip_address: Sequence[str] = Form(default=()),
        vip_source: Sequence[str] = Form(default=()),
        vip_tls: Sequence[str] = Form(default=()),
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
        return_to: str = Form(default="", max_length=64),
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
        elif operation == "network_publish":
            # A changed default silently moves every object that did not name a
            # VIP.  The cached page states that count next to this confirmation;
            # the helper remains the authority for the document itself.
            if default_vip_confirmation != "on":
                return _refusal(
                    request,
                    session,
                    token,
                    "Confirm the default VIP impact before publishing.",
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
                        removed_source_rows=network.row_numbers(source_remove),
                        removed_group_rows=network.row_numbers(group_remove),
                    )
                )
            except network.FormProblem as problem:
                # Safe to show: these messages name a row's position, never
                # anything that was typed into it.
                return _refusal(request, session, token, str(problem), back="/network")
            payload = {
                "network": document,
                "expected_head": expected_head,
                "comment": comment,
            }

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
        return RedirectResponse(_return_path(return_to), status_code=303)

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
    clusters, object_rows, captured_at = read_source(request, config, OBJECTS_SOURCE)
    if cluster not in clusters:
        raise HTTPException(status_code=404)
    stale_after = timedelta(seconds=config.poller.interval_seconds * 2)
    reading = next((row for row in object_rows if row.cluster == cluster), None)
    result = reading.result if reading is not None and isinstance(reading.result, dict) else {}
    commit = result.get("commit")

    _, network_rows, _ = read_source(request, config, NETWORK_SOURCE)
    described = next(
        (
            view
            for view in network.build_network_overview(
                clusters,
                network_rows,
                now=captured_at,
                stale_after=stale_after,
                captured=captured_at is not None,
            )
            if view.cluster == cluster
        ),
        None,
    )
    _, certificate_rows, _ = read_source(request, config, CERTIFICATE_SOURCE)
    held = next(
        (
            view
            for view in certificates.build_certificate_overview(
                clusters,
                certificate_rows,
                now=captured_at,
                stale_after=stale_after,
                captured=captured_at is not None,
            ).clusters
            if view.cluster == cluster
        ),
        None,
    )
    _, history_rows, _ = read_source(request, config, HISTORY_SOURCE)
    released = next(
        (
            version
            for view in history.build_history_overview(
                clusters,
                history_rows,
                now=captured_at,
                stale_after=stale_after,
                captured=captured_at is not None,
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
        draft = (
            _settled_draft(connection, cluster, name, {view.name for view in state.stored})
            if name
            else None
        )

    stored = next((view for view in state.stored if view.name == name), None)
    unexpressible = ""
    #
    # Whether this page is an answer to a question about the object. Read
    # before `form` is replaced below, because from there on the two are
    # indistinguishable.
    #
    # "Test health" is a submission too, and it is not that question: it asks
    # the nodes about the pool, and a page that answered it with a verdict on
    # the document would be reporting on work the person did not ask about.
    #
    submitted = form is not None and form.action != "recheck"
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
        form = editor_module.ObjectForm(**_form_defaults(fields))
        draft_revision = str(draft.revision) if draft is not None else ""

    fields = form.fields()
    #
    # What the nodes say about this object's pool right now. Read for the page
    # rather than for the check: it is an observation, not a verdict on the
    # document, and an object that has never been deployed simply has none.
    #
    _, status_rows, _ = read_source(request, config, STATUS_SOURCE)
    pool = health.pool_health(
        status_rows,
        cluster=cluster,
        obj=str(fields.get("name", "")).strip() or name,
        pool=str(fields.get("backend", "")).strip() or "web",
        #
        # The same address the probe binds, and read the same way. With one set,
        # only the node that carries it can answer for this pool - the other
        # runs the same check against an address it does not have.
        #
        source=probe_module.source_address(fields, editor_module.choices(state.choices)),
        #
        # As written in the form, so the card can say `198.51.100.10:8080`
        # instead of `s1`. The runtime name stays beside it: it is what appears
        # in the logs somebody will read next.
        #
        addresses=str(fields.get("servers", "")).splitlines(),
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
    result = editor_module.check(
        fields,
        state.choices,
        others=tuple((view.name, view.document) for view in state.stored),
    )
    return TEMPLATES.TemplateResponse(
        request,
        "editor.html",
        {
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
            "check_interval": DEFAULT_INTERVAL,
            "check_rise": DEFAULT_RISE,
            "check_fall": DEFAULT_FALL,
            "result": result,
            "draft": draft,
            "draft_revision": draft_revision,
            "unexpressible": unexpressible,
            "submitted": submitted,
            "pool_health": pool,
            "probe": report,
            "notice": notice,
            "action": action,
            "unchanged": editor_module.unchanged(
                result.document, stored.document if stored else None
            ),
            "management_writes": config.management_writes,
            "demo_fixture": config.demo_fixture,
            "production_snapshot": config.production_snapshot,
            "snapshot_age": None,
        },
    )


def _form_defaults(fields: dict[str, Any]) -> dict[str, Any]:
    """The form model's own view of a field mapping.

    `allow_from` is the only one that needs saying: the model holds a list and
    the mapping carries a tuple, and pydantic will not take the tuple for a
    field it was told is a list.
    """

    values = dict(fields)
    values["allow_from"] = list(values.get("allow_from") or ())
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

    if form.action == "check":
        return _editor_page(
            request, config, cluster, name, form, draft_revision=form.expected_revision
        )

    #
    # Asking the nodes to try the check the form describes, right now, against
    # the object as it is written on screen - published or not. The poller is
    # woken as well, because what it reports about a deployed pool is the other
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
    replaces_published = name if renaming and published else ""
    if renaming and not proxy_model.NAME.fullmatch(typed):
        return _refusal_page(
            request,
            config,
            f"{typed} is not a usable object name - {proxy_model.name_refusal(typed)}; "
            f"use {proxy_model.NAME_RULE}.",
            back=_proxy_path(cluster, name, "edit"),
        )

    revision = int(form.expected_revision) if form.expected_revision.isdigit() else None
    #
    # A new object has no draft to be a revision of, so the field is ignored
    # here rather than trusted. It is a hidden input, and a browser restores
    # hidden inputs when somebody navigates back into a form - so a revision
    # from the object saved a moment ago survived into the new-object form and
    # turned the next save into an update of a row that had never existed. The
    # answer was "the draft changed since it was read", about a draft nobody
    # had ever made, and the work was refused with nowhere obvious to go.
    #
    if not name:
        revision = None

    if form.action == "discard":
        if revision is None:
            return _refusal_page(
                request,
                config,
                "There is no draft to discard.",
                back=_proxy_path(cluster, name, "edit"),
            )
        with request.app.state.pool.connection() as connection:
            try:
                db.discard_draft(
                    connection, cluster=cluster, object_id=object_id, expected_revision=revision
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
                detail={"object": object_id},
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
        if any(view.name == object_id for view in state.stored):
            return RedirectResponse(
                _proxy_path(cluster, object_id) + "?discarded=1", status_code=303
            )
        return RedirectResponse(f"/proxies?discarded={object_id}", status_code=303)

    if form.action not in ("save", "publish"):
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
    # The rename of an unpublished draft, resolved here where the write is.
    # From this point the new name is the object: it is what gets saved, what
    # the redirect lands on, and what a publish would carry.
    #
    # The old row is deleted after the new one is written, and both happen in
    # the transaction below - a rename that left the draft under both names
    # would put two objects in the listing where the person made one.
    #
    # The new name has to be free of both a stored object and another draft.
    # A draft is not visible on the listing the way a published object is, so
    # without the second check a rename could silently land on somebody else's
    # unfinished work and take its revision with it.
    #
    renamed_from = ""
    rename_revision = 0
    if renaming:
        with request.app.state.pool.connection() as connection:
            taken = _settled_draft(connection, cluster, typed, {view.name for view in state.stored})
        if any(view.name == typed for view in state.stored) or taken is not None:
            return _refusal_page(
                request,
                config,
                f"{typed} is already taken in this cluster, as an object or as a draft.",
                back=_proxy_path(cluster, name, "edit"),
            )
        #
        # The move is only for a draft that exists. Without a revision there is
        # no row under the old name - nothing was ever saved there - so the new
        # name is simply where this work is saved, and nothing is left behind
        # because nothing was there.
        #
        object_id = typed
        if revision is not None:
            renamed_from, rename_revision = name, revision

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

    with request.app.state.pool.connection() as connection:
        try:
            if renamed_from:
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
                    object_id=renamed_from,
                    new_object_id=object_id,
                    yaml=result.document,
                    base_version=state.base_version,
                    base_hash=state.commit,
                    updated_by=session.username,
                    expected_revision=rename_revision,
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
                    expected_revision=revision,
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
            action="save_draft",
            cluster=cluster,
            request_id=uuid4(),
            detail=(
                {"object": object_id, "revision": saved.revision, "renamed_from": renamed_from}
                if renamed_from
                else {"object": object_id, "revision": saved.revision}
            ),
        )
        connection.commit()
    #
    # 303 rather than a rendered page, as everywhere else that writes: a
    # refresh of this response must not save the draft a second time under a
    # revision that has since moved.
    #
    #
    # The flag is what the page says afterwards. A 303 leaves nothing behind,
    # so without it a save that worked and a page that was merely opened look
    # exactly alike - which is the moment somebody presses save again.
    #
    if form.action == "save":
        #
        # Back to the editor, which is where the work is. It went to the listing
        # with the object's name in the flag, while the only readers of the flag
        # are this page and the object's own and both look for "1" - so a save
        # that worked and a page that had merely been opened looked exactly
        # alike, which is the moment somebody presses save again.
        #
        # The name rather than `name`, because saving a new object lands on the
        # object it just created rather than back on the empty form.
        #
        return RedirectResponse(
            _proxy_path(cluster, object_id, "edit") + "?saved=1", status_code=303
        )

    #
    # Publishing is a job, and the draft is saved first on purpose. The two are
    # one button because saving and then publishing separately is three screens
    # for one change - but they stay two acts underneath, so a publish that is
    # refused leaves the work saved rather than lost.
    #
    # The key is derived from what is being published rather than generated, so
    # a double-click is the same request and not a second one. The revision is
    # in it because the next edit of the same object is a different publish.
    #
    objects: dict[str, str | None] = {object_id: None if saved.deleted else result.document}
    if replaces_published and not saved.deleted:
        #
        # Both halves of the rename, in one publish. The order in the mapping
        # does not matter - the helper applies the whole set and then generates
        # from the result - but the pairing does: sent apart, the first of the
        # two is a cluster with either two objects on one hostname or none.
        #
        objects[replaces_published] = None
    payload = {
        "objects": objects,
        "expected_head": state.commit,
        "comment": (
            f"Rename {replaces_published} to {object_id}"
            if replaces_published and not saved.deleted
            else f"Publish {object_id}"
        ),
        #
        # Which draft, and which revision of it. Carried by the job and never
        # forwarded to the helper - `operations.prepare` builds the helper's
        # request field by field - so this says what the interface has to know
        # afterwards without widening what runs as root.
        #
        # It is what lets a published draft be recognised as published. The row
        # is deleted once its publish is done, so a later edit of the same
        # object is a new row with a new id, and reverting one to a text
        # published earlier no longer looks like work that is already finished.
        #
        "draft": {"id": str(saved.id), "revision": saved.revision},
    }
    key = _publish_key(cluster, "objects_publish", payload)
    try:
        operations.prepare(
            operation="objects_publish", cluster=cluster, request_id=uuid4(), payload=payload
        )
    except operations.BadPayload:
        #
        # The form built this payload, so a refusal here is the interface's
        # mistake and not the person's. Said plainly rather than echoed: the
        # detail can carry what was typed.
        #
        return _refusal_page(
            request,
            config,
            "The draft was saved, but this interface could not build a publish for it.",
            back=_proxy_path(cluster, object_id, "edit"),
        )

    with request.app.state.pool.connection() as connection:
        try:
            job = db.queue_job(
                connection,
                operation="objects_publish",
                cluster=cluster,
                payload=payload,
                idempotency_key=key,
            )
        except db.ClusterBusy:
            connection.rollback()
            return _refusal_page(
                request,
                config,
                "This cluster is already running a job. The draft is saved; publish it when "
                "that job has finished.",
                back=_proxy_path(cluster, object_id, "edit"),
            )
        except db.RequestConflict:
            connection.rollback()
            return _refusal_page(
                request,
                config,
                "That publish was already asked for with different content.",
                back=_proxy_path(cluster, object_id, "edit"),
            )
        db.record_audit_event(
            connection,
            actor=session.username,
            action="queue_job",
            cluster=cluster,
            request_id=job.request_id,
            detail={"operation": "objects_publish", "job": job.id, "object": object_id},
        )
        connection.commit()

    return RedirectResponse("/proxies?published=" + quote(object_id), status_code=303)


def _removal_submit(
    request: Request, config: Config, cluster: str, name: str, csrf_token: str
) -> Response:
    """Publish the removal of one object.

    A removal is a publish like any other: the object leaves the repository and
    the configuration generated from it leaves with it, as one version. So this
    goes through the same queue, the same helper and the same lock, and differs
    only in carrying `null` where a document would be.

    It writes a draft first, exactly as saving does, and for the same reason -
    the draft is what the job names afterwards, so a removal can be told from
    an edit that happened to look like one. `deleted` is what the draft says:
    not that somebody abandoned an edit, but that they decided the object
    should go.
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
        existing = _settled_draft(connection, cluster, name, {name})
        try:
            saved = db.save_draft(
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
                deleted=True,
                expected_revision=existing.revision if existing else None,
            )
        except db.DraftConflict as conflict:
            connection.rollback()
            return _refusal_page(
                request, config, str(conflict), back=_proxy_path(cluster, name), stale=True
            )
        connection.commit()

    payload = {
        "objects": {name: None},
        "expected_head": state.commit,
        "comment": f"Remove {name}",
        "draft": {"id": str(saved.id), "revision": saved.revision},
    }
    key = _publish_key(cluster, "objects_publish", payload)
    try:
        operations.prepare(
            operation="objects_publish", cluster=cluster, request_id=uuid4(), payload=payload
        )
    except operations.BadPayload:
        return _refusal_page(
            request,
            config,
            "This interface could not build a removal for that object.",
            back=_proxy_path(cluster, name),
        )

    with request.app.state.pool.connection() as connection:
        try:
            job = db.queue_job(
                connection,
                operation="objects_publish",
                cluster=cluster,
                payload=payload,
                idempotency_key=key,
            )
        except db.ClusterBusy:
            connection.rollback()
            return _refusal_page(
                request,
                config,
                "This cluster is already running a job. The removal is saved as a draft; "
                "publish it when that job has finished.",
                back=_proxy_path(cluster, name),
            )
        except db.RequestConflict:
            connection.rollback()
            return _refusal_page(
                request,
                config,
                "That removal was already asked for with different content.",
                back=_proxy_path(cluster, name),
            )
        db.record_audit_event(
            connection,
            actor=session.username,
            action="queue_job",
            cluster=cluster,
            request_id=job.request_id,
            detail={"operation": "objects_publish", "job": job.id, "object": name, "removed": True},
        )
        connection.commit()

    return RedirectResponse("/proxies?published=" + quote(name), status_code=303)


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


def _published_drafts(connection: Any, cluster: str) -> set[tuple[str, int]]:
    """Which draft revisions a finished publish has already carried away.

    Named by identity - the draft's own id and the revision that was published -
    and never by what the document says. Content matched a draft that had been
    edited back to a text published earlier, which is somebody deliberately
    reverting, and it deleted their work as though it were finished.
    """

    settled = set()
    for job in db.recent_jobs(connection, cluster=cluster):
        if job.operation != "objects_publish" or job.state != "done":
            continue
        draft = job.payload.get("draft") if isinstance(job.payload, Mapping) else None
        if not isinstance(draft, Mapping):
            continue
        identity, revision = draft.get("id"), draft.get("revision")
        if isinstance(identity, str) and isinstance(revision, int):
            settled.add((identity, revision))
    return settled


def _reflects(draft: db.ProxyDraft, stored: Collection[str]) -> bool:
    """Whether the objects cache has caught up with what this draft published.

    A publish finishes before the poller reads the repository again, so between
    the two there is a stretch where the job is done and the object is not yet
    in the cache. Clearing the draft on the job alone made the row vanish for
    that stretch: the spinner said "waiting for publish", the publish finished,
    and the work was on no page at all until the next poll.

    So the draft is what carries the row until the object it published can. An
    edit is reflected the moment it is published, because the object was
    already listed; a new object, or a removal, has to be waited for.
    """

    return (draft.object_id not in stored) if draft.deleted else (draft.object_id in stored)


def _settled_draft(
    connection: Any, cluster: str, object_id: str, stored: Collection[str] = ()
) -> db.ProxyDraft | None:
    """One draft, cleared away if its own publish has finished.

    The editor reads this rather than the row directly, and that is the case
    that matters most: a draft opens in preference to the stored object, so a
    stale one would hand somebody their pre-publish copy of a document they
    have already published - and the next save would write it back.
    """

    draft = db.read_draft(connection, cluster, object_id)
    if draft is None:
        return None
    if (str(draft.id), draft.revision) not in _published_drafts(connection, cluster):
        return draft
    if not _reflects(draft, stored):
        #
        # Published, but the cache has not caught up. The draft is the only
        # thing that can carry the row until it does.
        #
        return draft
    #
    # A conflict here is somebody saving in another tab between the read and
    # the delete, and their draft is the newer one - so it stays, and the page
    # shows it. Uncaught it took the whole listing down with it, which is a
    # 500 for a tidying step that was allowed to change nothing.
    #
    try:
        db.discard_draft(
            connection, cluster=cluster, object_id=object_id, expected_revision=draft.revision
        )
    except db.DraftConflict:
        #
        # No rollback: the conflict is a delete that matched no row, not a
        # failed statement, so the transaction is still good - and rolling it
        # back here would throw away work the caller had already done.
        #
        return db.read_draft(connection, cluster, object_id)
    connection.commit()
    return None


def _settled_drafts(
    connection: Any, cluster: str, stored: Collection[str] = ()
) -> list[db.ProxyDraft]:
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
    settled = _published_drafts(connection, cluster)
    published = {
        draft.object_id
        for draft in drafts
        if (str(draft.id), draft.revision) in settled and _reflects(draft, stored)
    }
    if not published:
        return drafts
    #
    # As above: a draft saved between the read and the delete is the newer one
    # and is kept. Counted rather than assumed, because the rows returned below
    # have to match what the table now holds.
    #
    kept: set[str] = set()
    for draft in drafts:
        if draft.object_id not in published:
            continue
        try:
            db.discard_draft(
                connection,
                cluster=cluster,
                object_id=draft.object_id,
                expected_revision=draft.revision,
            )
        except db.DraftConflict:
            #
            # As above, and it matters more here: a rollback would undo the
            # deletes this loop has already made.
            #
            kept.add(draft.object_id)
    connection.commit()
    return [
        draft for draft in drafts if draft.object_id not in published or draft.object_id in kept
    ]


#
# Where an operation may send somebody afterwards. A closed set and not the
# submitted string: this value arrives in a form, and a redirect that trusts one
# is how a page is turned into a way of sending somebody somewhere else.
#
RETURN_PATHS = {
    "dashboard": "/",
    "proxies": "/proxies",
    "certificates": "/certificates",
    "history": "/history",
    "network": "/network",
    "jobs": "/jobs",
}


def _return_path(name: str) -> str:
    """The page an operation returns to, or the jobs page.

    The jobs page is the fallback rather than the default, so a form that has
    not been told where it lives still lands somewhere that shows what happened.
    """

    return RETURN_PATHS.get(name, "/jobs")


def _refusal_page(
    request: Request, config: Config, message: str, *, back: str, stale: bool = False
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
            "back": back,
            "back_label": back.lstrip("/") or "the dashboard",
            "section": back.lstrip("/").split("/")[0],
            "demo_fixture": config.demo_fixture,
            "production_snapshot": config.production_snapshot,
            "snapshot_age": None,
        },
        status_code=400,
    )


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
    clusters, network_rows, captured_at = read_source(request, config, NETWORK_SOURCE)
    overview = network.build_network_overview(
        clusters,
        network_rows,
        now=captured_at,
        stale_after=timedelta(seconds=config.poller.interval_seconds * 2),
        captured=captured_at is not None,
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
    _, status_rows, _ = read_source(request, config, STATUS_SOURCE)
    board = dashboard.build_dashboard(
        clusters,
        status_rows,
        now=captured_at,
        stale_after=timedelta(seconds=config.poller.interval_seconds * 2),
        captured=captured_at is not None,
    )
    serving = {view.cluster: view for view in board.clusters}
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
            "awaiting_deploy": awaiting,
            "deployment": state,
            "management_writes": config.management_writes,
            "demo_fixture": config.demo_fixture,
            "production_snapshot": config.production_snapshot,
            "snapshot_age": snapshot_age(captured_at),
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
