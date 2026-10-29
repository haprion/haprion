"""What several pages share and no one area owns (K01, review 2026-10-28).

The pages are in `haprion_ui.pages`, one module per area, and what they share
by subject has its own module: the templates (`templates`), the readings
(`reading`), the session and the write gate (`access`), the refusal pages
(`refusals`), saved work and what waits to be published (`saved_work`,
`pending`), the proxy form (`editor_flow`), signing in (`accounts`) and the
WAF's work (`waf_work`). What is left here is shared between a few pages: the
traffic log's filters and marks, the certificate pages' context and export,
the node job a first cluster and Settings queue, the network page, and what
the dashboard's attention list and Events read.
"""

from __future__ import annotations

import io
import logging
import zipfile
from collections.abc import Callable, Collection, Iterable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import anyio
from fastapi import File, Form, Request, Response
from fastapi.responses import (
    RedirectResponse,
)
from haprion.certificates import CERTIFICATE_OPENING
from haprion.config import CERTIFICATE_ID
from haprion.dns_profile_keys import DnsProfilePublicKey, KeyFileError, read_public_key
from starlette.datastructures import FormData

from haprion_ui import (
    attention,
    auth,
    backups,
    certificates,
    dashboard,
    db,
    features,
    first_cluster,
    health,
    jobs,
    metrics,
    moments,
    network,
    objects,
    operations,
    refusals,
    sorting,
    traffic_logs,
    waf,
)
from haprion_ui.access import current_session
from haprion_ui.config import Config
from haprion_ui.db import AuthenticatedSession
from haprion_ui.reading import (
    BACKUP_SOURCE,
    CERTIFICATE_SOURCE,
    NETWORK_SOURCE,
    OBJECTS_SOURCE,
    STATUS_SOURCE,
    cluster_creations,
    listed_clusters,
    read_certificate_takeouts,
    read_manager_certificates,
    read_source,
)
from haprion_ui.saved_work import saved_network_rows
from haprion_ui.templates import TEMPLATES
from haprion_ui.waf_work import waf_not_working

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


def log_freshness_warnings(reading: traffic_logs.Reading, now: datetime) -> tuple[Any, ...]:
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


def log_time_filter(
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


def traffic_marks(request: Request, marked: metrics.Selection) -> dict[str, object]:
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
# The figures an object's traffic card draws, by what serves it: dnsdist counts
# a dns pool's queries (Fas 19a B4), IPVS a syslog pool's messages (19b B3),
# HAProxy everything else.
#
OBJECT_FIGURES = {"dns": metrics.DNS_FIGURES, "syslog": metrics.SYSLOG_FIGURES}

EXPIRED = (
    "This run has expired: it was prepared more than an hour ago. Start a new restore from the "
    "backup page."
)


#
# A page number past this is not one anybody reached by clicking Next.
#
MAX_SEARCH_PAGE = 10000


#
# Why the Servers card's buttons did nothing, by `?servers=` (B263). A queued
# job needs no sentence: the buttons give way to its spinner.
#
SERVER_NOTICES = {"none": "Tick the servers first.", **refusals.BUSY_NOTICES}
BLOCKED_NOTICES = {"none": "Tick the addresses first.", **refusals.BUSY_NOTICES}


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


def posted_form(request: Request) -> FormData:
    """The request's form, read from a handler running in the thread pool."""

    return anyio.from_thread.run(_read_form, request)


def registry_overview(config: Config, request: Request) -> certificates.RegistryView | None:
    clusters, certificate_rows = read_source(request, config, CERTIFICATE_SOURCE)
    overview = certificates.build_certificate_overview(
        clusters,
        certificate_rows,
        manager=read_manager_certificates(request, config),
        stale_after=config.poller.stale_after,
    )
    return overview.registry


def certificate_page_context(
    config: Config, request: Request, session: AuthenticatedSession
) -> tuple[str, certificates.RegistryView | None, dict[str, Any]]:
    token = request.cookies.get(auth.SESSION_COOKIE, "")
    registry = registry_overview(config, request)
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


def read_backup_overview(config: Config, request: Request) -> Any:
    clusters, backup_rows = read_source(request, config, BACKUP_SOURCE)
    return backups.build_backup_overview(
        clusters,
        backup_rows,
        stale_after=config.poller.stale_after,
    )


def read_status_row(config: Config, request: Request, cluster: str) -> Any | None:
    clusters, rows = read_source(request, config, STATUS_SOURCE)
    if cluster not in clusters:
        return None
    return next((row for row in rows if row.cluster == cluster), None)


def queue_node_job(
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
        except (db.ClusterBusy, db.RequestConflict) as refused:
            connection.rollback()
            #
            # A join key is sealed again on every submission, so a second click
            # is other bytes under the same key (review 26-10-24, 02-06).
            #
            if db.job_for_key(connection, key, operation=operation, cluster=cluster) is None:
                if isinstance(refused, db.RequestConflict):
                    raise refused
                return again(refusals.conflict_sentence(refused))
        else:
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


def first_cluster_view(
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
        creations=cluster_creations(request, recent),
        busy=busy,
        vip=vip,
        phase=request.query_params.get("first-cluster", ""),
        deployed_recently=first_cluster.deployed_recently(recent, cluster),
        failure=first_cluster.failure(recent, cluster) if cluster else None,
    )


def read_dns_public_key(config: Config) -> DnsProfilePublicKey | None:
    """The key the web seals against, read fresh: a rotation is a file swap."""

    if config.dns_profiles_public_key is None:
        return None
    try:
        return read_public_key(config.dns_profiles_public_key)
    except KeyFileError as exc:
        logger.error("dns_profiles.public_key cannot be read: %s", exc)
        return None


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


def return_path_for(name: str, *, open: str = "") -> str:
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


def public_certificate_files(
    certificate_id: str, fullchain_pem: str
) -> list[tuple[str, bytes, bool]]:
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


def zip_response(files: Sequence[tuple[str, bytes, bool]], filename: str) -> Response:
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


def network_page(request: Request, config: Config) -> Response:
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
        network_rows, saved_network = saved_network_rows(connection, list(network_rows))
    overview = network.build_network_overview(
        clusters,
        network_rows,
        stale_after=config.poller.stale_after,
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
        _, judged = attention_jobs(connection, clusters)
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
        stale_after=config.poller.stale_after,
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
    failures = jobs.last_failure(judged)
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


#
# How many of the newest jobs Needs attention reads, beside every cluster's,
# step's and subject's newest finished job however old.
#
ATTENTION_RECENT = 200


def attention_jobs(connection: Any, clusters: Collection[str]) -> tuple[list[db.Job], list[db.Job]]:
    """The newest jobs, and the jobs Needs attention judges, newest first.

    One set for every page that names or counts what went wrong: *Need review*
    on Jobs and the deploy cell on Network read the page's newest 20, and a
    failed deploy followed by twenty other jobs was listed here and counted
    nowhere (review 26-10-29, C02).

    A removed cluster's failures are no longer anybody's to settle: no step
    runs on a cluster that is gone, and a new cluster given the name would
    inherit them (review 26-10-25, 4-02). An unread list hides nothing. The
    newest are returned as read, for what is about the manager rather than a
    cluster.
    """

    recent = db.recent_jobs(connection, limit=ATTENTION_RECENT)
    known = {job.id for job in recent}
    every = recent + [job for job in db.attention_evidence(connection) if job.id not in known]
    judged = sorted(
        (job for job in every if job.cluster is None or not clusters or job.cluster in clusters),
        key=lambda job: (job.created_at, job.id),
        reverse=True,
    )
    return recent, judged


def attention_items(request: Request, config: Config) -> attention.Attention:
    """What needs doing, worked out from the pages' own builders (B274)."""

    stale_after = config.poller.stale_after
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
        recent, judged = attention_jobs(connection, clusters)
        items += attention.from_jobs(judged)
        cluster_list_at = db.cluster_list_observed(connection)
        items += attention.from_manager(
            cluster_list_at=cluster_list_at,
            poller_silent_after=max(stale_after, timedelta(minutes=5)),
            rows=recent,
            writes=config.management_writes,
            horizons=db.partition_horizons(connection, attention.MAINTENANCE_AHEAD),
            now=now,
            maintained_at=db.retention_completed(connection),
            claim_pause=db.claim_pause(connection),
        )
        items += attention.from_packages(db.package_waiting(connection))
        if config.traffic_logs.enabled:
            items += attention.from_waf(
                waf_not_working(request, config, connection, clusters),
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
        list_age=None if cluster_list_at is None else int((now - cluster_list_at).total_seconds()),
        now=now,
    )
