"""The dashboard and the pages around it: search, attention, status, jobs and history."""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping, Sequence
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any
from uuid import UUID, uuid4

from fastapi import APIRouter, Form, Request, Response
from fastapi.responses import (
    HTMLResponse,
    PlainTextResponse,
    RedirectResponse,
)
from haprion.digits import is_digits
from haprion.version_history import comment_problem

from haprion_ui import (
    audit,
    auth,
    blocked,
    certificates,
    cluster_settings_page,
    dashboard,
    db,
    features,
    first_cluster,
    getting_started,
    health,
    history,
    jobs,
    metrics,
    moments,
    network,
    node_events,
    objects,
    operations,
    search_index,
    traffic_summary,
)
from haprion_ui import version_changes as version_changes_view
from haprion_ui.access import admin_write_gate, client_address, current_session, forbidden_page
from haprion_ui.accounts import listed_accounts
from haprion_ui.config import Config, cluster_id_of
from haprion_ui.db import AuthenticatedSession
from haprion_ui.pending import held_server_counts, pending_count, pending_package, publish_key
from haprion_ui.reading import (
    HISTORY_SOURCE,
    NETWORK_SOURCE,
    OBJECTS_SOURCE,
    SEARCHED_SOURCES,
    SETTINGS_SOURCE,
    STATUS_SOURCE,
    listed_clusters,
    read_manager_certificates,
    read_source,
)
from haprion_ui.refusals import refusal_page
from haprion_ui.saved_work import COMMIT_ID
from haprion_ui.templates import TEMPLATES
from haprion_ui.views import (
    AUDIT_KEEP_DAYS,
    AUDIT_PAGE,
    AUDIT_TABLE,
    MAX_SEARCH_PAGE,
    NODE_EVENT_KEEP_DAYS,
    NODE_EVENT_TABLE,
    attention_items,
    attention_jobs,
    first_cluster_view,
    log_time_filter,
    network_page,
    read_backup_overview,
    registry_overview,
    return_path_for,
)

#
# What a refused form says, by operation, where the form can be got wrong in a
# way a person can put right. Never the validation detail (07-01).
#
REFUSED_FORMS = {
    "backup_schedule": "A weekly schedule needs at least one day, and the time must be HH:MM.",
}


def build_router(config: Config) -> APIRouter:
    router = APIRouter()

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
            stale_after=config.poller.stale_after,
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
        running = jobs.in_flight(recent, writes=config.management_writes)
        #
        # The first cluster's guide (B315) is the getting started list's first
        # row while it has a step to show, never the dashboard in its place
        # (B328, 26-10-18): a guide in the dashboard's place had no way out.
        #
        first = first_cluster_view(
            config,
            request,
            session,
            recent=recent,
            busy=running,
            status_rows=status_rows,
            network_readings=network_rows,
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
                cluster: pending_package(request, config, cluster)
                for cluster in listed_clusters(request, config)
                if pending_count(request, config, cluster)
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
                "attention": attention_items(request, config),
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
                "held_servers": held_server_counts(request, config, clusters, status_rows),
                "section": "dashboard",
                "demo_fixture": config.demo_fixture,
                #
                # The page redraws itself once per poll (live.js), so the CPU,
                # memory and freshness on it move without a reload. Not for
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

    @router.get("/network", response_class=HTMLResponse)
    def network_overview(request: Request) -> Response:
        return network_page(request, config)

    @router.post("/getting-started/hide")
    def hide_getting_started(
        request: Request, csrf_token: Annotated[str, Form(max_length=128)]
    ) -> Response:
        """Hide the getting started list for the whole installation (B316)."""

        gate = admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return forbidden_page(request, config)
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

        gate = admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return forbidden_page(request, config)
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
                stale_after=config.poller.stale_after,
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
                for view in read_backup_overview(config, request).clusters
                if view.schedule is not None and view.schedule.enabled
            }
            if backups_on
            else set()
        )
        registry = registry_overview(config, request)
        served = certificates.interface_served(read_manager_certificates(request, config))
        _, object_rows = read_source(request, config, OBJECTS_SOURCE)
        proxies = {
            reading.cluster: len(objects.cluster_object_views(reading)) for reading in object_rows
        }
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
                    proxies=proxies.get(view.cluster, 0),
                )
                for view in dashboard_view.clusters
                if view.configured
            ),
            interface_self_signed=served.self_signed if served is not None else None,
            accounts=len(listed_accounts(config, request)),
            sso=provider is not None and provider.enabled,
            site_certificates=registry.for_proxies if registry else 0,
            node_backups_on=backups_on,
            status_access=bool(access),
            features_changed=any(switch.updated_by for switch in switches.values()),
            guide=guide.resumed if guide is not None else None,
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

        gate = admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return forbidden_page(request, config)
        #
        # Only a row the list shows now: a key made up, or one that has gone
        # since the page was drawn, is acknowledged by nothing.
        #
        shown = next(
            (
                item
                for item in attention_items(request, config).items
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

    @router.get("/history/{cluster}/versions/{commit}", response_class=HTMLResponse)
    def version_changes(request: Request, cluster: str, commit: str) -> Response:
        """What one version changed, as the poller fetched it (B220, 2026-10-01).

        A page of its own, so the button is a plain link that works without
        script; the Versions page opens the same section in a dialog.
        """

        session = current_session(request)
        if session is None:
            return RedirectResponse("/login", status_code=303)
        #
        # The difference is the objects' documents and the generated
        # configuration: every backend address, and whatever an advanced text
        # wrote, passwords included. The object page is an administrator's for
        # that reason (B68, B221), and so is this (review 2026-10-22, 5-3).
        #
        if session.role != "admin":
            return forbidden_page(request, config)
        clusters, history_rows = read_source(request, config, HISTORY_SOURCE)
        if cluster not in clusters:
            return HTMLResponse("Not found", status_code=404)
        overview = history.build_history_overview(
            clusters,
            history_rows,
            stale_after=config.poller.stale_after,
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
                "management_writes": config.management_writes,
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
        _listed, status_rows = read_source(request, config, STATUS_SOURCE)
        overview = history.build_history_overview(
            clusters,
            history_rows,
            stale_after=config.poller.stale_after,
        )
        with request.app.state.pool.connection() as connection:
            running = jobs.in_flight(db.recent_jobs(connection), writes=config.management_writes)
        #
        # What is saved and not yet published, per cluster (B257): the one
        # place a publish is made. Only where a publish could be.
        #
        pending = (
            {
                view.cluster: pending_package(request, config, view.cluster)
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
                "behind": {row.cluster for row in status_rows if dashboard.behind(row)},
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
        idempotency_key: str = Form(default="", max_length=64),
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

        gate = admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return forbidden_page(request, config)
        if cluster not in listed_clusters(request, config):
            return PlainTextResponse("Not found", status_code=404)
        deploy = then == "deploy"
        back = "/" if deploy else "/history"
        package = pending_package(request, config, cluster)
        if package.problem:
            return refusal_page(request, config, package.problem, back=back)
        if not package.rows:
            return refusal_page(request, config, "Nothing is saved to publish.", back=back)
        if expected_head != package.head:
            return refusal_page(
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
            return refusal_page(
                request,
                config,
                "The saved changes changed after this page was opened. Read the list again "
                "before publishing.",
                back=back,
            )
        if not comment.strip():
            return refusal_page(
                request, config, "A comment is needed: it is the version's.", back=back
            )
        #
        # The helper's own rule, said here before a job is queued to be
        # refused (1A-4): a line separator pasted into the comment.
        #
        problem = comment_problem(comment.strip())
        if problem:
            return refusal_page(request, config, f"The comment {problem}.", back=back)
        payload = {
            **package.payload,
            "comment": comment.strip(),
            "requested_by": gate.username,
            **({"deploy": True} if deploy else {}),
        }
        try:
            drawn = UUID(idempotency_key)
        except ValueError:
            return PlainTextResponse("A request key is required", status_code=400)
        key = publish_key(cluster, "changes_publish", payload, drawn=drawn)
        try:
            operations.prepare(
                operation="changes_publish", cluster=cluster, request_id=uuid4(), payload=payload
            )
        except operations.BadPayload:
            return refusal_page(
                request,
                config,
                "This interface could not build a publish from what is saved.",
                back=back,
            )
        with request.app.state.pool.connection() as connection:
            job = db.queue_job(
                connection,
                operation="changes_publish",
                cluster=cluster,
                payload=payload,
                idempotency_key=key,
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
        return RedirectResponse("/history?published=" + cluster, status_code=303)

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
            attention_items(request, config).as_json(),
            media_type="application/json",
            headers={"Cache-Control": "no-store"},
        )

    @router.get("/status/metrics")
    def status_metrics(request: Request) -> Response:
        if not _status_allowed(request):
            return PlainTextResponse("Not found", status_code=404)
        return Response(
            attention_items(request, config).as_metrics(),
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
        """Run or discard a job held after a restart or a restore (0082, review 2026-10-20 R1)."""

        gate = admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return forbidden_page(request, config)
        if decision not in {"run", "discard"}:
            return PlainTextResponse("Refused", status_code=400)
        with request.app.state.pool.connection() as connection:
            taken = db.decide_held_job(
                connection, job_id=job_id, decision=decision, actor=gate.username
            )
            if taken:
                db.record_audit_event(
                    connection,
                    actor=gate.username,
                    action="held_job_decided",
                    detail={"job": job_id, "decision": decision},
                )
            connection.commit()
        #
        # Another admin answered first, or the job ended: said, rather than a
        # page that looks as if the answer was taken (review 26-10-29, b).
        #
        return RedirectResponse(
            "/jobs" if taken else "/jobs?not_held=" + str(job_id), status_code=303
        )

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
        clusters = listed_clusters(request, config)
        with request.app.state.pool.connection() as connection:
            listed = db.recent_jobs(connection)
            _, judged = attention_jobs(connection, clusters)
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
                judged=judged,
                writes=config.management_writes,
            )
            claim_pause = db.claim_pause(connection)
        not_held = request.query_params.get("not_held", "")
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
                "claim_pause": claim_pause,
                "management_writes": config.management_writes,
                "not_held": int(not_held) if is_digits(not_held) and len(not_held) < 19 else None,
                "section": "jobs",
                "view": "jobs",
            },
        )

    def _audit_page(request: Request, session: AuthenticatedSession, token: str) -> Response:
        """The record, newest first, a page at a time as the traffic log pages (B275, 26-10-11)."""

        query = request.query_params
        actor = query.get("who", "")[:255]
        cluster = cluster_id_of(query.get("cluster", ""))
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
            since = log_time_filter(
                selected_from, earliest=local_earliest.astimezone(UTC), latest=now, outside=outside
            )
            until = log_time_filter(
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
                "time_min": moments.picked(local_earliest),
                "time_max": moments.picked(local_now),
                "time_today": moments.picked_midnight(local_now),
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
        cluster = cluster_id_of(query.get("cluster", ""))
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
            since = log_time_filter(
                selected_from, earliest=local_earliest.astimezone(UTC), latest=now, outside=outside
            )
            until = log_time_filter(
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
                "time_min": moments.picked(local_earliest),
                "time_max": moments.picked(local_now),
                "time_today": moments.picked_midnight(local_now),
                "clusters": listed_clusters(request, config),
                "node_sorts": NODE_EVENT_TABLE.links(sort, kept),
            },
        )
        if asked:
            NODE_EVENT_TABLE.remember(response, sort, secure=config.session.cookie_secure)
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
            return forbidden_page(request, config)
        if session.role != "admin":
            return forbidden_page(request, config)
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
        elif operation == "network_save":
            revision = int(saved_revision) if is_digits(saved_revision) else None
            if network_action == "discard":
                if revision is None:
                    return refusal_page(
                        request, config, "There is nothing to discard.", back="/network"
                    )
                with request.app.state.pool.connection() as connection:
                    db.discard_cluster_change(
                        connection, cluster=cluster, kind="network", expected_revision=revision
                    )
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
                return refusal_page(
                    request,
                    config,
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
                return refusal_page(request, config, str(problem), back="/network")
            if not COMMIT_ID.fullmatch(expected_head):
                return PlainTextResponse("Invalid operation parameters", status_code=400)
            #
            # Saved, and published with the next publish from Versions (B257).
            #
            with request.app.state.pool.connection() as connection:
                change = db.save_cluster_change(
                    connection,
                    cluster=cluster,
                    kind="network",
                    document=document,
                    base_hash=expected_head,
                    updated_by=session.username,
                    expected_revision=revision,
                )
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
            #
            # A fixed sentence, never the validation detail: that can carry
            # request-derived values, and belongs in neither a client response
            # nor CodeQL's stack-trace surface. Said inside the interface's own
            # page, which a bare text answer was not (review 26-10-24, 07-01).
            #
            return refusal_page(
                request,
                config,
                REFUSED_FORMS.get(
                    operation, "The form was not accepted. Go back and check its fields."
                ),
                back=return_path_for(return_to, open=return_open),
            )

        with request.app.state.pool.connection() as connection:
            job = db.queue_job(
                connection,
                operation=operation,
                cluster=cluster,
                payload=payload,
                idempotency_key=key,
            )
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
        return RedirectResponse(return_path_for(return_to, open=return_open), status_code=303)

    return router
