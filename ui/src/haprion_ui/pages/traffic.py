"""The traffic pages: a cluster's metrics, the traffic log and the WAF."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlencode

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
)
from haprion import (
    labels,
    proxy_model,
)
from haprion.proxy_model import (
    ModelError,
    load_proxy,
)

from haprion_ui import (
    auth,
    db,
    jobs,
    metrics,
    moments,
    objects,
    traffic_log_table,
    traffic_logs,
)
from haprion_ui.access import current_session, forbidden_page
from haprion_ui.cluster_identity import accent_index
from haprion_ui.config import Config, cluster_id_of
from haprion_ui.editor_flow import earlier_names
from haprion_ui.reading import (
    OBJECTS_SOURCE,
    STATUS_SOURCE,
    cluster_creations,
    listed_clusters,
    read_concurrently,
    read_source,
)
from haprion_ui.templates import TEMPLATES
from haprion_ui.views import log_freshness_warnings, log_time_filter, posted_form, traffic_marks
from haprion_ui.waf_work import (
    allow_waf_exception,
    remove_waf_exception,
    waf_overview,
    waf_work_page,
)


def build_router(config: Config) -> APIRouter:
    router = APIRouter()

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
            busy = {
                cluster: state.label
                for cluster, state in jobs.in_flight(
                    recent, writes=config.management_writes
                ).items()
            }
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
        for entry in cluster_creations(request, recent):
            if entry.running:
                busy.setdefault(entry.cluster, entry.running.label)
        return JSONResponse({"busy": busy, "catching_up": catching_up})

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
            return forbidden_page(request, config)
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
            earlier = earlier_names(name, targets_of[cluster], aliases[cluster])

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

            earlier = earlier_names(name, targets_of[cluster], aliases[cluster])
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
        answers = read_concurrently(pool, reads)
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
                **traffic_marks(request, marked),
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
        selected = cluster_id_of(request.query_params.get("cluster", ""))
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
                "freshness_warnings": log_freshness_warnings(reading, datetime.now(UTC)),
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
        return waf_work_page(request, config, "exceptions" if view == "exceptions" else "findings")

    @router.get("/waf/allow", response_class=HTMLResponse)
    def waf_allow_page(request: Request) -> Response:
        return allow_waf_exception(request, config, None)

    @router.post("/waf/allow", response_class=HTMLResponse)
    def waf_allow(request: Request) -> Response:
        return allow_waf_exception(request, config, posted_form(request))

    @router.post("/waf/exceptions/remove", response_class=HTMLResponse)
    def waf_remove_exception(request: Request) -> Response:
        return remove_waf_exception(request, config, posted_form(request))

    def _traffic_log_page(request: Request, *, waf_page: bool) -> Response:
        session = current_session(request)
        if session is None:
            return RedirectResponse("/login", status_code=303)
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        selected_cluster = cluster_id_of(request.query_params.get("cluster", ""))
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
            outside = (
                "Choose a date and time within the last "
                f"{labels.counted(config.traffic_logs.retention_days, 'day')}."
            )
            from_at = log_time_filter(selected_from, earliest=earliest, latest=now, outside=outside)
            to_at = log_time_filter(
                selected_to, earliest=earliest, latest=now, end_of_minute=True, outside=outside
            )
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
        # Reading what the collector stored, never asking a node. A node that
        # is slow, unreachable or hostile cannot make this request hang - it
        # can only make its own records old, which is exactly what the compact
        # warning reports.
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
        freshness_warnings = log_freshness_warnings(reading, now)
        #
        # The WAF page's Requests tab carries the same three figures as its
        # other two (mock round 7), over the same clusters and days.
        #
        waf_tabs: dict[str, Any] = {}
        if waf_page:
            listed = listed_clusters(request, config)
            chosen = (selected_cluster,) if selected_cluster in listed else tuple(listed)
            waf_tabs = {"tab_counts": waf_overview(request, config, chosen).tab_counts()}
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
                "time_min": moments.picked(local_earliest),
                "time_max": moments.picked(local_now),
                "max_lines": config.traffic_logs.max_lines,
                "log_sorts": table.links(sort, filters),
            },
        )
        if asked:
            table.remember(response, sort, secure=config.session.cookie_secure)
        return response

    return router
