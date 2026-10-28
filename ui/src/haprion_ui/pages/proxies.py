"""The proxy pages: the list, the editor, saved changes and what a cluster serves."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from datetime import UTC, datetime
from typing import Annotated, Any
from uuid import UUID, uuid4

from fastapi import APIRouter, Form, HTTPException, Request, Response
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
)
from haprion import (
    proxy_model,
    server_state,
)
from haprion.proxy_model import (
    ModelError,
    load_proxy,
)

from haprion_ui import (
    advanced_dialog,
    audit,
    auth,
    blocked,
    dashboard,
    db,
    features,
    health,
    history,
    jobs,
    metrics,
    network,
    objects,
    operations,
    proxies,
    search_index,
    server_card,
)
from haprion_ui import editor as editor_module
from haprion_ui.config import Config
from haprion_ui.db import AuthenticatedSession
from haprion_ui.templates import TEMPLATES
from haprion_ui.views import (
    BLOCKED_NOTICES,
    HISTORY_SOURCE,
    INVENTORY_SOURCE,
    NETWORK_SOURCE,
    OBJECT_FIGURES,
    OBJECTS_SOURCE,
    SAVED_NOTICE,
    SERVER_NOTICES,
    STATUS_SOURCE,
    _admin_write_gate,
    _advanced_submit,
    _earlier_names,
    _editor_page,
    _editor_state,
    _editor_submit,
    _lookup_again,
    _objects_reading,
    _posted,
    _read_concurrently,
    _refusal_page,
    _removal_submit,
    _settled_draft,
    _settled_drafts,
    _top_layers,
    _traffic_marks,
    current_session,
    forbidden_page,
    listed_clusters,
    moved_dns_servers,
    read_source,
)


def build_router(config: Config) -> APIRouter:
    router = APIRouter()

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
            stale_after=config.poller.stale_after,
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
            return forbidden_page(request, config)
        state = _editor_state(request, config, cluster)
        stored = next((view for view in state.stored if view.name == name), None)
        if stored is None:
            return _refusal_page(
                request,
                config,
                "This cluster has no proxy of that name to remove.",
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
            return forbidden_page(request, config)
        listed = next((one for one in listed_clusters(request, config) if one == cluster), None)
        if listed is None or not proxy_model.NAME.fullmatch(name):
            return PlainTextResponse("Not found", status_code=404)
        try:
            key = UUID(idempotency_key)
        except ValueError:
            return PlainTextResponse("A request key is required", status_code=400)
        back = "/proxies/" + listed + "/" + name
        posted = _posted(request)
        #
        # One past the bound, so the helper's own limit refuses a request
        # over it rather than this quietly sending part of one.
        #
        chosen = list(dict.fromkeys(str(entry)[:300] for entry in posted.getlist("server")))[
            : server_state.MAX_SERVERS + 1
        ]
        if not chosen:
            return RedirectResponse(back + "?servers=none", status_code=303)
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
                return RedirectResponse(back + "?servers=busy", status_code=303)
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
            return forbidden_page(request, config)
        listed = next((one for one in listed_clusters(request, config) if one == cluster), None)
        if listed is None or not proxy_model.NAME.fullmatch(name):
            return PlainTextResponse("Not found", status_code=404)
        try:
            key = UUID(idempotency_key)
        except ValueError:
            return PlainTextResponse("A request key is required", status_code=400)
        back = "/proxies/" + listed + "/" + name
        posted = _posted(request)
        #
        # One past the bound, so the helper's own limit refuses a request over
        # it rather than this quietly sending part of one.
        #
        chosen = list(dict.fromkeys(str(entry)[:64] for entry in posted.getlist("address")))[
            : server_state.MAX_ADDRESSES + 1
        ]
        if not chosen:
            return RedirectResponse(back + "?blocked=none", status_code=303)
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
                return RedirectResponse(back + "?blocked=busy", status_code=303)
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
            return forbidden_page(request, config)
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        clusters, object_rows = read_source(request, config, OBJECTS_SOURCE)
        if cluster not in clusters:
            raise HTTPException(status_code=404)
        _, inventory_rows = read_source(request, config, INVENTORY_SOURCE)
        overview = proxies.build_proxy_overview(
            clusters,
            inventory_rows,
            stale_after=config.poller.stale_after,
        )
        published = tuple(
            proxy for view in overview.clusters if view.cluster == cluster for proxy in view.proxies
        )
        _, history_rows = read_source(request, config, HISTORY_SOURCE)
        listing = history.build_history_overview(
            clusters,
            history_rows,
            stale_after=config.poller.stale_after,
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
            stale_after=config.poller.stale_after,
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
                    stale_after=config.poller.stale_after,
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
            stale_after=config.poller.stale_after,
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

    return router
