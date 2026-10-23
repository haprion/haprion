"""The settings pages: users, sign-in, clusters, nodes, the interface and its features."""

from __future__ import annotations

import contextlib
from collections.abc import Mapping, Sequence
from dataclasses import replace
from datetime import UTC, datetime
from typing import Annotated, Any
from uuid import UUID, uuid4

from fastapi import APIRouter, Form, Request, Response
from fastapi.responses import (
    HTMLResponse,
    PlainTextResponse,
    RedirectResponse,
)
from haprion import cluster_settings as cluster_settings_module
from haprion.config import CLUSTER_ID, ConfigError
from haprion.digits import is_digits

from haprion_ui import (
    attention,
    auth,
    certificates,
    cluster_identity,
    cluster_nodes,
    cluster_settings_page,
    dashboard,
    db,
    feature_switch,
    features,
    jobs,
    location_data,
    moments,
    network,
    oidc_web,
    update_check,
    users,
    waf,
)
from haprion_ui.config import Config
from haprion_ui.db import AuthenticatedSession
from haprion_ui.views import (
    COMMIT_ID,
    OBJECTS_SOURCE,
    SETTINGS_SOURCE,
    STATUS_SOURCE,
    SWITCHED,
    TEMPLATES,
    UNAVAILABLE_PROVIDER,
    _account_rows,
    _admin_write_gate,
    _backup_overview,
    _creations,
    _dns_public_key,
    _new_password_problem,
    _oidc_page,
    _oidc_provider,
    _page_context,
    _posted,
    _queue_node_job,
    _reading_head,
    _registry_overview,
    _settled_changes,
    _start_oidc,
    _status_row,
    forbidden_page,
    listed_clusters,
    read_manager_certificates,
    read_source,
)


def build_router(config: Config) -> APIRouter:
    router = APIRouter()

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
            return forbidden_page(request, config)
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
                        shown=moments.moment,
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
            return forbidden_page(request, config)
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
            return forbidden_page(request, config)
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
            return forbidden_page(request, config)
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
            return forbidden_page(request, config)
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
            return forbidden_page(request, config)
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
            return forbidden_page(request, config)
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
            return forbidden_page(request, config)
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
            return forbidden_page(request, config)
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
            return forbidden_page(request, config)
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
            return forbidden_page(request, config)
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

    return router
