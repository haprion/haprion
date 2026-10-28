"""The first cluster's guide, from an empty manager to a cluster that serves."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Form, Request, Response
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    PlainTextResponse,
    RedirectResponse,
)

from haprion_ui import (
    auth,
    cluster_nodes,
    db,
    first_cluster,
    jobs,
)
from haprion_ui.access import admin_write_gate, current_session, forbidden_page
from haprion_ui.config import Config
from haprion_ui.db import AuthenticatedSession
from haprion_ui.reading import NETWORK_SOURCE, STATUS_SOURCE, listed_clusters, read_source
from haprion_ui.templates import TEMPLATES
from haprion_ui.views import (
    _dns_public_key,
    _first_cluster,
    _queue_node_job,
    _registry_overview,
    _status_row,
)


def build_router(config: Config) -> APIRouter:
    router = APIRouter()

    def _first_cluster_page(
        request: Request,
        guide: first_cluster.Guide,
        *,
        form: Mapping[str, str] | None = None,
        block: str = "",
        host: str = "",
        preview: Any = None,
        problem: str = "",
        status_code: int = 200,
    ) -> Response:
        session = current_session(request)
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        return TEMPLATES.TemplateResponse(
            request,
            "first-cluster.html",
            {
                "guide": guide,
                "form": form or guide.form,
                "block": block,
                "host": host,
                "preview": preview,
                "problem": problem,
                "node_package": first_cluster.node_package_name(),
                "username": session.username if session else "",
                "role": session.role if session else "",
                "csrf_token": auth.csrf_token(token),
                "management_writes": config.management_writes,
                "demo_fixture": config.demo_fixture,
            },
            status_code=status_code,
        )

    def _first_cluster_gate(request: Request, csrf_token: str) -> AuthenticatedSession | Response:
        gate = admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return forbidden_page(request, config)
        return gate

    @router.post("/first-cluster/name", response_class=HTMLResponse)
    def first_cluster_name(
        request: Request,
        cluster: str = Form(default="", max_length=64),
        display_name: str = Form(default="", max_length=64),
        vip: str = Form(default="", max_length=64),
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        """Step 1: read, not written - *Create cluster* takes them with the first node."""

        gate = _first_cluster_gate(request, csrf_token)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        form = {
            "cluster": cluster.strip(),
            "display_name": display_name.strip(),
            "vip": vip.strip(),
        }
        problem = cluster_nodes.name_problem(form, listed=listed_clusters(request, config))
        if problem:
            return _first_cluster_page(
                request, first_cluster.Guide(step=1), form=form, problem=problem, status_code=400
            )
        return _first_cluster_page(request, first_cluster.Guide(step=2), form=form)

    @router.post("/first-cluster/first-node", response_class=HTMLResponse)
    def first_cluster_first_node(
        request: Request,
        cluster: str = Form(default="", max_length=64),
        display_name: str = Form(default="", max_length=64),
        vip: str = Form(default="", max_length=64),
        block: str = Form(default="", max_length=8192),
        host: str = Form(default="", max_length=253),
        action: str = Form(default="", max_length=16),
        confirm: str = Form(default="", max_length=64),
        idempotency_key: str = Form(default="", max_length=64),
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        """Step 2: the first node's block read and shown, then *Create cluster* with it."""

        gate = _first_cluster_gate(request, csrf_token)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        form = {"cluster": cluster, "display_name": display_name, "vip": vip}
        if action == "back":
            return _first_cluster_page(request, first_cluster.Guide(step=1), form=form)
        step = first_cluster.Guide(step=2)
        registry = _registry_overview(config, request)
        try:
            creation = cluster_nodes.read_creation(
                {**form, "block_1": block, "host_1": host},
                listed=listed_clusters(request, config),
                certificates=(
                    entry.identifier for entry in (registry.certificates if registry else ())
                ),
            )
        except cluster_nodes.FormProblem as problem:
            return _first_cluster_page(
                request,
                step,
                form=form,
                block=block,
                host=host,
                problem=str(problem),
                status_code=400,
            )
        node = creation.nodes[0]
        if confirm.strip() != node.name:
            return _first_cluster_page(
                request, step, form=form, block=block, host=host, preview=node
            )
        try:
            key = UUID(idempotency_key)
            payload = creation.payload(_dns_public_key(config))
        except ValueError:
            return PlainTextResponse("A request key is required", status_code=400)
        except cluster_nodes.FormProblem as problem:
            return _first_cluster_page(
                request,
                step,
                form=form,
                block=block,
                host=host,
                problem=str(problem),
                status_code=400,
            )
        return _queue_node_job(
            config,
            request,
            gate,
            creation.cluster,
            payload,
            key,
            None,
            lambda problem: _first_cluster_page(
                request, step, form=form, block=block, host=host, problem=problem, status_code=409
            ),
            operation="cluster_define",
            back="/first-cluster",
        )

    @router.post("/first-cluster/second-node", response_class=HTMLResponse)
    def first_cluster_second_node(
        request: Request,
        cluster: str = Form(default="", max_length=64),
        block: str = Form(default="", max_length=8192),
        host: str = Form(default="", max_length=253),
        confirm: str = Form(default="", max_length=64),
        idempotency_key: str = Form(default="", max_length=64),
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        """Step 3: the second node, as *Add node* adds one."""

        gate = _first_cluster_gate(request, csrf_token)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        if cluster not in listed_clusters(request, config):
            return PlainTextResponse("Not found", status_code=404)
        reading = _status_row(config, request, cluster)
        step = first_cluster.Guide(step=3, cluster=cluster, joined=first_cluster.joined(reading))
        try:
            addition = cluster_nodes.read_addition(
                block,
                cluster=cluster,
                host=host.strip(),
                count=len(cluster_nodes.node_rows(reading)),
            )
        except cluster_nodes.FormProblem as problem:
            return _first_cluster_page(
                request, step, block=block, host=host, problem=str(problem), status_code=400
            )
        if confirm.strip() != addition.name:
            return _first_cluster_page(request, step, block=block, host=host, preview=addition)
        try:
            key = UUID(idempotency_key)
        except ValueError:
            return PlainTextResponse("A request key is required", status_code=400)
        try:
            stored, join_key = cluster_nodes.sealed_block(
                addition.block, cluster=cluster, public_key=_dns_public_key(config)
            )
        except cluster_nodes.FormProblem as problem:
            return _first_cluster_page(
                request, step, block=block, host=host, problem=str(problem), status_code=400
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
            lambda problem: _first_cluster_page(
                request, step, block=block, host=host, problem=problem, status_code=409
            ),
            back="/first-cluster",
        )

    @router.get("/first-cluster", response_class=HTMLResponse)
    def first_cluster_guide(request: Request) -> Response:
        """The guide's page (B328): its step, or the dashboard when it has none."""

        session = current_session(request)
        if session is None:
            return RedirectResponse("/login", status_code=303)
        _, status_rows = read_source(request, config, STATUS_SOURCE)
        _, network_rows = read_source(request, config, NETWORK_SOURCE)
        with request.app.state.pool.connection() as connection:
            recent = db.recent_jobs(connection)
        guide = _first_cluster(
            config,
            request,
            session,
            recent=recent,
            busy=jobs.in_flight(recent),
            status_rows=status_rows,
            network_readings=network_rows,
        )
        if guide is None:
            return RedirectResponse("/", status_code=303)
        return _first_cluster_page(request, guide)

    @router.get("/first-cluster/{name}")
    def first_cluster_node_package(request: Request, name: str) -> Response:
        """The node package the CLI release carries, under its versioned name, for the guide."""

        gate = admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        if name != first_cluster.node_package_name() or not first_cluster.NODE_PACKAGE.is_file():
            return PlainTextResponse("Not found", status_code=404)
        return FileResponse(
            first_cluster.NODE_PACKAGE,
            media_type="application/vnd.debian.binary-package",
            filename=name,
        )

    return router
