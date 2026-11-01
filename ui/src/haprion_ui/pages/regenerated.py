"""What publishing a cluster again would change, and the one button that publishes it (0.99.11)."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID, uuid4

from fastapi import APIRouter, Form, Request, Response
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse

from haprion_ui import auth, db, history, jobs, operations, regenerated
from haprion_ui.access import admin_write_gate, current_session, forbidden_page
from haprion_ui.config import Config
from haprion_ui.db import AuthenticatedSession
from haprion_ui.pending import pending_package, publish_key, regenerate_payload
from haprion_ui.reading import HISTORY_SOURCE, REGENERATION_SOURCE, listed_clusters, read_source
from haprion_ui.refusals import refusal_page
from haprion_ui.templates import TEMPLATES

#
# The version's comment: the page asks for none, and the version says what it is.
#
COMMENT = "Regenerated with the installed version."


def build_router(config: Config) -> APIRouter:
    router = APIRouter()

    def history_view(request: Request, cluster: str) -> history.HistoryClusterView | None:
        clusters, history_rows = read_source(request, config, HISTORY_SOURCE, cluster=cluster)
        overview = history.build_history_overview(
            clusters, history_rows, stale_after=config.poller.stale_after
        )
        return next((view for view in overview.clusters if view.cluster == cluster), None)

    @router.get("/history/{cluster}/regenerated", response_class=HTMLResponse)
    def regenerated_page(request: Request, cluster: str) -> Response:
        session = current_session(request)
        if session is None:
            return RedirectResponse("/login", status_code=303)
        if cluster not in listed_clusters(request, config):
            return HTMLResponse("Not found", status_code=404)
        _, rows = read_source(request, config, REGENERATION_SOURCE, cluster=cluster)
        view = regenerated.build(cluster, next(iter(rows), None))
        versions = history_view(request, cluster)
        with request.app.state.pool.connection() as connection:
            running = jobs.in_flight(db.recent_jobs(connection), writes=config.management_writes)
        return TEMPLATES.TemplateResponse(
            request,
            "regenerated.html",
            {
                "username": session.username,
                "role": session.role,
                "management_writes": config.management_writes,
                "csrf_token": auth.csrf_token(request.cookies.get(auth.SESSION_COOKIE, "")),
                "section": "history",
                "view": view,
                "head": versions.head_commit if versions is not None else "",
                #
                # The versions saved after the published one, which a publish
                # carries because it is made on the newest.
                #
                "ahead": versions.unpublished if versions is not None else 0,
                "running": running.get(cluster),
                #
                # Saved changes publish together, and that publish makes the
                # generated layer again too; this one would leave them stale.
                #
                "saved": len(pending_package(request, config, cluster).rows),
                "demo_fixture": config.demo_fixture,
            },
        )

    @router.post("/history/{cluster}/regenerated", response_class=HTMLResponse)
    def publish_regenerated(
        request: Request,
        cluster: str,
        expected_head: Annotated[str, Form(max_length=64)] = "",
        fingerprint: Annotated[str, Form(max_length=64)] = "",
        csrf_token: Annotated[str, Form(max_length=128)] = "",
        idempotency_key: Annotated[str, Form(max_length=64)] = "",
    ) -> Response:
        """Publish the generated layer made again, and deploy it (*Publish & deploy*).

        Only what the page showed: the answer it was drawn from (`fingerprint`)
        and the newest version it was made on (`expected_head`) must still be
        the ones held, or the page is shown again.
        """

        gate = admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return forbidden_page(request, config)
        if cluster not in listed_clusters(request, config):
            return PlainTextResponse("Not found", status_code=404)
        back = f"/history/{cluster}/regenerated"
        _, rows = read_source(request, config, REGENERATION_SOURCE, cluster=cluster)
        view = regenerated.build(cluster, next(iter(rows), None))
        if view.state != "changed":
            return refusal_page(
                request, config, "Publishing again would not change what runs.", back=back
            )
        if pending_package(request, config, cluster).rows:
            return refusal_page(
                request,
                config,
                "Changes are saved for this cluster. Publishing them also makes the "
                "configuration again with the installed version.",
                back=back,
            )
        versions = history_view(request, cluster)
        head = versions.head_commit if versions is not None else ""
        if not head or expected_head != head or fingerprint != view.fingerprint:
            return refusal_page(
                request,
                config,
                "The page was drawn before something changed. Read it again before publishing.",
                back=back,
            )
        payload = regenerate_payload(
            expected_head=head, comment=COMMENT, requested_by=gate.username, deploy=True
        )
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
                request, config, "This interface could not build a publish.", back=back
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
                detail={"operation": "changes_publish", "job": job.id, "regenerate": True},
            )
            connection.commit()
        return RedirectResponse("/", status_code=303)

    return router
