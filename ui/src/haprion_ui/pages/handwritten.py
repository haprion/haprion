"""The files changed by hand in core/ and manual/, and the button that publishes them (B529)."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID, uuid4

from fastapi import APIRouter, Form, Request, Response
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from haprion.version_history import comment_problem

from haprion_ui import auth, db, handwritten, history, jobs, operations
from haprion_ui.access import admin_write_gate, current_session, forbidden_page
from haprion_ui.config import Config
from haprion_ui.db import AuthenticatedSession
from haprion_ui.pending import handwritten_payload, publish_key
from haprion_ui.reading import HANDWRITTEN_SOURCE, HISTORY_SOURCE, listed_clusters, read_source
from haprion_ui.refusals import refusal_page
from haprion_ui.templates import TEMPLATES


def build_router(config: Config) -> APIRouter:
    router = APIRouter()

    def history_view(request: Request, cluster: str) -> history.HistoryClusterView | None:
        clusters, history_rows = read_source(request, config, HISTORY_SOURCE, cluster=cluster)
        overview = history.build_history_overview(
            clusters, history_rows, stale_after=config.poller.stale_after
        )
        return next((view for view in overview.clusters if view.cluster == cluster), None)

    def view_of(request: Request, cluster: str) -> handwritten.Handwritten:
        _, rows = read_source(request, config, HANDWRITTEN_SOURCE, cluster=cluster)
        return handwritten.build(cluster, next(iter(rows), None))

    @router.get("/history/{cluster}/handwritten", response_class=HTMLResponse)
    def handwritten_page(request: Request, cluster: str) -> Response:
        session = current_session(request)
        if session is None:
            return RedirectResponse("/login", status_code=303)
        if cluster not in listed_clusters(request, config):
            return HTMLResponse("Not found", status_code=404)
        view = view_of(request, cluster)
        versions = history_view(request, cluster)
        with request.app.state.pool.connection() as connection:
            running = jobs.in_flight(db.recent_jobs(connection), writes=config.management_writes)
        return TEMPLATES.TemplateResponse(
            request,
            "handwritten.html",
            {
                "username": session.username,
                "role": session.role,
                "management_writes": config.management_writes,
                "csrf_token": auth.csrf_token(request.cookies.get(auth.SESSION_COOKIE, "")),
                "section": "history",
                "view": view,
                #
                # The reading was made on the newest version; until the
                # poller reads again after a publish, the page waits.
                #
                "current": versions is not None and versions.head_commit == view.head,
                "ahead": versions.unpublished if versions is not None else 0,
                "running": running.get(cluster),
                "demo_fixture": config.demo_fixture,
            },
        )

    @router.post("/history/{cluster}/handwritten", response_class=HTMLResponse)
    def publish_handwritten(
        request: Request,
        cluster: str,
        expected_head: Annotated[str, Form(max_length=64)] = "",
        fingerprint: Annotated[str, Form(max_length=64)] = "",
        comment: Annotated[str, Form(max_length=4096)] = "",
        csrf_token: Annotated[str, Form(max_length=128)] = "",
        idempotency_key: Annotated[str, Form(max_length=64)] = "",
    ) -> Response:
        """Publish the files changed by hand, and deploy them (*Publish & deploy*).

        Only what the page showed: the reading it was drawn from (`fingerprint`)
        and the version it was made on (`expected_head`) must still be the ones
        held, or the page is shown again. The helper reads the files once more
        and refuses them if they changed since.
        """

        gate = admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return forbidden_page(request, config)
        if cluster not in listed_clusters(request, config):
            return PlainTextResponse("Not found", status_code=404)
        back = f"/history/{cluster}/handwritten"
        view = view_of(request, cluster)
        if view.state != "pending":
            return refusal_page(
                request, config, "Nothing changed by hand waits to be published.", back=back
            )
        versions = history_view(request, cluster)
        head = versions.head_commit if versions is not None else ""
        if (
            not head
            or head != view.head
            or expected_head != head
            or fingerprint != view.fingerprint
        ):
            return refusal_page(
                request,
                config,
                "The page was drawn before something changed. Read it again before publishing.",
                back=back,
            )
        said = comment.strip()
        if not said:
            return refusal_page(
                request, config, "A comment is needed: it is the version's.", back=back
            )
        problem = comment_problem(said)
        if problem:
            return refusal_page(request, config, f"The comment {problem}.", back=back)
        payload = handwritten_payload(
            expected_head=head,
            fingerprint=view.fingerprint,
            comment=said,
            requested_by=gate.username,
            deploy=True,
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
                detail={
                    "operation": "changes_publish",
                    "job": job.id,
                    "handwritten": [path for path, _kind in view.files],
                },
            )
            connection.commit()
        return RedirectResponse("/", status_code=303)

    return router
