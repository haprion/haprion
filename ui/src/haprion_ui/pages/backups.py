"""The backup pages: the archives a cluster keeps, and restoring a node from one."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from fastapi import APIRouter, Form, Request, Response
from fastapi.responses import (
    HTMLResponse,
    PlainTextResponse,
    RedirectResponse,
)
from haprion import (
    backup_retention,
    backup_schedule,
)

from haprion_ui import (
    auth,
    backups,
    db,
    jobs,
    metrics,
    moments,
    node_restores,
    operations,
)
from haprion_ui.config import Config
from haprion_ui.db import AuthenticatedSession
from haprion_ui.views import (
    BACKUP_SOURCE,
    EXPIRED,
    TEMPLATES,
    _admin_write_gate,
    current_session,
    forbidden_page,
    read_source,
)


def build_router(config: Config) -> APIRouter:
    router = APIRouter()

    @router.get("/backups", response_class=HTMLResponse)
    def backup_overview(request: Request) -> Response:
        session = current_session(request)
        if session is None:
            return RedirectResponse("/login", status_code=303)
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        clusters, backup_rows = read_source(request, config, BACKUP_SOURCE)
        overview = backups.build_backup_overview(
            clusters,
            backup_rows,
            stale_after=config.poller.stale_after,
        )
        with request.app.state.pool.connection() as connection:
            running = jobs.in_flight(db.recent_jobs(connection))
            restore_rows = [
                job
                for operation in node_restores.OPERATIONS
                for job in db.operation_jobs(connection, operation, limit=100)
            ]
        return TEMPLATES.TemplateResponse(
            request,
            "backups.html",
            {
                "username": session.username,
                "role": session.role,
                "csrf_token": auth.csrf_token(token),
                "backups": overview,
                "in_flight": running,
                "restores": node_restores.recent_runs(
                    restore_rows, shown=metrics.shown, now=datetime.now(UTC)
                ),
                #
                # The zone the schedule form's time is read in: the manager's,
                # named so an operator on another clock is not left guessing -
                # the host's own, not the reader's `shown`.
                #
                "clock": datetime.now(UTC).astimezone().tzname() or "local time",
                "weekdays": tuple(
                    (day, backups.WEEKDAY_NAMES[day]) for day in backup_schedule.WEEKDAYS
                ),
                "day_of_month_max": backup_schedule.DAY_OF_MONTH_MAX,
                "archives_per_page": backups.ARCHIVES_PER_PAGE,
                "retention_bounds": (
                    backup_retention.RETENTION_MIN,
                    backup_retention.RETENTION_MAX,
                ),
                "section": "backups",
                "management_writes": config.management_writes,
                "demo_fixture": config.demo_fixture,
            },
        )

    # - Node restore (§15.2, B175) -----------------------------------------

    def _backup_cluster(request: Request, cluster: str) -> backups.BackupClusterView | None:
        clusters, backup_rows = read_source(request, config, BACKUP_SOURCE)
        overview = backups.build_backup_overview(
            clusters,
            backup_rows,
            stale_after=config.poller.stale_after,
        )
        return next((view for view in overview.clusters if view.cluster == cluster), None)

    def _restore_form_page(
        request: Request,
        session: AuthenticatedSession,
        *,
        cluster: str,
        node: str,
        archive: str,
        problem: str = "",
        form: Mapping[str, str] | None = None,
    ) -> Response:
        view = _backup_cluster(request, cluster)
        chosen = next(
            (
                item
                for item in (view.archives if view else ())
                if item.node == node and item.version == archive
            ),
            None,
        )
        if chosen is None:
            return PlainTextResponse("Not found", status_code=404)
        entered = {
            "target": "",
            "mode": "new_vm",
            "test_hostname": "",
            "test_address": "",
            "test_vip": "",
        }
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        with request.app.state.pool.connection() as connection:
            running = jobs.in_flight(db.recent_jobs(connection, cluster=cluster))
            if not form:
                # The node's own address: right for a repair, overwritten for a new VM.
                entered["target"] = node_restores.node_address(
                    db.cluster_statuses(connection), cluster, node
                )
        if form:
            entered.update(form)
        return TEMPLATES.TemplateResponse(
            request,
            "node-restore-new.html",
            {
                "username": session.username,
                "role": session.role,
                "csrf_token": auth.csrf_token(token),
                "cluster": cluster,
                "node": node,
                "archive": chosen,
                "form": entered,
                "problem": problem,
                "running": running.get(cluster),
                "section": "backups",
                "management_writes": config.management_writes,
                "demo_fixture": config.demo_fixture,
            },
        )

    def _restore_page(
        request: Request, session: AuthenticatedSession, run: str, *, problem: str = ""
    ) -> Response:
        if not node_restores.usable_run(run):
            return PlainTextResponse("Not found", status_code=404)
        with request.app.state.pool.connection() as connection:
            restore = node_restores.run_view(
                run, db.restore_jobs(connection, run), now=datetime.now(UTC)
            )
        if restore is None:
            return PlainTextResponse("Not found", status_code=404)
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        return TEMPLATES.TemplateResponse(
            request,
            "node-restore.html",
            {
                "username": session.username,
                "role": session.role,
                "csrf_token": auth.csrf_token(token),
                "restore": restore,
                "steps": node_restores.step_states(restore),
                "expires": moments.time_of_day(restore.expires_at) if restore.expires_at else "",
                "problem": problem,
                "editable": config.management_writes and session.role == "admin",
                "section": "backups",
                "management_writes": config.management_writes,
                "demo_fixture": config.demo_fixture,
            },
        )

    def _queue_restore_job(
        request: Request,
        session: AuthenticatedSession,
        *,
        operation: str,
        cluster: str,
        payload: Mapping[str, Any],
        key: UUID,
        again: Callable[[str], Response],
        to_backups: bool = False,
    ) -> Response:
        """Queue one restore job and go to the run's page, or say why not.

        `to_backups` goes back to the backup page instead: a run discarded from
        its line there is gone from the list, and that is the answer.
        """

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
                # A run's ID is drawn on every submission, so a second click is
                # other bytes under the same key (review 26-10-24, 02-06); its
                # answer is the run the first click queued.
                #
                earlier = db.job_for_key(connection, key, operation=operation, cluster=cluster)
                if earlier is None:
                    if isinstance(refused, db.RequestConflict):
                        raise refused
                    return again(
                        f"A job is already running for {cluster}. Wait for it to finish, then ask again."
                    )
                job = earlier
            else:
                #
                # The run, node and archive, never the fingerprint or the pasted
                # line: the audit log says who restored what, not how it was reached.
                #
                db.record_audit_event(
                    connection,
                    actor=session.username,
                    action="queue_job",
                    cluster=cluster,
                    request_id=job.request_id,
                    detail={"operation": operation, "job": job.id, "run": payload["run"]},
                )
                connection.commit()
        #
        # To the run as the queue stored it, and only when it is still a run
        # ID: the row the insert returned, not the value this request carried.
        #
        stored = job.payload.get("run")
        if to_backups:
            return RedirectResponse("/backups", status_code=303)
        if isinstance(stored, str) and node_restores.usable_run(stored):
            return RedirectResponse("/backups/restore/" + stored, status_code=303)
        return RedirectResponse("/jobs", status_code=303)

    @router.get("/backups/restore/new", response_class=HTMLResponse)
    def node_restore_form(
        request: Request, cluster: str = "", node: str = "", archive: str = ""
    ) -> Response:
        """Start a restore from one archive row: the target and the mode."""

        gate = _admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        return _restore_form_page(request, gate, cluster=cluster, node=node, archive=archive)

    @router.post("/backups/restore/new", response_class=HTMLResponse)
    def node_restore_prepare(
        request: Request,
        cluster: str = Form(default="", max_length=64),
        node: str = Form(default="", max_length=253),
        archive: str = Form(default="", max_length=32),
        target: str = Form(default="", max_length=64),
        mode: str = Form(default="", max_length=16),
        test_hostname: str = Form(default="", max_length=64),
        test_address: str = Form(default="", max_length=64),
        test_vip: str = Form(default="", max_length=64),
        idempotency_key: str = Form(default="", max_length=64),
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        """Queue `node_restore_prepare` under a new run ID, then show the run."""

        gate = _admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return forbidden_page(request, config)
        try:
            key = UUID(idempotency_key)
        except ValueError:
            return PlainTextResponse("A request key is required", status_code=400)
        entered = {
            "target": target,
            "mode": mode,
            "test_hostname": test_hostname,
            "test_address": test_address,
            "test_vip": test_vip,
        }

        def again(problem: str) -> Response:
            return _restore_form_page(
                request,
                gate,
                cluster=cluster,
                node=node,
                archive=archive,
                problem=problem,
                form=entered,
            )

        view = _backup_cluster(request, cluster)
        try:
            payload = node_restores.prepare_payload(
                run=node_restores.new_run_id(),
                node=node,
                archive=archive,
                target=target,
                mode=mode,
                test_hostname=test_hostname,
                test_address=test_address,
                test_vip=test_vip,
                archives=((item.node, item.version) for item in (view.archives if view else ())),
            )
        except node_restores.RestoreProblem as refused:
            return again(str(refused))
        return _queue_restore_job(
            request,
            gate,
            operation="node_restore_prepare",
            cluster=cluster,
            payload=payload,
            key=key,
            again=again,
        )

    @router.get("/backups/restore/{run}", response_class=HTMLResponse)
    def node_restore_page(request: Request, run: str) -> Response:
        """One restore run, drawn from its jobs."""

        session = current_session(request)
        if session is None:
            return RedirectResponse("/login", status_code=303)
        return _restore_page(request, session, run)

    def _restore_step(
        request: Request, run: str, csrf_token: str, idempotency_key: str
    ) -> tuple[AuthenticatedSession, node_restores.RestoreRun, UUID] | Response:
        gate = _admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return forbidden_page(request, config)
        try:
            key = UUID(idempotency_key)
        except ValueError:
            return PlainTextResponse("A request key is required", status_code=400)
        if not node_restores.usable_run(run):
            return PlainTextResponse("Not found", status_code=404)
        with request.app.state.pool.connection() as connection:
            restore = node_restores.run_view(
                run, db.restore_jobs(connection, run), now=datetime.now(UTC)
            )
        if restore is None:
            return PlainTextResponse("Not found", status_code=404)
        return gate, restore, key

    @router.post("/backups/restore/{run}/preview", response_class=HTMLResponse)
    def node_restore_preview(
        request: Request,
        run: str,
        fingerprint: str = Form(default="", max_length=512),
        idempotency_key: str = Form(default="", max_length=64),
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        """Queue `node_restore_preview` with the fingerprint read on the console."""

        step = _restore_step(request, run, csrf_token, idempotency_key)
        if isinstance(step, Response):
            return step
        session, restore, key = step

        def again(problem: str) -> Response:
            return _restore_page(request, session, run, problem=problem)

        if restore.stage == "expired":
            return again(EXPIRED)
        if restore.stage != "fingerprint":
            return again("This run is not waiting for a fingerprint.")
        try:
            payload = node_restores.preview_payload(run, fingerprint)
        except node_restores.RestoreProblem as refused:
            return again(str(refused))
        return _queue_restore_job(
            request,
            session,
            operation="node_restore_preview",
            cluster=restore.cluster,
            payload=payload,
            key=key,
            again=again,
        )

    @router.post("/backups/restore/{run}/run", response_class=HTMLResponse)
    def node_restore_run(
        request: Request,
        run: str,
        confirm: str = Form(default="", max_length=128),
        backup_failed_ok: str = Form(default="", max_length=8),
        break_traffic: str = Form(default="", max_length=8),
        idempotency_key: str = Form(default="", max_length=64),
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        """Queue `node_restore` once the node's name has been typed.

        An overwrite also takes the ticks for going on without a backup or
        breaking live traffic, when its preview showed either (B172).
        """

        step = _restore_step(request, run, csrf_token, idempotency_key)
        if isinstance(step, Response):
            return step
        session, restore, key = step

        def again(problem: str) -> Response:
            return _restore_page(request, session, run, problem=problem)

        if restore.stage == "expired":
            return again(EXPIRED)
        if restore.stage != "confirm":
            return again("This run has no preview waiting for confirmation.")
        try:
            payload = node_restores.run_payload(
                run,
                confirm,
                restore.confirm_name,
                overwrite=restore.mode == "overwrite",
                backup_failed_ok=backup_failed_ok == "yes",
                break_traffic=break_traffic == "yes",
            )
        except node_restores.RestoreProblem as refused:
            return again(str(refused))
        return _queue_restore_job(
            request,
            session,
            operation="node_restore",
            cluster=restore.cluster,
            payload=payload,
            key=key,
            again=again,
        )

    @router.post("/backups/restore/{run}/discard", response_class=HTMLResponse)
    def node_restore_discard(
        request: Request,
        run: str,
        return_to: str = Form(default="", max_length=16),
        idempotency_key: str = Form(default="", max_length=64),
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        """Queue `node_restore_discard`: the run is given up and its key removed (B182)."""

        step = _restore_step(request, run, csrf_token, idempotency_key)
        if isinstance(step, Response):
            return step
        session, restore, key = step

        def again(problem: str) -> Response:
            return _restore_page(request, session, run, problem=problem)

        if not restore.discardable:
            return again("This run cannot be discarded now.")
        try:
            payload = node_restores.discard_payload(run)
        except node_restores.RestoreProblem as refused:
            return again(str(refused))
        return _queue_restore_job(
            request,
            session,
            operation="node_restore_discard",
            cluster=restore.cluster,
            payload=payload,
            key=key,
            again=again,
            to_backups=return_to == "backups",
        )

    @router.post("/backups/restore/{run}/status", response_class=HTMLResponse)
    def node_restore_status(
        request: Request,
        run: str,
        idempotency_key: str = Form(default="", max_length=64),
        csrf_token: str = Form(default="", alias=auth.CSRF_FIELD),
    ) -> Response:
        """Queue `node_restore_status`: ask how a run whose job lost its answer ended."""

        step = _restore_step(request, run, csrf_token, idempotency_key)
        if isinstance(step, Response):
            return step
        session, restore, key = step

        def again(problem: str) -> Response:
            return _restore_page(request, session, run, problem=problem)

        if not restore.askable:
            return again("This run's outcome is already known.")
        try:
            payload = node_restores.status_payload(run)
        except node_restores.RestoreProblem as refused:
            return again(str(refused))
        return _queue_restore_job(
            request,
            session,
            operation="node_restore_status",
            cluster=restore.cluster,
            payload=payload,
            key=key,
            again=again,
        )

    return router
