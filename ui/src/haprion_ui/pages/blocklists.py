"""*Settings → Blocklists*: a list's form, its Test, and its removal (B496, 13; B500).

The card itself is drawn by the Settings page; these are the pages it links
to. Saving and removing go through `blocklist_form`, which `haprion-blocklists`
shares. *Test* asks the blocklist check helper to fetch the list as the form
holds it and keeps nothing; a script asks it without leaving the page, so a
typed password stays in its field, and without script the form is drawn again
with the answer and without the password.
"""

from __future__ import annotations

from functools import partial
from time import monotonic, sleep
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Form, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from haprion import blocklist_check_socket
from haprion.blocklist_check import CheckError

from haprion_ui import auth, blocklist_form, db, finished_change, jobs
from haprion_ui.access import admin_write_gate, forbidden_page
from haprion_ui.config import Config
from haprion_ui.db import AuthenticatedSession
from haprion_ui.editor_flow import editor_state
from haprion_ui.reading import listed_clusters
from haprion_ui.refusals import refusal_page
from haprion_ui.templates import TEMPLATES
from haprion_ui.views import posted_form, read_dns_public_key

#
# How long a save waits for its apply job before Settings is drawn: the job
# is one helper call, done within a second when the queue is idle, as a DNS
# profile's is. In seconds.
#
APPLY_WAIT = 6.0
CARD = "/settings#blocklists"


def build_router(config: Config) -> APIRouter:
    router = APIRouter()

    def _existing(request: Request, name: str) -> db.Blocklist | None:
        with request.app.state.pool.connection() as connection:
            return db.blocklist(connection, name)

    def _page(
        request: Request,
        gate: AuthenticatedSession,
        form: blocklist_form.Form,
        *,
        existing: db.Blocklist | None,
        problem: str = "",
        tested: tuple[str, str] | None = None,
        status_code: int = 200,
    ) -> Response:
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        with request.app.state.pool.connection() as connection:
            recent = db.recent_jobs(connection)
        return TEMPLATES.TemplateResponse(
            request,
            "blocklist-form.html",
            {
                "username": gate.username,
                "role": gate.role,
                "csrf_token": auth.csrf_token(token),
                "section": "settings",
                "management_writes": config.management_writes,
                "form": form,
                "existing": existing,
                "auth_labels": blocklist_form.AUTH_LABEL,
                "secret_labels": blocklist_form.SECRET_LABEL,
                "hours": (1, 6, 12, 24),
                "problem": problem,
                "tested": tested,
                "public_key": read_dns_public_key(config),
                "certificate_job": jobs.certificate_in_flight(
                    recent, writes=config.management_writes
                ),
            },
            status_code=status_code,
        )

    def _posted(request: Request) -> dict[str, str] | None:
        """The form's text fields, or None when the CSRF token does not match."""

        posted = posted_form(request)
        text = {key: value for key, value in posted.items() if isinstance(value, str)}
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, text.get(auth.CSRF_FIELD, "")):
            return None
        return text

    def _await(request: Request, job_id: int) -> None:
        deadline = monotonic() + APPLY_WAIT
        while monotonic() < deadline:
            sleep(0.25)
            with request.app.state.pool.connection() as connection:
                state = db.job_state(connection, job_id)
            if state not in {"pending", "running"}:
                return

    @router.get("/settings/blocklists/new", response_class=HTMLResponse)
    def blocklist_new(request: Request) -> Response:
        gate = admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        return _page(request, gate, blocklist_form.EMPTY, existing=None)

    @router.get("/settings/blocklists/{name}/edit", response_class=HTMLResponse)
    def blocklist_edit(request: Request, name: str) -> Response:
        gate = admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        existing = _existing(request, name)
        if existing is None:
            return PlainTextResponse("Not found", status_code=404)
        return _page(request, gate, blocklist_form.from_row(existing), existing=existing)

    @router.post("/settings/blocklists/new", response_class=HTMLResponse)
    def blocklist_create(request: Request) -> Response:
        gate = admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        text = _posted(request)
        if text is None:
            return forbidden_page(request, config)
        return _submit(request, gate, text, existing=None)

    @router.post("/settings/blocklists/{name}/edit", response_class=HTMLResponse)
    def blocklist_save(request: Request, name: str) -> Response:
        gate = admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        text = _posted(request)
        if text is None:
            return forbidden_page(request, config)
        existing = _existing(request, name)
        if existing is None:
            return PlainTextResponse("Not found", status_code=404)
        return _submit(request, gate, text, existing=existing)

    def _submit(
        request: Request,
        gate: AuthenticatedSession,
        text: dict[str, str],
        *,
        existing: db.Blocklist | None,
    ) -> Response:
        form = blocklist_form.from_posted(text, existing)
        if text.get("action") == "test":
            return _test(request, gate, form, existing=existing)
        try:
            key = UUID(text.get("idempotency_key", ""))
        except ValueError:
            return PlainTextResponse("A request key is required", status_code=400)

        def again(problem: str, status_code: int = 400) -> Response:
            return _page(
                request, gate, form, existing=existing, problem=problem, status_code=status_code
            )

        public_key = read_dns_public_key(config)
        if public_key is None:
            return again(
                "This installation has no DNS profile key, which seals a blocklist's password; "
                "see The DNS profile key pair in the user manual.",
                409,
            )
        try:
            definition = blocklist_form.checked(form)
            secret, keep = blocklist_form.secret_choice(form, existing)
        except blocklist_form.FormProblem as problem:
            return again(str(problem))
        with request.app.state.pool.connection() as connection:
            if db.job_for_key(connection, key, operation=blocklist_form.OPERATION, cluster=None):
                return RedirectResponse(CARD, status_code=303)
            try:
                job = blocklist_form.save(
                    connection,
                    definition,
                    existing=existing,
                    secret=secret,
                    keep=keep,
                    public_key=public_key,
                    actor=gate.username,
                    key=key,
                )
            except blocklist_form.FormProblem as problem:
                refused = str(problem)
            else:
                refused = ""
        if refused:
            return again(refused, 409)
        _await(request, job.id)
        return RedirectResponse(CARD, status_code=303)

    def _test(
        request: Request,
        gate: AuthenticatedSession,
        form: blocklist_form.Form,
        *,
        existing: db.Blocklist | None,
    ) -> Response:
        """Fetch the list as the form holds it; JSON for the page's script, the form otherwise."""

        wants_json = "application/json" in request.headers.get("accept", "")
        try:
            definition = blocklist_form.checked(form)
            secret, keep = blocklist_form.secret_choice(form, existing)
            tested = blocklist_check_socket.test(
                name=definition.name,
                url=definition.url,
                every_hours=definition.every_hours,
                authorization=definition.authorization,
                username=definition.username,
                excepts=definition.excepts,
                secret=secret,
                keep_secret=keep,
            )
        except (blocklist_form.FormProblem, CheckError) as problem:
            answer = ("critical", blocklist_form.sentence(problem))
        else:
            answer = (
                ("healthy", tested.sentence())
                if tested.answer == "fetched"
                else ("critical", tested.sentence())
            )
        if wants_json:
            return JSONResponse({"tone": answer[0], "answer": answer[1]})
        return _page(request, gate, form, existing=existing, tested=answer)

    @router.get("/settings/blocklists/{name}/remove", response_class=HTMLResponse)
    def blocklist_remove_form(request: Request, name: str) -> Response:
        gate = admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        with request.app.state.pool.connection() as connection:
            existing = db.blocklist(connection, name)
            if existing is None:
                return PlainTextResponse("Not found", status_code=404)
            used = blocklist_form.users(connection, name)
            recent = db.recent_jobs(connection)
        return _remove_page(request, gate, existing, used=used, recent=recent)

    def _remove_page(
        request: Request,
        gate: AuthenticatedSession,
        existing: db.Blocklist,
        *,
        used: dict[str, tuple[str, ...]],
        recent: Any,
        problem: str = "",
        status_code: int = 200,
    ) -> Response:
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        return TEMPLATES.TemplateResponse(
            request,
            "blocklist-remove.html",
            {
                "username": gate.username,
                "role": gate.role,
                "csrf_token": auth.csrf_token(token),
                "section": "settings",
                "management_writes": config.management_writes,
                "blocklist": existing,
                "in_use": blocklist_form.in_use_sentence(existing.name, used) if used else "",
                "problem": problem,
                "certificate_job": jobs.certificate_in_flight(
                    recent, writes=config.management_writes
                ),
            },
            status_code=status_code,
        )

    @router.post("/settings/blocklists/{name}/remove")
    def blocklist_remove(
        request: Request,
        name: str,
        csrf_token: Annotated[str, Form(max_length=128)],
        idempotency_key: Annotated[str, Form(max_length=64)],
    ) -> Response:
        gate = admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return forbidden_page(request, config)
        try:
            key = UUID(idempotency_key)
        except ValueError:
            return PlainTextResponse("A request key is required", status_code=400)
        with request.app.state.pool.connection() as connection:
            existing = db.blocklist(connection, name)
            if existing is None:
                return PlainTextResponse("Not found", status_code=404)
            if db.job_for_key(connection, key, operation=blocklist_form.OPERATION, cluster=None):
                return RedirectResponse(CARD, status_code=303)
            try:
                job = blocklist_form.remove(connection, existing, actor=gate.username, key=key)
            except blocklist_form.FormProblem as problem:
                refused = str(problem)
                used = blocklist_form.users(connection, name)
                recent = db.recent_jobs(connection)
            else:
                refused = ""
        if refused:
            return _remove_page(
                request, gate, existing, used=used, recent=recent, problem=refused, status_code=409
            )
        _await(request, job.id)
        return RedirectResponse(CARD, status_code=303)

    @router.post("/settings/blocklists/{name}/add-to-proxies", response_class=HTMLResponse)
    def blocklist_add_to_proxies(
        request: Request,
        name: str,
        csrf_token: Annotated[str, Form(max_length=128)],
    ) -> Response:
        """The list under Denied in every object HAProxy serves, as saved changes (B496, 13).

        Saved, not published: each cluster's changes go out with its next
        publish, as an edit's do. An object with a draft is left as it is.
        """

        gate = admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return forbidden_page(request, config)
        if _existing(request, name) is None:
            return PlainTextResponse("Not found", status_code=404)
        with request.app.state.pool.connection() as connection:
            fetched = blocklist_form.fetched_names(connection)
        if name not in fetched:
            return refusal_page(
                request,
                config,
                f"{name} has not been fetched yet. Add it to the proxies once it has been.",
                back=CARD,
                status_code=409,
            )
        results: list[blocklist_form.Added] = []
        for cluster in listed_clusters(request, config):
            state = editor_state(request, config, cluster)
            added: list[str] = []
            skipped: list[tuple[str, str]] = []
            for view in state.stored:
                if view.protocol not in blocklist_form.DENIED_PROTOCOLS:
                    continue
                problem = finished_change.save(
                    request,
                    gate,
                    state,
                    name=view.name,
                    change=partial(blocklist_form.with_list, name, view.name),
                    detail={"blocklist_added": name},
                )
                if problem:
                    skipped.append((view.name, problem))
                else:
                    added.append(view.name)
            results.append(blocklist_form.Added(cluster, tuple(added), tuple(skipped)))
        return TEMPLATES.TemplateResponse(
            request,
            "blocklist-added.html",
            {
                "username": gate.username,
                "role": gate.role,
                "csrf_token": auth.csrf_token(token),
                "section": "settings",
                "management_writes": config.management_writes,
                "name": name,
                "results": results,
            },
        )

    return router
