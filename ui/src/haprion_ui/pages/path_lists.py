"""*Settings → Path lists*: a list's form, its removal, and *Add to proxies* (B527, B532).

The card itself is drawn by the Settings page; these are the pages it links
to. Saving and removing go through `path_list_form`, which `haprion-path-lists`
shares.
"""

from __future__ import annotations

from functools import partial
from time import monotonic, sleep
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Form, Request, Response
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse

from haprion_ui import auth, db, finished_change, jobs, path_list_form
from haprion_ui.access import admin_write_gate, forbidden_page
from haprion_ui.blocklist_form import unread_sentence
from haprion_ui.config import Config
from haprion_ui.db import AuthenticatedSession
from haprion_ui.editor_flow import editor_state
from haprion_ui.reading import listed_clusters
from haprion_ui.refusals import refusal_page
from haprion_ui.templates import TEMPLATES
from haprion_ui.views import posted_form

#
# How long a save waits for its apply job before Settings is drawn, as a
# blocklist's does: one helper call. In seconds.
#
APPLY_WAIT = 6.0
CARD = path_list_form.CARD


def build_router(config: Config) -> APIRouter:
    router = APIRouter()

    def _existing(request: Request, name: str) -> db.PathList | None:
        with request.app.state.pool.connection() as connection:
            return db.path_list(connection, name)

    def _context(request: Request, gate: AuthenticatedSession) -> dict[str, object]:
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        with request.app.state.pool.connection() as connection:
            recent = db.recent_jobs(connection)
        return {
            "username": gate.username,
            "role": gate.role,
            "csrf_token": auth.csrf_token(token),
            "section": "settings",
            "management_writes": config.management_writes,
            "certificate_job": jobs.certificate_in_flight(recent, writes=config.management_writes),
        }

    def _page(
        request: Request,
        gate: AuthenticatedSession,
        form: path_list_form.Form,
        *,
        existing: db.PathList | None,
        problem: str = "",
        status_code: int = 200,
    ) -> Response:
        return TEMPLATES.TemplateResponse(
            request,
            "path-list-form.html",
            {
                **_context(request, gate),
                "form": form,
                "existing": existing,
                "problem": problem,
            },
            status_code=status_code,
        )

    def _await(request: Request, job_id: int) -> None:
        deadline = monotonic() + APPLY_WAIT
        while monotonic() < deadline:
            sleep(0.25)
            with request.app.state.pool.connection() as connection:
                state = db.job_state(connection, job_id)
            if state not in {"pending", "running"}:
                return

    @router.get("/settings/path-lists/new", response_class=HTMLResponse)
    def path_list_new(request: Request) -> Response:
        gate = admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        return _page(request, gate, path_list_form.EMPTY, existing=None)

    @router.get("/settings/path-lists/{name}/edit", response_class=HTMLResponse)
    def path_list_edit(request: Request, name: str) -> Response:
        gate = admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        existing = _existing(request, name)
        if existing is None:
            return PlainTextResponse("Not found", status_code=404)
        return _page(request, gate, path_list_form.from_row(existing), existing=existing)

    def _posted(request: Request) -> dict[str, str] | None:
        """The form's text fields, or None when the CSRF token does not match."""

        posted = posted_form(request)
        text = {key: value for key, value in posted.items() if isinstance(value, str)}
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, text.get(auth.CSRF_FIELD, "")):
            return None
        return text

    @router.post("/settings/path-lists/new", response_class=HTMLResponse)
    def path_list_create(request: Request) -> Response:
        gate = admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        text = _posted(request)
        if text is None:
            return forbidden_page(request, config)
        return _submit(request, gate, text, existing=None)

    @router.post("/settings/path-lists/{name}/edit", response_class=HTMLResponse)
    def path_list_save(request: Request, name: str) -> Response:
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
        existing: db.PathList | None,
    ) -> Response:
        form = path_list_form.from_posted(text, existing)
        try:
            key = UUID(text.get("idempotency_key", ""))
        except ValueError:
            return PlainTextResponse("A request key is required", status_code=400)
        try:
            item = path_list_form.checked(form)
        except path_list_form.FormProblem as problem:
            return _page(
                request, gate, form, existing=existing, problem=str(problem), status_code=400
            )
        with request.app.state.pool.connection() as connection:
            if db.job_for_key(connection, key, operation=path_list_form.OPERATION, cluster=None):
                return RedirectResponse(CARD, status_code=303)
            try:
                job = path_list_form.save(
                    connection, item, existing=existing, actor=gate.username, key=key
                )
            except path_list_form.FormProblem as problem:
                refused = str(problem)
            else:
                refused = ""
        if refused:
            return _page(request, gate, form, existing=existing, problem=refused, status_code=409)
        _await(request, job.id)
        return RedirectResponse(CARD, status_code=303)

    def _remove_page(
        request: Request,
        gate: AuthenticatedSession,
        existing: db.PathList,
        *,
        used: dict[str, tuple[str, ...]],
        problem: str = "",
        status_code: int = 200,
    ) -> Response:
        return TEMPLATES.TemplateResponse(
            request,
            "path-list-remove.html",
            {
                **_context(request, gate),
                "path_list": existing,
                "in_use": path_list_form.in_use_sentence(existing.name, used) if used else "",
                "problem": problem,
            },
            status_code=status_code,
        )

    @router.get("/settings/path-lists/{name}/remove", response_class=HTMLResponse)
    def path_list_remove_form(request: Request, name: str) -> Response:
        gate = admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        with request.app.state.pool.connection() as connection:
            existing = db.path_list(connection, name)
            if existing is None:
                return PlainTextResponse("Not found", status_code=404)
            used = path_list_form.users(connection, name)
            unread = "" if used else unread_sentence(connection)
        return _remove_page(request, gate, existing, used=used, problem=unread)

    @router.post("/settings/path-lists/{name}/remove")
    def path_list_remove(
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
            existing = db.path_list(connection, name)
            if existing is None:
                return PlainTextResponse("Not found", status_code=404)
            if db.job_for_key(connection, key, operation=path_list_form.OPERATION, cluster=None):
                return RedirectResponse(CARD, status_code=303)
            try:
                job = path_list_form.remove(connection, existing, actor=gate.username, key=key)
            except path_list_form.FormProblem as problem:
                refused = str(problem)
                used = path_list_form.users(connection, name)
            else:
                refused = ""
        if refused:
            return _remove_page(
                request, gate, existing, used=used, problem=refused, status_code=409
            )
        _await(request, job.id)
        return RedirectResponse(CARD, status_code=303)

    @router.post("/settings/path-lists/{name}/apply-again")
    def path_list_apply_again(
        request: Request, name: str, csrf_token: Annotated[str, Form(max_length=128)]
    ) -> Response:
        """The stored revision applied again: a row root's file does not match (review 26-11-24, PW02)."""

        gate = admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return forbidden_page(request, config)
        with request.app.state.pool.connection() as connection:
            existing = db.path_list(connection, name)
            if existing is None:
                return PlainTextResponse("Not found", status_code=404)
            try:
                job = path_list_form.apply_again(
                    connection, existing, actor=gate.username, via="web"
                )
            except path_list_form.FormProblem as problem:
                refused = str(problem)
            else:
                refused = ""
        if refused:
            return refusal_page(request, config, refused, back=CARD, status_code=409)
        _await(request, job.id)
        return RedirectResponse(CARD, status_code=303)

    @router.post("/settings/path-lists/{name}/take-in")
    def path_list_take_in(
        request: Request, name: str, csrf_token: Annotated[str, Form(max_length=128)]
    ) -> Response:
        """A list only the manager's file has, made a row as the file says it (review 26-11-24, PW02)."""

        gate = admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return forbidden_page(request, config)
        with request.app.state.pool.connection() as connection:
            entry = next(
                (
                    candidate
                    for candidate in db.list_files(connection, path_list_form.KIND)
                    if candidate.name == name
                ),
                None,
            )
            if entry is None:
                return PlainTextResponse("Not found", status_code=404)
            try:
                path_list_form.take_in(connection, entry, actor=gate.username)
            except path_list_form.FormProblem as problem:
                refused = str(problem)
            else:
                refused = ""
        if refused:
            return refusal_page(request, config, refused, back=CARD, status_code=409)
        return RedirectResponse(CARD, status_code=303)

    def _add_page(
        request: Request,
        gate: AuthenticatedSession,
        name: str,
        *,
        chosen: tuple[str, ...] = (),
        problem: str = "",
        status_code: int = 200,
    ) -> Response:
        with request.app.state.pool.connection() as connection:
            reach = path_list_form.reach(connection, name)
        return TEMPLATES.TemplateResponse(
            request,
            "path-list-add.html",
            {
                **_context(request, gate),
                "name": name,
                "clusters": [
                    (cluster, reach.get(cluster)) for cluster in listed_clusters(request, config)
                ],
                "chosen": chosen,
                "problem": problem,
            },
            status_code=status_code,
        )

    @router.get("/settings/path-lists/{name}/add-to-proxies", response_class=HTMLResponse)
    def path_list_add_form(request: Request, name: str) -> Response:
        gate = admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        if _existing(request, name) is None:
            return PlainTextResponse("Not found", status_code=404)
        return _add_page(request, gate, name)

    @router.post("/settings/path-lists/{name}/add-to-proxies", response_class=HTMLResponse)
    def path_list_add_to_proxies(
        request: Request,
        name: str,
        csrf_token: Annotated[str, Form(max_length=128)],
        clusters: Annotated[list[str] | None, Form(max_length=64)] = None,
    ) -> Response:
        """The list under *Denied paths* in each proxy of the chosen clusters, as saved changes.

        In `log only` where the proxy had no denied paths (B527): what the list
        would refuse shows on the traffic page first. Saved, not published, as
        an edit is; an object with a draft is left as it is.
        """

        gate = admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return forbidden_page(request, config)
        if _existing(request, name) is None:
            return PlainTextResponse("Not found", status_code=404)
        listed = listed_clusters(request, config)
        chosen = tuple(cluster for cluster in listed if cluster in set(clusters or ()))
        if not chosen:
            return _add_page(
                request, gate, name, problem="Choose at least one cluster.", status_code=400
            )
        results: list[path_list_form.Added] = []
        for cluster in chosen:
            state = editor_state(request, config, cluster)
            added: list[str] = []
            already: list[str] = []
            skipped: list[tuple[str, str]] = []
            for view in state.stored:
                if view.protocol not in path_list_form.DENIED_PROTOCOLS:
                    continue
                applied = finished_change.apply(
                    request,
                    gate,
                    state,
                    name=view.name,
                    change=partial(path_list_form.with_list, name, view.name),
                    detail={"path_list_added": name},
                )
                if applied.problem:
                    skipped.append((view.name, applied.problem))
                elif applied.changed:
                    added.append(view.name)
                else:
                    already.append(view.name)
            results.append(
                path_list_form.Added(cluster, tuple(added), tuple(already), tuple(skipped))
            )
        return TEMPLATES.TemplateResponse(
            request,
            "path-list-added.html",
            {**_context(request, gate), "name": name, "results": results},
        )

    return router
