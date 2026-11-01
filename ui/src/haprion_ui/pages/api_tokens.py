"""Settings -> API tokens: who may call `/api/v1`, made, extended, revoked and removed here (B416).

The rules, the audit events and the sentences a refusal is made of are
`api_token_apply`'s, shared with `haprion-api-token`. What is the page's own is
the secret's one appearance: it is in the response to the form that made the
token, marked `no-store`, and nowhere else - not in a redirect, the audit
record or the log. The name is unique, so a form sent twice makes one token
and the second send is refused as taken.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Form, Request, Response
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse

from haprion_ui import api_token_apply, api_tokens, auth, db, demo, moments
from haprion_ui.access import admin_write_gate, forbidden_page, reading_gate
from haprion_ui.config import Config
from haprion_ui.db import AuthenticatedSession
from haprion_ui.reading import OBJECTS_SOURCE, read_source
from haprion_ui.templates import TEMPLATES

LIST = "/settings/api-tokens"
DAY_CHOICES = (30, 90, 180, 365, 730)
LEVEL_HELP = {
    "read": "Sees what a reader sees.",
    "block": "Blocks addresses on its proxies, nothing else.",
    "write": "Does what an admin does.",
}
TONES = {"active": "healthy", "revoked": "unknown", "expired": "critical"}


@dataclass(frozen=True, slots=True)
class TokenRow:
    name: str
    prefix: str
    level: str
    scope: str
    sources: str
    valid_until: str
    ending: bool
    ending_title: str
    last_used: str
    state: str
    tone: str


def token_rows(rows: list[db.ApiToken], now: datetime) -> list[TokenRow]:
    """The table's rows, by name; a date within the warning or past is marked."""

    shown: list[TokenRow] = []
    for token in sorted(rows, key=lambda row: row.name):
        state = api_token_apply.state(token, now)
        ending = api_token_apply.ending(token, now)
        shown.append(
            TokenRow(
                name=token.name,
                prefix=token.prefix,
                level=token.level.capitalize(),
                scope=api_token_apply.scope(token),
                sources=", ".join(token.sources) or "Anywhere",
                valid_until=moments.day(token.expires_at),
                ending=ending,
                ending_title="Has ended" if now >= token.expires_at else "Ends within 30 days",
                last_used=api_token_apply.last_used(token),
                state=state.capitalize(),
                tone=TONES[state],
            )
        )
    return shown


def build_router(config: Config) -> APIRouter:
    router = APIRouter()

    def context(request: Request, gate: AuthenticatedSession) -> dict[str, Any]:
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        return {
            "username": gate.username,
            "role": gate.role,
            "csrf_token": auth.csrf_token(token),
            "section": "settings",
            "management_writes": config.management_writes,
        }

    def stored(request: Request) -> list[db.ApiToken]:
        if config.demo_fixture:
            return list(demo.api_token_rows())
        with request.app.state.pool.connection() as connection:
            return db.api_tokens(connection)

    def choices(request: Request) -> tuple[tuple[str, ...], dict[str, tuple[str, ...]]]:
        """The clusters, and in each the objects a `block` token can name."""

        clusters, readings = read_source(request, config, OBJECTS_SOURCE)
        readings = list(readings)
        return clusters, {
            name: api_token_apply.blocking_objects(readings, name) for name in clusters
        }

    def list_page(
        request: Request, gate: AuthenticatedSession, *, problem: str = "", status_code: int = 200
    ) -> Response:
        return TEMPLATES.TemplateResponse(
            request,
            "settings-api-tokens.html",
            {
                **context(request, gate),
                "tokens": token_rows(stored(request), datetime.now(UTC)),
                "problem": problem,
            },
            status_code=status_code,
        )

    def form_page(
        request: Request,
        gate: AuthenticatedSession,
        *,
        problem: str = "",
        form: dict[str, Any] | None = None,
        status_code: int = 200,
    ) -> Response:
        clusters, blocking = choices(request)
        proxies: dict[str, list[str]] = {}
        for cluster in clusters:
            for item in blocking[cluster]:
                proxies.setdefault(item, []).append(cluster)
        entered = {
            "name": "",
            "level": "read",
            "days": api_tokens.DEFAULT_DAYS,
            "cluster_scope": "all",
            "clusters": [],
            "objects": [],
            "sources": "",
            **(form or {}),
        }
        #
        # A block token names the proxies it may block on (review 26-10-31,
        # P3-8): with none to choose, the level is shown closed, with why.
        #
        levels = dict(LEVEL_HELP)
        if entered["level"] == "block" and not proxies:
            entered["level"] = "read"
        return TEMPLATES.TemplateResponse(
            request,
            "settings-api-token-new.html",
            {
                **context(request, gate),
                "form": entered,
                "levels": levels,
                "day_choices": DAY_CHOICES,
                "clusters": clusters,
                "proxies": dict(sorted(proxies.items())),
                "problem": problem,
            },
            status_code=status_code,
        )

    @router.get(LIST, response_class=HTMLResponse)
    def tokens_page(request: Request) -> Response:
        gate = reading_gate(request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        return list_page(request, gate)

    @router.get(LIST + "/new", response_class=HTMLResponse)
    def new_token_page(request: Request) -> Response:
        gate = admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        return form_page(request, gate)

    @router.post(LIST + "/new", response_class=HTMLResponse)
    def create_token(
        request: Request,
        name: Annotated[str, Form(max_length=64)] = "",
        level: Annotated[str, Form(max_length=16)] = "",
        days: Annotated[str, Form(max_length=8)] = "",
        cluster_scope: Annotated[str, Form(max_length=16)] = "",
        clusters: Annotated[list[str] | None, Form()] = None,
        objects: Annotated[list[str] | None, Form()] = None,
        sources: Annotated[str, Form(max_length=4096)] = "",
        csrf_token: Annotated[str, Form(alias=auth.CSRF_FIELD, max_length=128)] = "",
    ) -> Response:
        gate = admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return forbidden_page(request, config)
        scope = (
            cluster_scope
            if cluster_scope in ("all", "chosen")
            else ("chosen" if clusters else "all")
        )
        entered: dict[str, Any] = {
            "name": name.strip(),
            "level": level,
            "days": days.strip(),
            #
            # "All clusters" is a token without a cluster list, which also
            # sees a cluster made later; boxes left ticked under it say nothing.
            # A post without the choice is read from the boxes.
            #
            "cluster_scope": scope,
            "clusters": list(dict.fromkeys(clusters or [])) if scope == "chosen" else [],
            "objects": list(dict.fromkeys(objects or [])),
            "sources": sources,
        }

        def again(problem: str, status_code: int = 400) -> Response:
            return form_page(request, gate, problem=problem, form=entered, status_code=status_code)

        if entered["cluster_scope"] == "chosen" and not entered["clusters"]:
            return again("Choose the clusters the token may see, or All clusters.")
        try:
            length = int(entered["days"])
        except ValueError:
            return again("The validity must be a number of days.")
        new = api_token_apply.NewToken(
            name=entered["name"],
            level=level,
            clusters=tuple(entered["clusters"]),
            objects=tuple(entered["objects"]),
            sources=api_token_apply.sources_from_text(sources),
            days=length,
        )
        known, blocking = choices(request)
        if text := api_token_apply.problem(new, clusters=known, blocking=blocking):
            return again(text)
        refusal: str | None = None
        with request.app.state.pool.connection() as connection:
            try:
                made, secret = api_token_apply.issue(
                    connection, new, actor=gate.username, via="web"
                )
            except api_token_apply.Refused as refused:
                connection.rollback()
                refusal = str(refused)
            else:
                connection.commit()
                refusal = None
        # The form reads again, so it is drawn after the connection is given back.
        if refusal is not None:
            return again(refusal, 409)
        return TEMPLATES.TemplateResponse(
            request,
            "settings-api-token-created.html",
            {**context(request, gate), "name": made.name, "secret": secret},
            headers={"Cache-Control": "no-store"},
        )

    def found(request: Request, name: str) -> db.ApiToken | None:
        return next((row for row in stored(request) if row.name == name), None)

    @router.get(LIST + "/{name}/revoke", response_class=HTMLResponse)
    def revoke_page(request: Request, name: str) -> Response:
        """The question before a token is ended for good."""

        gate = admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        row = found(request, name)
        if row is None:
            return PlainTextResponse("Not found", status_code=404)
        if row.revoked_at is not None:
            return RedirectResponse(LIST, status_code=303)
        return TEMPLATES.TemplateResponse(
            request, "settings-api-token-revoke.html", {**context(request, gate), "name": name}
        )

    def extend_form(
        request: Request,
        gate: AuthenticatedSession,
        name: str,
        *,
        days: str | int = api_tokens.DEFAULT_DAYS,
        problem: str = "",
        status_code: int = 200,
    ) -> Response:
        row = found(request, name)
        return TEMPLATES.TemplateResponse(
            request,
            "settings-api-token-extend.html",
            {
                **context(request, gate),
                "name": name,
                "until": moments.day(row.expires_at) if row is not None else "",
                "ended": row is not None and row.expires_at <= datetime.now(UTC),
                "days": days,
                "day_choices": DAY_CHOICES,
                "problem": problem,
            },
            status_code=status_code,
        )

    @router.get(LIST + "/{name}/extend", response_class=HTMLResponse)
    def extend_page(request: Request, name: str) -> Response:
        """The length a token is given, before it is extended."""

        gate = admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        row = found(request, name)
        if row is None:
            return PlainTextResponse("Not found", status_code=404)
        if row.revoked_at is not None:
            return RedirectResponse(LIST, status_code=303)
        return extend_form(request, gate, name)

    @router.post(LIST + "/{name}/extend")
    def extend_token(
        request: Request,
        name: str,
        days: Annotated[str, Form(max_length=8)] = "",
        csrf_token: Annotated[str, Form(alias=auth.CSRF_FIELD, max_length=128)] = "",
    ) -> Response:
        gate = admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return forbidden_page(request, config)
        try:
            length = int(days.strip())
        except ValueError:
            return extend_form(
                request,
                gate,
                name,
                days=days,
                problem="The validity must be a number of days.",
                status_code=400,
            )
        refusal: api_token_apply.Refused | None = None
        with request.app.state.pool.connection() as connection:
            try:
                api_token_apply.extend(
                    connection, name, days=length, actor=gate.username, via="web"
                )
            except api_token_apply.Refused as refused:
                connection.rollback()
                refusal = refused
            else:
                connection.commit()
                refusal = None
        if refusal is not None:
            if refusal.code == "not_found":
                return list_page(request, gate, problem=str(refusal), status_code=404)
            return extend_form(
                request, gate, name, days=days, problem=str(refusal), status_code=400
            )
        return RedirectResponse(LIST, status_code=303)

    def change(request: Request, name: str, csrf_token: str, action: str) -> Response:
        gate = admin_write_gate(config, request)
        if not isinstance(gate, AuthenticatedSession):
            return gate
        token = request.cookies.get(auth.SESSION_COOKIE, "")
        if not auth.csrf_token_is_valid(token, csrf_token):
            return forbidden_page(request, config)
        do = api_token_apply.revoke if action == "revoke" else api_token_apply.remove
        refusal: api_token_apply.Refused | None = None
        with request.app.state.pool.connection() as connection:
            try:
                do(connection, name, actor=gate.username, via="web")
            except api_token_apply.Refused as refused:
                connection.rollback()
                refusal = refused
            else:
                connection.commit()
                refusal = None
        if refusal is not None:
            missing = refusal.code == "not_found"
            return list_page(
                request, gate, problem=str(refusal), status_code=404 if missing else 409
            )
        return RedirectResponse(LIST, status_code=303)

    @router.post(LIST + "/{name}/revoke")
    def revoke_token(
        request: Request,
        name: str,
        csrf_token: Annotated[str, Form(alias=auth.CSRF_FIELD, max_length=128)] = "",
    ) -> Response:
        return change(request, name, csrf_token, "revoke")

    @router.post(LIST + "/{name}/remove")
    def remove_token(
        request: Request,
        name: str,
        csrf_token: Annotated[str, Form(alias=auth.CSRF_FIELD, max_length=128)] = "",
    ) -> Response:
        return change(request, name, csrf_token, "remove")

    return router
