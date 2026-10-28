"""The WAF's findings as work: what it blocked, and the exceptions an admin allows or removes (K01, review 2026-10-28).

The WAF page groups a week's findings per object and rule; an exception made
from one is a change to the object, saved for the next publish like any other
and fenced on the reading it was made from. Whether the WAF works at all - a
node not sending, a rule set missing - is said on the dashboard too.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlencode
from uuid import uuid4

from fastapi import Request, Response
from fastapi.responses import (
    PlainTextResponse,
    RedirectResponse,
)
from haprion import (
    crs,
    proxy_model,
)
from haprion.digits import is_digits
from haprion.proxy_model import (
    ModelError,
    load_written,
)

from haprion_ui import (
    auth,
    db,
    objects,
    waf,
)
from haprion_ui import editor as editor_module
from haprion_ui.access import current_session, forbidden_page
from haprion_ui.config import Config
from haprion_ui.db import AuthenticatedSession
from haprion_ui.editor_flow import carried_base, editor_state, state_reading
from haprion_ui.reading import (
    OBJECTS_SOURCE,
    listed_clusters,
    read_source,
)
from haprion_ui.saved_work import (
    objects_reading_of,
    settled_drafts,
    settled_work,
    top_layers,
)
from haprion_ui.templates import TEMPLATES

# - WAF page (Fas 21 del B, B234) ------------------------------------------
#
# What the engine found per object and rule, and the exceptions objects carry.
# A finding is let through with an exception that is saved into the object's
# draft, as the editor saves one: the same row, the same revision check, the
# same refusal of a document the engine will not take. Publishing it is the
# object's own publish.
#
WAF_DAYS = 7


def _waf_documents(
    request: Request, config: Config, connection: Any, clusters: Sequence[str]
) -> tuple[dict[tuple[str, str], str], dict[tuple[str, str], str]]:
    """Each object's stored document, and its draft's where it has one (not a removal)."""

    _, object_rows = read_source(request, config, OBJECTS_SOURCE)
    stored: dict[tuple[str, str], str] = {}
    readings: dict[str, Any] = {}
    for row in object_rows:
        if row.cluster not in clusters:
            continue
        readings[row.cluster] = row
        for view in objects.cluster_object_views(row):
            if view.readable:
                stored[(row.cluster, view.name)] = view.document
    drafted: dict[tuple[str, str], str] = {}
    for cluster in clusters:
        names = {name for owner, name in stored if owner == cluster}
        for draft in top_layers(
            settled_drafts(connection, cluster, objects_reading_of(readings.get(cluster), names))
        ):
            if not draft.deleted:
                drafted[(cluster, draft.object_id)] = draft.yaml
    return stored, drafted


@dataclass(frozen=True, slots=True)
class WafOverview:
    """What the WAF page's three tabs show, and the figure on each (mock round 7)."""

    days: int
    findings: list[Any]
    exceptions: list[Any]
    request_count: int

    def tab_counts(self) -> dict[str, int]:
        return {
            "findings": sum(len(card.findings) for card in self.findings),
            "exceptions": len(self.exceptions),
            "requests": self.request_count,
        }


def waf_not_working(
    request: Request, config: Config, connection: Any, chosen: Sequence[str]
) -> set[tuple[str, str, Any]]:
    """The published exceptions the WAF page marks *Not working*, for the attention list."""

    days = min(WAF_DAYS, config.traffic_logs.retention_days)
    since = datetime.now(UTC) - timedelta(days=days)
    stored, _drafted = _waf_documents(request, config, connection, chosen)
    rows = db.waf_findings(connection, clusters=chosen, since=since)
    reached = {
        (cluster, moment): done
        for cluster, moments in waf.exception_moments(rows, stored).items()
        for moment, done in db.deploys_carrying(
            connection, cluster=cluster, moments=sorted(moments)
        ).items()
    }
    return waf.ineffective_exceptions(rows, stored, reached)


def waf_overview(request: Request, config: Config, chosen: Sequence[str]) -> WafOverview:
    days = min(WAF_DAYS, config.traffic_logs.retention_days)
    since = datetime.now(UTC) - timedelta(days=days)
    rules = crs.installed_catalog()
    with request.app.state.pool.connection() as connection:
        stored, drafted = _waf_documents(request, config, connection, chosen)
        rows = db.waf_findings(connection, clusters=chosen, since=since)
        verdicts = db.waf_verdicts(connection, clusters=chosen, since=since)
        request_count = db.waf_request_count(connection, clusters=chosen, since=since)
        #
        # What each exception let through, as its counter counted it within
        # what the exception covers (B273, review 26-10-11).
        #
        counted = db.waf_counted(connection, scopes=waf.counter_scopes(stored, rules), since=since)
        #
        # When each published exception that covers a finding reached the
        # nodes: the first deploy after it was made (26-10-11). Matches after
        # that mean the exception is not working, which the page says rather
        # than hides.
        #
        reached = {
            (cluster, moment): done
            for cluster, moments in waf.exception_moments(rows, stored).items()
            for moment, done in db.deploys_carrying(
                connection, cluster=cluster, moments=sorted(moments)
            ).items()
        }
    return WafOverview(
        days=days,
        findings=waf.build_findings(rows, verdicts, stored, drafted, rules, reached),
        exceptions=waf.build_exceptions(
            stored, drafted, rules, waf.ineffective_exceptions(rows, stored, reached), counted
        ),
        request_count=request_count,
    )


def waf_work_page(request: Request, config: Config, view: str, problem: str = "") -> Response:
    session = current_session(request)
    if session is None:
        return RedirectResponse("/login", status_code=303)
    token = request.cookies.get(auth.SESSION_COOKIE, "")
    clusters = listed_clusters(request, config)
    selected = request.query_params.get("cluster", "")[:32]
    chosen = (selected,) if selected in clusters else tuple(clusters)
    overview = waf_overview(request, config, chosen)
    days, findings, exceptions = overview.days, overview.findings, overview.exceptions
    return TEMPLATES.TemplateResponse(
        request,
        "waf.html",
        {
            "username": session.username,
            "role": session.role,
            "csrf_token": auth.csrf_token(token),
            "section": "waf",
            "management_writes": config.management_writes,
            "view": view,
            "days": days,
            "clusters": clusters,
            "selected_cluster": selected if selected in clusters else "",
            "findings": findings,
            "tab_counts": overview.tab_counts(),
            "exceptions": exceptions,
            "where": waf.where,
            "saved": request.query_params.get("saved", "")[:40],
            "saved_in": request.query_params.get("in", "")[:32],
            "can_write": config.management_writes and session.role == "admin",
            "problem": problem,
        },
        status_code=409 if problem else 200,
    )


def _waf_write_gate(
    request: Request, config: Config, csrf: str | None
) -> AuthenticatedSession | Response:
    session = current_session(request)
    if session is None:
        return RedirectResponse("/login", status_code=303)
    if not config.management_writes:
        return PlainTextResponse("Not found", status_code=404)
    token = request.cookies.get(auth.SESSION_COOKIE, "")
    if csrf is not None and not auth.csrf_token_is_valid(token, csrf):
        return forbidden_page(request, config)
    if session.role != "admin":
        return forbidden_page(request, config)
    return session


def _waf_save(
    request: Request,
    config: Config,
    session: AuthenticatedSession,
    *,
    cluster: str,
    name: str,
    change: Callable[[str], str],
    detail: dict[str, Any],
) -> str | None:
    """Apply one change to the object's draft (or its stored document); the problem, or None."""

    state = editor_state(request, config, cluster)
    stored = next((view for view in state.stored if view.name == name), None)
    with request.app.state.pool.connection() as connection:
        work = settled_work(connection, cluster, name, state_reading(state))
    #
    # An exception is finished work, so it is a saved change (B257), made on
    # the saved change or the stored object and never on a draft somebody has
    # not finished.
    #
    if work.draft is not None:
        return f"{name} has a draft. Save or discard it in the editor first."
    draft = work.saved
    if draft is not None and draft.deleted:
        return f"The saved changes remove {name}."
    base = draft.yaml if draft is not None else (stored.document if stored is not None else "")
    if not base or state.commit is None:
        return "The stored proxies have not been read yet."
    try:
        document = change(base)
        load_written(name, document.encode())
    except (ValueError, ModelError) as exc:
        return str(exc)
    if editor_module.unchanged(document, base):
        return None
    with request.app.state.pool.connection() as connection:
        try:
            saved = db.save_change(
                connection,
                cluster=cluster,
                object_id=name,
                yaml=document,
                base_version=state.base_version,
                base_hash=state.commit,
                updated_by=session.username,
                base_document=carried_base(state, name, draft),
                replaces=draft.replaces if draft is not None else None,
                saved_revision=draft.revision if draft is not None else None,
                draft_revision=None,
            )
        except db.DraftConflict as conflict:
            connection.rollback()
            return f"{conflict}. Reload the page and try again."
        db.record_audit_event(
            connection,
            actor=session.username,
            action="save_change",
            cluster=cluster,
            request_id=uuid4(),
            detail={"object": name, "revision": saved.revision, **detail},
        )
        connection.commit()
    return None


def _waf_target(request: Request, config: Config, cluster: str, name: str) -> bool:
    return cluster in listed_clusters(request, config) and bool(proxy_model.NAME.fullmatch(name))


def allow_waf_exception(request: Request, config: Config, form: Any) -> Response:
    """The Allow dialog (B234, B235): where to let a finding through, as narrow as it allows."""

    values = form if form is not None else request.query_params
    gate = _waf_write_gate(
        request, config, str(values.get("csrf_token", "")) if form is not None else None
    )
    if not isinstance(gate, AuthenticatedSession):
        return gate
    session = gate
    cluster = str(values.get("cluster", ""))[:32]
    name = str(values.get("object", ""))[:40]
    rule_text = str(values.get("rule", ""))[:6]
    field = str(values.get("field", ""))[:256]
    offered = [str(path)[:1024] for path in values.getlist("path")][:20]
    if not _waf_target(request, config, cluster, name) or not is_digits(rule_text):
        return PlainTextResponse("Not found", status_code=404)
    rule = int(rule_text)
    if field and not proxy_model.waf_field(field):
        field = ""
    #
    # A path the engine could not be told exactly - percent-encoded, with an
    # empty segment - is not offered; the object or the field still is.
    #
    paths = [path for path in dict.fromkeys(offered) if proxy_model.WAF_PATH.fullmatch(path)]
    #
    # Why, in one line (26-10-10): a pasted line break becomes a space, and
    # the engine refuses whatever else a note may not hold, in its own words.
    #
    reason = " ".join(str(values.get("reason", ""))[: proxy_model.MAX_NOTE].split())
    problem = ""
    if form is not None:
        chosen = str(values.get("scope", ""))
        at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            exception = waf.exception_for(
                chosen,
                rule=rule,
                field=field,
                paths=[path for path in values.getlist("chosen_path") if path in paths],
                by=session.username,
                at=at,
                reason=reason,
            )
        except ValueError as exc:
            problem = str(exc)
        else:
            problem = (
                _waf_save(
                    request,
                    config,
                    session,
                    cluster=cluster,
                    name=name,
                    change=lambda base: waf.with_exception(name, base, exception),
                    detail={"waf_exception": {k: v for k, v in exception.items() if k != "at"}},
                )
                or ""
            )
            if not problem:
                return RedirectResponse(
                    "/waf?" + urlencode({"saved": name, "in": cluster}), status_code=303
                )
    catalog = crs.installed_catalog().get(rule)
    kind, explanation = waf.kind(rule // 1000)
    token = request.cookies.get(auth.SESSION_COOKIE, "")
    return TEMPLATES.TemplateResponse(
        request,
        "waf-allow.html",
        {
            "username": session.username,
            "role": session.role,
            "csrf_token": auth.csrf_token(token),
            "section": "waf",
            "management_writes": config.management_writes,
            "cluster": cluster,
            "name": name,
            "rule": rule,
            "field": field,
            "shown_field": waf.shown_field(field) if field else "",
            "paths": paths,
            "kind": kind,
            "explanation": explanation,
            "message": catalog.message
            if catalog is not None and catalog.message
            else f"Rule {rule}",
            "severity": catalog.severity if catalog is not None else "",
            "matched": str(values.get("matched", ""))[:1024],
            "reason": reason,
            "scope": str(values.get("scope", ""))
            or (
                "field_paths"
                if field and paths
                else "field"
                if field
                else "paths"
                if paths
                else "object"
            ),
            "problem": problem,
        },
        status_code=409 if problem else 200,
    )


def remove_waf_exception(request: Request, config: Config, form: Any) -> Response:
    gate = _waf_write_gate(request, config, str(form.get("csrf_token", "")))
    if not isinstance(gate, AuthenticatedSession):
        return gate
    cluster = str(form.get("cluster", ""))[:32]
    name = str(form.get("object", ""))[:40]
    rule_text = str(form.get("rule", ""))[:6]
    if not _waf_target(request, config, cluster, name) or not is_digits(rule_text):
        return PlainTextResponse("Not found", status_code=404)
    field = str(form.get("field", ""))[:256]
    paths = [str(path)[:1024] for path in form.getlist("path")][:20]
    problem = _waf_save(
        request,
        config,
        gate,
        cluster=cluster,
        name=name,
        change=lambda base: waf.without_exception(
            name, base, rule=int(rule_text), field=field, paths=paths
        ),
        detail={"waf_exception_removed": {"rule": int(rule_text), "field": field, "paths": paths}},
    )
    if problem:
        return waf_work_page(request, config, "exceptions", problem=problem)
    return RedirectResponse(
        "/waf?" + urlencode({"view": "exceptions", "saved": name, "in": cluster}), status_code=303
    )
