"""The WAF's findings and exceptions.

A finding quotes what the engine matched in a request (`matched`) and the
paths it was found on, so it can hold a visitor's input; read it as the WAF
page's Findings view is read, by someone allowed to see traffic.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from haprion_ui import api_tokens
from haprion_ui.api.answers import answer
from haprion_ui.api.caller import Caller, in_scope, needs
from haprion_ui.api.traffic import known_cluster, moment
from haprion_ui.waf import ExceptionRow, Finding, ObjectFindings, exception_moment
from haprion_ui.waf_work import waf_overview

router = APIRouter(tags=["waf"])


def _finding(finding: Finding) -> dict[str, Any]:
    return {
        "rule": finding.rule,
        "kind": finding.kind,
        "explanation": finding.explanation,
        "message": finding.message,
        "severity": finding.severity,
        "field": finding.field,
        "field_label": finding.shown_field,
        "matched": finding.matched,
        "paths": list(finding.paths),
        "more_paths": finding.more_paths,
        "requests": finding.requests,
        "clients": finding.clients,
        "last_seen": moment(finding.last_seen),
        "in_draft": finding.in_draft,
        "not_working": finding.ineffective,
    }


def _object(card: ObjectFindings) -> dict[str, Any]:
    return {
        "object": card.name,
        "mode": card.mode,
        "requests_judged": card.judged,
        "clients": card.clients,
        "findings": [_finding(finding) for finding in card.findings],
    }


def _exception(row: ExceptionRow) -> dict[str, Any]:
    return {
        "object": row.name,
        "rule": row.exception.rule,
        "kind": row.kind,
        "explanation": row.explanation,
        "message": row.message,
        "severity": row.severity,
        # Text the document may leave out is null here, as everywhere in the API.
        "field": row.exception.field or None,
        "paths": list(row.exception.paths),
        "reason": row.exception.reason or None,
        "added_by": row.exception.by or None,
        "added_at": moment(added) if (added := exception_moment(row.exception)) else None,
        "in_draft": row.in_draft,
        "not_working": row.ineffective,
        "let_through": {
            "counted": row.counted,
            "requests": row.requests,
            "clients": row.clients,
            "last_seen": moment(row.last_seen) if row.last_seen is not None else None,
        },
    }


@router.get("/clusters/{cluster}/waf/findings", name="waf_findings")
def waf_findings(
    request: Request,
    cluster: str,
    caller: Caller = Depends(needs("read")),  # noqa: B008
) -> JSONResponse:
    """What the engine found per object and rule over the last `days`, still needing a decision."""

    in_scope(caller, cluster)
    known_cluster(request, cluster)
    overview = waf_overview(request, request.app.state.config, (cluster,))
    return answer(
        request,
        {
            "days": overview.days,
            "objects": [
                _object(card)
                for card in overview.findings
                if api_tokens.covers(caller.issued, cluster, card.name)
            ],
        },
        cluster=cluster,
    )


@router.get("/clusters/{cluster}/waf/exceptions", name="waf_exceptions")
def waf_exceptions(
    request: Request,
    cluster: str,
    caller: Caller = Depends(needs("read")),  # noqa: B008
) -> JSONResponse:
    """The exceptions the cluster's objects carry, with what each let through over `days`."""

    in_scope(caller, cluster)
    known_cluster(request, cluster)
    overview = waf_overview(request, request.app.state.config, (cluster,))
    return answer(
        request,
        {
            "days": overview.days,
            "exceptions": [
                _exception(row)
                for row in overview.exceptions
                if api_tokens.covers(caller.issued, cluster, row.name)
            ],
        },
        cluster=cluster,
    )
