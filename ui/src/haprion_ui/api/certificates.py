"""Certificates and where they are deployed."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse

from haprion_ui import api_tokens
from haprion_ui.api import contract
from haprion_ui.api.answers import answer
from haprion_ui.api.caller import Caller, needs
from haprion_ui.certificates import RegistryCertificateView, TargetView
from haprion_ui.sorting import tone_rank
from haprion_ui.views import read_certificate_overview

router = APIRouter(tags=["certificates"])

# A registry holds tens of certificates; the limit is for the day it holds thousands.
DEFAULT_LIMIT = 200
MAX_LIMIT = 1000


def _iso(moment: datetime | None) -> str | None:
    return moment.astimezone(UTC).isoformat() if moment is not None else None


def _target(target: TargetView) -> dict[str, Any]:
    return {
        "name": target.name,
        "kind": target.kind,
        "published_at": _iso(target.published_at),
        "current": target.current,
    }


def _certificate(entry: RegistryCertificateView, caller: Caller, now: datetime) -> dict[str, Any]:
    #
    # A token limited to some clusters is told about those clusters only: the
    # others, and the receivers, which belong to no cluster, are not its to see.
    #
    limited = bool(caller.issued.clusters)
    targets = [
        target
        for target in entry.targets
        if not limited
        or (target.kind == "cluster" and api_tokens.covers(caller.issued, target.name))
    ]
    state = (entry.state_label, entry.state_detail, entry.state_tone)
    if limited:
        #
        # The combined State counts the receivers and the other clusters'
        # nodes. A limited token gets the worst of its own clusters' States.
        #
        state = min(
            (
                (own.label, own.detail, own.tone)
                for own in entry.cluster_states
                if api_tokens.covers(caller.issued, own.cluster)
            ),
            key=lambda each: tone_rank(each[2]),
            default=state,
        )
    left = entry.expires_at - now if entry.expires_at is not None else None
    return {
        "id": entry.identifier,
        "common_name": entry.common_name,
        "names": list(entry.sans),
        "issuer": entry.issuer if entry.readable else None,
        "source": entry.source_kind,
        "lifecycle": entry.lifecycle,
        "readable": entry.readable,
        "problem": entry.problem,
        "not_after": _iso(entry.expires_at),
        "days_left": left.days if left is not None else None,
        "expired": left is not None and left.total_seconds() <= 0,
        "expiry_state": entry.tone,
        "state": {"label": state[0], "detail": state[1], "tone": state[2]},
        "needs_publish": entry.needs_publish,
        "targets": [_target(target) for target in targets],
    }


def visible(entry: RegistryCertificateView, caller: Caller) -> bool:
    """Whether the token may see a certificate: one deployed to a cluster it covers.

    A limited token sees nothing that is deployed only elsewhere or nowhere;
    an unlimited one sees everything.
    """

    if not caller.issued.clusters:
        return True
    return any(
        target.kind == "cluster" and api_tokens.covers(caller.issued, target.name)
        for target in entry.targets
    )


@router.get(
    "/certificates", name="certificate_list", responses=contract.responses("certificate_list")
)
def certificate_list(
    request: Request,
    limit: int = Query(DEFAULT_LIMIT, ge=1, le=MAX_LIMIT),
    caller: Caller = Depends(needs("read")),  # noqa: B008
) -> JSONResponse:
    """The registry as the Certificates page lists it, within the token's clusters."""

    overview, _, _ = read_certificate_overview(request.app.state.config, request)
    registry = overview.registry
    now = datetime.now(UTC)
    shown = [entry for entry in registry.certificates if visible(entry, caller)] if registry else []
    return answer(
        request,
        {
            "certificates": [_certificate(entry, caller, now) for entry in shown[:limit]],
            "count": len(shown),
            "truncated": len(shown) > limit,
            "observed_at": _iso(registry.observed_at) if registry is not None else None,
            "stale": registry.stale if registry is not None else False,
        },
    )
