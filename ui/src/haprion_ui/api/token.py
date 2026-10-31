"""`GET /token`: the calling token itself, so an integration can see when it ends."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from haprion_ui.api import contract
from haprion_ui.api.answers import answer
from haprion_ui.api.caller import Caller, current_caller

router = APIRouter(tags=["token"])


def token_fields(token: Any) -> dict[str, Any]:
    """A token as the API shows it: never its hash, and only the prefix of its secret."""

    return {
        "name": token.name,
        "level": token.level,
        "clusters": list(token.clusters),
        "objects": list(token.objects),
        "sources": list(token.sources),
        "prefix": token.prefix,
        "created_at": token.created_at.isoformat(),
        "expires_at": token.expires_at.isoformat(),
    }


@router.get("/token", name="token_show", responses=contract.responses("token_show"))
def show(request: Request, caller: Caller = Depends(current_caller)) -> JSONResponse:  # noqa: B008
    return answer(request, {"token": token_fields(caller.issued)})
