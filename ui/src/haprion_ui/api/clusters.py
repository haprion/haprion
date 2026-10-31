"""`GET /clusters`: the clusters a token may see."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from haprion_ui import api_tokens
from haprion_ui.api.answers import answer
from haprion_ui.api.caller import Caller, needs
from haprion_ui.reading import listed_clusters

router = APIRouter(tags=["clusters"])


@router.get("/clusters", name="cluster_list")
def cluster_list(request: Request, caller: Caller = Depends(needs("read"))) -> JSONResponse:  # noqa: B008
    clusters = [
        cluster
        for cluster in listed_clusters(request, request.app.state.config)
        if api_tokens.covers(caller.issued, cluster)
    ]
    return answer(request, {"clusters": [{"name": cluster} for cluster in clusters]})
