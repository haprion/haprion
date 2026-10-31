"""`GET /clusters`, `GET /clusters/{cluster}`: the clusters a token may see, as the dashboard shows them."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from haprion_ui import api_tokens, dashboard
from haprion_ui.api import contract
from haprion_ui.api.answers import Refusal, answer
from haprion_ui.api.caller import Caller, in_scope, needs
from haprion_ui.attention import Item
from haprion_ui.reading import NETWORK_SOURCE, STATUS_SOURCE, listed_clusters, read_source
from haprion_ui.views import attention_items

router = APIRouter(tags=["clusters"])


def _iso(moment: datetime | None) -> str | None:
    return moment.astimezone(UTC).isoformat() if moment is not None else None


def _node(view: dashboard.NodeView) -> dict[str, Any]:
    return {
        "name": view.name,
        "state": view.label,
        "tone": view.tone,
        "detail": view.detail,
        #
        # The dashboard's Owner and Standby; anything else (a node not read,
        # one never deployed) says nothing about the address.
        #
        "holds_vip": {"Owner": True, "Standby": False}.get(view.vip),
        "release_version": view.release_number,
        "on_published_version": view.current,
        "haproxy_version": view.haproxy_version,
        "node_package_version": view.package_version,
    }


def _attention(item: Item) -> dict[str, Any]:
    return {
        "kind": item.kind,
        "severity": item.severity,
        "cluster": item.cluster,
        "subject": item.subject,
        "message": item.message,
        "since": _iso(item.since),
        # What tells this row from the same row worse; part of what an acknowledgement names.
        "variant": item.variant,
    }


def _cluster(view: dashboard.ClusterView, items: list[Item]) -> dict[str, Any]:
    holder = view.vip if view.vip in {node.name for node in view.nodes} else None
    return {
        "name": view.cluster,
        "status": {"label": view.label, "tone": view.tone, "detail": view.detail},
        #
        # Read within two polls; a reading older than that is last known, not now.
        #
        "fresh": view.observed_at is not None and not view.stale,
        "observed_at": _iso(view.observed_at),
        "published_version": view.target_version,
        # The dashboard's words ("Converged") as codes: "converged", "behind".
        "release_state": view.release_state.lower().replace(" ", "_"),
        "vip_holder": holder,
        "vip_count": view.vip_count,
        "nodes": [_node(node) for node in view.nodes],
        "attention": [_attention(item) for item in items if item.cluster == view.cluster],
    }


def cluster_entries(request: Request, names: list[str]) -> list[dict[str, Any]]:
    """The named clusters as the dashboard builds them, with their Needs attention rows."""

    config = request.app.state.config
    clusters, status_rows = read_source(request, config, STATUS_SOURCE)
    _, network_rows = read_source(request, config, NETWORK_SOURCE)
    board = dashboard.build_dashboard(
        clusters,
        status_rows,
        stale_after=config.poller.stale_after,
        network_readings=network_rows,
    )
    views = {view.cluster: view for view in board.clusters if view.configured}
    items = list(attention_items(request, config).items)
    return [_cluster(views[name], items) for name in names if name in views]


@router.get("/clusters", name="cluster_list", responses=contract.responses("cluster_list"))
def cluster_list(request: Request, caller: Caller = Depends(needs("read"))) -> JSONResponse:  # noqa: B008
    names = [
        cluster
        for cluster in listed_clusters(request, request.app.state.config)
        if api_tokens.covers(caller.issued, cluster)
    ]
    return answer(request, {"clusters": cluster_entries(request, names)})


@router.get(
    "/clusters/{cluster}", name="cluster_show", responses=contract.responses("cluster_show")
)
def cluster_show(
    request: Request,
    cluster: str,
    caller: Caller = Depends(needs("read")),  # noqa: B008
) -> JSONResponse:
    in_scope(caller, cluster)
    if cluster not in listed_clusters(request, request.app.state.config):
        raise Refusal(404, "not_found", "No such cluster or object.")
    entries = cluster_entries(request, [cluster])
    if not entries:
        # Removed between the two readings.
        raise Refusal(404, "not_found", "No such cluster or object.")
    return answer(request, entries[0], cluster=cluster)


@router.get("/attention", name="attention_list", responses=contract.responses("attention_list"))
def attention_list(request: Request, caller: Caller = Depends(needs("read"))) -> JSONResponse:  # noqa: B008
    """Needs attention as the dashboard lists it, within the token's clusters.

    The rows that belong to no cluster (certificates, the poller, packages,
    tokens) are the installation's, and only a token limited to no cluster sees them.
    """

    items = attention_items(request, request.app.state.config).items
    return answer(
        request,
        {
            "items": [
                _attention(item)
                for item in items
                if (
                    not caller.issued.clusters
                    if item.cluster is None
                    else api_tokens.covers(caller.issued, item.cluster)
                )
            ]
        },
    )
