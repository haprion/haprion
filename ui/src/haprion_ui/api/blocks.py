"""Addresses blocked on an object."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from haprion.proxy_model import ModelError, load_proxy

from haprion_ui import blocked, objects
from haprion_ui.api import contract
from haprion_ui.api.answers import Refusal, answer
from haprion_ui.api.caller import Caller, in_scope, needs
from haprion_ui.preview import DEFAULTS
from haprion_ui.reading import OBJECTS_SOURCE, STATUS_SOURCE, read_source

router = APIRouter(tags=["blocks"])

NOT_FOUND = Refusal(404, "not_found", "No such cluster or object.")


def _iso(moment: datetime | None) -> str | None:
    return moment.astimezone(UTC).isoformat() if moment is not None else None


def block_for_default(document: str | None, name: str) -> str:
    """The object's *Block for*, as the form shows it: its own, or the engine's default."""

    if document is not None:
        try:
            block = load_proxy(name, document.encode()).dynamic_block
        except ModelError:
            block = None
        if block is not None and block.block_for:
            return block.block_for
    return str(DEFAULTS["block_for"])


def _address(row: blocked.BlockedAddress, now: datetime) -> dict[str, Any]:
    return {
        "address": row.address,
        "until": _iso(row.until),
        "seconds_left": max(0, int((row.until - now).total_seconds())) if row.until else None,
        "ending": row.ending,
        "nodes": list(row.nodes),
    }


def object_blocks(
    request: Request, cluster: str, name: str, *, now: datetime | None = None
) -> dict[str, Any]:
    """What the object page's Blocked card shows, as a result; a 404 refusal for no such object.

    One function so the route that lets a `block` token read its own object's
    blocks answers exactly as this one does.
    """

    config = request.app.state.config
    moment = now or datetime.now(UTC)
    listed, status_rows = read_source(request, config, STATUS_SOURCE, cluster=cluster)
    if cluster not in listed:
        raise NOT_FOUND
    _, object_rows = read_source(request, config, OBJECTS_SOURCE, cluster=cluster)
    stored = next(
        (
            view
            for row in object_rows
            for view in objects.cluster_object_views(row)
            if view.name == name
        ),
        None,
    )
    card = blocked.object_card(status_rows, cluster=cluster, name=name, now=moment)
    if stored is None and card is None:
        raise NOT_FOUND
    addresses = card.addresses if card is not None else ()
    return {
        "object": name,
        "block_for": block_for_default(stored.document if stored is not None else None, name),
        "count": card.count if card is not None else 0,
        "addresses": [_address(row, moment) for row in addresses],
        #
        # The nodes list at most a hundred addresses each, however many they hold.
        #
        "truncated": card is not None and card.more > 0,
        "observed_at": _iso(card.observed_at) if card is not None else None,
    }


@router.get(
    "/clusters/{cluster}/objects/{name}/blocks",
    name="object_blocks",
    responses=contract.responses("object_blocks"),
)
def object_block_list(
    request: Request,
    cluster: str,
    name: str,
    caller: Caller = Depends(needs("read")),  # noqa: B008
) -> JSONResponse:
    in_scope(caller, cluster, name)
    return answer(request, object_blocks(request, cluster, name), cluster=cluster)
