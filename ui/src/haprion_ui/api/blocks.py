"""Addresses blocked on an object: read them, place a block, lift one.

A block is placed in the call that asks for it (B416 §5): a publish holds the
cluster's one place in the job queue, and a ban from a firewall must not wait
behind it. The web asks `haprion-block-api-helper` over its socket, which
does what the ssh path does, and writes the audit row itself. Lifting a block
is an ordinary job, as the object page's *Unblock* queues it.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Annotated, Any
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from haprion import block_api_socket
from haprion.envelope import Message, envelope
from haprion.proxy_model import NAME, ModelError, load_proxy
from haprion.server_state import MAX_ADDRESSES, UNBLOCK_OPERATION, normalized_address
from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from haprion_ui import api_tokens, blocked, db, objects
from haprion_ui.api import contract, writing
from haprion_ui.api.answers import Refusal, answer, operation_of
from haprion_ui.api.caller import Caller, Needs, current_caller, in_scope, needs
from haprion_ui.preview import DEFAULTS
from haprion_ui.reading import OBJECTS_SOURCE, STATUS_SOURCE, listed_clusters, read_source

router = APIRouter(tags=["blocks"])

logger = logging.getLogger("haprion_ui.api")

NOT_FOUND = Refusal(404, "not_found", "No such cluster or object.")

#
# What a block token is told where the text is the helper's or a node's: the
# paths and reasons behind it are a write token's to read (B417).
#
GENERIC_NODE = "The node did not take the block."
GENERIC_SERVICE = "The block service could not place the block."


class ReadsOwnBlocks(Needs):
    """`read` and up, and also a `block` token: it reads the blocks it can place.

    The narrowing to the token's own objects is the route's `in_scope`. The
    boundary test asks each route which levels it admits (`admits`), so a
    route that admits `block` says so rather than being the one exception.
    """

    def __init__(self) -> None:
        super().__init__("read")

    def admits(self, held: str) -> bool:
        return held == "block" or api_tokens.reaches(held, self.level)

    def __call__(self, caller: Caller = Depends(current_caller)) -> Caller:  # noqa: B008
        if not self.admits(caller.issued.level):
            raise Refusal(
                403,
                "forbidden",
                f"This token's level ({caller.issued.level}) does not reach {self.level}.",
            )
        return caller


class Addresses(BaseModel):
    """The body of a block and of an unblock: the addresses, one to the engine's limit."""

    model_config = ConfigDict(extra="forbid")

    addresses: list[Annotated[str, StringConstraints(max_length=64)]] = Field(
        min_length=1, max_length=MAX_ADDRESSES
    )


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


def stored_object(object_rows: Any, name: str) -> Any:
    """The object as the poller last read it from the cluster's repository, or None."""

    return next(
        (
            view
            for row in object_rows
            for view in objects.cluster_object_views(row)
            if view.name == name
        ),
        None,
    )


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
    stored = stored_object(object_rows, name)
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
    caller: Caller = Depends(ReadsOwnBlocks()),  # noqa: B008
) -> JSONResponse:
    in_scope(caller, cluster, name)
    return answer(request, object_blocks(request, cluster, name), cluster=cluster)


def _exempt_or_invalid(address: str, code: str, reason: str) -> dict[str, str]:
    return {"address": address, "code": code, "reason": reason}


def _sentence(caller: Caller, said: object, fallback: str) -> str:
    """The text a helper or a node gave, for a token that may read it; a generic one otherwise."""

    if caller.issued.level == "write" and isinstance(said, str) and said:
        return said[:300]
    return fallback


def _nodes(caller: Caller, reported: object) -> list[dict[str, Any]]:
    nodes: list[dict[str, Any]] = []
    for entry in reported if isinstance(reported, list) else ():
        if not isinstance(entry, dict):
            continue
        outcome = str(entry.get("outcome"))
        each = entry.get("addresses")
        nodes.append(
            {
                "node": str(entry.get("node")),
                "outcome": outcome,
                "message": None
                if outcome == "done"
                else _sentence(caller, entry.get("message"), GENERIC_NODE),
                "addresses": [
                    {"address": str(one.get("address")), "outcome": str(one.get("outcome"))}
                    for one in (each if isinstance(each, list) else ())
                    if isinstance(one, dict)
                ],
            }
        )
    return nodes


def _warnings(caller: Caller, reported: object) -> list[Message]:
    """The helper's warnings; a node's own reason is a write token's to read."""

    found: list[Message] = []
    for entry in reported if isinstance(reported, list) else ():
        if not isinstance(entry, dict):
            continue
        code = str(entry.get("code"))
        node = entry.get("node")
        details = entry.get("details")
        found.append(
            Message(
                code=code,
                message=(
                    str(entry.get("message"))[:300]
                    if code == "address_exempt"
                    else _sentence(caller, entry.get("message"), GENERIC_NODE)
                ),
                node=node if isinstance(node, str) else None,
                details=details if isinstance(details, dict) else None,
            )
        )
    return found


def _refusal_of(caller: Caller, code: str, said: object) -> Refusal:
    """What the API answers for a request the helper refused before any node was asked."""

    if code == "bad_input" and isinstance(said, str):
        return Refusal(400, "bad_input", said[:300])
    if code == "server_not_found":
        return NOT_FOUND
    return Refusal(503, "unavailable", _sentence(caller, said, GENERIC_SERVICE))


def _recorded(
    request: Request,
    caller: Caller,
    cluster: str,
    request_id: UUID,
    detail: dict[str, Any],
) -> None:
    """The audit row for a block that was asked of the nodes, whatever they answered.

    A row that cannot be written is logged and does not hide the block: the
    nodes already hold it, and the answer must say so.
    """

    try:
        with request.app.state.pool.connection() as connection:
            db.record_audit_event(
                connection,
                actor=caller.actor,
                action="api_block",
                cluster=cluster,
                request_id=request_id,
                detail={"via": "api", **detail},
            )
            connection.commit()
    except Exception:
        logger.exception(
            "api: the audit row for a block on %s/%s was not written", cluster, detail["object"]
        )


@router.post(
    "/clusters/{cluster}/objects/{name}/blocks",
    name="object_block",
    responses=contract.responses("object_block"),
)
def object_block(
    request: Request,
    cluster: str,
    name: str,
    body: Addresses,
    caller: Caller = Depends(needs("block")),  # noqa: B008
) -> JSONResponse:
    """Block addresses on an object, answered in this call (B416 §5).

    No `Idempotency-Key`: blocking an address again only renews its time, so a
    client that retries a lost answer does no harm, and a firewall's hook
    should not have to invent a key.
    """

    in_scope(caller, cluster, name)
    config = request.app.state.config
    if not config.management_writes:
        raise writing.WRITES_OFF
    if cluster not in listed_clusters(request, config) or not NAME.fullmatch(name):
        raise NOT_FOUND
    wanted: list[str] = []
    refused: list[dict[str, str]] = []
    for entry in body.addresses:
        address = normalized_address(entry)
        if address is None:
            refused.append(
                _exempt_or_invalid(entry, "address_invalid", f"{entry} is not an IP address.")
            )
        elif address not in wanted:
            wanted.append(address)
    if not wanted:
        raise Refusal(400, "bad_input", "None of the addresses is an IP address.")
    #
    # Read before the nodes are asked: a database that fails afterwards would
    # answer an error for a block that is already placed.
    #
    _, object_rows = read_source(request, config, OBJECTS_SOURCE, cluster=cluster)
    stored = stored_object(object_rows, name)
    block_for = block_for_default(stored.document if stored is not None else None, name)

    request_id = uuid4()
    detail: dict[str, Any] = {"object": name, "addresses": wanted}
    try:
        document = block_api_socket.ask(
            cluster, name, wanted, actor=caller.actor, request_id=str(request_id)
        )
    except block_api_socket.HelperBusy:
        raise Refusal(
            429,
            "busy",
            "The block service is answering other calls; try again in a second.",
            headers={"Retry-After": "1"},
        ) from None
    except block_api_socket.HelperSilent:
        _recorded(request, caller, cluster, request_id, {**detail, "outcome": "unknown"})
        raise Refusal(
            504,
            "outcome_unknown",
            "The block service did not answer, so the block may or may not have been placed; "
            "read the object's blocks before asking again.",
        ) from None
    except block_api_socket.HelperUnavailable as unavailable:
        logger.warning("api: the block service could not be asked: %s", unavailable)
        raise Refusal(
            503, "unavailable", _sentence(caller, str(unavailable), GENERIC_SERVICE)
        ) from None

    outcome = document.get("outcome")
    reported = document.get("result")
    failure = document.get("error")
    if not isinstance(reported, dict) or outcome not in ("done", "partial", "failed"):
        code = failure.get("code") if isinstance(failure, dict) else None
        said = failure.get("message") if isinstance(failure, dict) else None
        raise _refusal_of(caller, str(code), said)

    nodes = _nodes(caller, reported.get("nodes"))
    warnings = _warnings(caller, document.get("warnings"))
    for warning in warnings:
        if warning.code == "address_exempt" and warning.details:
            refused.append(
                _exempt_or_invalid(
                    str(warning.details.get("address")), "address_exempt", warning.message
                )
            )
    _recorded(
        request,
        caller,
        cluster,
        request_id,
        {
            **detail,
            "outcome": outcome,
            **({"refused": [r["address"] for r in refused]} if refused else {}),
        },
    )
    if outcome == "failed":
        said = failure.get("message") if isinstance(failure, dict) else None
        return JSONResponse(
            envelope(
                operation=operation_of(request),
                outcome="failed",
                cluster=cluster,
                result=None,
                request_id=str(request_id),
                warnings=tuple(warnings),
                error=Message(
                    code="blocking_failed",
                    message=_sentence(caller, said, "No node took the block."),
                ),
            ),
            status_code=502,
        )
    warnings = [
        *(
            Message(code=entry["code"], message=entry["reason"])
            for entry in refused
            if entry["code"] == "address_invalid"
        ),
        *warnings,
    ]
    result = {
        "object": name,
        "block_for": block_for,
        "blocked": [
            address
            for address in wanted
            if any(
                one["address"] == address and one["outcome"] == "done"
                for node in nodes
                for one in node["addresses"]
            )
        ],
        "refused": refused,
        "nodes": nodes,
    }
    return JSONResponse(
        envelope(
            operation=operation_of(request),
            outcome="partial" if warnings else "done",
            cluster=cluster,
            result=result,
            request_id=str(request_id),
            warnings=tuple(warnings),
        )
    )


@router.delete(
    "/clusters/{cluster}/objects/{name}/blocks",
    name="object_unblock",
    status_code=202,
    responses=contract.responses("object_unblock", status=202),
)
def object_unblock(
    request: Request,
    cluster: str,
    name: str,
    body: Addresses,
    caller: Caller = Depends(needs("write")),  # noqa: B008
) -> JSONResponse:
    """Lift the block on addresses: the job the object page's *Unblock* queues."""

    in_scope(caller, cluster, name)
    if cluster not in listed_clusters(request, request.app.state.config) or not NAME.fullmatch(
        name
    ):
        raise NOT_FOUND
    payload = blocked.unblock_payload(name, body.addresses)
    return writing.queue(
        request,
        caller,
        operation=UNBLOCK_OPERATION,
        cluster=cluster,
        payload=payload,
        detail={"object": name, "addresses": payload["addresses"]},
    )
