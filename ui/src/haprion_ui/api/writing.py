"""How the API asks for a change: one job in the queue, as the pages ask (B416, release 2-3).

Every route that changes something goes through `queue`, so each write is
the job a page would queue, run by the same worker and root helpers, and
answered `202` with the job to follow at `/api/v1/jobs/{id}`.

* **An `Idempotency-Key` header is required.** The same key asking for the
  same thing is the same job, so a client that retries after a lost answer
  does not do the work twice; the same key asking for something else is a
  `409`. "The same thing" is the call itself - caller, method, route, path
  parameters and body, stored as a digest beside the job - and not the
  payload built from it, which most routes draw from the state at the call and
  which is another one once the job has run (review 26-11-01, a-P2-1). A
  retry is answered before the route reads any state, and writes no second
  history row.
* **The token is judged again in the transaction that queues.** It was judged
  when the request arrived; a revocation committed since then stops the job
  from being queued (review 26-10-31, a-P3-5).
* **The history names the token**: `token:<name>` is the actor of the audit
  row beside the job.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from fastapi import Request
from fastapi.responses import JSONResponse
from psycopg import Connection
from pydantic import BaseModel

from haprion_ui import api_tokens, db, operations, refusals
from haprion_ui.api.answers import Refusal, answer
from haprion_ui.api.caller import NOT_VALID, Caller

IDEMPOTENCY_HEADER = "Idempotency-Key"

logger = logging.getLogger("haprion_ui.api")

WRITES_OFF = Refusal(
    403,
    "writes_off",
    "Changes are switched off on this installation (management_writes).",
)


KEY_REUSED = Refusal(
    409,
    "idempotency_conflict",
    f"This {IDEMPOTENCY_HEADER} was already used for another change.",
)


#
# A job through the API takes seconds, not minutes (measured at an installation test), so
# a client told to wait half a minute idles for work long done.
#
RETRY_AFTER = "5"

CLUSTER_BUSY = "Another job runs on this cluster; try again when it has finished."


def busy_refusal(code: str, busy: Exception, default: str | None) -> Refusal:
    """A busy queue: wait and retry, unless the job holding it waits for a person.

    A job held after a restart or a restore, or one no worker holds, does not
    finish by itself, so no `Retry-After` promises that it will (review
    26-11-01, a-P3-1).
    """

    sentence = refusals.not_finishing(busy)
    return Refusal(
        409,
        code,
        sentence or refusals.conflict_sentence(busy, default),
        headers={} if sentence else {"Retry-After": RETRY_AFTER},
    )


def idempotency_key(request: Request) -> UUID:
    """The request's `Idempotency-Key`, a UUID; a `400` without one."""

    value = request.headers.get(IDEMPOTENCY_HEADER, "").strip()
    try:
        return UUID(value)
    except ValueError:
        raise Refusal(
            400,
            "bad_input",
            f"A change needs an {IDEMPOTENCY_HEADER} header holding a UUID, new for each change.",
        ) from None


def request_digest(request: Request, caller: Caller, body: BaseModel | None) -> bytes:
    """What the key is held to: who asks, for which route and parameters, with which body.

    The body as its model reads it, so the same document written with other
    spacing or key order is the same call.
    """

    route = request.scope.get("route")
    document = {
        "actor": caller.actor,
        "method": request.method,
        "route": getattr(route, "name", ""),
        "path": request.path_params,
        "body": body.model_dump(mode="json") if body is not None else None,
    }
    text = json.dumps(document, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(text.encode()).digest()


def accepted(request: Request, job: db.Job) -> JSONResponse:
    """`202` with the job and where to follow it."""

    follow = f"/api/v1/jobs/{job.id}"
    response = answer(
        request,
        {
            "job": {
                "id": job.id,
                "request_id": str(job.request_id),
                "operation": job.operation,
                "state": job.state,
            },
            "follow": follow,
        },
        cluster=job.cluster,
        status=202,
    )
    response.headers["Location"] = follow
    return response


def replayed(
    request: Request, caller: Caller, body: BaseModel | None = None
) -> JSONResponse | None:
    """The answer to a call this key already queued, or None for a key not seen.

    Called by every queued route after the refusals that need no state (token,
    scope, writes off, the key itself) and before it reads any: a retry after a
    lost answer is the job it queued, whatever the state has become since. The
    key used for another call is a `409`.
    """

    if not request.app.state.config.management_writes:
        raise WRITES_OFF
    key = idempotency_key(request)
    digest = request_digest(request, caller, body)
    with request.app.state.pool.connection() as connection:
        found = db.job_for_call(connection, key, request_digest=digest)
    if found is None:
        return None
    job, same = found
    if not same:
        raise KEY_REUSED
    return accepted(request, job)


def still_valid(connection: Connection[Any], request: Request, caller: Caller) -> None:
    """Judge the token again in the caller's own transaction, holding its row.

    It was judged when the request arrived; a revocation committed since then
    stops the write, and one that commits after this waits for it (review
    26-11-01, a-P3-4). A `401` when the token may no longer be used.
    """

    token = db.api_token_by_hash(connection, caller.digest, lock=True)
    verdict = api_tokens.evaluate(token, now=datetime.now(UTC), source=caller.source)
    if verdict.usable:
        return
    logger.warning(
        "api: %s %s from %s refused before the write: %s (token %s)",
        request.method,
        request.url.path,
        caller.source,
        verdict.reason,
        caller.issued.name,
    )
    raise NOT_VALID


def queue(
    request: Request,
    caller: Caller,
    *,
    operation: str,
    cluster: str | None,
    payload: Mapping[str, Any],
    detail: Mapping[str, Any] | None = None,
    body: BaseModel | None = None,
) -> JSONResponse:
    """Queue `operation` for the caller, and answer `202` with the job.

    `payload` is checked as the worker will read it before anything is
    written. `detail` is what the audit row says beside the job - never a
    secret, a key or a document. `body` is the request's body as its model
    reads it, which the key is held to (`replayed`).
    """

    if not request.app.state.config.management_writes:
        raise WRITES_OFF
    key = idempotency_key(request)
    try:
        operations.prepare(
            operation=operation, cluster=cluster, request_id=uuid4(), payload=payload
        )
    except operations.BadPayload as refused:
        raise Refusal(400, "bad_input", str(refused)) from None
    with request.app.state.pool.connection() as connection:
        still_valid(connection, request, caller)
        try:
            job = db.queue_job(
                connection,
                operation=operation,
                cluster=cluster,
                payload=payload,
                idempotency_key=key,
                request_digest=request_digest(request, caller, body),
            )
        except db.ClusterBusy as busy:
            connection.rollback()
            raise busy_refusal("cluster_busy", busy, CLUSTER_BUSY) from None
        except db.CertificateBusy as busy:
            connection.rollback()
            raise busy_refusal("certificate_busy", busy, None) from None
        except db.RequestConflict:
            connection.rollback()
            raise KEY_REUSED from None
        #
        # A key the queue had already seen (two retries racing) queued nothing:
        # the history has the one row already.
        #
        if job.fresh:
            db.record_audit_event(
                connection,
                actor=caller.actor,
                action="queue_job",
                cluster=cluster,
                request_id=job.request_id,
                detail={"operation": operation, "job": job.id, "via": "api", **(detail or {})},
            )
        connection.commit()
    return accepted(request, job)
