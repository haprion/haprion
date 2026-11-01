"""How the API asks for a change: one job in the queue, as the pages ask (B416, release 2-3).

Every route that changes something goes through `queue`, so each write is
the job a page would queue, run by the same worker and root helpers, and
answered `202` with the job to follow at `/api/v1/jobs/{id}`.

* **An `Idempotency-Key` header is required.** The same key asking for the
  same thing is the same job, so a client that retries after a lost answer
  does not do the work twice; the same key asking for something else is a
  `409`. The forms carry such a key for the same reason.
* **The token is judged again in the transaction that queues.** It was judged
  when the request arrived; a revocation committed since then stops the job
  from being queued (review 26-10-31, a-P3-5).
* **The history names the token**: `token:<name>` is the actor of the audit
  row beside the job.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from fastapi import Request
from fastapi.responses import JSONResponse

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


def queue(
    request: Request,
    caller: Caller,
    *,
    operation: str,
    cluster: str | None,
    payload: Mapping[str, Any],
    detail: Mapping[str, Any] | None = None,
) -> JSONResponse:
    """Queue `operation` for the caller, and answer `202` with the job.

    `payload` is checked as the worker will read it before anything is
    written. `detail` is what the audit row says beside the job - never a
    secret, a key or a document.
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
        token = db.api_token_by_hash(connection, caller.digest)
        verdict = api_tokens.evaluate(token, now=datetime.now(UTC), source=caller.source)
        if not verdict.usable:
            logger.warning(
                "api: %s %s from %s refused before queueing: %s (token %s)",
                request.method,
                request.url.path,
                caller.source,
                verdict.reason,
                caller.issued.name,
            )
            raise NOT_VALID
        try:
            job = db.queue_job(
                connection,
                operation=operation,
                cluster=cluster,
                payload=payload,
                idempotency_key=key,
            )
        except db.ClusterBusy:
            connection.rollback()
            raise Refusal(
                409,
                "cluster_busy",
                "Another job runs on this cluster; try again when it has finished.",
                headers={"Retry-After": "30"},
            ) from None
        except db.CertificateBusy as busy:
            connection.rollback()
            raise Refusal(
                409,
                "certificate_busy",
                refusals.conflict_sentence(busy),
                headers={"Retry-After": "30"},
            ) from None
        except db.RequestConflict:
            connection.rollback()
            raise Refusal(
                409,
                "idempotency_conflict",
                f"This {IDEMPOTENCY_HEADER} was used for another change; use a new one.",
            ) from None
        db.record_audit_event(
            connection,
            actor=caller.actor,
            action="queue_job",
            cluster=cluster,
            request_id=job.request_id,
            detail={"operation": operation, "job": job.id, "via": "api", **(detail or {})},
        )
        connection.commit()
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
        cluster=cluster,
        status=202,
    )
    response.headers["Location"] = follow
    return response
