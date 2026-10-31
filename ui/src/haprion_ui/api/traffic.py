"""The traffic log. Its rows carry visitors' addresses.

Every request row names the client that made it, its address in `client` and
what it asked for in `host` and `path`. A token that reads this route reads
what the Traffic logs page shows an administrator, so it is issued as
carefully as a login.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal

import psycopg
from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse
from haprion.proxy_model import NAME_BODY

from haprion_ui import objects, traffic_logs
from haprion_ui.api.answers import Refusal, answer
from haprion_ui.api.caller import Caller, in_scope, needs
from haprion_ui.reading import OBJECTS_SOURCE, listed_clusters, read_source
from haprion_ui.traffic_log_scope import log_scope

router = APIRouter(tags=["traffic"])

DEFAULT_LIMIT = 100
MAX_LIMIT = 1000
#
# The page reads everything the log keeps unless told otherwise, and a person
# is waiting for it. A script that polls would read the whole retention each
# time for a rare match, so a read without `from` is the last hour.
#
DEFAULT_WINDOW = timedelta(hours=1)


def moment(at: datetime) -> str:
    """ISO 8601 with an offset; a time that carries none is the database's UTC."""

    return (at if at.tzinfo is not None else at.replace(tzinfo=UTC)).isoformat()


def known_cluster(request: Request, cluster: str) -> None:
    """A cluster this installation does not list is answered as one outside the token's scope."""

    if cluster not in listed_clusters(request, request.app.state.config):
        raise Refusal(404, "not_found", "No such cluster or object.")


def _utc(at: datetime | None) -> datetime | None:
    return None if at is None else (at if at.tzinfo is not None else at.replace(tzinfo=UTC))


def _request(entry: traffic_logs.Entry) -> dict[str, Any]:
    name, _, mode = entry.rule.partition(":")
    return {
        "time": moment(entry.at),
        "node": entry.node,
        "request_number": entry.request,
        "client": entry.client,
        "method": entry.method,
        "host": entry.host,
        "path": entry.path,
        "frontend": entry.frontend,
        "backend": entry.backend,
        "server": entry.server,
        "status": entry.status,
        #
        # HAProxy's own timings in milliseconds, -1 where the request never
        # reached that phase.
        #
        "request_time": entry.request_time,
        "queue_time": entry.queue_time,
        "connect_time": entry.connect_time,
        "response_time": entry.response_time,
        "total_time": entry.total_time,
        "bytes": entry.bytes,
        "rule": entry.rule,
        "rule_name": name,
        "rule_action": ("denied" if mode == "deny" else "logged") if entry.rule else "",
        "termination": entry.termination,
        "ended": entry.ended,
    }


def _node(item: traffic_logs.Freshness) -> dict[str, Any]:
    last_attempt, last_success = _utc(item.last_attempt), _utc(item.last_success)
    return {
        "node": item.node,
        "last_attempt": moment(last_attempt) if last_attempt else None,
        "last_success": moment(last_success) if last_success else None,
        "outcome": item.outcome,
        "catching_up": item.catching_up(),
    }


@router.get("/clusters/{cluster}/traffic", name="traffic_list")
def traffic_list(
    request: Request,
    cluster: str,
    status: Annotated[str | None, Query(pattern=r"^([0-9]{3}|[0-9]xx)$")] = None,
    q: Annotated[str | None, Query(max_length=200)] = None,
    from_: Annotated[datetime | None, Query(alias="from")] = None,
    to: datetime | None = None,
    waf: Literal["hits", "none"] | None = None,
    object_: Annotated[str | None, Query(alias="object", pattern=rf"^{NAME_BODY}$")] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
    caller: Caller = Depends(needs("read")),  # noqa: B008
) -> JSONResponse:
    """Newest first. `from` and `to` are ISO 8601 (UTC where no offset is given); the window read is in the result."""

    in_scope(caller, cluster, object_)
    known_cluster(request, cluster)
    config = request.app.state.config
    from_at, to_at = _utc(from_), _utc(to)
    if from_at is not None and to_at is not None and from_at > to_at:
        raise Refusal(400, "bad_input", "from must be earlier than to.")
    #
    # A window wider than the retention is harmless: the table holds no more
    # than that. A missing end is now, a missing start an hour before the end.
    #
    to_shown = to_at or datetime.now(UTC)
    from_shown = from_at or to_shown - DEFAULT_WINDOW
    reading = traffic_logs.Reading((), (), 0, False)
    if config.traffic_logs.enabled:
        _, object_rows = read_source(request, config, OBJECTS_SOURCE, cluster=cluster)
        #
        # The filter reads an object the platform writes. A name that is none
        # of them would match nothing, and a script told "no 5xx" for a
        # mistyped name would believe it.
        #
        if object_ is not None and not any(
            view.name == object_
            for row in object_rows
            if row.cluster == cluster
            for view in objects.cluster_object_views(row)
        ):
            raise Refusal(404, "not_found", "No such cluster or object.")
        addresses, owned = log_scope(object_rows, cluster=cluster, selected_object=object_ or "")
        try:
            with request.app.state.pool.connection() as connection:
                #
                # One more than asked for, so a cut is known and not guessed.
                #
                reading = traffic_logs.read_database(
                    connection,
                    config.traffic_logs.directory,
                    listed_clusters(request, config),
                    limit=limit + 1,
                    cluster=cluster,
                    status=status or "",
                    substring=q or "",
                    from_at=from_shown,
                    to_at=to_at,
                    server_addresses=addresses,
                    waf=waf or "",
                    owned=owned,
                )
        except psycopg.errors.QueryCanceled:
            # The database's statement_timeout: a narrower window is the way on.
            raise Refusal(
                503,
                "query_timeout",
                "The query took too long; narrow from and to, or the search.",
            ) from None
        if reading.filter_error is not None:
            raise Refusal(400, "bad_input", reading.filter_error)
    return answer(
        request,
        {
            "enabled": config.traffic_logs.enabled,
            "from": moment(from_shown),
            "to": moment(to_shown),
            "requests": [_request(entry) for entry in reading.entries[:limit]],
            "truncated": len(reading.entries) > limit,
            "limit": limit,
            "nodes": [_node(item) for item in reading.nodes],
        },
        cluster=cluster,
    )
