"""The traffic log. Its rows carry visitors' addresses.

Every request row names the client that made it, its address in `client` and
what it asked for in `host` and `path`. A token that reads this route reads
what the Traffic logs page shows an administrator, so it is issued as
carefully as a login.
"""

from __future__ import annotations

import base64
import re
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse
from haprion.proxy_model import NAME_BODY

from haprion_ui import objects, traffic_logs
from haprion_ui.api import contract
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


def _now() -> datetime:
    return datetime.now(UTC)


def known_cluster(request: Request, cluster: str) -> None:
    """A cluster this installation does not list is answered as one outside the token's scope."""

    if cluster not in listed_clusters(request, request.app.state.config):
        raise Refusal(404, "not_found", "No such cluster or object.")


#
# What a window may name. Beyond these Python or the database cannot hold the
# time once an hour is taken from it or an offset applied; no log reaches back
# before 1970 or past year 9999 (review 26-11-01, c-P3-7).
#
EARLIEST = datetime(1970, 1, 1, tzinfo=UTC)
LATEST = datetime(9999, 1, 1, tzinfo=UTC)


NODE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


def _cursor(entry: traffic_logs.Entry, from_shown: datetime) -> str:
    """The place after a row, as an opaque string.

    Its time, request number and node, and the start of the window it was cut
    from: a read without `from` starts an hour before now, and a next page that
    started an hour before a later now would drop the oldest rows (26-11-01).
    """

    text = f"{moment(from_shown)}|{moment(entry.at)}|{entry.request}|{entry.node}"
    return base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")


def _place(cursor: str | None) -> tuple[datetime, tuple[datetime, int, str]] | None:
    """The window start and the place a cursor holds; a 400 for anything this log did not give."""

    if cursor is None:
        return None
    try:
        text = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)).decode()
        start, at, request, node = text.split("|")
        number = int(request)
        if not NODE_NAME.fullmatch(node) or not 0 <= number < 2**63:
            raise ValueError(node)
        return datetime.fromisoformat(start), (datetime.fromisoformat(at), number, node)
    except ValueError:
        raise Refusal(400, "bad_input", "before is not a place this log gave.") from None


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


@router.get(
    "/clusters/{cluster}/traffic", name="traffic_list", responses=contract.responses("traffic_list")
)
def traffic_list(
    request: Request,
    cluster: str,
    status: Annotated[str | None, Query(pattern=r"^([0-9]{3}|[0-9]xx)$")] = None,
    q: Annotated[str | None, Query(max_length=200)] = None,
    from_: Annotated[datetime | None, Query(alias="from")] = None,
    to: datetime | None = None,
    waf: Literal["hits", "none"] | None = None,
    object_: Annotated[str | None, Query(alias="object", pattern=rf"^{NAME_BODY}$")] = None,
    before: Annotated[str | None, Query(max_length=300)] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
    caller: Caller = Depends(needs("read")),  # noqa: B008
) -> JSONResponse:
    """Newest first. `from` and `to` are ISO 8601 (UTC where no offset is given); the window read is in the result."""

    in_scope(caller, cluster, object_)
    known_cluster(request, cluster)
    config = request.app.state.config
    from_at, to_at = _utc(from_), _utc(to)
    for name, at in (("from", from_at), ("to", to_at)):
        if at is not None and not EARLIEST <= at < LATEST:
            raise Refusal(400, "bad_input", f"{name} is not a time the log can hold.")
    if from_at is not None and to_at is not None and from_at > to_at:
        raise Refusal(400, "bad_input", "from must be earlier than to.")
    #
    # A window wider than the retention is harmless: the table holds no more
    # than that. A missing end is now, a missing start an hour before the end.
    #
    held = _place(before)
    after = held[1] if held else None
    to_shown = to_at or _now()
    #
    # A page that follows another stays in the window the first one was cut
    # from, so the rows are each listed once however much later it is asked.
    #
    from_shown = from_at or (_utc(held[0]) if held else None) or to_shown - DEFAULT_WINDOW
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
        # Read before the connection is taken: a read holds one at a time (26-11-01).
        clusters = listed_clusters(request, config)
        with request.app.state.pool.connection() as connection:
            #
            # One more than asked for, so a cut is known and not guessed.
            #
            reading = traffic_logs.read_database(
                connection,
                config.traffic_logs.directory,
                clusters,
                limit=limit + 1,
                cluster=cluster,
                status=status or "",
                substring=q or "",
                from_at=from_shown,
                to_at=to_at,
                server_addresses=addresses,
                waf=waf or "",
                owned=owned,
                before=after,
            )
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
            # Where the next page begins: pass it as `before`.
            "next": _cursor(reading.entries[limit - 1], from_shown)
            if len(reading.entries) > limit
            else None,
            "limit": limit,
            "nodes": [_node(item) for item in reading.nodes],
        },
        cluster=cluster,
    )
