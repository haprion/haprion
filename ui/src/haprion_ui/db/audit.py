"""The audit record and the nodes' events."""

from __future__ import annotations

from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from psycopg import Connection
from psycopg.rows import class_row
from psycopg.types.json import Jsonb

from haprion_ui import node_events
from haprion_ui.traffic_logs import like_pattern


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """One row of the record, as *Audit* and the Servers card read it (B275)."""

    id: int
    at: datetime
    actor: str | None
    action: str
    cluster: str | None
    request_id: UUID | None
    detail: dict[str, Any]


#
# What the worker writes about jobs it ran; their outcome is the Jobs view's,
# so *Audit* leaves them out (B275).
#
JOB_EVENTS = ("job_finished", "job_requeued", "job_abandoned", "job_adopted")


#
# How far back a free-text search reaches: `detail::text` cannot use an
# index, and a search that read the whole record would slow every page that
# shares the database (B275).
#
AUDIT_SEARCH_WINDOW_DAYS = 90


_AUDIT_WHERE = (
    " where not action = any(%(excluded)s) "
    "   and (%(actor)s = '' or actor = %(actor)s) "
    "   and (%(cluster)s = '' or cluster = %(cluster)s) "
    "   and (%(since)s::timestamptz is null or at >= %(since)s) "
    "   and (%(until)s::timestamptz is null or at <= %(until)s) "
    "   and (%(search)s = '' or ("
    "        at > statement_timestamp() - make_interval(days => %(window)s) "
    "        and (actor ilike %(like)s or action ilike %(like)s "
    "             or detail::text ilike %(like)s))) "
)


def _audit_filter(
    *,
    actor: str,
    cluster: str,
    search: str,
    since: datetime | None,
    until: datetime | None,
    excluded: Sequence[str],
) -> dict[str, Any]:
    return {
        "excluded": list(excluded),
        "actor": actor,
        "cluster": cluster,
        "since": since,
        "until": until,
        "search": search,
        "like": like_pattern(search),
        "window": AUDIT_SEARCH_WINDOW_DAYS,
    }


#
# What each sortable Audit heading orders by (26-10-11). The sentence under
# *What* is built from the action, so it groups by kind of event; a tie keeps
# the newest first. Names only - the direction is the caller's bool.
#
AUDIT_ORDER_COLUMNS: Mapping[str, str] = {
    "time": "id",
    "who": "actor",
    "what": "action",
    "where": "cluster",
}


def audit_events(
    connection: Connection[Any],
    *,
    order: str = "time",
    descending: bool = True,
    offset: int = 0,
    limit: int = 50,
    actor: str = "",
    cluster: str = "",
    search: str = "",
    since: datetime | None = None,
    until: datetime | None = None,
    excluded: Sequence[str] = JOB_EVENTS,
) -> list[AuditEvent]:
    """One page of the record, newest first (B275; pages as the traffic log's, 26-10-11)."""

    with connection.cursor(row_factory=class_row(AuditEvent)) as cursor:
        cursor.execute(
            "select id, at, actor, action, cluster, request_id, detail "  # noqa: S608 - constant
            "  from audit_event "
            + _AUDIT_WHERE
            + f" order by {AUDIT_ORDER_COLUMNS.get(order, 'id')} {'desc' if descending else 'asc'}"
            " nulls last, id desc limit %(limit)s offset %(offset)s",
            {
                **_audit_filter(
                    actor=actor,
                    cluster=cluster,
                    search=search,
                    since=since,
                    until=until,
                    excluded=excluded,
                ),
                "limit": max(1, min(limit, 500)),
                "offset": max(0, offset),
            },
        )
        return cursor.fetchall()


def audit_count(
    connection: Connection[Any],
    *,
    actor: str = "",
    cluster: str = "",
    search: str = "",
    since: datetime | None = None,
    until: datetime | None = None,
    excluded: Sequence[str] = JOB_EVENTS,
) -> int:
    """How many rows the same filter matches: the "of N" under the page."""

    with connection.cursor() as cursor:
        cursor.execute(
            "select count(*) from audit_event " + _AUDIT_WHERE,  # noqa: S608 - constant
            _audit_filter(
                actor=actor,
                cluster=cluster,
                search=search,
                since=since,
                until=until,
                excluded=excluded,
            ),
        )
        row = cursor.fetchone()
        return int(row[0]) if row else 0


@dataclass(frozen=True, slots=True)
class NodeEventsWritten:
    events: int
    joining: frozenset[str]


def record_node_events(
    connection: Connection[Any], *, cluster: str, result: Mapping[str, Any]
) -> NodeEventsWritten:
    """Compare one status reading with the state kept, and write what changed (*Events → Nodes*).

    One transaction with the state it replaces, so two passes can never both
    see the old state and both write the change. Returns how many events, and
    which nodes have not answered yet (B329).
    """

    with connection.cursor() as cursor:
        cursor.execute(
            "select kind, subject, value from node_event_state where cluster = %(cluster)s "
            "   for update",
            {"cluster": cluster},
        )
        previous = {(row[0], row[1]): row[2] for row in cursor.fetchall()}
        changes, state, gone = node_events.compare(previous, node_events.observe(result))
        if changes:
            cursor.executemany(
                "insert into node_event (at, cluster, node, event, subject, detail) "
                "values (transaction_timestamp() - make_interval(secs => %(ago)s), "
                "        %(cluster)s, %(node)s, %(event)s, %(subject)s, %(detail)s)",
                [
                    {
                        "ago": change.seconds_ago or 0,
                        "cluster": cluster,
                        "node": change.node,
                        "event": change.event,
                        "subject": change.subject,
                        "detail": Jsonb(dict(change.detail)),
                    }
                    for change in changes
                ],
            )
        changed = [(key, value) for key, value in state.items() if previous.get(key) != value]
        if changed:
            cursor.executemany(
                "insert into node_event_state (cluster, kind, subject, value) "
                "values (%(cluster)s, %(kind)s, %(subject)s, %(value)s) "
                "on conflict (cluster, kind, subject) do update set value = excluded.value",
                [
                    {"cluster": cluster, "kind": key[0], "subject": key[1], "value": value}
                    for key, value in changed
                ],
            )
        if gone:
            cursor.execute(
                "delete from node_event_state "
                " where cluster = %(cluster)s and kind = 'server' and subject = any(%(gone)s)",
                {"cluster": cluster, "gone": [key[1] for key in gone]},
            )
    return NodeEventsWritten(len(changes), node_events.joining(state))


@dataclass(frozen=True, slots=True)
class NodeEvent:
    id: int
    at: datetime
    cluster: str
    node: str
    event: str
    subject: str
    detail: dict[str, Any]


_NODE_EVENT_WHERE = (
    " where (%(cluster)s = '' or cluster = %(cluster)s) "
    "   and (%(since)s::timestamptz is null or at >= %(since)s) "
    "   and (%(until)s::timestamptz is null or at <= %(until)s) "
    "   and (%(search)s = '' or node ilike %(like)s or subject ilike %(like)s) "
)


NODE_EVENT_ORDER_COLUMNS: Mapping[str, str] = {
    "time": "at",
    "node": "node",
    "what": "event",
    "where": "cluster",
}


def _node_event_filter(
    *, cluster: str, search: str, since: datetime | None, until: datetime | None
) -> dict[str, Any]:
    return {
        "cluster": cluster,
        "since": since,
        "until": until,
        "search": search,
        "like": like_pattern(search),
    }


def node_event_page(
    connection: Connection[Any],
    *,
    order: str = "time",
    descending: bool = True,
    offset: int = 0,
    limit: int = 50,
    cluster: str = "",
    search: str = "",
    since: datetime | None = None,
    until: datetime | None = None,
) -> list[NodeEvent]:
    """One page of *Events → Nodes*, newest first, as *Audit* pages."""

    with connection.cursor(row_factory=class_row(NodeEvent)) as cursor:
        cursor.execute(
            "select id, at, cluster, node, event, subject, detail "  # noqa: S608 - constant
            "  from node_event "
            + _NODE_EVENT_WHERE
            + f" order by {NODE_EVENT_ORDER_COLUMNS.get(order, 'at')} "
            f"{'desc' if descending else 'asc'}, id desc limit %(limit)s offset %(offset)s",
            {
                **_node_event_filter(cluster=cluster, search=search, since=since, until=until),
                "limit": max(1, min(limit, 500)),
                "offset": max(0, offset),
            },
        )
        return cursor.fetchall()


def node_event_count(
    connection: Connection[Any],
    *,
    cluster: str = "",
    search: str = "",
    since: datetime | None = None,
    until: datetime | None = None,
) -> int:
    with connection.cursor() as cursor:
        cursor.execute(
            "select count(*) from node_event " + _NODE_EVENT_WHERE,  # noqa: S608 - constant
            _node_event_filter(cluster=cluster, search=search, since=since, until=until),
        )
        row = cursor.fetchone()
        return int(row[0]) if row else 0


def requested_by(connection: Connection[Any], request_ids: Collection[UUID]) -> dict[UUID, str]:
    """Who queued each of these jobs, from the `queue_job` row beside it (B275)."""

    if not request_ids:
        return {}
    with connection.cursor() as cursor:
        cursor.execute(
            "select distinct on (request_id) request_id, actor "
            "  from audit_event "
            " where action = 'queue_job' and request_id = any(%(ids)s) and actor is not null "
            " order by request_id, id",
            {"ids": list(request_ids)},
        )
        return {row[0]: row[1] for row in cursor.fetchall()}


def account_names(connection: Connection[Any]) -> frozenset[str]:
    """Every account's name, lowercased: what tells a known name from a typed one (B275)."""

    with connection.cursor() as cursor:
        cursor.execute("select username_normalised from app_user")
        return frozenset(str(row[0]) for row in cursor.fetchall())


@dataclass(frozen=True, slots=True)
class TakenOut:
    """The newest download or export of an external certificate (26-10-18)."""

    actor: str
    at: datetime
    fingerprint: str


def certificate_takeouts(connection: Connection[Any]) -> dict[str, TakenOut]:
    """Each external certificate's newest download or export, by certificate ID (0077)."""

    with connection.cursor() as cursor:
        cursor.execute(
            "select distinct on (detail->>'certificate') "
            "       detail->>'certificate', actor, at, detail->>'fingerprint_sha256' "
            "  from audit_event "
            " where action in ('certificate_export', 'certificate_download') "
            "   and detail->>'certificate' is not null "
            " order by detail->>'certificate', id desc"
        )
        return {
            str(certificate): TakenOut(str(actor), at, str(fingerprint or ""))
            for certificate, actor, at, fingerprint in cursor.fetchall()
        }


def server_state_events(
    connection: Connection[Any], *, cluster: str, object_name: str, limit: int = 200
) -> list[AuditEvent]:
    """The newest drains, maintenances and readies queued for one object's servers (B275)."""

    with connection.cursor(row_factory=class_row(AuditEvent)) as cursor:
        cursor.execute(
            "select id, at, actor, action, cluster, request_id, detail "
            "  from audit_event "
            " where cluster = %(cluster)s and action = 'queue_job' "
            "   and detail->>'operation' = 'server_state' "
            "   and detail->>'object' = %(object)s "
            " order by id desc "
            " limit %(limit)s",
            {"cluster": cluster, "object": object_name, "limit": limit},
        )
        return cursor.fetchall()


def record_audit_event(
    connection: Connection[Any],
    *,
    actor: str | None,
    action: str,
    cluster: str | None = None,
    request_id: UUID | None = None,
    detail: Mapping[str, Any] | None = None,
) -> None:
    """Append to the record.

    Written in the caller's transaction, which is the entire reason this module
    takes connections instead of opening them: an audit row that commits
    separately from the thing it describes is a history that can disagree with
    what happened.

    A job is recorded as queued once (review 26-10-29, Q05). A form sent again
    under its key gets back the job the first send queued, and every route that
    queues wrote the record a second time, saying it was queued twice. Asked
    here rather than in each route, so a route added later cannot forget it.
    The first send's row is committed with its job before the second is
    answered, since the second's insert waits on the key the first holds.
    """

    values = {
        "actor": actor,
        "action": action,
        "cluster": cluster,
        "request_id": request_id,
        "detail": Jsonb(dict(detail or {})),
    }
    with connection.cursor() as cursor:
        if action == "queue_job" and request_id is not None:
            cursor.execute(
                "insert into audit_event (actor, action, cluster, request_id, detail) "
                "select %(actor)s::text, %(action)s::text, %(cluster)s::text, "
                "       %(request_id)s::uuid, %(detail)s::jsonb "
                " where not exists (select 1 from audit_event "
                "                    where action = 'queue_job' "
                "                      and request_id = %(request_id)s::uuid)",
                values,
            )
            return
        #
        # A statement of its own: the worker, which may not read the record,
        # is refused one that names it in a read, whether or not it is run.
        #
        cursor.execute(
            "insert into audit_event (actor, action, cluster, request_id, detail) "
            "values (%(actor)s, %(action)s, %(cluster)s, %(request_id)s, %(detail)s)",
            values,
        )
