"""What the WAF found and counted."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from haprion import crs
from psycopg import Connection
from psycopg.rows import class_row
from psycopg.types.json import Jsonb


@dataclass(frozen=True, slots=True)
class WafFinding:
    """One rule's matches on one object and part of the request (Fas 21, B234)."""

    cluster: str
    object: str
    rule_id: int
    field: str
    requests: int
    clients: int
    last_seen: datetime
    matched: str
    paths: list[str]
    path_count: int


#
# The paths a finding lists, and the findings a page shows. Bounded so a scan
# that touched ten thousand paths with one rule is one row with its first
# twenty paths, not a page nobody can read; the count says there were more.
#
WAF_FINDING_PATHS = 20


WAF_FINDING_LIMIT = 500


def waf_findings(
    connection: Connection[Any], *, clusters: Sequence[str], since: datetime
) -> list[WafFinding]:
    """What the engine matched since then, per cluster, object, rule and field.

    Read from the counts kept as the matches arrive (0054), not from the
    matches themselves: an attack's hundred thousand rows are a few rows here.
    The window starts on the hour `since` falls in, which is how they are kept.
    """

    with connection.cursor(row_factory=class_row(WafFinding)) as cursor:
        cursor.execute(
            "with paths as ("
            "  select cluster, object, rule_id, field, "
            "         sum(requests)::int as requests, "
            "         max(last_seen) as last_seen, "
            "         (array_agg(matched order by last_seen desc))[1] as matched, "
            "         (array_agg(distinct path order by path))[1:%(paths)s] as paths, "
            "         count(distinct path)::int as path_count "
            "    from waf_finding_path "
            "   where cluster = any(%(clusters)s) and hour >= date_trunc('hour', %(since)s, 'UTC') "
            "     and (rule_id >= %(first)s or rule_id / 1000 = %(engine)s) "
            "   group by cluster, object, rule_id, field"
            "), clients as ("
            "  select cluster, object, rule_id, field, "
            "         count(distinct nullif(client, ''))::int as clients "
            "    from waf_finding_client "
            "   where cluster = any(%(clusters)s) and hour >= date_trunc('hour', %(since)s, 'UTC') "
            "     and (rule_id >= %(first)s or rule_id / 1000 = %(engine)s) "
            "   group by cluster, object, rule_id, field"
            ") "
            "select paths.cluster, paths.object, paths.rule_id, paths.field, paths.requests, "
            "       coalesce(clients.clients, 0) as clients, paths.last_seen, paths.matched, "
            "       paths.paths, paths.path_count "
            "  from paths left join clients using (cluster, object, rule_id, field) "
            " order by paths.cluster, paths.object, paths.last_seen desc "
            " limit %(limit)s",
            {
                "clusters": list(clusters),
                "since": since,
                "paths": WAF_FINDING_PATHS,
                "limit": WAF_FINDING_LIMIT,
                "first": WAF_RULE_FIRST,
                "engine": crs.ENGINE_RULE_FILE,
            },
        )
        return cursor.fetchall()


#
# The rule set's IDs start here; below are the exceptions' counters (B273),
# which count what was let through and are no finding, and the installation's
# own rules (crs.ENGINE_RULES, 1900xx), which are.
#
WAF_RULE_FIRST = 900000


@dataclass(frozen=True, slots=True)
class CounterScope:
    """What one exception covers, as its counter is read (review 26-10-11).

    Its counter's number is its place among the object's exceptions on the
    same rule, so a number can pass to another exception when one is removed;
    reading only within what this one covers - its field where it names one,
    its paths where it names any - keeps another's matches off its row.
    """

    cluster: str
    object: str
    counter: int
    field: str
    paths: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class WafCounted:
    """What one exception's counter counted within what it covers (B273)."""

    requests: int
    clients: int
    last_seen: datetime | None


def _counted_paths(paths: Sequence[str]) -> list[str]:
    """The paths as the collector stores them: the root also as `//`, which the counter counts."""

    return sorted({*paths, *(("//",) if "/" in paths else ())})


def waf_counted(
    connection: Connection[Any], *, scopes: Sequence[CounterScope], since: datetime
) -> dict[CounterScope, WafCounted]:
    """What each exception's counter counted since then, within what the exception covers.

    A path is compared as the collector stored it, the request's own path; one
    the engine reached through normalising (`/a/./b`, an encoded letter) is
    counted by the counter and left out here.
    """

    if not scopes:
        return {}
    listed = [
        {
            "id": index,
            "cluster": scope.cluster,
            "object": scope.object,
            "counter": scope.counter,
            "field": scope.field,
            "paths": _counted_paths(scope.paths),
        }
        for index, scope in enumerate(scopes)
    ]
    with connection.cursor() as cursor:
        cursor.execute(
            "with scope as ("
            "  select * from jsonb_to_recordset(%(scopes)s) "
            "    as s (id int, cluster text, object text, counter int, field text, paths text[])"
            ") "
            "select scope.id, "
            "  (select coalesce(sum(p.requests), 0)::int from waf_finding_path p "
            "    where p.cluster = scope.cluster and p.object = scope.object "
            "      and p.rule_id = scope.counter and p.hour >= date_trunc('hour', %(since)s, 'UTC') "
            "      and (scope.field = '' or p.field = scope.field) "
            "      and (cardinality(scope.paths) = 0 or p.path = any(scope.paths))), "
            "  (select count(distinct nullif(c.client, ''))::int from waf_finding_client c "
            "    where c.cluster = scope.cluster and c.object = scope.object "
            "      and c.rule_id = scope.counter and c.hour >= date_trunc('hour', %(since)s, 'UTC') "
            "      and (scope.field = '' or c.field = scope.field) "
            "      and (cardinality(scope.paths) = 0 or c.path = any(scope.paths))), "
            "  (select max(p.last_seen) from waf_finding_path p "
            "    where p.cluster = scope.cluster and p.object = scope.object "
            "      and p.rule_id = scope.counter and p.hour >= date_trunc('hour', %(since)s, 'UTC') "
            "      and (scope.field = '' or p.field = scope.field) "
            "      and (cardinality(scope.paths) = 0 or p.path = any(scope.paths))) "
            "  from scope",
            {"scopes": Jsonb(listed), "since": since},
        )
        rows = cursor.fetchall()
    return {
        scopes[index]: WafCounted(requests=requests, clients=clients, last_seen=last_seen)
        for index, requests, clients, last_seen in rows
    }


def deploys_carrying(
    connection: Connection[Any], *, cluster: str, moments: Sequence[datetime]
) -> dict[datetime, datetime]:
    """For each moment something was saved, when a deploy carrying it finished.

    The moment is when an exception was saved, which is not when it was
    published: a deploy in between rolls out the version before it (review
    26-10-11). So first the publish that took it - the first `changes_publish`
    created after the moment, which publishes everything saved for the cluster
    - and then the first deploy created after that publish finished, or that
    publish itself where it deployed (*Publish & deploy*, B257). A publish is
    one whose job was done or whose publish half was, as in `change_publishes`
    (review 26-10-13, D1). A deploy is `done` only,
    which is a deploy whose every node took the release and reloaded the WAF
    engine. A moment no such deploy has followed yet is left out, as is one
    published outside the job queue: unknown is not *Not working*.
    """

    if not moments:
        return {}
    with connection.cursor() as cursor:
        cursor.execute(
            "select moment, ("
            "  select min(deployed.finished_at) from job deployed "
            "   where deployed.cluster = %(cluster)s and deployed.state = 'done' "
            "     and ((deployed.operation = 'deploy' and deployed.created_at >= published.at) "
            "          or (deployed.operation = 'changes_publish' "
            "              and deployed.payload->>'deploy' = 'true' "
            "              and deployed.created_at >= moment "
            "              and deployed.finished_at >= published.at))"
            ") from unnest(%(moments)s::timestamptz[]) as asked(moment) "
            "cross join lateral ("
            "  select min(finished_at) as at from job "
            "   where cluster = %(cluster)s "
            "     and (state = 'done' or result->'publish'->>'outcome' = 'done') "
            "     and operation = 'changes_publish' and created_at >= moment"
            ") published",
            {"cluster": cluster, "moments": list(moments)},
        )
        return {moment: done for moment, done in cursor.fetchall() if done is not None}


def waf_verdicts(
    connection: Connection[Any], *, clusters: Sequence[str], since: datetime
) -> dict[tuple[str, str], tuple[int, int]]:
    """Per cluster and object: requests the engine judged an attack, and their clients.

    Read from the traffic record (`crs:log` or `crs:deny`, 0051) and the
    engine's transaction ID that names the object (`<object>.<uuid>`, 0052).
    """

    with connection.cursor() as cursor:
        cursor.execute(
            "select cluster, split_part(waf_id, '.', 1), count(*)::int, "
            "       count(distinct client)::int "
            "  from traffic_log_read "
            " where cluster = any(%(clusters)s) and occurred_at >= %(since)s "
            "   and rule in ('crs:log', 'crs:deny') and waf_id <> '' "
            " group by 1, 2",
            {"clusters": list(clusters), "since": since},
        )
        return {(row[0], row[1]): (row[2], row[3]) for row in cursor.fetchall()}


def waf_request_count(
    connection: Connection[Any], *, clusters: Sequence[str], since: datetime
) -> int:
    """Requests a rule met (an access rule or the engine), the WAF page's Requests tab.

    The same rows the tab lists (`rule <> ''`), counted over the page's days;
    each partition's partial index on `occurred_at` (0050) answers it.
    """

    with connection.cursor() as cursor:
        cursor.execute(
            "select count(*)::int from traffic_log_read "
            " where cluster = any(%(clusters)s) and occurred_at >= %(since)s and rule <> ''",
            {"clusters": list(clusters), "since": since},
        )
        row = cursor.fetchone()
        return int(row[0]) if row is not None else 0
