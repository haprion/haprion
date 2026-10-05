"""The readers' arithmetic as it was before migrations 0048 and 0055, kept as the reference.

The readers now sum differences stored when each sample is written (0048), and
over long windows the hourly sums of those differences (0055). These are the
reads they replaced, verbatim, so the database integration test can run both
over the same rows - restarts, counters that go backwards, a frontend whose
holder moves, a window across the raw/rollup boundary - and require the same
answer to the last digit.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from psycopg import Connection, sql

from haproxy_ui import db, metrics


def backend_totals() -> sql.Composed:
    """Aggregate cumulative counters before drawing resolution can touch them.

    The recent or not-yet-rolled-up half reads every raw sample. The completed
    older half can only read the finest history that still exists, which is one
    cumulative reading per hour. The two are split on `observed_at`, so the
    boundary reading cannot occur in both halves.
    """

    names = tuple(name for name, _label in metrics.CARD_COUNTERS)
    columns = sql.SQL(", ").join(sql.Identifier(name) for name in names)
    previous = sql.SQL(", ").join(
        sql.SQL("lag({name}) over ordered as {before}").format(
            name=sql.Identifier(name), before=sql.Identifier(f"before_{name}")
        )
        for name in names
    )
    deltas = sql.SQL(", ").join(
        sql.SQL(
            "case when handed_over or {before} is null or {after} is null then null "
            "     when restarted then {after} "
            "     when {after} < {before} then null "
            "     else {after} - {before} end as {delta}"
        ).format(
            before=sql.Identifier(f"before_{name}"),
            after=sql.Identifier(name),
            delta=sql.Identifier(f"delta_{name}"),
        )
        for name in names
    )
    aggregates = sql.SQL(", ").join(
        sql.SQL(
            "coalesce(sum({delta}), 0)::bigint, "
            "coalesce(sum(span_sec) filter ("
            "    where {delta} is not null and not restarted and not handed_over"
            "), 0)"
        ).format(delta=sql.Identifier(f"delta_{name}"))
        for name in names
    )
    return sql.SQL(
        "with readings as ("
        "    select observed_at, uptime_sec, uptime_sec as floor_uptime_sec, node, {columns} "
        "      from metric_backend_member "
        "     where cluster = %(cluster)s and backend = %(backend)s "
        "       and member = %(member)s and observed_at >= %(since)s "
        "       and observed_at >= %(raw_from)s and observed_at <= %(until)s "
        "    union all "
        "    select observed_at, uptime_sec, floor_uptime_sec, node, {columns} "
        "      from metric_backend_hour "
        "     where cluster = %(cluster)s and backend = %(backend)s "
        "       and member = %(member)s "
        "       and bucket_at >= date_trunc('hour', %(since)s) "
        "       and bucket_at < %(raw_from)s and observed_at >= %(since)s "
        "       and observed_at < %(raw_from)s and observed_at <= %(until)s"
        "), paired as ("
        "    select observed_at as ended_at, "
        "           lag(observed_at) over ordered as started_at, "
        "           uptime_sec, floor_uptime_sec, node, {columns}, "
        "           lag(uptime_sec) over ordered as previous_uptime_sec, "
        "           lag(node) over ordered as previous_node, {previous} "
        "      from readings "
        "    window ordered as (partition by node order by observed_at)"
        "), marked as ("
        "    select *, "
        "           coalesce(floor_uptime_sec < previous_uptime_sec, false) as restarted, "
        "           (previous_node is not null and node is not null "
        "            and previous_node <> node) as handed_over, "
        "           extract(epoch from ended_at - started_at) as span_sec "
        "      from paired where started_at is not null"
        "), differences as ("
        "    select *, {deltas} from marked"
        ") "
        "select count(*)::bigint, min(started_at), max(ended_at), "
        "       coalesce(bool_or(restarted), false), "
        "       coalesce(bool_or(handed_over), false), "
        "       coalesce(sum(span_sec) filter (where not restarted and not handed_over), 0), "
        "       coalesce(sum(span_sec), 0), {aggregates} "
        "  from differences"
    ).format(columns=columns, previous=previous, deltas=deltas, aggregates=aggregates)


def frontend_totals(
    counters: tuple[tuple[str, str], ...] = metrics.CARD_COUNTERS, *, every_frontend: bool = False
) -> sql.Composed:
    """One frontend's figures, differenced at stored resolution.

    The same arithmetic `_backend_totals` performs, over one raw table instead of
    a raw and a rolled-up half: there is no frontend rollup to meet at a
    boundary, so there is no boundary to get wrong. The pairing is partitioned
    by node here as well, so `handed_over` cannot arise; the expression is kept
    identical rather than simplified away, so the two readers cannot drift into
    two ideas of what a measurable interval is.

    `every_frontend` sums every VIP frontend of the clusters in `%(clusters)s`
    instead of one - the dashboard's traffic, counted the way each card on the
    metrics page is. Each frontend is paired with its own readings only (the
    partition carries cluster and frontend), so for one frontend the answer is
    the same either way.
    """

    names = tuple(name for name, _label in counters)
    columns = sql.SQL(", ").join(sql.Identifier(name) for name in names)
    previous = sql.SQL(", ").join(
        sql.SQL("lag({name}) over ordered as {before}").format(
            name=sql.Identifier(name), before=sql.Identifier(f"before_{name}")
        )
        for name in names
    )
    deltas = sql.SQL(", ").join(
        sql.SQL(
            "case when handed_over or {before} is null or {after} is null then null "
            "     when restarted then {after} "
            "     when {after} < {before} then null "
            "     else {after} - {before} end as {delta}"
        ).format(
            before=sql.Identifier(f"before_{name}"),
            after=sql.Identifier(name),
            delta=sql.Identifier(f"delta_{name}"),
        )
        for name in names
    )
    aggregates = sql.SQL(", ").join(
        sql.SQL(
            "coalesce(sum({delta}), 0)::bigint, "
            "coalesce(sum(span_sec) filter ("
            "    where {delta} is not null and not restarted and not handed_over"
            "), 0)"
        ).format(delta=sql.Identifier(f"delta_{name}"))
        for name in names
    )
    return sql.SQL(
        "with readings as ("
        "    select cluster, frontend, observed_at, uptime_sec, "
        "           uptime_sec as floor_uptime_sec, node, {columns} "
        "      from metric_frontend "
        "     where {scope} "
        "       and owns_vip and observed_at >= %(since)s "
        "       and observed_at <= %(until)s"
        "), paired as ("
        "    select observed_at as ended_at, "
        "           lag(observed_at) over ordered as started_at, "
        "           uptime_sec, floor_uptime_sec, node, {columns}, "
        "           lag(uptime_sec) over ordered as previous_uptime_sec, "
        "           lag(node) over ordered as previous_node, {previous} "
        "      from readings "
        "    window ordered as (partition by cluster, frontend, node order by observed_at)"
        "), marked as ("
        "    select *, "
        "           coalesce(floor_uptime_sec < previous_uptime_sec, false) as restarted, "
        "           (previous_node is not null and node is not null "
        "            and previous_node <> node) as handed_over, "
        "           extract(epoch from ended_at - started_at) as span_sec "
        "      from paired where started_at is not null"
        "), differences as ("
        "    select *, {deltas} from marked"
        ") "
        "select count(*)::bigint, min(started_at), max(ended_at), "
        "       coalesce(bool_or(restarted), false), "
        "       coalesce(bool_or(handed_over), false), "
        "       coalesce(sum(span_sec) filter (where not restarted and not handed_over), 0), "
        "       coalesce(sum(span_sec), 0), {aggregates} "
        "  from differences"
    ).format(
        columns=columns,
        previous=previous,
        deltas=deltas,
        aggregates=aggregates,
        scope=sql.SQL(
            "cluster = any(%(clusters)s)"
            if every_frontend
            else "cluster = %(cluster)s and frontend = %(frontend)s"
        ),
    )


def _rolled_up() -> sql.Composed:
    """The hourly rollup, in the same shape the bucketed raw query returns (before 0055)."""

    columns = sql.SQL(", ").join(sql.Identifier(name) for name in metrics.METRIC_COUNTERS)
    return sql.SQL(
        "select bucket_at as at, observed_at, uptime_sec, floor_uptime_sec, node, {columns} "
        "  from metric_backend_hour "
        " where cluster = %(cluster)s and backend = %(backend)s "
        "   and member = %(member)s and bucket_at >= date_trunc('hour', %(since)s) "
        "   and bucket_at < %(raw_from)s and observed_at >= %(since)s "
        "   and observed_at < %(raw_from)s and observed_at <= %(until)s "
        " order by bucket_at, node"
    ).format(columns=columns)


def backend_series(
    connection: Connection[Any],
    *,
    cluster: str,
    backend: str,
    since: datetime,
    until: datetime,
    width: timedelta,
    raw_from: datetime,
    member: str = "BACKEND",
) -> list[metrics.Interval]:
    """`db.read_backend_series` before 0055: the rollup paired here, then the raw rows.

    `raw_from` is what `_backend_history_boundary` decided; the test passes
    where its raw rows begin.
    """

    arguments: dict[str, Any] = {
        "cluster": cluster,
        "backend": backend,
        "member": member,
        "since": since,
        "width": width,
        "raw_from": raw_from,
        "until": until,
        "after": since,
    }
    found: list[metrics.Interval] = []
    with connection.cursor() as cursor:
        if since < raw_from:
            cursor.execute(_rolled_up(), arguments)
            hours = [
                metrics.Sample(
                    observed_at=row[1],
                    member=member,
                    uptime_sec=row[2],
                    floor_uptime_sec=row[3],
                    node=row[4],
                    counters=dict(zip(metrics.METRIC_COUNTERS, row[5:], strict=True)),
                )
                for row in cursor.fetchall()
            ]
            found.extend(metrics.intervals(hours))
            if hours:
                arguments["after"] = max(sample.observed_at for sample in hours)
        cursor.execute(
            db._bucketed_changes(
                "metric_backend_member",
                sql.SQL("cluster = %(cluster)s and backend = %(backend)s and member = %(member)s"),
            ),
            arguments,
        )
        found.extend(db._changed_intervals(cursor.fetchall()))
    found.sort(key=lambda interval: (interval.ended_at, interval.started_at))
    return found
