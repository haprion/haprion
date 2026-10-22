"""The traffic counters and the series and totals drawn from them."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from haprion.generate import METRICS_FRONTEND
from psycopg import Connection, sql

from haprion_ui import metrics


def record_metric_samples(
    connection: Connection[Any],
    *,
    cluster: str,
    result: Mapping[str, Any],
) -> int:
    """Append one poll's samples. Returns how many rows were written.

    Append, never replace, which is what separates these tables from every
    cache above: a cache answers what is true now and a sample answers what was
    true then, and rewriting the second would destroy the only thing it is for.

    `observed_at` appears in neither statement. The database sets it from
    `transaction_timestamp()`, so every row of one poll carries the same
    instant and none of them can be written to look fresher than the read that
    produced it - the same reason the caches leave it out, for a different
    consequence.

    It is the *transaction's* timestamp and not the statement's, and that was a
    correction rather than a design: `executemany` sends one statement per row,
    so the first release to write samples spread one poll across microseconds.
    Migration 0019 has the measurement. This function's single commit is what
    makes the guarantee hold, so a caller that splits the write into two
    transactions breaks it.

    Nothing here is idempotent and nothing needs to be. Two polls a second
    apart are two measurements, not one measurement written twice; the primary
    key includes the timestamp precisely so both survive.
    """

    frontends, members = metrics.samples(result)
    member_columns = (*metrics.METRIC_COUNTERS, *metrics.DNS_COUNTERS, *metrics.SYSLOG_COUNTERS)
    if not frontends and not members:
        return 0

    with connection.cursor() as cursor:
        if frontends:
            cursor.executemany(
                _sample_insert("metric_frontend", ("node", "frontend", "owns_vip")),
                [
                    {
                        "cluster": cluster,
                        "node": sample.node,
                        "frontend": sample.frontend,
                        "owns_vip": sample.owns_vip,
                        "uptime_sec": sample.uptime_sec,
                        "counters_kept": sample.counters_kept,
                        "status": sample.status,
                        **_counter_values(sample.counters),
                    }
                    for sample in frontends
                ],
            )
        if members:
            cursor.executemany(
                _sample_insert(
                    "metric_backend_member",
                    ("node", "backend", "member", "check_status", "check_code"),
                    member_columns,
                ),
                [
                    {
                        "cluster": cluster,
                        "node": sample.node,
                        "backend": sample.backend,
                        "member": sample.member,
                        "check_status": sample.check_status,
                        "check_code": sample.check_code,
                        "uptime_sec": sample.uptime_sec,
                        "counters_kept": sample.counters_kept,
                        "status": sample.status,
                        **_counter_values(sample.counters, member_columns),
                    }
                    for sample in members
                ],
            )

    return len(frontends) + len(members)


def _sample_insert(
    table: str,
    identifying: tuple[str, ...],
    counters: tuple[str, ...] = metrics.METRIC_COUNTERS,
) -> sql.Composed:
    """The insert for one sample table, composed rather than formatted.

    Every name here is a literal from this module - the table, the identifying
    columns and `metrics.METRIC_COUNTERS` - so there is nothing a caller could
    put in one. It is composed through `psycopg.sql` anyway, because the way to
    know that stays true is for the code to be unable to express the other
    thing rather than for a reader to check that it does not.

    Columns are named one at a time, including where that is every column. The
    grants are written column by column for the same reason: a statement that
    named the table alone would silently widen the next time one is added.
    """

    columns = ("cluster", *identifying, "uptime_sec", "counters_kept", "status", *counters)
    return sql.SQL("insert into {table} ({columns}) values ({values})").format(
        table=sql.Identifier(table),
        columns=sql.SQL(", ").join(sql.Identifier(name) for name in columns),
        values=sql.SQL(", ").join(sql.Placeholder(name) for name in columns),
    )


def _counter_values(
    counters: Mapping[str, int], names: tuple[str, ...] = metrics.METRIC_COUNTERS
) -> dict[str, int | None]:
    """Every counter column, with the ones this row did not report as None.

    `executemany` needs every placeholder present in every row, and the missing
    ones must arrive as null rather than be left out or defaulted to zero.
    """

    return {name: counters.get(name) for name in names}


#
# The fixed grid every drawing is measured from, stated in UTC. A bare
# `timestamptz '2000-01-01'` is read in the session's time zone, and the
# installation's server runs in local time: the six-hour buckets then began at
# 23, 05, 11 and 17 UTC while the drawing's grid (`metrics.BUCKET_EPOCH`) began
# at 00, 06, 12 and 18 - measured 2026-10-04, with a day's load test drawn
# into the wrong bucket.
#
BUCKET_EPOCH_SQL = sql.SQL("timestamptz '2000-01-01 00:00:00+00'")


def _bucketed_changes(table: str, scope: sql.Composable) -> sql.Composed:
    """A series' stored changes (0048), summed per node and bucket, as intervals.

    **The graph sums what the figures sum.** It used to keep one cumulative
    reading per bucket and difference neighbouring buckets, and a restart is
    where that goes wrong: the reading kept is the newest process's, so a
    reload late in a bucket erased everything counted before it in the same
    bucket. Measured 2026-10-04: a load test of 28 998 requests at 17:44 UTC,
    reloads at 17:05 and 19:05, and the 30-day graph drew nothing where the
    figures beside it counted every request. Summing the per-sample changes
    loses at most the one sample a restart cuts, whatever the bucket's width.

    A sample whose pair lies in an earlier bucket is kept as its own interval,
    so the drawing shares it out over the time it covers - a poll that was late
    by an hour is an hour of traffic, not a spike in one bucket. The rest of the
    bucket's samples lie inside it and are one interval.

    An interval belongs to the range when it starts inside it - the totals'
    rule, so the first sample, which has nothing in the range to pair with,
    adds nothing to either.
    """

    bucket = sql.SQL("date_bin(%(width)s, observed_at, {epoch})").format(epoch=BUCKET_EPOCH_SQL)
    sums = sql.SQL(", ").join(
        sql.SQL("sum({delta})::bigint").format(delta=sql.Identifier(f"delta_{name}"))
        for name in _deltas(table)
    )
    return sql.SQL(
        "select min(previous_at), max(observed_at), coalesce(bool_or(restarted), false), {sums} "
        "  from {table} "
        " where {scope} and observed_at <= %(until)s "
        "   and previous_at >= %(after)s and observed_at > %(after)s "
        " group by node, {bucket}, previous_at < {bucket} "
        " order by {bucket}, node"
    ).format(sums=sums, table=sql.Identifier(table), scope=scope, bucket=bucket)


def _changed_intervals(rows: Sequence[Any], names: tuple[str, ...]) -> list[metrics.Interval]:
    """Rows of `_bucketed_changes` or `_hour_series`; `names` is that table's `_deltas`."""

    return [
        metrics.Interval(
            started_at=row[0],
            ended_at=row[1],
            counters={
                name: None if value is None else int(value)
                for name, value in zip(names, row[3:], strict=True)
            },
            restarted=bool(row[2]),
        )
        for row in rows
    ]


@dataclass(frozen=True, slots=True)
class EarlierName:
    """A name a backend had before, and until when its readings are the backend's.

    `until` is null while nobody has given the name to another backend.
    """

    name: str
    until: datetime | None = None


def _history(backend: str, earlier: Sequence[EarlierName]) -> dict[str, list[Any]]:
    """`%(backends)s` and `%(cutoffs)s` for the history scopes: the current name first."""

    names = [backend, *(item.name for item in earlier if item.name != backend)]
    cutoffs = [None, *(item.until for item in earlier if item.name != backend)]
    return {"backends": names, "cutoffs": cutoffs}


def read_backend_aliases(
    connection: Connection[Any], *, cluster: str
) -> dict[str, list[EarlierName]]:
    """Every backend's earlier names in one cluster, followed through each rename.

    `a` renamed `b` and then `c` gives `c` both. A chain that came back on
    itself would never end; a name is visited once.
    """

    with connection.cursor() as cursor:
        cursor.execute(
            "select old_name, new_name, reused_at from metric_backend_alias "
            " where cluster = %(cluster)s",
            {"cluster": cluster},
        )
        rows = cursor.fetchall()
    into: dict[str, list[tuple[str, datetime | None]]] = {}
    for old, new, reused in rows:
        into.setdefault(new, []).append((old, reused))
    found: dict[str, list[EarlierName]] = {}
    for current in into:
        seen = {current}
        pending: list[tuple[str, datetime | None]] = [(current, None)]
        names: list[EarlierName] = []
        while pending:
            name, cutoff = pending.pop()
            for old, reused in into.get(name, ()):
                if old in seen:
                    continue
                seen.add(old)
                bound = min((at for at in (cutoff, reused) if at is not None), default=None)
                names.append(EarlierName(old, bound))
                pending.append((old, bound))
        found[current] = names
    return found


def record_backend_renames(
    connection: Connection[Any],
    *,
    cluster: str,
    renamed: Mapping[str, str],
    introduced: Iterable[str],
) -> None:
    """Write down a publish's renames, and close the earlier names it gives out again.

    `renamed` maps an old backend name to its new one; `introduced` is every
    name the publish brings into use. A name that was renamed away and is now
    given to a backend again stops counting for the renamed card from now on.
    """

    with connection.cursor() as cursor:
        cursor.execute(
            "update metric_backend_alias set reused_at = statement_timestamp() "
            " where cluster = %(cluster)s and old_name = any(%(introduced)s) "
            "   and reused_at is null",
            {"cluster": cluster, "introduced": list(introduced)},
        )
        for old, new in renamed.items():
            cursor.execute(
                "insert into metric_backend_alias (cluster, old_name, new_name) "
                "values (%(cluster)s, %(old)s, %(new)s) "
                "on conflict (cluster, old_name) do update "
                "   set new_name = excluded.new_name, renamed_at = statement_timestamp(), "
                "       reused_at = null",
                {"cluster": cluster, "old": old, "new": new},
            )


def read_backend_series(
    connection: Connection[Any],
    *,
    cluster: str,
    backend: str,
    since: datetime,
    until: datetime,
    width: timedelta,
    member: str = "BACKEND",
    earlier: Sequence[EarlierName] = (),
) -> list[metrics.Interval]:
    """What one backend did, as intervals for its card's drawing, oldest first.

    `BACKEND` by default, which is HAProxy's own aggregate row for the backend -
    the sum across its servers, counted by the thing doing the balancing rather
    than added up here. A caller that wants one server names it.

    A window longer than a day, drawn in whole hours, is read from the hourly
    sums (migration 0055) with the hours at its edges read raw; anything
    shorter reads the raw samples. Both hold the same stored differences, so
    the drawing is the same either way.
    """

    arguments: dict[str, Any] = {
        "cluster": cluster,
        "member": member,
        "width": width,
        "until": until,
        "after": since,
        **_history(backend, earlier),
    }
    with connection.cursor() as cursor:
        if _reads_hours(since, until, width):
            cursor.execute(
                _hour_series(
                    "metric_backend_hour_delta",
                    "metric_backend_member",
                    BACKEND_HOUR_SCOPE,
                    BACKEND_SCOPE,
                ),
                arguments,
            )
        else:
            cursor.execute(_bucketed_changes("metric_backend_member", BACKEND_SCOPE), arguments)
        return _changed_intervals(cursor.fetchall(), BACKEND_DELTAS)


def read_frontend_series(
    connection: Connection[Any],
    *,
    cluster: str,
    frontend: str,
    since: datetime,
    until: datetime,
    width: timedelta,
) -> list[metrics.Interval]:
    """What one VIP frontend did, as intervals for its card's drawing, oldest first.

    **The VIP is what listens, so the series is the VIP's.** Every node reports
    its own frontends, but only the node holding the address receives anything
    on it; its peer binds the same ports and sits flat. Only the samples on
    which a node held the address count, and each stored its change from that
    node's previous such sample (0048) - which is also what keeps a failover
    from being read as one node's lifetime total. Long windows read the hourly
    sums of the same changes (0055), which keep 31 days.
    """

    arguments = {
        "cluster": cluster,
        "frontend": frontend,
        "width": width,
        "until": until,
        "after": since,
    }
    with connection.cursor() as cursor:
        if _reads_hours(since, until, width):
            cursor.execute(
                _hour_series(
                    "metric_frontend_hour_delta", "metric_frontend", FRONTEND_SCOPE, FRONTEND_HELD
                ),
                arguments,
            )
        else:
            cursor.execute(_bucketed_changes("metric_frontend", FRONTEND_HELD), arguments)
        return _changed_intervals(cursor.fetchall(), STORED_DELTAS)


#
# What counts as the cluster's newest poll: every row within this of the
# newest one. A poll writes all of a cluster's rows within a few seconds
# (measured at 2-3 s for a whole pass), so a minute holds one poll and never the
# one before it at the shortest interval the poller allows (10 s plus the pass).
#
NEWEST_POLL = timedelta(minutes=1)


def _active(table: str) -> sql.Composed:
    """The rows of the cluster's newest poll inside the window (2026-10-06).

    The page shows what HAProxy runs now, as the exporter does: a backend a
    rename or a removal took away is not listed, whatever history it has. Its
    readings are the newest poll's rather than the last minute's by the clock,
    so a poller that has stopped leaves the page as it last was instead of
    empty - an outage is the moment this page is opened.
    """

    #
    # The last ten minutes first, which is where the newest poll is whenever
    # the poller runs, and a few hundred rows; the whole window only when that
    # finds nothing. `coalesce` evaluates its second argument only then.
    #
    return sql.SQL(
        "{table}.observed_at >= coalesce("
        "    (select max(recent.observed_at) from {table} as recent "
        "      where recent.cluster = %(cluster)s "
        "        and recent.observed_at >= greatest(%(since)s, %(until)s - interval '10 minutes') "
        "        and recent.observed_at <= %(until)s), "
        "    (select max(newest.observed_at) from {table} as newest "
        "      where newest.cluster = %(cluster)s "
        "        and newest.observed_at >= %(since)s and newest.observed_at <= %(until)s)"
        ") - %(newest_poll)s"
    ).format(table=sql.Identifier(table))


def read_cluster_frontends(
    connection: Connection[Any], *, cluster: str, since: datetime, until: datetime
) -> list[tuple[str, bool]]:
    """Which VIP frontends this cluster serves now, and whether any node held each.

    Asked of the samples rather than of the configuration, and of the newest
    poll's (`_active`): a frontend that is gone is not listed, and one added this
    morning appears with its first reading whatever the document says.

    **Existing and being held are two questions, and asking them as one hid
    rows the table had.** `owns_vip` is `boolean` and nullable: false is "this
    node did not hold the address", and null is "this node could not say" - an
    older status script, or a `vip` block that would not read. `where
    owns_vip` is false for null, so filtering the list by it removed the whole
    address from the page while its rows sat in the table, and the page then
    said it had no samples. It also went blank during a total outage, when
    nothing holds the address at all - which is the one moment this page is
    opened.

    So the address is listed whenever anything was recorded for it, and
    ownership travels beside it as its own answer. The card is still drawn from
    the owner's readings; what changed is that an address with none of them
    says so instead of vanishing.

    This is also what reads the non-owning node's rows. They are written every
    poll, and until now nothing looked at them.
    """

    with connection.cursor() as cursor:
        cursor.execute(
            sql.SQL(
                "select frontend, coalesce(bool_or(owns_vip), false) from metric_frontend "
                " where cluster = %(cluster)s "
                "   and observed_at >= %(since)s and observed_at <= %(until)s and {active} "
                " group by frontend order by frontend"
            ).format(active=_active("metric_frontend")),
            {"cluster": cluster, "since": since, "until": until, "newest_poll": NEWEST_POLL},
        )
        return [(row[0], bool(row[1])) for row in cursor.fetchall()]


def read_cluster_backends(
    connection: Connection[Any],
    *,
    cluster: str,
    since: datetime,
    until: datetime,
    kind: str = "haproxy",
) -> list[str]:
    """Which backends this cluster serves now, by the runtime's own names.

    The newest poll's (`_active`): a pool renamed or removed is not listed,
    though its history is kept until retention takes it.

    `BACKEND` only - HAProxy's aggregate row for each backend, which is what the
    comparison is between. A per-server breakdown is a different question and
    belongs on the backend it is asked about, not on a page comparing backends.

    `kind` is `haproxy` for HAProxy's backends, `dns` for dnsdist's pools or
    `syslog` for IPVS's: told apart by the counters on the pool's own row
    (0057, 0061), since each counts something different.
    """

    which = POOL_KINDS[kind]

    with connection.cursor() as cursor:
        cursor.execute(
            sql.SQL(
                "select distinct backend from metric_backend_member "
                " where cluster = %(cluster)s and member = 'BACKEND' "
                "   and {which} "
                "   and observed_at >= %(since)s and observed_at <= %(until)s and {active} "
                " order by backend"
            ).format(active=_active("metric_backend_member"), which=which),
            {"cluster": cluster, "since": since, "until": until, "newest_poll": NEWEST_POLL},
        )
        return [row[0] for row in cursor.fetchall()]


#
# Which pools a kind is, by the counter only its pool's own row carries.
#
POOL_KINDS = {
    "haproxy": sql.SQL("dns_queries is null and syslog_messages is null"),
    "dns": sql.SQL("dns_queries is not null"),
    "syslog": sql.SQL("syslog_messages is not null"),
}


#
# The counters migration 0048 stores a difference for. A figure is only ever
# summed from these; a test holds the card's and the dashboard's lists to it.
#
STORED_DELTAS = (
    "req_tot",
    "hrsp_2xx",
    "hrsp_3xx",
    "hrsp_4xx",
    "hrsp_5xx",
    "econ",
    "wretr",
    "bin",
    "bout",
)


#
# A backend row's differences add dnsdist's (migration 0057) and IPVS's (0061);
# a frontend's do not.
#
BACKEND_DELTAS = (*STORED_DELTAS, *metrics.DNS_COUNTERS, *metrics.SYSLOG_COUNTERS)


def _deltas(table: str) -> tuple[str, ...]:
    """The differences a metrics table stores: a backend's include dnsdist's and IPVS's."""

    return BACKEND_DELTAS if table.startswith("metric_backend") else STORED_DELTAS


def _interval_aggregates(names: Sequence[str], *, by_cluster: bool = False) -> sql.Composed:
    """The one aggregate both readers end in, over rows shaped as intervals.

    Each row is one interval: `started_at`, `ended_at`, `restarted`,
    `handed_over`, `span_sec` and `delta_<counter>`. The columns come out in the
    order `_measurement` reads them.
    """

    per_counter = sql.SQL(", ").join(
        sql.SQL(
            "coalesce(sum({delta}), 0)::bigint, "
            "coalesce(sum(span_sec) filter ("
            "    where {delta} is not null and not restarted and not handed_over"
            "), 0)"
        ).format(delta=sql.Identifier(f"delta_{name}"))
        for name in names
    )
    return sql.SQL(
        "select {cluster}count(*)::bigint, min(started_at), max(ended_at), "
        "       coalesce(bool_or(restarted), false), "
        "       coalesce(bool_or(handed_over), false), "
        "       coalesce(sum(span_sec) filter (where not restarted and not handed_over), 0), "
        "       coalesce(sum(span_sec), 0), {per_counter} "
    ).format(per_counter=per_counter, cluster=sql.SQL("cluster, " if by_cluster else ""))


def _stored_intervals(names: Sequence[str]) -> sql.Composed:
    """The interval columns of a raw row, read from what migration 0048 stored."""

    return sql.SQL(
        "previous_at as started_at, observed_at as ended_at, restarted, "
        "false as handed_over, extract(epoch from observed_at - previous_at) as span_sec, {deltas}"
    ).format(deltas=sql.SQL(", ").join(sql.Identifier(f"delta_{name}") for name in names))


def _backend_totals(
    counters: tuple[tuple[str, str], ...] = metrics.CARD_COUNTERS,
) -> sql.Composed:
    """One backend's figures over raw samples, summed from the stored differences.

    Each raw sample carries what every counter did since the series' previous
    sample on that node, decided when it was written (migration 0048). An
    interval belongs to the range when it starts inside it, so the first
    sample in the range - which has nothing in the range to pair with - adds
    nothing. Windows longer than a day are read from the hourly sums instead
    (`_hour_totals`), which hold the same differences.
    """

    names = [name for name, _label in counters]
    return sql.SQL(
        "with intervals as ("
        "    select {stored} "
        "      from metric_backend_member "
        "     where {scope} "
        "       and observed_at >= %(since)s and observed_at <= %(until)s "
        "       and previous_at >= %(since)s"
        ") "
        "{aggregates} from intervals"
    ).format(
        stored=_stored_intervals(names),
        aggregates=_interval_aggregates(names),
        scope=BACKEND_SCOPE,
    )


#
# Windows longer than this are read from the hourly sums (migration 0055) when
# their buckets are whole hours. A day and shorter keep reading the raw rows:
# their buckets are minutes, and the rows are few.
#
HOURLY_FROM = timedelta(days=1)


HOUR = timedelta(hours=1)


def _reads_hours(since: datetime, until: datetime, width: timedelta | None = None) -> bool:
    if until - since <= HOURLY_FROM:
        return False
    return width is None or (width >= HOUR and width % HOUR == timedelta(0))


def _hour_pieces(
    hours: str, raw: str, scope: sql.Composable, raw_scope: sql.Composable
) -> sql.Composed:
    """A range's samples as hour rows where whole, and as raw rows where not.

    An hour row (migration 0055) counts whole when every sample in it lies in
    the range: its earliest pair at or after the start and its latest sample at
    or before the end. A crossing row is one sample, so that test is exact for
    it either way. An ordinary row that is not whole - the hour the range
    starts or ends in - is read from the raw rows of that hour and node instead,
    with the raw readers' own filters, which is at most two hours a node.

    Every piece has the hour table's columns, so the series and the figures
    aggregate pieces exactly as they would aggregate samples.

    An edge row is read back from the raw rows of its own series. A card that
    reads a renamed backend's earlier names too (`metric_backend_alias`) has
    several series in one hour on one node, and an edge matched by node alone
    would read each of their raw rows once per series.
    """

    key = sql.Identifier("backend" if hours == "metric_backend_hour_delta" else "frontend")
    names = _deltas(hours)

    deltas = sql.SQL(", ").join(
        sql.SQL("{delta}, {span}").format(
            delta=sql.Identifier(f"delta_{name}"), span=sql.Identifier(f"span_{name}_sec")
        )
        for name in names
    )
    return sql.SQL(
        "with hours as ("
        "    select node, hour as at, crossing, first_previous_at, last_observed_at, restarted, "
        "           samples, span_sec, span_clean_sec, {deltas}, {key} as series "
        "      from {hours} "
        "     where {scope} and hour >= date_trunc('hour', %(after)s::timestamptz, 'UTC') "
        "       and hour <= %(until)s"
        "), pieces as ("
        "    select * from hours "
        "     where first_previous_at >= %(after)s and last_observed_at <= %(until)s"
        "    union all "
        "    select edge.node, part.observed_at, false, part.previous_at, part.observed_at, "
        "           part.restarted, 1, extract(epoch from part.observed_at - part.previous_at), "
        "           case when part.restarted then 0 "
        "                else extract(epoch from part.observed_at - part.previous_at) end, "
        "           {raw_deltas_part}, edge.series "
        "      from hours as edge "
        "      cross join lateral ("
        "          select observed_at, previous_at, restarted, {raw_deltas} "
        "            from {raw} "
        "           where {raw_scope} and node = edge.node and {key} = edge.series "
        "             and observed_at >= edge.at and observed_at < edge.at + interval '1 hour' "
        "             and previous_at >= edge.at and previous_at >= %(after)s "
        "             and observed_at > %(after)s and observed_at <= %(until)s"
        "      ) as part "
        "     where not edge.crossing "
        "       and not (edge.first_previous_at >= %(after)s and edge.last_observed_at <= %(until)s)"
        ") "
    ).format(
        deltas=deltas,
        key=key,
        hours=sql.Identifier(hours),
        raw=sql.Identifier(raw),
        scope=scope,
        raw_scope=raw_scope,
        raw_deltas=sql.SQL(", ").join(
            sql.SQL("{delta}, {raw_span} as {span}").format(
                delta=sql.Identifier(f"delta_{name}"),
                raw_span=sql.SQL(
                    "case when {delta} is not null and not restarted "
                    "then extract(epoch from observed_at - previous_at) else 0 end"
                ).format(delta=sql.Identifier(f"delta_{name}")),
                span=sql.Identifier(f"span_{name}_sec"),
            )
            for name in names
        ),
        raw_deltas_part=sql.SQL(", ").join(
            sql.SQL("part.{delta}, part.{span}").format(
                delta=sql.Identifier(f"delta_{name}"), span=sql.Identifier(f"span_{name}_sec")
            )
            for name in names
        ),
    )


def _hour_series(
    hours: str, raw: str, scope: sql.Composable, raw_scope: sql.Composable
) -> sql.Composed:
    """`_bucketed_changes` over hour pieces: the same groups, the same columns.

    A raw sample is grouped by node, bucket and whether its pair lies in an
    earlier bucket. Every bucket here is whole hours, so a piece's hour is in
    the bucket its samples are in, and only a crossing piece - one sample - can
    have its pair before the bucket.
    """

    bucket = sql.SQL("date_bin(%(width)s, at, {epoch})").format(epoch=BUCKET_EPOCH_SQL)
    sums = sql.SQL(", ").join(
        sql.SQL("sum({delta})::bigint").format(delta=sql.Identifier(f"delta_{name}"))
        for name in _deltas(hours)
    )
    return sql.SQL(
        "{pieces}"
        "select min(first_previous_at), max(last_observed_at), "
        "       coalesce(bool_or(restarted), false), {sums} "
        "  from pieces "
        " group by node, {bucket}, crossing and first_previous_at < {bucket} "
        " order by {bucket}, node"
    ).format(pieces=_hour_pieces(hours, raw, scope, raw_scope), sums=sums, bucket=bucket)


def _hour_totals(
    hours: str,
    raw: str,
    scope: sql.Composable,
    raw_scope: sql.Composable,
    counters: tuple[tuple[str, str], ...] = metrics.CARD_COUNTERS,
) -> sql.Composed:
    """`_interval_aggregates` over hour pieces: the columns `_measurement` reads."""

    per_counter = sql.SQL(", ").join(
        sql.SQL("coalesce(sum({delta}), 0)::bigint, coalesce(sum({span}), 0)").format(
            delta=sql.Identifier(f"delta_{name}"), span=sql.Identifier(f"span_{name}_sec")
        )
        for name, _label in counters
    )
    return sql.SQL(
        "{pieces}"
        "select coalesce(sum(samples), 0)::bigint, min(first_previous_at), max(last_observed_at), "
        "       coalesce(bool_or(restarted), false), false, "
        "       coalesce(sum(span_clean_sec), 0), coalesce(sum(span_sec), 0), {per_counter} "
        "  from pieces"
    ).format(pieces=_hour_pieces(hours, raw, scope, raw_scope), per_counter=per_counter)


FRONTEND_SCOPE = sql.SQL("cluster = %(cluster)s and frontend = %(frontend)s")


# A frontend's raw rows count only where the node held the address (0048).
FRONTEND_HELD = sql.SQL("cluster = %(cluster)s and frontend = %(frontend)s and owns_vip")


#
# A backend and its earlier names (`metric_backend_alias`): each name in
# `%(backends)s` counts only before its own cutoff in `%(cutoffs)s` - null for
# the current name and for one nobody has taken again. An hour row counts only
# when the whole hour lies before the cutoff, so a name taken again within the
# hour is never drawn into the card that renamed it.
#
_HISTORY = (
    "cluster = %(cluster)s and member = %(member)s and exists ("
    "    select 1 from unnest(%(backends)s::text[], %(cutoffs)s::timestamptz[]) as h(name, cutoff)"
    "     where h.name = backend and {before} coalesce(h.cutoff, 'infinity'))"
)


BACKEND_SCOPE = sql.SQL(_HISTORY.format(before="observed_at <"))


BACKEND_HOUR_SCOPE = sql.SQL(_HISTORY.format(before="hour + interval '1 hour' <="))


def _frontend_totals(
    counters: tuple[tuple[str, str], ...] = metrics.CARD_COUNTERS,
    *,
    every_frontend: bool = False,
    by_cluster: bool = False,
) -> sql.Composed:
    """One frontend's figures, summed from the differences stored per sample.

    Only the samples on which a node held the address count, and each of them
    stored its difference from that node's previous such sample (migration
    0048) - which is how the readings were paired here before. There is no
    frontend rollup, so there is no boundary.

    `every_frontend` sums every VIP frontend of the clusters in `%(clusters)s`
    instead of one: the dashboard's traffic, counted the way each card on the
    metrics page is.
    """

    names = [name for name, _label in counters]
    return sql.SQL(
        "with intervals as ("
        "    select {cluster}{stored} "
        "      from metric_frontend "
        "     where {scope} "
        "       and owns_vip and observed_at >= %(since)s and observed_at <= %(until)s "
        "       and previous_at >= %(since)s"
        ") "
        "{aggregates} from intervals{grouping}"
    ).format(
        stored=_stored_intervals(names),
        aggregates=_interval_aggregates(names, by_cluster=by_cluster),
        cluster=sql.SQL("cluster, " if by_cluster else ""),
        grouping=sql.SQL(" group by cluster" if by_cluster else ""),
        #
        # Every frontend but the metrics exporter's, whose requests are the
        # monitoring system's scrapes and not traffic to anything served.
        #
        scope=(
            sql.SQL("cluster = any(%(clusters)s) and frontend <> {exporter}").format(
                exporter=sql.Literal(METRICS_FRONTEND)
            )
            if every_frontend
            else sql.SQL("cluster = %(cluster)s and frontend = %(frontend)s")
        ),
    )


def _measurement(
    row: Any, counters: tuple[tuple[str, str], ...] = metrics.CARD_COUNTERS
) -> metrics.BackendMeasurement:
    """One aggregate row, in the shape both totals readers return.

    Written once because the two queries deliberately produce the same columns
    in the same order. A second copy of this unpacking is how a column added to
    one of them would come back as a figure silently read from the wrong place.
    """

    span = float(row[6])
    totals = tuple(
        metrics.Total(
            label=label,
            value=int(row[7 + index * 2]),
            counted_sec=float(row[8 + index * 2]),
            span_sec=span,
        )
        for index, (_name, label) in enumerate(counters)
    )
    return metrics.BackendMeasurement(
        intervals=int(row[0]),
        started_at=row[1],
        ended_at=row[2],
        restarted=bool(row[3]),
        handed_over=bool(row[4]),
        totals=totals,
    )


def read_frontend_totals(
    connection: Connection[Any],
    *,
    cluster: str,
    frontend: str,
    since: datetime,
    until: datetime,
) -> metrics.BackendMeasurement:
    """One VIP frontend's figures at stored resolution, apart from its graph.

    A range longer than a day is summed from the hourly sums (0055), with the
    hours at its edges read raw; the figures are the raw rows' to the digit.
    """

    arguments = {"cluster": cluster, "frontend": frontend, "since": since, "until": until}
    with connection.cursor() as cursor:
        if _reads_hours(since, until):
            cursor.execute(
                _hour_totals(
                    "metric_frontend_hour_delta", "metric_frontend", FRONTEND_SCOPE, FRONTEND_HELD
                ),
                {**arguments, "after": since},
            )
        else:
            cursor.execute(_frontend_totals(), arguments)
        row = cursor.fetchone()

    if row is None:
        raise RuntimeError("the frontend totals aggregate returned no row")
    return _measurement(row)


def read_traffic_summary(
    connection: Connection[Any],
    *,
    clusters: Sequence[str],
    since: datetime,
    until: datetime,
) -> metrics.BackendMeasurement:
    """Every VIP frontend of these clusters summed: requests, bytes in, bytes out."""

    with connection.cursor() as cursor:
        cursor.execute(
            _frontend_totals(metrics.SUMMARY_COUNTERS, every_frontend=True),
            {"clusters": list(clusters), "since": since, "until": until},
        )
        row = cursor.fetchone()

    if row is None:
        raise RuntimeError("the traffic summary aggregate returned no row")
    return _measurement(row, metrics.SUMMARY_COUNTERS)


def read_traffic_summaries(
    connection: Connection[Any],
    *,
    clusters: Sequence[str],
    since: datetime,
    until: datetime,
) -> dict[str, metrics.BackendMeasurement]:
    """One aggregate per selected cluster, including clusters without readings."""

    empty = _measurement(
        (
            0,
            None,
            None,
            False,
            False,
            0,
            0,
            *(0 for _ in metrics.SUMMARY_COUNTERS for _ in range(2)),
        ),
        metrics.SUMMARY_COUNTERS,
    )
    result = dict.fromkeys(clusters, empty)
    if not clusters:
        return result
    with connection.cursor() as cursor:
        cursor.execute(
            _frontend_totals(metrics.SUMMARY_COUNTERS, every_frontend=True, by_cluster=True),
            {"clusters": list(clusters), "since": since, "until": until},
        )
        for row in cursor.fetchall():
            result[row[0]] = _measurement(row[1:], metrics.SUMMARY_COUNTERS)
    return result


def read_response_times_by_cluster(
    connection: Connection[Any],
    *,
    clusters: Sequence[str],
    since: datetime,
    until: datetime,
) -> dict[str, tuple[int, int | None, int | None]]:
    """Exact percentiles per cluster; unanswered requests remain excluded."""

    result: dict[str, tuple[int, int | None, int | None]] = dict.fromkeys(clusters, (0, None, None))
    if not clusters:
        return result
    with connection.cursor() as cursor:
        cursor.execute(
            "select cluster, count(*), "
            "       percentile_disc(0.5) within group (order by response_time), "
            "       percentile_disc(0.95) within group (order by response_time) "
            "  from traffic_log_read "
            " where cluster = any(%(clusters)s) and response_time >= 0 "
            "   and occurred_at >= %(since)s and occurred_at <= %(until)s "
            " group by cluster",
            {"clusters": list(clusters), "since": since, "until": until},
        )
        for row in cursor.fetchall():
            result[row[0]] = int(row[1]), int(row[2]), int(row[3])
    return result


def read_response_times(
    connection: Connection[Any],
    *,
    clusters: Sequence[str],
    since: datetime,
    until: datetime,
) -> tuple[int, int | None, int | None]:
    """How many answered requests the traffic log holds, and their median and 95th percentile.

    `response_time` is HAProxy's `%Tr`: from the request being sent to the
    server until its response headers came back, in milliseconds. -1 means no
    server answered - an abort, or a redirect HAProxy gave itself - and those
    are left out rather than counted as instant.
    """

    with connection.cursor() as cursor:
        cursor.execute(
            "select count(*), "
            "       percentile_disc(0.5) within group (order by response_time), "
            "       percentile_disc(0.95) within group (order by response_time) "
            "  from traffic_log_read "
            " where cluster = any(%(clusters)s) and response_time >= 0 "
            "   and occurred_at >= %(since)s and occurred_at <= %(until)s",
            {"clusters": list(clusters), "since": since, "until": until},
        )
        row = cursor.fetchone()
    if row is None or not row[0]:
        return 0, None, None
    return int(row[0]), int(row[1]), int(row[2])


def read_backend_totals(
    connection: Connection[Any],
    *,
    cluster: str,
    backend: str,
    since: datetime,
    until: datetime,
    member: str = "BACKEND",
    earlier: Sequence[EarlierName] = (),
    counters: tuple[tuple[str, str], ...] = metrics.CARD_COUNTERS,
) -> metrics.BackendMeasurement:
    """One backend's figures at stored resolution, independent of its graph.

    Read like the frontend's: the hourly sums for a range longer than a day,
    the raw rows otherwise. `counters` names the figures: HAProxy's card's by
    default, a dns pool's (`metrics.DNS_SUMMED`) for one.
    """

    arguments = {
        "cluster": cluster,
        "member": member,
        "since": since,
        "until": until,
        "after": since,
        **_history(backend, earlier),
    }
    with connection.cursor() as cursor:
        if _reads_hours(since, until):
            cursor.execute(
                _hour_totals(
                    "metric_backend_hour_delta",
                    "metric_backend_member",
                    BACKEND_HOUR_SCOPE,
                    BACKEND_SCOPE,
                    counters,
                ),
                arguments,
            )
        else:
            cursor.execute(_backend_totals(counters), arguments)
        row = cursor.fetchone()

    if row is None:
        raise RuntimeError("the backend totals aggregate returned no row")
    return _measurement(row, counters)
