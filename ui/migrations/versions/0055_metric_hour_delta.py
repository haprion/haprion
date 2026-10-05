"""Each series' stored changes summed per hour as the samples arrive (2026-10-05).

The 7- and 30-day traffic cards read a week of raw samples per card, twice -
once for the drawing and once for the figures. Measured 26-10-05 in
production: about 28 000 rows a card, 42 queries, 300-380 ms for the page warm
and 1.1 s cold. Frontends have no rollup at all, so a VIP's 30-day card could
only ever show the seven days the raw rows are kept.

Two small tables hold the same sums in advance, one row per series, node,
hour and whether the row's samples cross into the hour from the one before:

- the stored changes of migration 0048 (`delta_*`), summed;
- what the figures need beside them: how many samples, the seconds they span,
  the seconds not cut by a restart, and per counter the seconds in which that
  counter could be counted;
- the first `previous_at` and the last `observed_at`, so a reader can still say
  where its readings begin and end.

**Why `crossing` keeps every figure exact.** A reader groups samples by node,
bucket and whether the sample's pair lies in an earlier bucket. Only the first
sample of an hour can pair across the hour's start, so a crossing row is one
sample and keeps its `previous_at` exactly. Every bucket the long windows draw
is a whole number of UTC hours, so grouping these rows gives the groups the raw
rows give. Shorter windows still read the raw rows.

Only samples that have a pair are summed - a reader has always skipped the
first one - and a frontend's only where the node held the address, which is
already the only place 0048 stores a pair.

A statement trigger keeps them current, the same way as the WAF findings
(0054). Its transition table holds what 0048's row trigger computed, so the
poller is unchanged and needs no grant: the function runs as its owner. The
trigger is created before the tables are filled; its lock holds the poller's
next insert until this migration commits, so no sample is counted twice or
missed.

**What is filled in.** Every raw sample still kept, by the same sums. For
backends, the hours before a series' oldest kept raw sample come from the
hourly rollup, paired exactly as the reader paired them until now (one reading
per hour, the last one, with the lowest uptime in the hour marking a restart).
That reading is the sample the next raw row was paired with, so the two halves
meet without a gap. Frontends had no rollup and start from their raw rows.

Not partitioned on purpose: a trigger that could meet a missing partition
could fail the poller's insert. The retention command deletes hours older than
the longest window.

Revision ID: 0055
Revises: 0054
"""

from __future__ import annotations

from alembic import op

revision = "0055"
down_revision = "0054"
branch_labels = None
depends_on = None

#
# 0048's stored changes. A test holds this list against that migration's.
#
COUNTERS = (
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

SERIES = {
    "metric_frontend_hour_delta": ("metric_frontend", ("cluster", "frontend")),
    "metric_backend_hour_delta": ("metric_backend_member", ("cluster", "backend", "member")),
}

HOUR = "date_trunc('hour', observed_at, 'UTC')"
#
# The longest window is 30 days; retention deletes hours older than this, so
# the fill takes no older rollup hours either.
#
KEPT = "interval '31 days'"
SPAN = "extract(epoch from observed_at - previous_at)"


def _columns() -> str:
    return ",\n        ".join(
        f"delta_{name} bigint,\n        span_{name}_sec numeric not null" for name in COUNTERS
    )


def _sums() -> str:
    """The aggregate columns over raw samples, in table column order."""

    return ",\n           ".join(
        [
            "min(previous_at)",
            "max(observed_at)",
            "bool_or(restarted)",
            "count(*)",
            f"sum({SPAN})",
            f"coalesce(sum({SPAN}) filter (where not restarted), 0)",
        ]
        + [
            f"sum(delta_{name}), coalesce(sum({SPAN}) filter "
            f"(where delta_{name} is not null and not restarted), 0)"
            for name in COUNTERS
        ]
    )


def _value_columns() -> str:
    return ", ".join(
        [
            "first_previous_at",
            "last_observed_at",
            "restarted",
            "samples",
            "span_sec",
            "span_clean_sec",
        ]
        + [f"delta_{name}, span_{name}_sec" for name in COUNTERS]
    )


def _merge(table: str, keys: tuple[str, ...]) -> str:
    """Add one statement's sums to what an hour already holds."""

    deltas = ",\n               ".join(
        f"delta_{name} = case when kept.delta_{name} is null then excluded.delta_{name} "
        f"when excluded.delta_{name} is null then kept.delta_{name} "
        f"else kept.delta_{name} + excluded.delta_{name} end,\n"
        f"               span_{name}_sec = kept.span_{name}_sec + excluded.span_{name}_sec"
        for name in COUNTERS
    )
    return f"""
        on conflict ({", ".join(keys)}, node, hour, crossing) do update
           set first_previous_at = least(kept.first_previous_at, excluded.first_previous_at),
               last_observed_at = greatest(kept.last_observed_at, excluded.last_observed_at),
               restarted = kept.restarted or excluded.restarted,
               samples = kept.samples + excluded.samples,
               span_sec = kept.span_sec + excluded.span_sec,
               span_clean_sec = kept.span_clean_sec + excluded.span_clean_sec,
               {deltas}"""  # noqa: S608 - every value interpolated here is a constant of this module


def _summed(table: str, source: str, keys: tuple[str, ...], where: str) -> str:
    key_list = ", ".join(keys)
    group = ", ".join(str(index) for index in range(1, len(keys) + 4))
    return f"""
        insert into {table} as kept ({key_list}, node, hour, crossing, {_value_columns()})
        select {key_list}, node, {HOUR}, previous_at < {HOUR},
               {_sums()}
          from {source}
         where previous_at is not null {where}
         group by {group}"""  # noqa: S608 - every value interpolated here is a constant of this module


def _from_rollup(where: str = "") -> str:
    """Backend hours older than any kept raw sample, paired as the reader paired them.

    A restart is the hour's lowest uptime below the reading before, compared as
    the reader compared it: an hour without any uptime is not a restart.
    """

    keys = SERIES["metric_backend_hour_delta"][1]
    key_list = ", ".join(keys)
    lagged = ", ".join(f"lag({name}) over ordered as before_{name}" for name in COUNTERS)
    deltas = ", ".join(
        f"case when before_{name} is null or {name} is null then null "
        f"when is_restart then {name} when {name} < before_{name} then null "
        f"else {name} - before_{name} end as delta_{name}"
        for name in COUNTERS
    )
    return f"""
        with kept_from as (
            select {key_list}, node, min(observed_at) as oldest
              from metric_backend_member
             group by {key_list}, node
        ), readings as (
            select {key_list}, node, rolled.observed_at, rolled.uptime_sec,
                   rolled.floor_uptime_sec,
                   {", ".join(f"rolled.{name}" for name in COUNTERS)}
              from metric_backend_hour as rolled
              left join kept_from using ({key_list}, node)
             where (kept_from.oldest is null or rolled.observed_at < kept_from.oldest)
               and rolled.bucket_at >= statement_timestamp() - {KEPT} {where}
        ), paired as (
            select *,
                   lag(observed_at) over ordered as previous_at,
                   coalesce(floor_uptime_sec < lag(uptime_sec) over ordered, false) as is_restart,
                   {lagged}
              from readings
            window ordered as (partition by {key_list}, node order by observed_at)
        ), changes as (
            select {key_list}, node, observed_at, previous_at, is_restart as restarted, {deltas}
              from paired
             where previous_at is not null
        )
        {_summed("metric_backend_hour_delta", "changes", keys, "")}
        {_merge("metric_backend_hour_delta", keys)}"""  # noqa: S608 - every value interpolated here is a constant of this module


def _trigger(table: str, source: str, keys: tuple[str, ...]) -> str:
    return f"""
    create function {table}_add()
        returns trigger
        language plpgsql
        security definer
        set search_path = pg_catalog, public
    as $$
    begin
        {_summed(table, "added", keys, "")}
        {_merge(table, keys)};
        return null;
    end;
    $$;
    revoke all on function {table}_add() from public;

    create trigger {table}_add
        after insert on {source}
        referencing new table as added
        for each statement execute function {table}_add();
    """


def upgrade() -> None:
    for table, (source, keys) in SERIES.items():
        key_columns = ",\n        ".join(f"{name} text not null" for name in keys)
        op.execute(f"""
        create table {table} (
            {key_columns},
            node              text not null,
            hour              timestamptz not null,
            crossing          boolean not null,
            first_previous_at timestamptz not null,
            last_observed_at  timestamptz not null,
            restarted         boolean not null,
            samples           integer not null,
            span_sec          numeric not null,
            span_clean_sec    numeric not null,
            {_columns()},
            primary key ({", ".join(keys)}, node, hour, crossing)
        );
        -- Retention removes hours before a day.
        create index {table}_hour on {table} (hour);
        """)
        op.execute(_trigger(table, source, keys))

    #
    # Filled after the triggers exist; see the docstring.
    #
    for table, (source, keys) in SERIES.items():
        op.execute(_summed(table, source, keys, "") + _merge(table, keys))
    op.execute(_from_rollup())

    columns = ", ".join(["node", "hour", "crossing", *_value_columns().split(", ")])
    op.execute(f"""
    grant select (cluster, frontend, {columns}) on metric_frontend_hour_delta to app_web;
    grant select (cluster, backend, member, {columns}) on metric_backend_hour_delta to app_web;
    """)


def downgrade() -> None:
    for table, (source, _keys) in SERIES.items():
        op.execute(f"""
        drop trigger if exists {table}_add on {source};
        drop function if exists {table}_add();
        drop table if exists {table};
        """)
