"""Each raw sample carries what changed since the one before it (2026-10-01).

A traffic card's figures were the sum of what every counter did between
consecutive samples, found on read: the page sorted a week of readings per
series and node, paired each with the one before it, and decided per pair
whether it was a restart, a counter that went backwards, or plain growth.
Measured against a copy at production density with PostgreSQL held to two
CPUs, that was about 150 ms per card for a seven-day window - sort, window and
per-row arithmetic over 60 000 rows - and most of the metrics page.

The same decision is now made once, when the row is written, by the same
rules, and stored beside the cumulative counters the row already has:

* `previous_at` - the sample this one is paired with: the series' previous
  row on the same node, and for a frontend the previous row on which that node
  held the address, because a frontend's figures are the holder's.
* `restarted` - the runtime's uptime went down: the process is new and its
  counters started again.
* `delta_<counter>` - null where either side is unknown or the counter went
  backwards without a restart; the new value after a restart; the difference
  otherwise. Exactly the expression the read used.

A read then sums the rows whose `previous_at` falls inside its range, which is
the read's old rule ("the first sample in the range has nothing to pair with")
said as a filter. The cumulative columns stay the record of what the node
said; these are derived from them and from nothing else.

Computed by a trigger, as the table owner's rule rather than the poller's
arithmetic: the poller may not write these columns at all, so a figure on the
page is the database's reading of what the node reported. The lookup is
bounded to 31 days back. Every window the interface draws is 30 days or less,
so a sample paired across a longer gap never counts in one either way, and
the bound keeps each insert to the partitions that can hold the answer.

Rows already stored are filled in here, by the same rules over the same order.
The hourly rollup is untouched: it keeps one reading per hour and the read
still pairs those itself, over a few hundred rows.

The raw tables stay partitioned by day so retention can drop a day whole; a
row whose partner is dropped keeps its `previous_at` as a moment, which is all
a read asks of it.

Revision ID: 0048
Revises: 0047
"""

from __future__ import annotations

from alembic import op

revision = "0048"
down_revision = "0047"
branch_labels = None
depends_on = None

#
# The counters a figure is ever summed from: the card's (`metrics.CARD_COUNTERS`)
# and the dashboard's bytes (`metrics.SUMMARY_COUNTERS`). A test holds the two
# lists against this one; a counter summed but not stored would make the reader
# fail on a column that does not exist rather than count it some other way.
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

#
# How far back a pairing is looked for. See the docstring.
#
LOOKBACK = "31 days"

_ADD = ", ".join(f"add column delta_{name} bigint" for name in COUNTERS)
_DROP = ", ".join(f"drop column if exists delta_{name}" for name in COUNTERS)
_GRANT = ", ".join(f"delta_{name}" for name in COUNTERS)


def _backfill(table: str, series: str, held: str) -> str:
    """Fill the rows a table already has, pairing exactly as the trigger does.

    `series` names the columns a series is told apart by, node included;
    `held` restricts the rows that pair at all (a frontend's holder's).
    """

    keys = [column.strip() for column in series.split(",")]
    before = ", ".join(f"lag({name}) over ordered as before_{name}" for name in COUNTERS)
    deltas = ", ".join(
        f"delta_{name} = case when paired.before_{name} is null or paired.{name} is null "
        f"then null when paired.is_restart then paired.{name} "
        f"when paired.{name} < paired.before_{name} then null "
        f"else paired.{name} - paired.before_{name} end"
        for name in COUNTERS
    )
    match = " and ".join(f"target.{name} = paired.{name}" for name in (*keys, "observed_at"))
    return f"""
    update {table} as target
       set previous_at = paired.before_at,
           restarted = paired.is_restart,
           {deltas}
      from (
        select *, coalesce(uptime_sec < before_uptime, false) as is_restart
          from (
            select {series}, observed_at, uptime_sec, {", ".join(COUNTERS)},
                   lag(observed_at) over ordered as before_at,
                   lag(uptime_sec) over ordered as before_uptime,
                   {before}
              from {table}
             where {held}
            window ordered as (partition by {series} order by observed_at)
          ) as lagged
         where before_at >= observed_at - interval '{LOOKBACK}'
      ) as paired
     where {match};
    """  # noqa: S608 - every value interpolated here is a constant of this module


def _assign(target: str) -> str:
    return "\n".join(
        f"        {target}.delta_{name} := case when previous.{name} is null "
        f"or {target}.{name} is null then null when {target}.restarted then {target}.{name} "
        f"when {target}.{name} < previous.{name} then null "
        f"else {target}.{name} - previous.{name} end;"
        for name in COUNTERS
    )


def upgrade() -> None:
    op.execute(f"""
    alter table metric_backend_member
        add column previous_at timestamptz,
        add column restarted boolean,
        {_ADD};

    alter table metric_frontend
        add column previous_at timestamptz,
        add column restarted boolean,
        {_ADD};

    --
    -- A frontend pairs only with samples on which the node held the address,
    -- and a node can go days without holding it. Without this the lookup
    -- would walk every one of those rows back to the last one it held.
    --
    create index metric_frontend_holder
        on metric_frontend (cluster, node, frontend, observed_at) where owns_vip;
    """)

    op.execute(f"""
    create function metric_backend_member_delta() returns trigger
        language plpgsql
        set search_path = pg_catalog, public
    as $$
    declare
        previous record;
    begin
        select observed_at, uptime_sec, {", ".join(COUNTERS)}
          into previous
          from metric_backend_member
         where cluster = new.cluster and node = new.node
           and backend = new.backend and member = new.member
           and observed_at < new.observed_at
           and observed_at >= new.observed_at - interval '{LOOKBACK}'
         order by observed_at desc
         limit 1;
        if not found then
            new.previous_at := null;
            new.restarted := null;
            return new;
        end if;
        new.previous_at := previous.observed_at;
        new.restarted := coalesce(new.uptime_sec < previous.uptime_sec, false);
{_assign("new")}
        return new;
    end;
    $$;

    create function metric_frontend_delta() returns trigger
        language plpgsql
        set search_path = pg_catalog, public
    as $$
    declare
        previous record;
    begin
        if new.owns_vip is not true then
            new.previous_at := null;
            new.restarted := null;
            return new;
        end if;
        select observed_at, uptime_sec, {", ".join(COUNTERS)}
          into previous
          from metric_frontend
         where cluster = new.cluster and node = new.node and frontend = new.frontend
           and owns_vip
           and observed_at < new.observed_at
           and observed_at >= new.observed_at - interval '{LOOKBACK}'
         order by observed_at desc
         limit 1;
        if not found then
            new.previous_at := null;
            new.restarted := null;
            return new;
        end if;
        new.previous_at := previous.observed_at;
        new.restarted := coalesce(new.uptime_sec < previous.uptime_sec, false);
{_assign("new")}
        return new;
    end;
    $$;

    create trigger metric_backend_member_delta
        before insert on metric_backend_member
        for each row execute function metric_backend_member_delta();

    create trigger metric_frontend_delta
        before insert on metric_frontend
        for each row execute function metric_frontend_delta();
    """)  # noqa: S608 - every value interpolated here is a constant of this module

    #
    # The rows already there, by the same rules: the previous row in the same
    # order, inside the same bound.
    #
    op.execute(_backfill("metric_backend_member", "cluster, node, backend, member", "true"))
    op.execute(_backfill("metric_frontend", "cluster, node, frontend", "owns_vip"))

    op.execute(f"""
    grant select (previous_at, restarted, {_GRANT}) on metric_backend_member to app_web;
    grant select (previous_at, restarted, {_GRANT}) on metric_frontend to app_web;
    """)


def downgrade() -> None:
    op.execute(f"""
    drop trigger if exists metric_backend_member_delta on metric_backend_member;
    drop trigger if exists metric_frontend_delta on metric_frontend;
    drop function if exists metric_backend_member_delta();
    drop function if exists metric_frontend_delta();
    drop index if exists metric_frontend_holder;
    alter table metric_backend_member drop column if exists previous_at,
        drop column if exists restarted, {_DROP};
    alter table metric_frontend drop column if exists previous_at,
        drop column if exists restarted, {_DROP};
    """)
