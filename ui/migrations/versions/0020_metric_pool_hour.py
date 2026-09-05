"""Keep an hourly reading of each pool for a year.

Revision ID: 0020
Revises: 0019
"""

from __future__ import annotations

from alembic import op

revision = "0020"
down_revision = "0019"
branch_labels = None
depends_on = None

#
# The same list, for the same reason as 0018: HAProxy's own column names, so a
# value can be looked up in HAProxy's documentation.
#
COUNTERS = (
    "scur",
    "stot",
    "bin",
    "bout",
    "req_tot",
    "qcur",
    "ereq",
    "econ",
    "eresp",
    "dreq",
    "dresp",
    "wretr",
    "wredis",
    "hrsp_2xx",
    "hrsp_3xx",
    "hrsp_4xx",
    "hrsp_5xx",
)

_COLUMNS = "".join(f"        {name} bigint,\n" for name in COUNTERS)
_GRANTABLE = ", ".join(COUNTERS)


def upgrade() -> None:
    #
    # A rollup row has the same shape as a bucketed raw reading, deliberately:
    # the last cumulative value in the hour, and the lowest uptime seen inside
    # it. That is exactly what the reader already asks the raw table for at a
    # wider bucket, so one difference-and-restart implementation serves both
    # and the only thing that changes with the window is which table answers.
    #
    # The alternative - storing the hour's delta - was rejected for that
    # reason. It reads more directly, and it would need a second reader with
    # its own idea of what a restart means, sitting beside the one that already
    # has that idea and is tested.
    #
    # `floor_uptime_sec` is why an hour of samples can be thrown away without
    # losing a restart that happened inside it.
    #
    op.execute(f"""
    create table metric_pool_hour (
        cluster           text not null,
        node              text not null,
        backend           text not null,
        member            text not null,
        bucket_at         timestamptz not null,
        observed_at       timestamptz not null,
        uptime_sec        bigint,
        floor_uptime_sec  bigint,
        status            text,
        check_status      text,
        check_code        text,
{_COLUMNS}
        constraint metric_pool_hour_cluster_shape
            check (cluster ~ '^[a-z0-9][a-z0-9_-]{{0,31}}$'),
        constraint metric_pool_hour_on_the_hour
            check (bucket_at = date_trunc('hour', bucket_at)),

        primary key (cluster, node, backend, member, bucket_at)
    ) partition by range (bucket_at);
    """)

    #
    # Monthly rather than daily. A year of daily partitions is 365 tables to
    # plan every query against, for rows that arrive an hour at a time; the
    # raw table is partitioned by day because it is dropped by the day.
    #
    op.execute("""
    create function metric_month_partition(table_name text, month date)
        returns text language plpgsql as $$
    declare
        partition text;
        first     date;
    begin
        if table_name not in ('metric_pool_hour') then
            raise exception 'not a rollup table: %', table_name;
        end if;

        first := date_trunc('month', month)::date;
        partition := format('%s_%s', table_name, to_char(first, 'YYYYMM'));

        execute format(
            'create table if not exists %I partition of %I for values from (%L) to (%L)',
            partition, table_name, first, first + interval '1 month'
        );
        return partition;
    end;
    $$;
    """)

    #
    # Read-only for every application role. Nothing here is written by an
    # application: the rows are derived from the raw table by the retention
    # command, as the migration role, which is the same hand that creates the
    # partitions and drops them. See B93.
    #
    op.execute(f"""
    grant select (cluster, node, backend, member, bucket_at, observed_at, uptime_sec,
                  floor_uptime_sec, status, check_status, check_code, {_GRANTABLE})
        on metric_pool_hour to app_poller, app_web;
    """)


def downgrade() -> None:
    op.execute("""
    drop table if exists metric_pool_hour;
    drop function if exists metric_month_partition(text, date);
    """)
