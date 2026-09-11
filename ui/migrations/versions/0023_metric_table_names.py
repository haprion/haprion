"""Name the metric tables after what HAProxy calls the things they measure.

Revision ID: 0023
Revises: 0022
"""

from __future__ import annotations

from alembic import op

revision = "0023"
down_revision = "0022"
branch_labels = None
depends_on = None

#
# The interface stopped saying "pool" and "listener" in B133: HAProxy has
# frontends, backends and servers, and a reader who knows HAProxy should not
# have to translate. The code followed, and these tables are the last place the
# old words were load-bearing. Old name, new name, and the pattern its
# partitions are named by - every partition is renamed with its parent, because
# the retention command finds a day's partition by `<table>_YYYYMMDD` and a
# partition left under the old prefix would never be dropped.
#
RENAMED = (
    ("metric_listener", "metric_frontend"),
    ("metric_pool_member", "metric_backend_member"),
    ("metric_pool_hour", "metric_backend_hour"),
)

#
# Every relation and constraint whose name starts with an old table name is
# renamed the same way: the parent, its partitions, the primary keys and read
# indexes on both, and the check constraints. Names are what the catalogue
# holds and nothing else, so no name is guessed - a partition that exists is
# renamed and one that does not is not invented.
#
_RENAME_EVERYTHING = """
do $$
declare
    old_name text;
    new_name text;
    item     record;
begin
    for old_name, new_name in
        values ('metric_listener', 'metric_frontend'),
               ('metric_pool_member', 'metric_backend_member'),
               ('metric_pool_hour', 'metric_backend_hour')
    loop
        -- Tables first: the partitioned parent and each of its partitions.
        for item in
            select c.relname
              from pg_class c
              join pg_namespace n on n.oid = c.relnamespace
             where n.nspname = 'public'
               and c.relkind in ('r', 'p')
               and (c.relname = old_name or c.relname like old_name || '\\_%')
        loop
            execute format('alter table %I rename to %I',
                           item.relname, new_name || substr(item.relname, length(old_name) + 1));
        end loop;

        -- Then indexes, which also renames the constraints they back.
        for item in
            select c.relname
              from pg_class c
              join pg_namespace n on n.oid = c.relnamespace
             where n.nspname = 'public'
               and c.relkind in ('i', 'I')
               and c.relname like old_name || '\\_%'
        loop
            execute format('alter index %I rename to %I',
                           item.relname, new_name || substr(item.relname, length(old_name) + 1));
        end loop;

        -- Then the check and not-null constraints, which no index backs. Renamed on the
        -- parent only: a partition shares its parent's check constraint by
        -- name, and the rename reaches it from there.
        for item in
            select con.conname, rel.relname
              from pg_constraint con
              join pg_class rel on rel.oid = con.conrelid
              join pg_namespace n on n.oid = rel.relnamespace
             where n.nspname = 'public'
               and con.contype in ('c', 'n')
               and not rel.relispartition
               and con.conname like old_name || '\\_%'
        loop
            execute format('alter table %I rename constraint %I to %I',
                           item.relname, item.conname,
                           new_name || substr(item.conname, length(old_name) + 1));
        end loop;
    end loop;
end;
$$;
"""

_RENAME_EVERYTHING_BACK = (
    _RENAME_EVERYTHING.replace(
        "values ('metric_listener', 'metric_frontend'),",
        "values ('metric_frontend', 'metric_listener'),",
    )
    .replace(
        "('metric_pool_member', 'metric_backend_member'),",
        "('metric_backend_member', 'metric_pool_member'),",
    )
    .replace(
        "('metric_pool_hour', 'metric_backend_hour')", "('metric_backend_hour', 'metric_pool_hour')"
    )
)

#
# The same column lists as 0018 and 0020, because the views below must grant
# exactly what the tables grant and nothing wider. 03-verify reads the grants
# column by column and expects these.
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
_GRANTABLE = ", ".join(COUNTERS)


def upgrade() -> None:
    op.execute(_RENAME_EVERYTHING)

    #
    # The partition makers check the table name against a list, so the list
    # changes with the names. The old names stay accepted and are mapped to
    # the new tables: the retention command installed beside the previous UI
    # release still asks for `metric_listener` partitions until it is
    # reinstalled, and a partition it asks for must exist under the new name
    # rather than be refused.
    #
    op.execute("""
    create or replace function metric_partition(table_name text, day date)
        returns text language plpgsql as $$
    declare
        partition text;
    begin
        table_name := case table_name
            when 'metric_listener' then 'metric_frontend'
            when 'metric_pool_member' then 'metric_backend_member'
            else table_name
        end;
        if table_name not in ('metric_frontend', 'metric_backend_member') then
            raise exception 'not a metric table: %', table_name;
        end if;

        partition := format('%s_%s', table_name, to_char(day, 'YYYYMMDD'));

        execute format(
            'create table if not exists %I partition of %I for values from (%L) to (%L)',
            partition, table_name, day, day + 1
        );
        return partition;
    end;
    $$;

    create or replace function metric_month_partition(table_name text, month date)
        returns text language plpgsql as $$
    declare
        partition text;
        first     date;
    begin
        table_name := case table_name
            when 'metric_pool_hour' then 'metric_backend_hour'
            else table_name
        end;
        if table_name not in ('metric_backend_hour') then
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

    update metric_rollup_state set rollup_name = 'backend_hour' where rollup_name = 'pool_hour';
    """)

    #
    # The old names live on as plain views over the new tables, with the
    # grants the tables had. This is what makes the previous UI release accept
    # this revision honestly: it keeps reading and writing the old names during
    # the minutes between migration and activation, and it works again if this
    # release is rolled back. A view with no joins and no expressions is
    # updatable, so the poller's inserts pass straight through and the base
    # table's `observed_at` default still applies. The views are dropped by the
    # next schema change, once no installed release names them.
    #
    op.execute("""
    create view metric_listener as select * from metric_frontend;
    create view metric_pool_member as select * from metric_backend_member;
    create view metric_pool_hour as select * from metric_backend_hour;
    """)
    op.execute(f"""
    grant insert (cluster, node, frontend, owns_vip, uptime_sec, status, {_GRANTABLE})
        on metric_listener to app_poller;
    grant select (cluster, node, frontend, observed_at, owns_vip, uptime_sec, status, {_GRANTABLE})
        on metric_listener to app_poller, app_web;

    grant insert (cluster, node, backend, member, uptime_sec, status,
                  check_status, check_code, {_GRANTABLE})
        on metric_pool_member to app_poller;
    grant select (cluster, node, backend, member, observed_at, uptime_sec, status,
                  check_status, check_code, {_GRANTABLE})
        on metric_pool_member to app_poller, app_web;

    grant select (cluster, node, backend, member, bucket_at, observed_at, uptime_sec,
                  floor_uptime_sec, status, check_status, check_code, {_GRANTABLE})
        on metric_pool_hour to app_poller, app_web;
    """)


def downgrade() -> None:
    op.execute("""
    drop view if exists metric_listener;
    drop view if exists metric_pool_member;
    drop view if exists metric_pool_hour;
    update metric_rollup_state set rollup_name = 'pool_hour' where rollup_name = 'backend_hour';
    """)
    op.execute(_RENAME_EVERYTHING_BACK)
    op.execute("""
    create or replace function metric_partition(table_name text, day date)
        returns text language plpgsql as $$
    declare
        partition text;
    begin
        if table_name not in ('metric_listener', 'metric_pool_member') then
            raise exception 'not a metric table: %', table_name;
        end if;

        partition := format('%s_%s', table_name, to_char(day, 'YYYYMMDD'));

        execute format(
            'create table if not exists %I partition of %I for values from (%L) to (%L)',
            partition, table_name, day, day + 1
        );
        return partition;
    end;
    $$;

    create or replace function metric_month_partition(table_name text, month date)
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
