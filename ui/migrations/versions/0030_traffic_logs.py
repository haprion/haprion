"""Store traffic logs in daily PostgreSQL partitions.

Revision ID: 0030
Revises: 0029
"""

from __future__ import annotations

from alembic import op

revision = "0030"
down_revision = "0029"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    create table traffic_log (
        event_id       bytea not null,
        cluster        text not null,
        node           text not null,
        occurred_at    timestamptz not null,
        request_number bigint not null,
        client         text not null,
        method         text not null,
        host           text not null,
        path           text not null,
        frontend       text not null,
        backend        text not null,
        server         text not null,
        status         integer not null,
        request_time   bigint not null,
        queue_time     bigint not null,
        connect_time   bigint not null,
        response_time  bigint not null,
        total_time     bigint not null,
        bytes          bigint not null,
        inserted_at    timestamptz not null default statement_timestamp(),

        constraint traffic_log_cluster_shape
            check (cluster ~ '^[a-z0-9][a-z0-9_-]{0,31}$'),
        constraint traffic_log_node_shape
            check (node ~ '^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$'),
        constraint traffic_log_event_id_shape check (octet_length(event_id) = 32),
        constraint traffic_log_status_range check (status between 0 and 999),
        constraint traffic_log_bytes_range check (bytes >= 0),

        primary key (occurred_at, event_id)
    ) partition by range (occurred_at);

    create function traffic_log_partition(day date)
        returns text language plpgsql as $$
    declare
        partition text := format('traffic_log_%s', to_char(day, 'YYYYMMDD'));
    begin
        execute format(
            'create table if not exists %I partition of traffic_log '
            'for values from (%L) to (%L)',
            partition, day, day + 1
        );
        execute format(
            'create index if not exists %I on %I (occurred_at desc)',
            partition || '_occurred_at', partition
        );
        execute format(
            'create index if not exists %I on %I using gin '
            '((host || '' '' || path || '' '' || backend) gin_trgm_ops)',
            partition || '_search', partition
        );
        return partition;
    end;
    $$;

    select traffic_log_partition(day::date)
      from generate_series(current_date - 6, current_date + 7, interval '1 day') as day;

    create function traffic_log_ignore_duplicate()
        returns trigger
        language plpgsql
        security definer
        set search_path = pg_catalog, public
    as $$
    begin
        if exists (
            select 1 from traffic_log
             where occurred_at = new.occurred_at and event_id = new.event_id
        ) then
            return null;
        end if;
        return new;
    end;
    $$;

    create trigger traffic_log_duplicate
        before insert on traffic_log
        for each row execute function traffic_log_ignore_duplicate();
    revoke all on function traffic_log_ignore_duplicate() from public;

    grant insert (
        event_id, cluster, node, occurred_at, request_number, client, method,
        host, path, frontend, backend, server, status, request_time, queue_time,
        connect_time, response_time, total_time, bytes
    ) on traffic_log to app_collector;
    grant select (
        cluster, node, occurred_at, request_number, client, method, host, path,
        frontend, backend, server, status, request_time, queue_time,
        connect_time, response_time, total_time, bytes
    ) on traffic_log to app_web;
    """)


def downgrade() -> None:
    op.execute("""
    drop table if exists traffic_log;
    drop function if exists traffic_log_partition(date);
    drop function if exists traffic_log_ignore_duplicate();
    """)
