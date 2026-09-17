"""Drop the per-partition occurred_at index: the primary key already orders by it.

Revision ID: 0031
Revises: 0030

The primary key (occurred_at, event_id) is a B-tree with occurred_at leading, and
PostgreSQL reads it backwards for `order by occurred_at desc` and forwards for a
range; the separate `(occurred_at desc)` index gave the planner nothing it did
not have. Measured on a 500 000-row partition (review 2026-09-17, finding 6): 19 MB
of 86 MB of indexes, about 40 of the 410 bytes each record costs, and one B-tree
insert per row, for a plan the planner chooses on its own once the index is gone.
"""

from __future__ import annotations

from alembic import op

revision = "0031"
down_revision = "0030"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    create or replace function traffic_log_partition(day date)
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
            'create index if not exists %I on %I using gin '
            '((host || '' '' || path || '' '' || backend) gin_trgm_ops)',
            partition || '_search', partition
        );
        return partition;
    end;
    $$;

    do $$
    declare
        name text;
    begin
        for name in
            select indexname from pg_indexes
             where schemaname = 'public'
               and indexname ~ '^traffic_log_[0-9]{8}_occurred_at$'
        loop
            execute format('drop index if exists %I', name);
        end loop;
    end;
    $$;
    """)


def downgrade() -> None:
    op.execute("""
    create or replace function traffic_log_partition(day date)
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

    do $$
    declare
        name text;
    begin
        for name in
            select tablename from pg_tables
             where schemaname = 'public' and tablename ~ '^traffic_log_[0-9]{8}$'
        loop
            execute format(
                'create index if not exists %I on %I (occurred_at desc)',
                name || '_occurred_at', name
            );
        end loop;
    end;
    $$;
    """)
