"""The web reads the traffic log through a view, and each partition is indexed by cluster (D1, 2026-10-21).

Measured on fabricated load in a disposable cluster on two CPUs: 7 days of 2 M
rows a day in one cluster and 2 000 in another, and 90 days of 300 000 and
300.

The view. The web role holds column grants on `traffic_log` (0030), and with
column grants alone PostgreSQL does not let the planner read the statistics of
an expression index - here the trigram index the search uses. Without them it
guesses a search matches about 1 % of the rows, and walks the primary key
backwards rather than asking the index: a search that finds nothing read every
row, 36 s at 7 days and 138 s at 90, where the index answers in 1 ms. Granting
every column one by one does not change it; table-level SELECT and a view do,
since a view's tables are checked as its owner. The view names the columns the
web was granted, so a new column is still invisible to the web until it is
named, here and in its grant.

The grants on the table stay: a UI from before reads `traffic_log` itself and
still works over this migration. The web's own code reads the view
(`traffic_logs.read_database` and the `db` aggregates), and a test holds the
view's columns to the grants.

The index. The primary key leads with `occurred_at`, so a small cluster beside
a large one is found by reading the large one's rows until enough of the small
one's turn up: its 5xx or one of its objects took 1.3-1.5 s at 7 days and
passed the web's 5 s statement timeout at 90. `(cluster, occurred_at desc,
request_number desc)` - the page's order - answers those in 3-60 ms. It costs
about 40 bytes a row, a tenth of the table, and no measurable insert rate
(42 000 rows/s through the collector's COPY with and without it).

Revision ID: 0083
Revises: 0082
"""

from __future__ import annotations

from alembic import op

revision = "0083"
down_revision = "0082"
branch_labels = None
depends_on = None

ROLLBACK_SAFE = True
ROLLBACK_SAFE_BECAUSE = (
    "adds a view and an index and keeps the web's grants on traffic_log, which a UI from before "
    "reads directly"
)


def upgrade() -> None:
    op.execute("""
    create view traffic_log_read as
        select cluster, node, occurred_at, request_number, client, method, host, path,
               frontend, backend, server, status, request_time, queue_time, connect_time,
               response_time, total_time, bytes, rule, waf_rules, waf_score, waf_id
          from traffic_log;
    grant select on traffic_log_read to app_web;

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
        execute format(
            'create index if not exists %I on %I (occurred_at) where rule <> ''''',
            partition || '_rule', partition
        );
        execute format(
            'create index if not exists %I on %I (cluster, occurred_at desc, request_number desc)',
            partition || '_cluster', partition
        );
        return partition;
    end;
    $$;

    do $$
    declare
        name text;
    begin
        for name in
            select child.relname
              from pg_inherits
              join pg_class child on child.oid = pg_inherits.inhrelid
              join pg_class parent on parent.oid = pg_inherits.inhparent
             where parent.relname = 'traffic_log'
        loop
            execute format(
                'create index if not exists %I on %I (cluster, occurred_at desc, request_number desc)',
                name || '_cluster', name
            );
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
            'create index if not exists %I on %I using gin '
            '((host || '' '' || path || '' '' || backend) gin_trgm_ops)',
            partition || '_search', partition
        );
        execute format(
            'create index if not exists %I on %I (occurred_at) where rule <> ''''',
            partition || '_rule', partition
        );
        return partition;
    end;
    $$;

    do $$
    declare
        name text;
    begin
        for name in
            select child.relname
              from pg_inherits
              join pg_class child on child.oid = pg_inherits.inhrelid
              join pg_class parent on parent.oid = pg_inherits.inhparent
             where parent.relname = 'traffic_log'
        loop
            execute format('drop index if exists %I', name || '_cluster');
        end loop;
    end;
    $$;

    drop view traffic_log_read;
    """)
