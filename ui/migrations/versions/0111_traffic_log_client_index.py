"""The traffic log can be searched for a client address or network without reading every row (review 26-11-01).

The search field finds a client address or a network, and a day's partition
has no index on `client`: the planner would read the whole day for each. One
expression index per partition, the way the trigram index of the search text
and the other two are per partition: a day that leaves the window is dropped
whole with its indexes, and an index on the parent could not be built without
locking every day at once.

`client` is text a node wrote (a compromised node can write anything of 64
characters), so the index and the search both go through `traffic_log_client_inet`,
which is null for what is no address where a plain cast would stop the whole
search. One btree answers an address (`=`) and a network (`<<=`, as a range).
`pg_input_is_valid` is PostgreSQL 16 and newer, the least the installation
accepts.

`traffic_log_partition()` makes the index for the days made from now on; this
makes it for the days that exist. The build holds a day's writes for as long as
it takes, a second or so for a busy day; the collector re-reads from its
checkpoint, so a write waiting for it is only late (a build past the
collector's 15 s statement timeout fails that round, and the next one retries).

The view also gives `event_id`, a row's own identity, so a page ends at one
row where several share a time, a request number and a node.

Revision ID: 0111
Revises: 0110
"""

from __future__ import annotations

from alembic import op

revision = "0111"
down_revision = "0110"
branch_labels = None
depends_on = None

ROLLBACK_SAFE = True
ROLLBACK_SAFE_BECAUSE = "an index and a function code from before neither names nor needs, and a view widened at its end"


def upgrade() -> None:
    op.execute(r"""
    CREATE OR REPLACE FUNCTION public.traffic_log_partition(day date) RETURNS text
        LANGUAGE plpgsql
        AS $$
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
            execute format(
                'create index if not exists %I on %I (traffic_log_client_inet(client))',
                partition || '_client', partition
            );
            return partition;
        end;
        $$;

    -- Immutable although `pg_input_is_valid` is declared stable: reading an inet
    -- depends on no setting, and an index may only hold an immutable expression.
    -- plpgsql and not a SQL `case`: the planner folds the cast of a constant
    -- before the `case` can keep it from a value that is no address, and an
    -- insert of one would fail. Without an exception block it costs no
    -- subtransaction per row.
    CREATE FUNCTION public.traffic_log_client_inet(client text) RETURNS inet
        LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
        AS $$
        begin
            if pg_input_is_valid(client, 'inet') then
                return host(client::inet)::inet;
            end if;
            return null;
        end;
        $$;

    DO $$
    declare
        child regclass;
    begin
        for child in
            select inhrelid::regclass from pg_inherits where inhparent = 'traffic_log'::regclass
        loop
            execute format(
                'create index if not exists %I on %s (traffic_log_client_inet(client))',
                substring(child::text from '[^.]+$') || '_client', child
            );
            -- A day that is full is never analyzed again by autovacuum, and the
            -- planner knows nothing of the new expression until it is.
            execute format('analyze %s', child);
        end loop;
    end;
    $$;

    create or replace view traffic_log_read as
        select cluster, node, occurred_at, request_number, client, method, host, path,
               frontend, backend, server, status, request_time, queue_time, connect_time,
               response_time, total_time, bytes, rule, waf_rules, waf_score, waf_id,
               termination, event_id
          from traffic_log;
    """)
