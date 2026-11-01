"""The traffic log can be searched for a client address without reading every row (review 26-11-01).

The search field finds a client address or a network, and a day's partition
has no index on `client`: the planner would read the whole day for each. One btree per partition, the way the trigram index of the search
text and the other two are per partition: a day that leaves the window is
dropped whole with its indexes, and an index on the parent could not be built
without locking every day at once.

`traffic_log_partition()` makes it for the days made from now on; this makes it
for the days that exist. `client` is text a node wrote (a compromised node can
write anything of 64 characters), so a network is judged by a function that says
"not in it" for what is no address, where a cast would stop the whole search. The build holds a day's writes for as long as it takes;
the collector re-reads from its checkpoint, so a write waiting for it is only late.

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
ROLLBACK_SAFE_BECAUSE = "an index that code from before neither names nor needs"


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
                'create index if not exists %I on %I (client)',
                partition || '_client', partition
            );
            return partition;
        end;
        $$;

    CREATE FUNCTION public.traffic_log_client_in(client text, network inet) RETURNS boolean
        LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
        AS $$
        begin
            return client::inet <<= network;
        exception when others then
            return false;
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
                'create index if not exists %I on %s (client)',
                substring(child::text from '[^.]+$') || '_client', child
            );
        end loop;
    end;
    $$;
    """)
