"""The traffic log keeps each request's ID and the client's TLS and HTTP version (B517 p. 1 and 6, B523).

`request_id` is the ID the frontend gave the request and sent to the backend as
`X-Request-ID`: a UUID version 7, or the ID a trusted proxy sent in the form
the generator accepts. `tls` is HAProxy's name for the client's TLS version
(`TLSv1.3`), empty without TLS; `http` its HTTP version (`1.1`, `2.0`, `3.0`).
A row from a node with the older format has all three empty, as the defaults
say.

A request ID is searched for exactly, and the versions by value, so each has an
index per partition: `traffic_log_partition()` makes them for the days made
from now on, and this makes them for the days that exist, as 0117 did for
`inserted_at`. The request ID's index leaves the empty rows out. The builds run
in the migration's one transaction and hold the day's writes until it commits;
the collector re-reads from its checkpoint, so a write waiting for it is only
late.

`traffic_log_read` gets the three columns at its end.

Revision ID: 0123
Revises: 0122
"""

from __future__ import annotations

from alembic import op

revision = "0123"
down_revision = "0122"
branch_labels = None
depends_on = None

ROLLBACK_SAFE = True
ROLLBACK_SAFE_BECAUSE = (
    "the columns have defaults, which 1.2.2's collector does not name in its copy; the view "
    "gets three columns at its end, which 1.2.2's web does not select; the partition function "
    "makes three more indexes, which nothing in 1.2.2 names or needs"
)

PARTITION_FUNCTION = r"""
create or replace function public.traffic_log_partition(day date) returns text
    language plpgsql
    as $$
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
        execute format(
            'create index if not exists %I on %I using brin (inserted_at) '
            'with (autosummarize = on)',
            partition || '_inserted', partition
        );
        execute format(
            'create index if not exists %I on %I (request_id) where request_id <> ''''',
            partition || '_request_id', partition
        );
        execute format(
            'create index if not exists %I on %I (tls)',
            partition || '_tls', partition
        );
        execute format(
            'create index if not exists %I on %I (http)',
            partition || '_http', partition
        );
        return partition;
    end;
    $$
"""

EXISTING_PARTITIONS = r"""
do $$
declare
    child regclass;
    name text;
begin
    for child in
        select inhrelid::regclass from pg_inherits where inhparent = 'traffic_log'::regclass
    loop
        name := substring(child::text from '[^.]+$');
        execute format(
            'create index if not exists %I on %s (request_id) where request_id <> ''''',
            name || '_request_id', child
        );
        execute format('create index if not exists %I on %s (tls)', name || '_tls', child);
        execute format('create index if not exists %I on %s (http)', name || '_http', child);
    end loop;
end;
$$
"""

VIEW = """
create or replace view traffic_log_read as
select cluster, node, occurred_at, request_number, client, method, host, path, frontend,
       backend, server, status, request_time, queue_time, connect_time, response_time,
       total_time, bytes, rule, waf_rules, waf_score, waf_id, termination, event_id,
       inserted_at, request_id, tls, http
  from traffic_log
"""


def upgrade() -> None:
    op.execute(
        """
        alter table traffic_log
            add column request_id text not null default ''
                constraint traffic_log_request_id_shape
                check (request_id ~ '^([A-Za-z0-9._:=+/-]{1,128})?$'),
            add column tls text not null default ''
                constraint traffic_log_tls_shape check (tls ~ '^([A-Za-z0-9.]{1,16})?$'),
            add column http text not null default ''
                constraint traffic_log_http_shape check (http ~ '^([0-9][.][0-9])?$')
        """
    )
    op.execute("grant insert (request_id, tls, http) on traffic_log to app_collector")
    op.execute(VIEW)
    op.execute(PARTITION_FUNCTION)
    op.execute(EXISTING_PARTITIONS)
