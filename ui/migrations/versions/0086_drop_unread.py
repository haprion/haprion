"""What nothing reads any more: the 0023 views, and the matches' request index and web grant (review 2026-10-22, 3-6, 3-7).

0023 kept `metric_listener`, `metric_pool_member` and `metric_pool_hour` as
views over the renamed metric tables, with the tables' grants, so the UI
release before the rename kept working across the migration and a rollback,
"until the schema change that drops them". No release from the rollback
floor (0072) reads them, and they were a second way in to the poller's
tables and a list of grants to keep. They go.

0052 gave every `waf_match` partition an index on (cluster, request_id) for
the Requests view, and the web role `select` on the matched values. Since 0054
the page reads the hourly findings and nothing reads `waf_match` but the
triggers on it - so each match an attack produced cost one more index insert
for no query, and the web could read what a requester sent, which no page
shows. The index goes from the partition function and from every partition,
and the web's grant is taken back.

Revision ID: 0086
Revises: 0085
"""

from __future__ import annotations

from alembic import op

revision = "0086"
down_revision = "0085"
branch_labels = None
depends_on = None

ROLLBACK_SAFE = True
ROLLBACK_SAFE_BECAUSE = (
    "drops views and an index no release from 0072 on reads, and a select grant on waf_match "
    "no release from 0054 on uses"
)

#
# 0023's column lists, for the way back.
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

_PARTITION_FUNCTION = """
    create or replace function waf_match_partition(day date)
        returns text language plpgsql as $$
    declare
        partition text := format('waf_match_%s', to_char(day, 'YYYYMMDD'));
    begin
        execute format(
            'create table if not exists %I partition of waf_match '
            'for values from (%L) to (%L)',
            partition, day, day + 1
        );{index}
        return partition;
    end;
    $$;
"""

_REQUEST_INDEX = """
        execute format(
            'create index if not exists %I on %I (cluster, request_id)',
            partition || '_request', partition
        );"""


def upgrade() -> None:
    op.execute("""
    drop view if exists metric_listener;
    drop view if exists metric_pool_member;
    drop view if exists metric_pool_hour;

    revoke select on waf_match from app_web;
    """)
    op.execute(_PARTITION_FUNCTION.format(index=""))
    op.execute("""
    do $$
    declare
        found record;
    begin
        for found in
            select child.relname
              from pg_inherits
              join pg_class child on child.oid = pg_inherits.inhrelid
              join pg_class parent on parent.oid = pg_inherits.inhparent
             where parent.relname = 'waf_match'
        loop
            execute format('drop index if exists %I', found.relname || '_request');
        end loop;
    end;
    $$;
    """)


def downgrade() -> None:
    op.execute(_PARTITION_FUNCTION.format(index=_REQUEST_INDEX))
    op.execute("""
    do $$
    declare
        found record;
    begin
        for found in
            select child.relname
              from pg_inherits
              join pg_class child on child.oid = pg_inherits.inhrelid
              join pg_class parent on parent.oid = pg_inherits.inhparent
             where parent.relname = 'waf_match'
        loop
            execute format(
                'create index if not exists %I on %I (cluster, request_id)',
                found.relname || '_request', found.relname
            );
        end loop;
    end;
    $$;

    grant select (
        cluster, node, occurred_at, request_id, object, rule_id, field, matched,
        path, client
    ) on waf_match to app_web;

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
