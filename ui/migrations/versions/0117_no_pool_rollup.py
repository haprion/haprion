"""The hourly pool rollup and its boundary are taken away: nothing reads them (B451); the
traffic log view shows when a row was stored (B451, T08).

`haprion-retention` copied one reading per pool member and hour into
`metric_backend_hour` every night and kept it for a year, with
`metric_rollup_state` saying how far it had come. The interface never read it:
the metrics cards take their long windows from the hourly sums of stored
differences (`metric_backend_hour_delta`, 0055, kept 31 days) and their last
week from the raw samples. The rollup also held the raw pool samples back from
retention until it had gone past them. Taken away: the table and its monthly
partitions, the boundary table, and `metric_month_partition`, which only made
the rollup's partitions.

`traffic_log_read` gains `inserted_at`, the time a row reached the database, as
its last column. A request carries the time its node accepted it, and a node
that was behind delivers it hours later; a client that follows the traffic API
by `time` never sees such a row. The API gives the insert time and reads from
it (`inserted_after`). A client that follows the log by it asks, for the most
part, in vain, and without an index every such question reads every row of
every day. One BRIN index on `inserted_at` per partition answers it from a few
block ranges: rows arrive in time order, so the ranges are tight, and the index
is a fraction of a btree's size. The index is made with `autosummarize`: a range
is summarized when it is full, not when a vacuum sees it, and the last fifth of a
day that is finished is never vacuumed (B469). `traffic_log_partition()` makes it
for the days made from now on, and this makes it for the days that exist, as 0111
did for the client index. The build holds a day's writes for as long as it takes, a second
or so; the collector re-reads from its checkpoint, so a write waiting for it is
only late.

`node_event_state` gains `since`, the time its row was last written (B455). A node
that has not answered is `joining` only for the join timeout and two poller
rounds; the poller needs to know how long a row has said so. Rows already there
get the time of this migration, so a node still joining has a full limit from
it. Written with the value by the poller, which is granted the column.

Haprion 0.99.13's web, poller and worker never touch these tables. The only
code of its that did is `haprion-retention` and `03-verify`, which the
haprion-ui package installs outside the release directory, and a rollback moves
only the release: they stay as the installed package wrote them, without the
rollup.

Revision ID: 0117
Revises: 0116
"""

from __future__ import annotations

from alembic import op

revision = "0117"
down_revision = "0116"
branch_labels = None
depends_on = None

ROLLBACK_SAFE = True
ROLLBACK_SAFE_BECAUSE = (
    "it takes away tables nothing in 0.99.13's web, poller or worker reads or writes; its "
    "retention and 03-verify, the only code that did, are installed with the package and "
    "stay as the package wrote them over a rollback; the view gets one column at its end, "
    "which 0.99.13 does not select; the partition function makes one more index, which nothing in 0.99.13 names or needs; node_event_state gets a column with a default, which "
    "0.99.13's insert does not name and its conflict update leaves alone"
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
        return partition;
    end;
    $$
"""

EXISTING_PARTITIONS = r"""
do $$
declare
    child regclass;
begin
    for child in
        select inhrelid::regclass from pg_inherits where inhparent = 'traffic_log'::regclass
    loop
        execute format(
            'create index if not exists %I on %s using brin (inserted_at) '
            'with (autosummarize = on)',
            substring(child::text from '[^.]+$') || '_inserted', child
        );
        -- A day that is full is never analyzed again by autovacuum.
        execute format('analyze %s', child);
    end loop;
end;
$$
"""

VIEW = """
create or replace view traffic_log_read as
select cluster, node, occurred_at, request_number, client, method, host, path, frontend,
       backend, server, status, request_time, queue_time, connect_time, response_time,
       total_time, bytes, rule, waf_rules, waf_score, waf_id, termination, event_id,
       inserted_at
  from traffic_log
"""


def upgrade() -> None:
    op.execute("drop table metric_backend_hour")
    op.execute("drop table metric_rollup_state")
    op.execute("drop function metric_month_partition(text, date)")
    op.execute(VIEW)
    op.execute(PARTITION_FUNCTION)
    op.execute(EXISTING_PARTITIONS)
    op.execute("alter table node_event_state add column since timestamptz not null default now()")
    op.execute(
        "grant select (since), insert (since), update (since) on node_event_state to app_poller"
    )
