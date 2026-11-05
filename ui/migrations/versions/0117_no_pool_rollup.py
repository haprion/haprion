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
it (`inserted_after`).

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
    "which 0.99.13 does not select; node_event_state gets a column with a default, which "
    "0.99.13's insert does not name and its conflict update leaves alone"
)

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
    op.execute("alter table node_event_state add column since timestamptz not null default now()")
    op.execute("grant select (since), insert (since), update (since) on node_event_state to app_poller")
