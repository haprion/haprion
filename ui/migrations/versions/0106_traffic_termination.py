"""The traffic log keeps how each session ended: HAProxy's two letters.

`%ts` says who ended a session and in which state - `--` normally, `CD` a
client that went away mid-transfer, `SH` a server that closed before its
headers. Two answers without a server's response on 2026-10-31 had nothing
else to say which side stopped.

A collector from before writes no value, so its rows take the default; a web
from before names its columns in the view and never reads this one.

Revision ID: 0106
Revises: 0105
"""

from __future__ import annotations

from alembic import op

revision = "0106"
down_revision = "0105"
branch_labels = None
depends_on = None

ROLLBACK_SAFE = True
ROLLBACK_SAFE_BECAUSE = (
    "a column with a default and a view widened at its end; code from before names neither"
)


def upgrade() -> None:
    op.execute("""
    alter table traffic_log add column termination text not null default '';
    alter table traffic_log add constraint traffic_log_termination_shape
        check (termination ~ '^([A-Z-]{2})?$');
    grant insert (termination) on traffic_log to app_collector;
    create or replace view traffic_log_read as
        select cluster, node, occurred_at, request_number, client, method, host, path,
               frontend, backend, server, status, request_time, queue_time, connect_time,
               response_time, total_time, bytes, rule, waf_rules, waf_score, waf_id,
               termination
          from traffic_log;
    """)
