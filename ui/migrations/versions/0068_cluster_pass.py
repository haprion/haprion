"""When the poller last read a cluster through, from a start after which moment (26-10-11).

A page that watched a job finish redrew on the next status reading, but the
status is the first thing a pass records and the objects, network and settings
readings - what the dashboard's Publish & deploy counts from - come after it. A
redraw in between showed the button the job had just made untrue, and waited
for the next pass to fix it. A pass already running when the job ended was
worse: every reading in it was taken before the change.

`cluster_pass` says, per cluster, when the pass now running began and from
which beginning the last whole pass was read. A cluster has caught up with a
job once that beginning is later than the job's end. Both moments are the
database's: the poller names the cluster and nothing else.

Revision ID: 0068
Revises: 0067
"""

from __future__ import annotations

from alembic import op

revision = "0068"
down_revision = "0067"
branch_labels = None
depends_on = None

ROLLBACK_SAFE = True
ROLLBACK_SAFE_BECAUSE = (
    "adds one table; a UI from before neither writes nor reads it, and its pages wait on the "
    "status reading as they did"
)


def upgrade() -> None:
    op.execute("""
    create table cluster_pass (
        cluster       text primary key,
        began_at      timestamptz not null default statement_timestamp(),
        settled_from  timestamptz,

        constraint cluster_pass_cluster_shape
            check (cluster ~ '^[a-z0-9][a-z0-9_-]{0,31}$')
    );

    grant insert (cluster) on cluster_pass to app_poller;
    grant update (began_at, settled_from) on cluster_pass to app_poller;
    grant select (cluster, began_at, settled_from) on cluster_pass to app_poller, app_web;
    """)


def downgrade() -> None:
    op.execute("drop table if exists cluster_pass;")
