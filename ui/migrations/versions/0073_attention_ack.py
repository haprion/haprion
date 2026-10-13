"""What an admin has acknowledged in *Needs attention* (B299, 26-10-13).

A row there goes when what it says is put right, or for a job when the next
run of its operation works. Some never are: a restore given up, a receiver
that is down on purpose. An admin acknowledges one, and it is left out of the
dashboard and of `/status/attention.json` until it has gone - a later
failure, or the same state coming back after it went, is a row again.

A row is named by its kind, cluster and subject, as the list shows them; a
job's subject is its number, so a new failure is a new row. The web writes
and reads the acknowledgements and removes the ones whose row has gone.

Revision ID: 0073
Revises: 0072
"""

from __future__ import annotations

from alembic import op

revision = "0073"
down_revision = "0072"
branch_labels = None
depends_on = None

ROLLBACK_SAFE = True
ROLLBACK_SAFE_BECAUSE = "adds one table; a UI from before neither reads nor writes it"


def upgrade() -> None:
    op.execute("""
    create table attention_ack (
        kind             text not null check (length(kind) between 1 and 32),
        cluster          text not null default '' check (length(cluster) <= 64),
        subject          text not null check (length(subject) between 1 and 256),
        acknowledged_by  text not null check (length(acknowledged_by) between 1 and 64),
        acknowledged_at  timestamptz not null default statement_timestamp(),
        primary key (kind, cluster, subject)
    );

    grant select (kind, cluster, subject, acknowledged_by, acknowledged_at)
        on attention_ack to app_web;
    grant insert (kind, cluster, subject, acknowledged_by) on attention_ack to app_web;
    grant delete on attention_ack to app_web;
    """)


def downgrade() -> None:
    op.execute("drop table if exists attention_ack;")
