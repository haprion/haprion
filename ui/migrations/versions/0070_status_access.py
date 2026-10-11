"""Who may ask the monitoring endpoint what needs doing (B274, 26-10-11).

`/status/attention.json` and `/status/metrics` answer without a sign-in, so
that Uptime Kuma or Prometheus can ask. What they say is not secret, but it
names services and their trouble, so they answer only addresses on this list,
which an admin keeps on Settings. An empty list is the endpoint switched off.

Revision ID: 0070
Revises: 0069
"""

from __future__ import annotations

from alembic import op

revision = "0070"
down_revision = "0069"
branch_labels = None
depends_on = None

ROLLBACK_SAFE = True
ROLLBACK_SAFE_BECAUSE = "adds one table; a UI from before neither reads nor writes it"


def upgrade() -> None:
    op.execute("""
    create table status_access (
        network   cidr primary key,
        added_by  text not null,
        added_at  timestamptz not null default statement_timestamp()
    );

    grant select (network, added_by, added_at) on status_access to app_web;
    grant insert (network, added_by) on status_access to app_web;
    grant delete on status_access to app_web;
    """)


def downgrade() -> None:
    op.execute("drop table if exists status_access;")
