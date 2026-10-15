"""Whether the dashboard's getting started list is hidden (B316, 26-10-15).

One row at most: present once an admin has hidden the list, for the whole
installation and for good. Nothing on the list is stored - every tick is
read from what the installation is - so this is all there is to keep.

Revision ID: 0075
Revises: 0074
"""

from __future__ import annotations

from alembic import op

revision = "0075"
down_revision = "0074"
branch_labels = None
depends_on = None

ROLLBACK_SAFE = True
ROLLBACK_SAFE_BECAUSE = "adds one table; a UI from before neither reads nor writes it"


def upgrade() -> None:
    op.execute("""
    create table getting_started (
        hidden     boolean primary key default true check (hidden),
        hidden_by  text not null check (length(hidden_by) between 1 and 64),
        hidden_at  timestamptz not null default statement_timestamp()
    );

    grant select (hidden, hidden_by, hidden_at) on getting_started to app_web;
    grant insert (hidden_by) on getting_started to app_web;
    """)


def downgrade() -> None:
    op.execute("drop table if exists getting_started;")
