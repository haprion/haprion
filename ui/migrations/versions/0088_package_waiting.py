"""The manager's own packages with a newer version waiting in the repository (B357, 26-10-23).

The security review (26-10-22) asked for "fixed in the source, not yet
installed" as a state of its own. The poller compares what dpkg has installed
with what apt's lists already offer - nothing is fetched (B333) - and keeps
one row per `haprion-*` package that is behind. No row, nothing waiting.

`read_at` is when the poller found it so, which the dashboard's row says.

Revision ID: 0088
Revises: 0087
"""

from __future__ import annotations

from alembic import op

revision = "0088"
down_revision = "0087"
branch_labels = None
depends_on = None

ROLLBACK_SAFE = True
ROLLBACK_SAFE_BECAUSE = "adds one table; a UI from before never reads it"


def upgrade() -> None:
    op.execute("""
    create table package_waiting (
        name       text primary key check (name ~ '^haprion-[a-z0-9][a-z0-9.+-]{0,62}$'),
        installed  text not null check (char_length(installed) between 1 and 128),
        available  text not null check (char_length(available) between 1 and 128),
        read_at    timestamptz not null
    );

    --
    -- The poller replaces the rows; the web reads them. Nothing else touches it.
    --
    grant select (name, installed, available, read_at) on package_waiting to app_poller;
    grant insert (name, installed, available, read_at) on package_waiting to app_poller;
    grant delete on package_waiting to app_poller;
    grant select (name, installed, available, read_at) on package_waiting to app_web;
    """)


def downgrade() -> None:
    op.execute("drop table if exists package_waiting;")
