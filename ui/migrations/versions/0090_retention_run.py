"""When the nightly maintenance last finished (review 26-10-24, 05-09).

`haprion-retention prune` extends the partitions first and prunes after. A run
that failed in between - the rollup, the version diffs, the jobs - left the
partition horizon fresh, and Needs attention, which reads the horizon, said
nothing while jobs, audit records, sessions and sign-in attempts stopped being
pruned. The command now records here, last of all, that a run finished.

One row. Written by the migration role, which the command runs as; read by the
web. Set when the migration runs, so an installation is judged from then and a
maintenance that never finishes after an upgrade is said two days on.

Revision ID: 0090
Revises: 0089
"""

from __future__ import annotations

from alembic import op

revision = "0090"
down_revision = "0089"
branch_labels = None
depends_on = None

ROLLBACK_SAFE = True
ROLLBACK_SAFE_BECAUSE = "adds one table; a UI from before never reads it"


def upgrade() -> None:
    op.execute("""
    create table retention_run (
        singleton    boolean primary key default true check (singleton),
        completed_at timestamptz not null
    );
    insert into retention_run (completed_at) values (now());

    grant select (completed_at) on retention_run to app_web;
    """)


def downgrade() -> None:
    op.execute("drop table if exists retention_run;")
