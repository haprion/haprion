"""Record the continuous boundary covered by each metric rollup.

Revision ID: 0021
Revises: 0020
"""

from __future__ import annotations

from alembic import op

revision = "0021"
down_revision = "0020"
branch_labels = None
depends_on = None


def upgrade() -> None:
    #
    # A row in the rollup is not proof of continuous coverage: a complete hour
    # can legitimately contain no samples. The privileged retention command
    # advances this boundary in the same statement that writes the rollup, so
    # every instant before it has been considered whether or not it produced a
    # row. Application roles can read the boundary and cannot move it.
    #
    op.execute("""
    create table metric_rollup_state (
        rollup_name     text primary key,
        complete_before timestamptz not null,
        updated_at      timestamptz not null default transaction_timestamp(),

        constraint metric_rollup_state_boundary_on_the_hour
            check (complete_before = date_trunc('hour', complete_before))
    );

    insert into metric_rollup_state (rollup_name, complete_before)
    values (
        'pool_hour',
        date_trunc('hour', transaction_timestamp()) - interval '7 days'
    );

    grant select (rollup_name, complete_before)
        on metric_rollup_state to app_web;
    """)


def downgrade() -> None:
    op.execute("drop table if exists metric_rollup_state;")
