"""Index the metric tables the way the interface actually reads them.

Revision ID: 0022
Revises: 0021
"""

from __future__ import annotations

from alembic import op

revision = "0022"
down_revision = "0021"
branch_labels = None
depends_on = None


def upgrade() -> None:
    #
    # Both tables were created with a primary key and nothing else, and the
    # primary key is ordered for the writer: `(cluster, node, ...)`, because a
    # poll writes one row per node. Every read the interface makes binds the
    # cluster and the series and never the node - a pool's history is the same
    # history whichever machine recorded it, and a listener's is read across
    # both. So the second column of the index is a hole, and the lookup falls
    # back to scanning the partitions the window touches.
    #
    # It costs nothing measurable at today's volume - roughly 75 000 raw rows a
    # day - which is exactly why it is worth doing now: the page gets slower as
    # the history grows, and nothing breaks while it does.
    #
    # Created on the partitioned parents, so every existing partition gets its
    # own and every partition the retention command creates later inherits it.
    #
    op.execute("""
    create index metric_listener_read
        on metric_listener (cluster, frontend, observed_at);

    create index metric_pool_member_read
        on metric_pool_member (cluster, backend, member, observed_at);
    """)


def downgrade() -> None:
    op.execute("""
    drop index if exists metric_listener_read;
    drop index if exists metric_pool_member_read;
    """)
