"""A third feature switch: the clusters' colours (Fas 14 point 9, B204).

`cluster_colours` - the low-chroma rule down each cluster card's left edge,
one of six colours handed out in the order `ui.toml` lists the clusters. On to
begin with, since it is what the interface has always drawn. With more than
six clusters the interface treats it as off whatever the row says: a seventh
colour would repeat the first, and a marker that has to be doubted is worse
than none. The name stands beside every card either way.

Nothing else changes: the web may flip it like the other two, and cannot add,
remove or rename a switch.

Revision ID: 0042
Revises: 0041
"""

from __future__ import annotations

from alembic import op

revision = "0042"
down_revision = "0041"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    alter table feature_switch
        drop constraint feature_switch_name,
        add constraint feature_switch_name
            check (name in ('cert_receivers', 'node_backups', 'cluster_colours'));

    insert into feature_switch (name, enabled) values ('cluster_colours', true);
    """)


def downgrade() -> None:
    op.execute("""
    delete from feature_switch where name = 'cluster_colours';

    alter table feature_switch
        drop constraint feature_switch_name,
        add constraint feature_switch_name check (name in ('cert_receivers', 'node_backups'));
    """)
