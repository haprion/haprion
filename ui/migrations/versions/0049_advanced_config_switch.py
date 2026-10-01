"""A fourth feature switch: advanced config per object (Fas 17, B205, B224).

`advanced_config` - the *Advanced config* button on an object's page and the
dialog it opens, where HAProxy configuration is pasted as a layer on top of
the object. Off to begin with: the layer is the user's own text, checked by
`haproxy -c` but not by the form, and an installation chooses to offer it.

Off hides the button and the dialog and nothing else. The engine generates an
object's text whatever the switch says, and the object's page still shows
that the object has one - a switch that silently dropped published
configuration would change traffic by being flipped.

Nothing else changes: the web may flip it like the other three, and cannot
add, remove or rename a switch.

Revision ID: 0049
Revises: 0048
"""

from __future__ import annotations

from alembic import op

revision = "0049"
down_revision = "0048"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    alter table feature_switch
        drop constraint feature_switch_name,
        add constraint feature_switch_name
            check (name in ('cert_receivers', 'node_backups', 'cluster_colours', 'advanced_config'));

    insert into feature_switch (name, enabled) values ('advanced_config', false);
    """)


def downgrade() -> None:
    op.execute("""
    delete from feature_switch where name = 'advanced_config';

    alter table feature_switch
        drop constraint feature_switch_name,
        add constraint feature_switch_name
            check (name in ('cert_receivers', 'node_backups', 'cluster_colours'));
    """)
