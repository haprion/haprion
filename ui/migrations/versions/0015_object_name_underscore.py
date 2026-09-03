"""Let an object's name carry an underscore.

Revision ID: 0015
Revises: 0014
"""

from __future__ import annotations

from alembic import op

revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    #
    # `proxy_model.NAME`, widened (B72). The constraint exists so a draft cannot
    # be saved under a name a publish would then refuse - which means it has to
    # follow the model rather than hold an older opinion of it, and a test holds
    # the two together.
    #
    # Widening only. Every name that was storable before is storable still, so
    # no row can be made invalid by this and nothing has to be rewritten.
    #
    op.execute(
        """
        alter table proxy_draft
            drop constraint proxy_draft_object_shape,
            add constraint proxy_draft_object_shape
                check (object_id ~ '^[a-z][a-z0-9_-]{0,39}$')
        """
    )


def downgrade() -> None:
    #
    # This one can fail, and should. Going back narrows what may be stored, so a
    # draft saved under a name containing an underscore would have to be deleted
    # for the constraint to hold - and a migration that quietly deleted somebody's
    # unpublished work would be a worse outcome than a downgrade that stops.
    #
    op.execute(
        """
        alter table proxy_draft
            drop constraint proxy_draft_object_shape,
            add constraint proxy_draft_object_shape
                check (object_id ~ '^[a-z][a-z0-9-]{0,39}$')
        """
    )
