"""Give a draft an identity that survives being published.

Revision ID: 0017
Revises: 0016
"""

from __future__ import annotations

from alembic import op

revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None


def upgrade() -> None:
    #
    # A draft is keyed by cluster and object, and it is deleted once its publish
    # is done - so the next edit of the same object starts again at revision 1
    # under the same key. That is why "has this draft been published" could not
    # be answered from the row, and why it was being answered from the document
    # instead: two different pieces of work could produce the same text, and one
    # of them was then thrown away as though it had already been published.
    #
    # This is the missing half. `id` is unique to a draft row and never reused,
    # so the job that publishes one can name it, and the row that comes back
    # afterwards is visibly not the row that was published.
    #
    op.execute(
        """
        alter table proxy_draft
            add column id uuid not null default gen_random_uuid();

        --
        -- Read-only to the web role, exactly like `revision` and `updated_at`.
        -- A role that could set it could hand its own edit somebody else's
        -- identity, which is the one thing the column exists to prevent.
        --
        grant select (id) on proxy_draft to app_web;
        """
    )


def downgrade() -> None:
    op.execute("alter table proxy_draft drop column id")
