"""A saved change beside a draft, and the name a renamed object replaces (B257, 2026-10-08).

Until now every row was a draft, and a draft was what *Save and publish*
published. B257 tells the two apart: a *draft* is work somebody has not
finished and is never part of a publish; a *saved* change is finished and goes
out with the next one. An object can have both - a draft started on top of a
saved change leaves the saved change in the next publish until the draft is
saved over it - so `stage` joins the key.

The rows that exist become drafts. Nobody has said they are finished, and a
row that turned up in a publish without anybody deciding so is the thing this
change exists to prevent.

`replaces` is the published name a renamed object takes the place of. It was
worked out at the moment of publishing, from the name in the address and the
name in the form - so a rename that was saved and published later had lost it,
and the publish added the new object beside the old one. Kept on the row, the
publish that carries the row carries the removal too.

`update (object_id)` is granted as well: a rename moves the key, and the web
role could not - renaming an unpublished draft was refused by the database
(found 2026-10-08; every test of it imitated the cursor).

Revision ID: 0062
Revises: 0061
"""

from __future__ import annotations

from alembic import op

revision = "0062"
down_revision = "0061"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        alter table proxy_draft
            add column stage text not null default 'draft',
            add column replaces text,
            add constraint proxy_draft_stage check (stage in ('draft', 'saved')),
            --
            -- The engine's object name, as `object_id` is held to, and never the
            -- object's own: a row that replaced itself would remove what it
            -- publishes.
            --
            add constraint proxy_draft_replaces_shape
                check (
                    replaces is null
                    or (replaces ~ '^[a-z][a-z0-9_-]{0,39}$' and replaces <> object_id)
                ),
            drop constraint proxy_draft_pkey,
            add primary key (cluster, object_id, stage);

        --
        -- `stage` is written once, when the row is made. Saving a draft is a
        -- write of the saved row and a delete of the draft, so no row ever
        -- changes what it is.
        --
        grant select (stage, replaces) on proxy_draft to app_web;
        grant insert (stage, replaces) on proxy_draft to app_web;
        grant update (object_id, replaces) on proxy_draft to app_web;
        """
    )


def downgrade() -> None:
    #
    # Can fail, and should: a saved change and a draft of the same object are
    # two rows, and the old key holds one. Which to keep is somebody's
    # decision, not a migration's.
    #
    op.execute(
        """
        revoke update (object_id, replaces) on proxy_draft from app_web;
        alter table proxy_draft
            drop constraint proxy_draft_pkey,
            add primary key (cluster, object_id),
            drop column replaces,
            drop column stage;
        """
    )
