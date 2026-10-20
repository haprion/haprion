"""A draft keeps the object as it stood when the draft was written (26-10-20).

`base_hash` says which version a draft was written against, and every publish
of anything moves it - so a draft was called older than the cluster whenever
any object, the network or `core/` changed, and the way out was to open it and
save again. That save took the draft's document as it was: a change somebody
had published to the same object in between was written away without a word,
because the page's fingerprint (review 26-10-04, CR-01) is taken when the page
opens, from the object as it is published now.

`base_document` is the object as it was published when the draft was written:
its document, or empty where nothing of that name was published. Against it the
interface can tell "the cluster moved" - nothing to do, the draft publishes as
it is - from "this object moved", where the page shows what changed and asks.
Null on the rows from before, which are judged by `base_hash` as they were.

Revision ID: 0080
Revises: 0079
"""

from __future__ import annotations

from alembic import op

revision = "0080"
down_revision = "0079"
branch_labels = None
depends_on = None

ROLLBACK_SAFE = True
ROLLBACK_SAFE_BECAUSE = (
    "adds one nullable column and its grants; a UI from before neither reads nor writes it, "
    "and the rows it writes are judged by base_hash as before"
)


def upgrade() -> None:
    op.execute(
        """
        alter table proxy_draft
            add column base_document text,
            --
            -- The bound `yaml` has, for the same reason: it is a document the
            -- model read.
            --
            add constraint proxy_draft_base_document_size
                check (base_document is null or octet_length(base_document) <= 262144);

        grant select (base_document) on proxy_draft to app_web;
        grant insert (base_document) on proxy_draft to app_web;
        grant update (base_document) on proxy_draft to app_web;
        """
    )


def downgrade() -> None:
    op.execute(
        """
        revoke select (base_document), insert (base_document), update (base_document)
            on proxy_draft from app_web;
        alter table proxy_draft drop column base_document;
        """
    )
