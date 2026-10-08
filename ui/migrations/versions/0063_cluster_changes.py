"""A cluster's saved network description and settings, before they are published (B257, 2026-10-08).

Until now a change on the network page or to a cluster's settings was published
the moment it was made: a version of its own, and a revert of its own. B257
gathers saved changes into one publish, so these two documents get the saved
state a proxy object has (0062): written here, published with the next publish,
and cleared by the interface once that publish can be read.

One row per cluster and kind, and only the saved state. Each is one form with
one button, and nothing is half-finished on it the way an object's draft is.

The whole document, never a difference. The helper takes a whole document, and
a difference applied to a base that moved would be a document nobody wrote.

Revision ID: 0063
Revises: 0062
"""

from __future__ import annotations

from alembic import op

revision = "0063"
down_revision = "0062"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        create table cluster_change (
            cluster    text not null,
            kind       text not null,
            document   text not null,
            base_hash  text not null,
            revision   integer not null default 1,
            updated_by text not null,
            updated_at timestamptz not null default statement_timestamp(),
            --
            -- Never reused, as a proxy draft's (0017): the publish that carries
            -- the row names it, and the row saved after that publish is
            -- visibly not the one it carried.
            --
            id         uuid not null default gen_random_uuid(),

            primary key (cluster, kind),
            constraint cluster_change_cluster_shape
                check (cluster ~ '^[a-z0-9][a-z0-9_-]{0,31}$'),
            constraint cluster_change_kind check (kind in ('network', 'settings')),
            --
            -- `MAX_NETWORK_BYTES` in the engine, the larger of the two limits;
            -- the helper holds each document to its own.
            --
            constraint cluster_change_document_size
                check (octet_length(document) between 1 and 65536),
            constraint cluster_change_base_hash_shape check (base_hash ~ '^[0-9a-f]{40}$'),
            constraint cluster_change_updated_by_shape
                check (length(updated_by) between 1 and 64),
            constraint cluster_change_revision_positive check (revision >= 1)
        );

        --
        -- The revision and the time are the database's, as for a draft: the
        -- same trigger function, since it reads nothing but those two columns.
        --
        create trigger cluster_change_touch
            before update on cluster_change
            for each row execute function proxy_draft_touch();

        --
        -- The web role alone, as for drafts: the worker publishes from the job
        -- payload and never reads the table.
        --
        grant select (cluster, kind, document, base_hash, revision, updated_by, updated_at, id)
            on cluster_change to app_web;
        grant insert (cluster, kind, document, base_hash, updated_by) on cluster_change to app_web;
        grant update (document, base_hash, updated_by) on cluster_change to app_web;
        grant delete on cluster_change to app_web;
        """
    )


def downgrade() -> None:
    op.execute("drop table if exists cluster_change")
