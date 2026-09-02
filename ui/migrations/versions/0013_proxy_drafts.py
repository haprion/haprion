"""One editable draft per object, per cluster.

Revision ID: 0013
Revises: 0012
"""

from __future__ import annotations

from alembic import op

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    #
    # A draft is work in progress and never a source of truth. The cluster
    # repository is, and nothing here is published until somebody asks for it -
    # at which point the exact document and revision are copied into the job
    # payload, so later edits to the draft do not ride along with a publish
    # somebody already clicked.
    #
    # `deleted` marks an object the draft says should be *removed* on publish.
    # It is not a soft delete of the draft row: discarding a draft is a real
    # delete, because an abandoned edit should leave no trace to be confused
    # with a decision. Removing a site is itself an edit, and it needs the same
    # review and the same publish as any other.
    #
    # `revision` is what makes two tabs or two admins safe. It is maintained by
    # a trigger rather than by the caller: a writer that forgot to increment it
    # would silently turn optimistic concurrency off, and the failure would be
    # one edit quietly overwriting another.
    #
    op.execute("""
    create table proxy_draft (
        cluster      text not null,
        object_id    text not null,
        yaml         text not null,
        base_version integer,
        base_hash    text not null,
        revision     integer not null default 1,
        updated_by   text not null,
        updated_at   timestamptz not null default statement_timestamp(),
        deleted      boolean not null default false,

        primary key (cluster, object_id),

        --
        -- Shapes rather than lists, for the reason audit_event gives: cluster
        -- IDs come from runtime configuration, and enumerating them here would
        -- make every new cluster a migration.
        --
        constraint proxy_draft_cluster_shape
            check (cluster ~ '^[a-z0-9][a-z0-9_-]{0,31}$'),

        --
        -- The same name the engine's model accepts, so a draft cannot be
        -- created under a name a publish would then refuse.
        --
        constraint proxy_draft_object_shape
            check (object_id ~ '^[a-z][a-z0-9-]{0,62}$'),

        --
        -- `MAX_MODEL_BYTES` in the engine. A document larger than the model
        -- will read is not a draft anybody wrote.
        --
        constraint proxy_draft_yaml_size
            check (octet_length(yaml) <= 262144),

        --
        -- The commit the draft was made against, which is what a publish
        -- compares its snapshot to. Not nullable: an edit is always made
        -- against something, and a draft that could not say what would have to
        -- be published blind.
        --
        constraint proxy_draft_base_hash_shape
            check (base_hash ~ '^[0-9a-f]{40}$'),

        --
        -- Null where nothing is published yet, which is a new cluster rather
        -- than a broken one.
        --
        constraint proxy_draft_base_version_positive
            check (base_version is null or base_version >= 1),

        constraint proxy_draft_updated_by_shape
            check (length(updated_by) between 1 and 64),
        constraint proxy_draft_revision_positive check (revision >= 1),

        --
        -- A draft that removes an object carries no document to publish. The
        -- column stays `not null` so there is one shape to read; empty is the
        -- honest value, and it is refused for every other draft.
        --
        constraint proxy_draft_deleted_carries_no_document
            check (deleted or length(yaml) > 0)
    );

    --
    -- No index beyond the primary key. `(cluster, object_id)` is the key, so
    -- the listing a cluster page makes - every draft for one cluster, ordered
    -- by name - is already served by it. A second index on the same columns in
    -- the same order costs every write and answers nothing.
    --
    -- Both fields are the database's answer and not the caller's. A writer
    -- cannot backdate an edit or hold a revision still, which is what lets a
    -- reader trust the pair for concurrency.
    --
    create function proxy_draft_touch() returns trigger
        language plpgsql as $$
    begin
        new.revision := old.revision + 1;
        new.updated_at := statement_timestamp();
        return new;
    end;
    $$;

    create trigger proxy_draft_touch
        before update on proxy_draft
        for each row execute function proxy_draft_touch();

    --
    -- The web role alone. The poller never writes anything a person authored,
    -- and the worker publishes from the job payload rather than from the table
    -- - so neither needs to see a draft at all.
    --
    -- `revision` and `updated_at` are left out of both grants on purpose: they
    -- come from the default and the trigger, so the web role cannot set them.
    --
    grant select (cluster, object_id, yaml, base_version, base_hash, revision,
                  updated_by, updated_at, deleted)
        on proxy_draft to app_web;
    grant insert (cluster, object_id, yaml, base_version, base_hash, updated_by, deleted)
        on proxy_draft to app_web;
    grant update (yaml, base_version, base_hash, updated_by, deleted)
        on proxy_draft to app_web;
    grant delete on proxy_draft to app_web;
    """)


def downgrade() -> None:
    op.execute("""
    drop table if exists proxy_draft;
    drop function if exists proxy_draft_touch();
    """)
