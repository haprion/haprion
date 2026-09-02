"""Cache each cluster's proxy objects as they are written.

Revision ID: 0014
Revises: 0013
"""

from __future__ import annotations

from alembic import op

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    #
    # The source the editor loads and the preview renders. `cluster_inventory`
    # holds published HAProxy configuration, which is derived: it can say what a
    # frontend binds but not which route the author wrote first or what they
    # called a backend. Editing needs the object, so the object is cached too.
    #
    # It caches the commit's answer and never a working tree's, because that is
    # what the helper reads - a file somebody is halfway through saving must not
    # be able to look like a stored object.
    #
    # Nothing here is authoritative. The cluster repository is, and a draft is
    # published against `commit` in the cached result rather than against
    # anything this table decides.
    #
    # `partial` is not allowed, for the reason `cluster_network` gives: the
    # objects are read in one place, from one commit, so a half-answer would
    # mean the helper is doing something it should not.
    #
    op.execute("""
    create table cluster_objects (
        cluster      text primary key,
        observed_at  timestamptz not null default statement_timestamp(),
        outcome      text not null,
        result       jsonb not null,
        warnings     jsonb not null default '[]'::jsonb,
        error        jsonb,
        poll_error   text,

        constraint cluster_objects_cluster_shape
            check (cluster ~ '^[a-z0-9][a-z0-9_-]{0,31}$'),
        constraint cluster_objects_outcome_allowed
            check (outcome in ('done', 'failed', 'unavailable'))
    );

    create function cluster_objects_observed_at() returns trigger
        language plpgsql as $$
    begin
        new.observed_at := statement_timestamp();
        return new;
    end;
    $$;

    create trigger cluster_objects_observed_at
        before update on cluster_objects
        for each row execute function cluster_objects_observed_at();

    --
    -- The poller writes and the web role reads, as with every other cache.
    -- `observed_at` is in neither write grant: it comes from the default and
    -- the trigger, so a reading cannot be backdated into looking fresh.
    --
    grant insert (cluster, outcome, result, warnings, error, poll_error)
        on cluster_objects to app_poller;
    grant update (outcome, result, warnings, error, poll_error)
        on cluster_objects to app_poller;
    grant select (cluster, observed_at, outcome, result, warnings, error, poll_error)
        on cluster_objects to app_poller, app_web;
    """)


def downgrade() -> None:
    op.execute("""
    drop table if exists cluster_objects;
    drop function if exists cluster_objects_observed_at();
    """)
