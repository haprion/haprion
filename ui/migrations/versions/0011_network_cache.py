"""Cache each cluster's network description.

Revision ID: 0011
Revises: 0010
"""

from __future__ import annotations

from alembic import op

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    #
    # Addresses and address groups: what an object may be served on, leave from
    # and be restricted to. Nothing private is in the envelope, and nothing in
    # it is authoritative - the cluster repository is. This table exists so
    # that no page view has to reach a helper, the same reason every other
    # cache here exists.
    #
    # `partial` is not allowed. The description is read in one place, from one
    # file, so a half-answer would mean the helper is doing something it should
    # not.
    #
    op.execute("""
    create table cluster_network (
        cluster      text primary key,
        observed_at  timestamptz not null default statement_timestamp(),
        outcome      text not null,
        result       jsonb not null,
        warnings     jsonb not null default '[]'::jsonb,
        error        jsonb,
        poll_error   text,

        constraint cluster_network_cluster_shape
            check (cluster ~ '^[a-z0-9][a-z0-9_-]{0,31}$'),
        constraint cluster_network_outcome_allowed
            check (outcome in ('done', 'failed', 'unavailable'))
    );

    create function cluster_network_observed_at() returns trigger
        language plpgsql as $$
    begin
        new.observed_at := statement_timestamp();
        return new;
    end;
    $$;

    create trigger cluster_network_observed_at
        before update on cluster_network
        for each row execute function cluster_network_observed_at();

    grant insert (cluster, outcome, result, warnings, error, poll_error)
        on cluster_network to app_poller;
    grant update (outcome, result, warnings, error, poll_error)
        on cluster_network to app_poller;
    grant select (cluster, observed_at, outcome, result, warnings, error, poll_error)
        on cluster_network to app_poller, app_web;
    """)


def downgrade() -> None:
    op.execute("""
    drop table if exists cluster_network;
    drop function if exists cluster_network_observed_at();
    """)
