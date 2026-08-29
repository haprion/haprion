"""Cache the published proxy inventory separately from node status.

Revision ID: 0005
Revises: 0004
"""

from __future__ import annotations

from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    create table cluster_inventory (
        cluster      text primary key,
        observed_at  timestamptz not null default statement_timestamp(),
        outcome      text not null,
        result       jsonb not null,
        warnings     jsonb not null default '[]'::jsonb,
        error        jsonb,
        poll_error   text,

        constraint cluster_inventory_cluster_shape
            check (cluster ~ '^[a-z0-9][a-z0-9_-]{0,31}$'),
        constraint cluster_inventory_outcome_allowed
            check (outcome in ('done', 'failed', 'unavailable'))
    );

    create function cluster_inventory_observed_at() returns trigger
        language plpgsql as $$
    begin
        new.observed_at := statement_timestamp();
        return new;
    end;
    $$;

    create trigger cluster_inventory_observed_at
        before update on cluster_inventory
        for each row execute function cluster_inventory_observed_at();

    grant insert (cluster, outcome, result, warnings, error, poll_error)
        on cluster_inventory to app_poller;
    grant update (outcome, result, warnings, error, poll_error)
        on cluster_inventory to app_poller;
    grant select (cluster, observed_at, outcome, result, warnings, error, poll_error)
        on cluster_inventory to app_poller, app_web;
    """)


def downgrade() -> None:
    op.execute("""
    drop table if exists cluster_inventory;
    drop function if exists cluster_inventory_observed_at();
    """)
