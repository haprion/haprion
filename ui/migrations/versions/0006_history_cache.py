"""Cache each cluster's saved version listing separately from status and inventory.

Revision ID: 0006
Revises: 0005
"""

from __future__ import annotations

from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    create table cluster_history (
        cluster      text primary key,
        observed_at  timestamptz not null default statement_timestamp(),
        outcome      text not null,
        result       jsonb not null,
        warnings     jsonb not null default '[]'::jsonb,
        error        jsonb,
        poll_error   text,

        constraint cluster_history_cluster_shape
            check (cluster ~ '^[a-z0-9][a-z0-9_-]{0,31}$'),
        constraint cluster_history_outcome_allowed
            check (outcome in ('done', 'failed', 'unavailable'))
    );

    create function cluster_history_observed_at() returns trigger
        language plpgsql as $$
    begin
        new.observed_at := statement_timestamp();
        return new;
    end;
    $$;

    create trigger cluster_history_observed_at
        before update on cluster_history
        for each row execute function cluster_history_observed_at();

    grant insert (cluster, outcome, result, warnings, error, poll_error)
        on cluster_history to app_poller;
    grant update (outcome, result, warnings, error, poll_error)
        on cluster_history to app_poller;
    grant select (cluster, observed_at, outcome, result, warnings, error, poll_error)
        on cluster_history to app_poller, app_web;
    """)


def downgrade() -> None:
    op.execute("""
    drop table if exists cluster_history;
    drop function if exists cluster_history_observed_at();
    """)
