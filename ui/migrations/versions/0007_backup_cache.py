"""Cache each cluster's state backup listing separately from the other reads.

Revision ID: 0007
Revises: 0006
"""

from __future__ import annotations

from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    #
    # `partial` is allowed here, unlike inventory and history: a backup listing
    # reaches one directory per node, and one unreadable directory is a fact
    # about that node rather than a failed read of the cluster.
    #
    op.execute("""
    create table cluster_backups (
        cluster      text primary key,
        observed_at  timestamptz not null default statement_timestamp(),
        outcome      text not null,
        result       jsonb not null,
        warnings     jsonb not null default '[]'::jsonb,
        error        jsonb,
        poll_error   text,

        constraint cluster_backups_cluster_shape
            check (cluster ~ '^[a-z0-9][a-z0-9_-]{0,31}$'),
        constraint cluster_backups_outcome_allowed
            check (outcome in ('done', 'partial', 'failed', 'unavailable'))
    );

    create function cluster_backups_observed_at() returns trigger
        language plpgsql as $$
    begin
        new.observed_at := statement_timestamp();
        return new;
    end;
    $$;

    create trigger cluster_backups_observed_at
        before update on cluster_backups
        for each row execute function cluster_backups_observed_at();

    grant insert (cluster, outcome, result, warnings, error, poll_error)
        on cluster_backups to app_poller;
    grant update (outcome, result, warnings, error, poll_error)
        on cluster_backups to app_poller;
    grant select (cluster, observed_at, outcome, result, warnings, error, poll_error)
        on cluster_backups to app_poller, app_web;
    """)


def downgrade() -> None:
    op.execute("""
    drop table if exists cluster_backups;
    drop function if exists cluster_backups_observed_at();
    """)
