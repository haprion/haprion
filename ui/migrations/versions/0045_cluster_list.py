"""Which clusters exist, as the poller last read them (Fas 16, B206/B211).

One row: the cluster file's IDs and display names in its order, replaced by the
poller on every pass from `haproxy-cluster-list-helper`. The pages draw the
clusters it names, so a cluster created or removed from Settings appears or
goes at the next pass instead of after `ui.toml` is edited and the services are
restarted. One row rather than one per cluster, so replacing the list is an
update and the poller needs no delete privilege it has never had.

Revision ID: 0045
Revises: 0044
"""

from __future__ import annotations

from alembic import op

revision = "0045"
down_revision = "0044"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    create table cluster_list (
        id           smallint primary key default 1,
        observed_at  timestamptz not null default statement_timestamp(),
        clusters     jsonb not null,

        constraint cluster_list_one_row check (id = 1),
        constraint cluster_list_is_array check (jsonb_typeof(clusters) = 'array')
    );

    create function cluster_list_observed_at() returns trigger
        language plpgsql as $$
    begin
        new.observed_at := statement_timestamp();
        return new;
    end;
    $$;

    create trigger cluster_list_observed_at
        before update on cluster_list
        for each row execute function cluster_list_observed_at();

    grant insert (clusters) on cluster_list to app_poller;
    grant update (clusters) on cluster_list to app_poller;
    grant select (id, observed_at, clusters) on cluster_list to app_poller, app_web;
    """)


def downgrade() -> None:
    op.execute("""
    drop table if exists cluster_list;
    drop function if exists cluster_list_observed_at();
    """)
