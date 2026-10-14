"""What the manager holds, read for the manager rather than for a cluster (B304, 26-10-14).

The certificate registry - every certificate, the receivers, what the
interface is served with - travelled in each cluster's certificate listing,
and so in `cluster_certificates`. A manager with no cluster yet (B302) then
said nothing about its own certificates, not even the one it is served with.
The poller now asks for them once a pass with no cluster named, and keeps the
answer here: one row, like `cluster_list`.

The search found the registry's certificates through each cluster's rows, so
it gets the manager's too: `search_entry` rows with no cluster, from the
source `manager`, and only from it.

Revision ID: 0074
Revises: 0073
"""

from __future__ import annotations

from alembic import op

revision = "0074"
down_revision = "0073"
branch_labels = None
depends_on = None

ROLLBACK_SAFE = True
ROLLBACK_SAFE_BECAUSE = (
    "adds one table and lets search_entry hold rows with no cluster, which a UI from before "
    "neither writes nor matches; its registry view reads the cluster listing, so it needs the "
    "CLI release from before as well"
)


def upgrade() -> None:
    op.execute("""
    create table manager_certificates (
        id           smallint primary key default 1,
        observed_at  timestamptz not null default statement_timestamp(),
        outcome      text not null,
        result       jsonb not null,
        warnings     jsonb not null default '[]'::jsonb,
        error        jsonb,
        poll_error   text,

        constraint manager_certificates_one_row check (id = 1),
        constraint manager_certificates_outcome_allowed
            check (outcome in ('done', 'failed', 'unavailable'))
    );

    create function manager_certificates_observed_at() returns trigger
        language plpgsql as $$
    begin
        new.observed_at := statement_timestamp();
        return new;
    end;
    $$;

    create trigger manager_certificates_observed_at
        before update on manager_certificates
        for each row execute function manager_certificates_observed_at();

    grant insert (outcome, result, warnings, error, poll_error)
        on manager_certificates to app_poller;
    grant update (outcome, result, warnings, error, poll_error)
        on manager_certificates to app_poller;
    grant select (id, observed_at, outcome, result, warnings, error, poll_error)
        on manager_certificates to app_poller, app_web;

    alter table search_entry alter column cluster drop not null;
    alter table search_entry drop constraint search_entry_source_allowed;
    alter table search_entry add constraint search_entry_source_allowed
        check (source in ('objects', 'network', 'cert_list', 'status', 'cluster_list', 'manager'));
    alter table search_entry add constraint search_entry_manager_has_no_cluster
        check ((cluster is null) = (source = 'manager'));
    """)


def downgrade() -> None:
    op.execute("""
    delete from search_entry where cluster is null;
    alter table search_entry drop constraint search_entry_manager_has_no_cluster;
    alter table search_entry drop constraint search_entry_source_allowed;
    alter table search_entry add constraint search_entry_source_allowed
        check (source in ('objects', 'network', 'cert_list', 'status', 'cluster_list'));
    alter table search_entry alter column cluster set not null;
    drop table if exists manager_certificates;
    drop function if exists manager_certificates_observed_at();
    """)
