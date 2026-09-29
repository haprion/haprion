"""The cluster's own settings: a cache of them, and the job that publishes them (Fas 15).

`managed/cluster.yaml` holds each cluster's external log targets and metrics
exporter (B209). The poller reads it into `cluster_settings` the way it reads
the network description into `cluster_network`, so the Settings card never
reaches a helper; `cluster_settings_publish` is the worker's job that writes
it, a version like a network publish.

Revision ID: 0043
Revises: 0042
"""

from __future__ import annotations

from alembic import op

revision = "0043"
down_revision = "0042"
branch_labels = None
depends_on = None

OLD = (
    "'deploy', 'cert_deploy', 'revert', 'network_publish', 'objects_publish', "
    "'cert_issue', 'cert_publish', 'cert_target', 'dns_profile_apply', 'cert_delete', "
    "'ndes_profile_apply', 'cert_scep', 'cert_receiver', 'cert_import', 'cert_request', "
    "'backup_run', 'backup_schedule', 'node_restore_prepare', 'node_restore_preview', "
    "'node_restore', 'node_restore_discard', 'node_restore_status'"
)


def upgrade() -> None:
    op.execute(f"""
    alter table job drop constraint job_operation_allowed;
    alter table job add constraint job_operation_allowed
        check (operation in ({OLD}, 'cluster_settings_publish'));

    create table cluster_settings (
        cluster      text primary key,
        observed_at  timestamptz not null default statement_timestamp(),
        outcome      text not null,
        result       jsonb not null,
        warnings     jsonb not null default '[]'::jsonb,
        error        jsonb,
        poll_error   text,

        constraint cluster_settings_cluster_shape
            check (cluster ~ '^[a-z0-9][a-z0-9_-]{{0,31}}$'),
        constraint cluster_settings_outcome_allowed
            check (outcome in ('done', 'failed', 'unavailable'))
    );

    create function cluster_settings_observed_at() returns trigger
        language plpgsql as $$
    begin
        new.observed_at := statement_timestamp();
        return new;
    end;
    $$;

    create trigger cluster_settings_observed_at
        before update on cluster_settings
        for each row execute function cluster_settings_observed_at();

    grant insert (cluster, outcome, result, warnings, error, poll_error)
        on cluster_settings to app_poller;
    grant update (outcome, result, warnings, error, poll_error)
        on cluster_settings to app_poller;
    grant select (cluster, observed_at, outcome, result, warnings, error, poll_error)
        on cluster_settings to app_poller, app_web;
    """)


def downgrade() -> None:
    # Refuses while a settings job row exists; history is not discarded.
    op.execute(f"""
    drop table if exists cluster_settings;
    drop function if exists cluster_settings_observed_at();
    alter table job drop constraint job_operation_allowed;
    alter table job add constraint job_operation_allowed
        check (operation in ({OLD}));
    """)
