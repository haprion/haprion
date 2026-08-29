"""Cache each cluster's deployable certificate metadata.

Revision ID: 0008
Revises: 0007
"""

from __future__ import annotations

from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    #
    # Metadata only, and that is a property of what the helper sends rather than
    # of this table: no private key material exists in the envelope to store.
    # `partial` is not allowed - the read is of one directory, so a certificate
    # that cannot be read is reported inside the result, not as a half-answer.
    #
    op.execute("""
    create table cluster_certificates (
        cluster      text primary key,
        observed_at  timestamptz not null default statement_timestamp(),
        outcome      text not null,
        result       jsonb not null,
        warnings     jsonb not null default '[]'::jsonb,
        error        jsonb,
        poll_error   text,

        constraint cluster_certificates_cluster_shape
            check (cluster ~ '^[a-z0-9][a-z0-9_-]{0,31}$'),
        constraint cluster_certificates_outcome_allowed
            check (outcome in ('done', 'failed', 'unavailable'))
    );

    create function cluster_certificates_observed_at() returns trigger
        language plpgsql as $$
    begin
        new.observed_at := statement_timestamp();
        return new;
    end;
    $$;

    create trigger cluster_certificates_observed_at
        before update on cluster_certificates
        for each row execute function cluster_certificates_observed_at();

    grant insert (cluster, outcome, result, warnings, error, poll_error)
        on cluster_certificates to app_poller;
    grant update (outcome, result, warnings, error, poll_error)
        on cluster_certificates to app_poller;
    grant select (cluster, observed_at, outcome, result, warnings, error, poll_error)
        on cluster_certificates to app_poller, app_web;
    """)


def downgrade() -> None:
    op.execute("""
    drop table if exists cluster_certificates;
    drop function if exists cluster_certificates_observed_at();
    """)
