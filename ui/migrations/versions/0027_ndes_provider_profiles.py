"""Store sealed NDES provider profiles, and let the queue apply them.

Revision ID: 0027
Revises: 0026
"""

from __future__ import annotations

from alembic import op

revision = "0027"
down_revision = "0026"
branch_labels = None
depends_on = None

#
# A profile is one provider's credentials, sealed by the web process against
# the installation's public key (B146). The row holds the box and what binds
# it - which profile, which provider, which key, which revision - and nothing
# that could open it. The web writes rows and reads their metadata; the
# worker reads a row to hand the box to the root helper; nobody in this
# database can turn a row back into a token.
#
# `revision` is the replacement counter (B147): a replaced profile is the same
# row with a higher revision and a new box, and the helper refuses a box whose
# revision is lower than the job that carries it. `provider_id` never changes:
# a different provider is a different profile, because the credentials file
# that the profile becomes has a provider-specific shape.
#


def upgrade() -> None:
    op.execute("""
    create table ndes_provider_profile (
        id              text primary key,
        name            text not null,
        provider_id     text not null,
        schema_version  integer not null,
        key_id          text not null,
        revision        integer not null default 1,
        ciphertext      bytea not null,
        created_at      timestamptz not null default statement_timestamp(),
        created_by      text not null,
        updated_at      timestamptz not null default statement_timestamp(),
        updated_by      text not null,

        constraint ndes_provider_profile_id_shape
            check (id ~ '^[a-z0-9][a-z0-9-]{0,31}$'),
        constraint ndes_provider_profile_name_shape
            check (char_length(name) between 1 and 80),
        constraint ndes_provider_profile_provider_shape
            check (provider_id = 'ndes'),
        constraint ndes_provider_profile_key_shape
            check (key_id ~ '^[0-9a-f]{16}$'),
        constraint ndes_provider_profile_schema_version
            check (schema_version = 1),
        constraint ndes_provider_profile_revision_range
            check (revision between 1 and 1000000),
        constraint ndes_provider_profile_ciphertext_size
            check (octet_length(ciphertext) between 48 and 16384)
    );

    --
    -- The web creates and replaces profiles and lists them; it may never
    -- change which provider a profile is for, and the column list says so.
    -- The worker reads what the helper needs and nothing about who made it.
    --
    grant select (id, name, provider_id, schema_version, key_id, revision,
                  created_at, created_by, updated_at, updated_by)
        on ndes_provider_profile to app_web;
    grant insert (id, name, provider_id, schema_version, key_id, revision, ciphertext,
                  created_by, updated_by)
        on ndes_provider_profile to app_web;
    grant update (name, schema_version, key_id, revision, ciphertext, updated_at, updated_by)
        on ndes_provider_profile to app_web;
    grant select (id, provider_id, schema_version, key_id, revision, ciphertext)
        on ndes_provider_profile to app_worker;

    --
    -- Applying a profile is a certificate-scoped job: no cluster, one at a
    -- time with the other certificate work, because the helper writes into
    -- the protected NDES profile directory. No renewal is enabled.
    --
    alter table job drop constraint job_operation_allowed;
    alter table job add constraint job_operation_allowed
        check (operation in ('deploy', 'cert_deploy', 'revert', 'network_publish',
                             'objects_publish', 'cert_issue', 'cert_publish',
                             'cert_target', 'dns_profile_apply', 'cert_delete', 'ndes_profile_apply'));

    alter table job drop constraint job_cluster_presence;
    alter table job add constraint job_cluster_presence
        check ((operation in ('cert_issue', 'cert_publish', 'cert_target',
                              'dns_profile_apply', 'cert_delete', 'ndes_profile_apply'))
               = (cluster is null));
    """)


def downgrade() -> None:
    #
    # Fails where a profile job exists, for the reason 0026 gives. The table
    # goes with it: a box nobody can apply is not worth keeping over a schema
    # that no longer describes it, and the credentials it held are re-entered,
    # never restored.
    #
    op.execute("""
    alter table job drop constraint job_cluster_presence;
    alter table job add constraint job_cluster_presence
        check ((operation in ('cert_issue', 'cert_publish', 'cert_target', 'dns_profile_apply', 'cert_delete'))
               = (cluster is null));

    alter table job drop constraint job_operation_allowed;
    alter table job add constraint job_operation_allowed
        check (operation in ('deploy', 'cert_deploy', 'revert', 'network_publish',
                             'objects_publish', 'cert_issue', 'cert_publish',
                             'cert_target', 'dns_profile_apply', 'cert_delete'));

    drop table if exists ndes_provider_profile;
    """)
