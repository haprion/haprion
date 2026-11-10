"""Blocklists: what Settings defines, and what the refresh timer last did (B496, 13; B500).

`blocklist` is one row per list as Settings saved it. The password or token is
the sealed box the web made against the installation's DNS profile key: the
web writes it and cannot read it back, and the worker reads it for the
`blocklist_apply` job, whose root helper opens it and writes the definition
the refresh timer reads. `revision` rises with every save, and the helper
refuses a box older than the job's. A removal is a job too, and the worker
deletes the row once the helper has removed the definition, as it does a DNS
profile's: a row gone before that would leave a list the timer fetches and
nobody sees. The column is `auth`: `authorization` is a
word PostgreSQL keeps for itself.

`blocklist_state` is what the timer's last pass did with each list, as the
poller reads it from the manager's state file through the readings helper:
when it was fetched, when it was last tried and failed, why, and how many
entries the last good list holds. The poller writes it whole each cycle and
removes the rows of lists that are gone; the web reads it for Settings, the
Network page and *Needs attention*.

`job_operation_allowed` takes `blocklist_apply`. The constraint stays `not
valid`, as 0109 left it for the retired `block_client` rows.

Haprion 1.0.1's web, poller and worker never name either table, and its worker
refuses a `blocklist_apply` job as an operation it does not know.

Revision ID: 0119
Revises: 0118
"""

from __future__ import annotations

from alembic import op

revision = "0119"
down_revision = "0118"
branch_labels = None
depends_on = None

ROLLBACK_SAFE = True
ROLLBACK_SAFE_BECAUSE = (
    "it adds two tables nothing in 1.0.1 reads or writes, and widens the job operations by one "
    "that 1.0.1's worker refuses"
)


def upgrade() -> None:
    op.execute(
        """
        create table public.blocklist (
            name text primary key
                constraint blocklist_name_check check (name ~ '^[a-z][a-z0-9-]{0,39}$'),
            description text not null default ''
                constraint blocklist_description_check check (char_length(description) <= 200),
            url text not null
                constraint blocklist_url_check
                check (char_length(url) between 9 and 2048 and url like 'https://%'),
            auth text not null default 'none'
                constraint blocklist_auth_check check (auth in ('none', 'basic', 'bearer')),
            username text not null default ''
                constraint blocklist_username_check check (char_length(username) <= 200),
            every_hours integer not null
                constraint blocklist_every_hours_check check (every_hours in (1, 6, 12, 24)),
            excepts text[] not null default '{}'
                constraint blocklist_excepts_check check (cardinality(excepts) <= 256),
            key_id text
                constraint blocklist_key_id_check check (key_id ~ '^[0-9a-f]{16}$'),
            ciphertext bytea
                constraint blocklist_ciphertext_check
                check (octet_length(ciphertext) between 48 and 16384),
            revision integer not null
                constraint blocklist_revision_check check (revision between 1 and 1000000),
            created_at timestamp with time zone not null default statement_timestamp(),
            updated_at timestamp with time zone not null default statement_timestamp(),
            updated_by text not null
                constraint blocklist_updated_by_check check (char_length(updated_by) between 1 and 255),
            constraint blocklist_secret_check check (
                (auth = 'none' and key_id is null and ciphertext is null)
                or (auth <> 'none' and key_id is not null and ciphertext is not null)
            )
        )
        """
    )
    op.execute(
        "grant select (name, description, url, auth, username, every_hours, excepts, key_id, "
        "revision, created_at, updated_at, updated_by), "
        "insert (name, description, url, auth, username, every_hours, excepts, key_id, "
        "ciphertext, revision, updated_by), "
        "update (description, url, auth, username, every_hours, excepts, key_id, ciphertext, "
        "revision, updated_at, updated_by) on public.blocklist to app_web"
    )
    op.execute(
        "grant select (name, description, url, auth, username, every_hours, excepts, key_id, "
        "ciphertext, revision), delete on public.blocklist to app_worker"
    )
    op.execute(
        """
        create table public.blocklist_state (
            name text primary key
                constraint blocklist_state_name_check check (name ~ '^[a-z][a-z0-9-]{0,39}$'),
            fetched_at timestamp with time zone,
            attempted_at timestamp with time zone,
            failed_at timestamp with time zone,
            error text not null default ''
                constraint blocklist_state_error_check check (char_length(error) <= 500),
            entries integer not null default 0
                constraint blocklist_state_entries_check check (entries between 0 and 1000000),
            skipped integer not null default 0
                constraint blocklist_state_skipped_check check (skipped between 0 and 1000000),
            seen_at timestamp with time zone not null
        )
        """
    )
    op.execute(
        "grant select (name, fetched_at, attempted_at, failed_at, error, entries, skipped, "
        "seen_at), insert (name, fetched_at, attempted_at, failed_at, error, entries, skipped, "
        "seen_at), update (fetched_at, attempted_at, failed_at, error, entries, skipped, "
        "seen_at), delete on public.blocklist_state to app_poller"
    )
    op.execute(
        "grant select (name, fetched_at, attempted_at, failed_at, error, entries, skipped, "
        "seen_at) on public.blocklist_state to app_web"
    )
    op.execute("alter table public.job drop constraint job_operation_allowed")
    op.execute(
        "alter table public.job add constraint job_operation_allowed "
        "check ((operation = any (array["
        "'backup_run'::text, "
        "'backup_schedule'::text, "
        "'blocklist_apply'::text, "
        "'cert_delete'::text, "
        "'cert_deploy'::text, "
        "'cert_import'::text, "
        "'cert_issue'::text, "
        "'cert_publish'::text, "
        "'cert_receiver'::text, "
        "'cert_request'::text, "
        "'cert_scep'::text, "
        "'cert_target'::text, "
        "'changes_publish'::text, "
        "'cluster_define'::text, "
        "'cluster_node'::text, "
        "'deploy'::text, "
        "'dns_profile_apply'::text, "
        "'dynamic_unblock'::text, "
        "'ndes_profile_apply'::text, "
        "'node_restore'::text, "
        "'node_restore_discard'::text, "
        "'node_restore_prepare'::text, "
        "'node_restore_preview'::text, "
        "'node_restore_status'::text, "
        "'revert'::text, "
        "'server_state'::text"
        "]))) not valid;"
    )
