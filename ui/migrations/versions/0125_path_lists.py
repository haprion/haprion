"""Path lists: what Settings keeps for *Denied paths* (B527, B532).

`path_list` is one row per list as Settings saved it: a name, a description
and the paths. The `path_list_apply` job has a root helper write the list to
/etc/haprion/path-lists, where every publish reads the lists its objects name.
`revision` rises with every save. A removal is a job too, and the worker
deletes the row once the helper has removed the list, as it does a
blocklist's.

`job_operation_allowed` takes `path_list_apply`. The constraint stays `not
valid`, as 0109 left it. And `job_cluster_presence` names it among the
operations queued with no cluster: a list is the manager's, named by objects
in any cluster.

`list_file` is what the poller last read of the files root keeps for path lists
and blocklists (the `list_files` reading): per list a revision and a digest of
what the file says, which the web compares with its own rows. A path list file
the database has no row for also carries its description and paths, which is
what *Take in* stores. Written whole by the poller each pass; the web reads.

`list_file_read` is the one row that says when the poller last made that
reading. The rows cannot say it: with both directories empty (a database
restored on a new manager) there are none, and a list's missing file would go
unnoticed (review 26-11-24, PW02).

Haprion 1.3.1's web, poller and worker never name the table, and its worker
refuses a `path_list_apply` job as an operation it does not know.

Revision ID: 0125
Revises: 0124
"""

from __future__ import annotations

from alembic import op

revision = "0125"
down_revision = "0124"
branch_labels = None
depends_on = None

ROLLBACK_SAFE = True
ROLLBACK_SAFE_BECAUSE = (
    "it adds a table nothing in 1.3.1 reads or writes, and widens the job operations by one "
    "that 1.3.1's worker refuses"
)


def upgrade() -> None:
    op.execute(
        """
        create table public.path_list (
            name text primary key
                constraint path_list_name_check check (name ~ '^[a-z][a-z0-9-]{0,39}$'),
            description text not null default ''
                constraint path_list_description_check check (char_length(description) <= 200),
            paths text[] not null
                constraint path_list_paths_check check (cardinality(paths) between 1 and 500),
            revision integer not null
                constraint path_list_revision_check check (revision between 1 and 1000000),
            created_at timestamp with time zone not null default statement_timestamp(),
            updated_at timestamp with time zone not null default statement_timestamp(),
            updated_by text not null
                constraint path_list_updated_by_check check (char_length(updated_by) between 1 and 255)
        )
        """
    )
    op.execute(
        "grant select (name, description, paths, revision, created_at, updated_at, updated_by), "
        "insert (name, description, paths, revision, updated_by), "
        "update (description, paths, revision, updated_at, updated_by) "
        "on public.path_list to app_web"
    )
    op.execute(
        "grant select (name, description, paths, revision), delete on public.path_list to app_worker"
    )
    op.execute(
        """
        create table public.list_file (
            kind text not null
                constraint list_file_kind_check check (kind in ('path_list', 'blocklist')),
            name text not null
                constraint list_file_name_check check (name ~ '^[a-z][a-z0-9-]{0,39}$'),
            revision integer not null
                constraint list_file_revision_check check (revision between 0 and 1000000),
            digest text not null
                constraint list_file_digest_check check (digest ~ '^([0-9a-f]{64})?$'),
            description text
                constraint list_file_description_check check (char_length(description) <= 200),
            paths text[]
                constraint list_file_paths_check check (cardinality(paths) between 1 and 500),
            seen_at timestamp with time zone not null,
            primary key (kind, name)
        )
        """
    )
    op.execute(
        "grant select (kind, name, revision, digest, description, paths, seen_at), "
        "insert (kind, name, revision, digest, description, paths, seen_at), "
        "update (revision, digest, description, paths, seen_at), delete "
        "on public.list_file to app_poller"
    )
    op.execute(
        "grant select (kind, name, revision, digest, description, paths, seen_at) "
        "on public.list_file to app_web"
    )
    op.execute(
        """
        create table public.list_file_read (
            only_row boolean primary key default true
                constraint list_file_read_only_row_check check (only_row),
            read_at timestamp with time zone not null
        )
        """
    )
    op.execute(
        "grant select (only_row, read_at), insert (only_row, read_at), update (read_at) "
        "on public.list_file_read to app_poller"
    )
    op.execute("grant select (only_row, read_at) on public.list_file_read to app_web")
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
        "'path_list_apply'::text, "
        "'revert'::text, "
        "'server_state'::text"
        "]))) not valid;"
    )
    op.execute("alter table public.job drop constraint job_cluster_presence")
    op.execute(
        "alter table public.job add constraint job_cluster_presence "
        "check (((operation = any (array["
        "'blocklist_apply'::text, "
        "'cert_issue'::text, "
        "'cert_publish'::text, "
        "'cert_target'::text, "
        "'dns_profile_apply'::text, "
        "'cert_delete'::text, "
        "'ndes_profile_apply'::text, "
        "'cert_scep'::text, "
        "'cert_receiver'::text, "
        "'cert_import'::text, "
        "'cert_request'::text, "
        "'path_list_apply'::text"
        "])) = (cluster is null)))"
    )
