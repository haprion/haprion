"""A job remembers the request that queued it, not only the payload it built (B416, review 26-11-01).

An `Idempotency-Key` names a call. The API builds most payloads from the state
at the time of the call - the saved changes, the version head, the registry -
so after the job has run, the same call builds another payload and the
payload's hash no longer says "this is the retry". The digest of the request
itself (caller, method, route, path parameters, body) is stored beside the key:
the same key with the same digest is the job already queued, whatever the state
has become since; the same key with another digest is a key used for another
change.

Null for every job the pages and the engine queue, and for every job from
before: they keep the payload comparison. The web may write and read the column
and nothing else may change it.

It also ends a `block_client` job a 0.99.9 web queued between 0109's ending of
them and its narrower constraint (B419, review 26-11-01): such a job is
pending, the constraint refuses its every update, and the worker's claim would
fail on it each pass with all younger jobs waiting behind. 0109 is frozen, so
the same ending is run again here, with the constraint out of the way for the
update and back, as 0109 wrote it. 0109's `alter table` holds its lock until
the migrations commit, so nothing can queue another after it.

Revision ID: 0110
Revises: 0109
"""

from __future__ import annotations

from alembic import op

revision = "0110"
down_revision = "0109"
branch_labels = None
depends_on = None

ROLLBACK_SAFE = True
ROLLBACK_SAFE_BECAUSE = "a nullable column that code from before neither names nor reads"


# 0109's ending of the unfinished block client jobs, word for word.
END_UNFINISHED = """
    update job
       set state = case state when 'pending' then 'failed' else 'unknown' end,
           outcome = case state when 'pending' then 'failed' else 'unknown' end,
           finished_at = statement_timestamp(),
           lease_until = null,
           stderr_excerpt = 'Blocking over ssh was removed; the upgrade ended this job.'
     where operation = 'block_client' and state in ('pending', 'running');
"""


def upgrade() -> None:
    op.execute("alter table job drop constraint job_operation_allowed;")
    op.execute(END_UNFINISHED)
    #
    # 0109's constraint again: written out for the queue's tests, which read
    # the newest migration that speaks of it.
    #
    op.execute("""
    alter table job add constraint job_operation_allowed check (operation in (
        'backup_run', 'backup_schedule', 'cert_delete', 'cert_deploy',
        'cert_import', 'cert_issue', 'cert_publish', 'cert_receiver', 'cert_request',
        'cert_scep', 'cert_target', 'changes_publish', 'cluster_define', 'cluster_node',
        'deploy', 'dns_profile_apply', 'dynamic_unblock', 'ndes_profile_apply', 'node_restore',
        'node_restore_discard', 'node_restore_prepare', 'node_restore_preview',
        'node_restore_status', 'revert', 'server_state'
    )) not valid;
    """)
    op.execute("""
    alter table job add column request_digest bytea;
    alter table job add constraint job_request_digest_sha256
        check (request_digest is null or octet_length(request_digest) = 32);

    grant select (request_digest), insert (request_digest) on job to app_web;
    """)
