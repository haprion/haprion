"""The queue no longer takes `block_client` (B419).

Blocking from outside goes through the API (a `block` token), and the ssh path
0105 queued jobs for is gone: no helper answers that operation any more. A job
row is what the worker runs as root, so what may be queued is decided here and
should name only what exists (`TheQueueMustAcceptWhatTheCodeBuilds`).

`not valid`: the block client jobs 0.99.7 to 0.99.9 ran are history and stay
readable on the jobs page; the constraint holds for every row written from now
on. 0105 added nothing else - no table, no grant - so nothing more is removed.

Revision ID: 0109
Revises: 0108
"""

from __future__ import annotations

from alembic import op

revision = "0109"
down_revision = "0108"
branch_labels = None
depends_on = None

ROLLBACK_SAFE = True
ROLLBACK_SAFE_BECAUSE = (
    "narrows one check constraint to what this release queues; only the External blocking "
    "page of a UI from before queued the operation it drops"
)


#
# A `block_client` job still waiting or running at the upgrade is ended first.
# The constraint is checked on every update too, so such a row could never
# change state again: the worker takes the oldest waiting job, and that claim
# would fail on every pass, with the job holding its cluster's one active slot.
# One that waited never ran (`failed`); one that ran may have taken effect
# (`unknown`).
#
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
    op.execute(END_UNFINISHED)
    #
    # Written out rather than joined from a list: the queue's tests read the
    # newest constraint from the migration's text.
    #
    op.execute("""
    alter table job drop constraint job_operation_allowed;
    alter table job add constraint job_operation_allowed check (operation in (
        'backup_run', 'backup_schedule', 'cert_delete', 'cert_deploy',
        'cert_import', 'cert_issue', 'cert_publish', 'cert_receiver', 'cert_request',
        'cert_scep', 'cert_target', 'changes_publish', 'cluster_define', 'cluster_node',
        'deploy', 'dns_profile_apply', 'dynamic_unblock', 'ndes_profile_apply', 'node_restore',
        'node_restore_discard', 'node_restore_prepare', 'node_restore_preview',
        'node_restore_status', 'revert', 'server_state'
    )) not valid;
    """)
