"""The queue takes `block_client`: add or remove a client that may block from outside (B412).

A job row is what the worker runs as root, so what may be queued is decided
here and not by an import (`TheQueueMustAcceptWhatTheCodeBuilds`).

A UI from before never queues it, so it runs over this schema as before.

Revision ID: 0105
Revises: 0104
"""

from __future__ import annotations

from alembic import op

revision = "0105"
down_revision = "0104"
branch_labels = None
depends_on = None

ROLLBACK_SAFE = True
ROLLBACK_SAFE_BECAUSE = "it only widens what the queue accepts; a UI from before never queues it"


def upgrade() -> None:
    #
    # Written out rather than joined from a list: the queue's tests read the
    # newest constraint from the migration's text.
    #
    op.execute("""
    alter table job drop constraint job_operation_allowed;
    alter table job add constraint job_operation_allowed check (operation in (
        'backup_run', 'backup_schedule', 'block_client', 'cert_delete', 'cert_deploy',
        'cert_import', 'cert_issue', 'cert_publish', 'cert_receiver', 'cert_request',
        'cert_scep', 'cert_target', 'changes_publish', 'cluster_define', 'cluster_node',
        'deploy', 'dns_profile_apply', 'dynamic_unblock', 'ndes_profile_apply', 'node_restore',
        'node_restore_discard', 'node_restore_prepare', 'node_restore_preview',
        'node_restore_status', 'revert', 'server_state'
    ));
    """)
