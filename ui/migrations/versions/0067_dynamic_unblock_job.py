"""Permit lifting a dynamic block in the job queue (B271, 26-10-10).

`dynamic_unblock`: source addresses lifted from one object's dynamic block on
every node of a cluster by `haprion-server-state-helper`. A cluster operation;
the job's result names each node's answer per address.

Revision ID: 0067
Revises: 0066
"""

from __future__ import annotations

from alembic import op

revision = "0067"
down_revision = "0066"
branch_labels = None
depends_on = None

ROLLBACK_SAFE = True
ROLLBACK_SAFE_BECAUSE = (
    "widens one check constraint; a UI from before never queues the new operation, and its "
    "worker leaves a row it does not know as blocked"
)

OLD = (
    "'deploy', 'cert_deploy', 'revert', 'network_publish', 'objects_publish', "
    "'cert_issue', 'cert_publish', 'cert_target', 'dns_profile_apply', 'cert_delete', "
    "'ndes_profile_apply', 'cert_scep', 'cert_receiver', 'cert_import', 'cert_request', "
    "'backup_run', 'backup_schedule', 'node_restore_prepare', 'node_restore_preview', "
    "'node_restore', 'node_restore_discard', 'node_restore_status', 'cluster_settings_publish', "
    "'cluster_node', 'cluster_define', 'changes_publish', 'server_state'"
)


def upgrade() -> None:
    op.execute(f"""
    alter table job drop constraint job_operation_allowed;
    alter table job add constraint job_operation_allowed
        check (operation in ({OLD}, 'dynamic_unblock'));
    """)


def downgrade() -> None:
    # Refuses while such a job row exists; history is not discarded.
    op.execute(f"""
    alter table job drop constraint job_operation_allowed;
    alter table job add constraint job_operation_allowed
        check (operation in ({OLD}));
    """)
