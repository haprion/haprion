"""Permit drain, maintenance and ready in the job queue (Fas 20, B263, 2026-10-09).

`server_state`: one object's servers set to drain, maint or ready on every node
of a cluster by `haproxy-server-state-helper`. A cluster operation; the job's
result names each node's answer per server.

Revision ID: 0066
Revises: 0065
"""

from __future__ import annotations

from alembic import op

revision = "0066"
down_revision = "0065"
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
    "'cluster_node', 'cluster_define', 'changes_publish'"
)


def upgrade() -> None:
    op.execute(f"""
    alter table job drop constraint job_operation_allowed;
    alter table job add constraint job_operation_allowed
        check (operation in ({OLD}, 'server_state'));
    """)


def downgrade() -> None:
    # Refuses while such a job row exists; history is not discarded.
    op.execute(f"""
    alter table job drop constraint job_operation_allowed;
    alter table job add constraint job_operation_allowed
        check (operation in ({OLD}));
    """)
