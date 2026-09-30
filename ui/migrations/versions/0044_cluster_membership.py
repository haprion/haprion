"""The jobs that change which nodes and clusters the manager knows (Fas 16, B211).

`cluster_node` adds a node to a cluster or takes one away; `cluster_define`
creates or removes a whole cluster. Both are root helpers behind a socket, and
both are asked for by an admin on the Settings page. Allowed here together, so
one bridge release covers both steps of the rollout.

Revision ID: 0044
Revises: 0043
"""

from __future__ import annotations

from alembic import op

revision = "0044"
down_revision = "0043"
branch_labels = None
depends_on = None

OLD = (
    "'deploy', 'cert_deploy', 'revert', 'network_publish', 'objects_publish', "
    "'cert_issue', 'cert_publish', 'cert_target', 'dns_profile_apply', 'cert_delete', "
    "'ndes_profile_apply', 'cert_scep', 'cert_receiver', 'cert_import', 'cert_request', "
    "'backup_run', 'backup_schedule', 'node_restore_prepare', 'node_restore_preview', "
    "'node_restore', 'node_restore_discard', 'node_restore_status', 'cluster_settings_publish'"
)


def upgrade() -> None:
    op.execute(f"""
    alter table job drop constraint job_operation_allowed;
    alter table job add constraint job_operation_allowed
        check (operation in ({OLD}, 'cluster_node', 'cluster_define'));
    """)


def downgrade() -> None:
    # Refuses while such a job row exists; history is not discarded.
    op.execute(f"""
    alter table job drop constraint job_operation_allowed;
    alter table job add constraint job_operation_allowed
        check (operation in ({OLD}));
    """)
