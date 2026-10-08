"""Permit the publish of saved changes in the job queue (B257, 2026-10-08).

`changes_publish`: the proxy objects, network description and cluster settings
somebody saved, published as one version by `haproxy-changes-publish-helper`.
A cluster operation, like the three single-document publishes it replaces in
the interface; those stay allowed for the jobs already recorded under them.

Revision ID: 0064
Revises: 0063
"""

from __future__ import annotations

from alembic import op

revision = "0064"
down_revision = "0063"
branch_labels = None
depends_on = None

OLD = (
    "'deploy', 'cert_deploy', 'revert', 'network_publish', 'objects_publish', "
    "'cert_issue', 'cert_publish', 'cert_target', 'dns_profile_apply', 'cert_delete', "
    "'ndes_profile_apply', 'cert_scep', 'cert_receiver', 'cert_import', 'cert_request', "
    "'backup_run', 'backup_schedule', 'node_restore_prepare', 'node_restore_preview', "
    "'node_restore', 'node_restore_discard', 'node_restore_status', 'cluster_settings_publish', "
    "'cluster_node', 'cluster_define'"
)


def upgrade() -> None:
    op.execute(f"""
    alter table job drop constraint job_operation_allowed;
    alter table job add constraint job_operation_allowed
        check (operation in ({OLD}, 'changes_publish'));
    """)


def downgrade() -> None:
    # Refuses while such a job row exists; history is not discarded.
    op.execute(f"""
    alter table job drop constraint job_operation_allowed;
    alter table job add constraint job_operation_allowed
        check (operation in ({OLD}));
    """)
