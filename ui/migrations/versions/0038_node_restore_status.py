"""Allow asking a node restore run how it stands (review 2026-09-25, track 8).

Revision ID: 0038
Revises: 0037
"""

from __future__ import annotations

from alembic import op

revision = "0038"
down_revision = "0037"
branch_labels = None
depends_on = None

OLD = (
    "'deploy', 'cert_deploy', 'revert', 'network_publish', 'objects_publish', "
    "'cert_issue', 'cert_publish', 'cert_target', 'dns_profile_apply', 'cert_delete', "
    "'ndes_profile_apply', 'cert_scep', 'cert_receiver', 'cert_import', 'cert_request', "
    "'backup_run', 'backup_schedule', 'node_restore_prepare', 'node_restore_preview', "
    "'node_restore', 'node_restore_discard'"
)


def upgrade() -> None:
    op.execute(f"""
    alter table job drop constraint job_operation_allowed;
    alter table job add constraint job_operation_allowed
        check (operation in ({OLD}, 'node_restore_status'));
    """)


def downgrade() -> None:
    # Refuses while a status job row exists; history is not discarded.
    op.execute(f"""
    alter table job drop constraint job_operation_allowed;
    alter table job add constraint job_operation_allowed
        check (operation in ({OLD}));
    """)
