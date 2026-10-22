"""The queue permits only what the worker can prepare (review 2026-10-22, 6-6).

`network_publish`, `objects_publish` and `cluster_settings_publish` went with
the old publish helpers on 2026-10-08, when saved changes came to be published
as one version (`changes_publish`), and the check constraint went on permitting
them. A job row is what the worker later runs as root, so what may be queued is
the database's own decision, and it should name what exists.

`not valid`: the jobs those three ran are history and stay readable on the
jobs page; the constraint holds for every row written from now on.

Revision ID: 0087
Revises: 0086
"""

from __future__ import annotations

from alembic import op

revision = "0087"
down_revision = "0086"
branch_labels = None
depends_on = None

ROLLBACK_SAFE = True
ROLLBACK_SAFE_BECAUSE = (
    "narrows one check constraint to the operations every UI from 0072 on queues; the three "
    "it drops left the code on 2026-10-08"
)

CURRENT = (
    "'backup_run', 'backup_schedule', 'cert_delete', 'cert_deploy', 'cert_import', "
    "'cert_issue', 'cert_publish', 'cert_receiver', 'cert_request', 'cert_scep', "
    "'cert_target', 'changes_publish', 'cluster_define', 'cluster_node', 'deploy', "
    "'dns_profile_apply', 'dynamic_unblock', 'ndes_profile_apply', 'node_restore', "
    "'node_restore_discard', 'node_restore_prepare', 'node_restore_preview', "
    "'node_restore_status', 'revert', 'server_state'"
)
RETIRED = "'network_publish', 'objects_publish', 'cluster_settings_publish'"


def upgrade() -> None:
    op.execute(f"""
    alter table job drop constraint job_operation_allowed;
    alter table job add constraint job_operation_allowed
        check (operation in ({CURRENT})) not valid;
    """)


def downgrade() -> None:
    op.execute(f"""
    alter table job drop constraint job_operation_allowed;
    alter table job add constraint job_operation_allowed
        check (operation in ({CURRENT}, {RETIRED}));
    """)
