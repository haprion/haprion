"""Permit the bounded network-publish operation in the job queue.

Revision ID: 0012
Revises: 0011
"""

from __future__ import annotations

from alembic import op

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    alter table job drop constraint job_operation_allowed;
    alter table job add constraint job_operation_allowed
        check (operation in ('deploy', 'cert_deploy', 'revert', 'network_publish'));
    """)


def downgrade() -> None:
    op.execute("""
    alter table job drop constraint job_operation_allowed;
    alter table job add constraint job_operation_allowed
        check (operation in ('deploy', 'cert_deploy', 'revert'));
    """)
