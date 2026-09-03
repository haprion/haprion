"""Permit the bounded objects-publish operation in the job queue.

Revision ID: 0016
Revises: 0015
"""

from __future__ import annotations

from alembic import op

revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    #
    # The whitelist is the database's own opinion of what the queue may carry,
    # and it is deliberately not derived from the code: a job row is what the
    # worker will run as root, so the set of operations that can exist at all
    # is a decision recorded here rather than one an import could change.
    #
    # Which also means it has to be kept in step by hand, and this one was not:
    # the editor's publish button reached a working helper, a granted sudoers
    # rule and a prepared payload, and then met this constraint - a 500 at the
    # last step of a chain whose every other link had been built.
    #
    op.execute("""
    alter table job drop constraint job_operation_allowed;
    alter table job add constraint job_operation_allowed
        check (operation in ('deploy', 'cert_deploy', 'revert', 'network_publish',
                             'objects_publish'));
    """)


def downgrade() -> None:
    #
    # This can fail where a publish job exists, and should: narrowing the set
    # would otherwise mean deleting somebody's queued or recorded work to make
    # the constraint hold.
    #
    op.execute("""
    alter table job drop constraint job_operation_allowed;
    alter table job add constraint job_operation_allowed
        check (operation in ('deploy', 'cert_deploy', 'revert', 'network_publish'));
    """)
