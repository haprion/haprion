"""Let the queue delete certificates.

Revision ID: 0026
Revises: 0025
"""

from __future__ import annotations

from alembic import op

revision = "0026"
down_revision = "0025"
branch_labels = None
depends_on = None

#
# One more operation the worker may run as root, and the only one that removes
# key material (B139). Widened here, in the database, for the reason 0016
# gives: what may be queued is a decision, not something an import can add.
#
# `cert_delete` is clusterless like the other certificate jobs - it rewrites
# the registry and touches every cluster a certificate named - and it takes
# the same single slot (`job_one_active_certificate`): a deletion and a
# publication that ran at once would meet inside the registry writer with one
# of them reading an entry the other had just removed.
#


def upgrade() -> None:
    op.execute("""
    alter table job drop constraint job_operation_allowed;
    alter table job add constraint job_operation_allowed
        check (operation in ('deploy', 'cert_deploy', 'revert', 'network_publish',
                             'objects_publish', 'cert_issue', 'cert_publish',
                             'cert_target', 'dns_profile_apply', 'cert_delete'));

    alter table job drop constraint job_cluster_presence;
    alter table job add constraint job_cluster_presence
        check ((operation in ('cert_issue', 'cert_publish', 'cert_target',
                              'dns_profile_apply', 'cert_delete'))
               = (cluster is null));
    """)


def downgrade() -> None:
    #
    # Fails where a delete job exists, for the reason 0024 gives: a row the
    # narrower constraint cannot describe is history, not something to drop.
    #
    op.execute("""
    alter table job drop constraint job_cluster_presence;
    alter table job add constraint job_cluster_presence
        check ((operation in ('cert_issue', 'cert_publish', 'cert_target',
                              'dns_profile_apply'))
               = (cluster is null));

    alter table job drop constraint job_operation_allowed;
    alter table job add constraint job_operation_allowed
        check (operation in ('deploy', 'cert_deploy', 'revert', 'network_publish',
                             'objects_publish', 'cert_issue', 'cert_publish',
                             'cert_target', 'dns_profile_apply'));
    """)
