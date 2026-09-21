"""Let the queue import an uploaded certificate (B165).

Revision ID: 0033
Revises: 0032
"""

from __future__ import annotations

from alembic import op

revision = "0033"
down_revision = "0032"
branch_labels = None
depends_on = None

#
# `cert_import` is a certificate-scoped job like `cert_issue`: no cluster, one
# at a time with the other certificate work, because the helper writes the
# import store and the registry. The interface's import page queues it with
# the file sealed in the payload; the operator's `haproxy-cert-import` command
# is the same code reading files from disk.
#

OPERATIONS = (
    "'deploy', 'cert_deploy', 'revert', 'network_publish', 'objects_publish', "
    "'cert_issue', 'cert_publish', 'cert_target', 'dns_profile_apply', 'cert_delete', "
    "'ndes_profile_apply', 'cert_scep', 'cert_receiver'"
)
CLUSTERLESS = (
    "'cert_issue', 'cert_publish', 'cert_target', 'dns_profile_apply', 'cert_delete', "
    "'ndes_profile_apply', 'cert_scep', 'cert_receiver'"
)


def _constraints(operations: str, clusterless: str) -> str:
    return f"""
    alter table job drop constraint job_operation_allowed;
    alter table job add constraint job_operation_allowed
        check (operation in ({operations}));

    alter table job drop constraint job_cluster_presence;
    alter table job add constraint job_cluster_presence
        check ((operation in ({clusterless})) = (cluster is null));
    """


def upgrade() -> None:
    op.execute(_constraints(OPERATIONS + ", 'cert_import'", CLUSTERLESS + ", 'cert_import'"))


def downgrade() -> None:
    #
    # Fails where a cert_import job exists, for the reason 0026 gives.
    #
    op.execute(_constraints(OPERATIONS, CLUSTERLESS))
