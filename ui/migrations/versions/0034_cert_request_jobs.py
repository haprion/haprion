"""Let the queue make a signing request on the manager (C9b).

Revision ID: 0034
Revises: 0033
"""

from __future__ import annotations

from alembic import op

revision = "0034"
down_revision = "0033"
branch_labels = None
depends_on = None

#
# `cert_request` is a certificate-scoped job like `cert_import`: no cluster,
# one at a time with the other certificate work, because the helper writes
# the import store under the certificate lock. The certificate form queues
# it as its fourth method; the operator's `haproxy-cert-request` command is
# the same code from the terminal.
#

OPERATIONS = (
    "'deploy', 'cert_deploy', 'revert', 'network_publish', 'objects_publish', "
    "'cert_issue', 'cert_publish', 'cert_target', 'dns_profile_apply', 'cert_delete', "
    "'ndes_profile_apply', 'cert_scep', 'cert_receiver', 'cert_import'"
)
CLUSTERLESS = (
    "'cert_issue', 'cert_publish', 'cert_target', 'dns_profile_apply', 'cert_delete', "
    "'ndes_profile_apply', 'cert_scep', 'cert_receiver', 'cert_import'"
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
    op.execute(_constraints(OPERATIONS + ", 'cert_request'", CLUSTERLESS + ", 'cert_request'"))


def downgrade() -> None:
    #
    # Fails where a cert_request job exists, for the reason 0026 gives.
    #
    op.execute(_constraints(OPERATIONS, CLUSTERLESS))
