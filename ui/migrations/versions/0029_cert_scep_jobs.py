"""Let the queue enroll a certificate over NDES/SCEP.

Revision ID: 0029
Revises: 0028
"""

from __future__ import annotations

from alembic import op

revision = "0029"
down_revision = "0028"
branch_labels = None
depends_on = None

#
# `cert_scep` is a certificate-scoped job like `cert_issue`: no cluster, one
# at a time with the other certificate work, because the helper writes into
# the import store and the registry. Its `partial` outcome is the CA holding
# the request; the same job is queued again with `resume` to finish it.
#

OPERATIONS = (
    "'deploy', 'cert_deploy', 'revert', 'network_publish', 'objects_publish', "
    "'cert_issue', 'cert_publish', 'cert_target', 'dns_profile_apply', 'cert_delete', "
    "'ndes_profile_apply'"
)
CLUSTERLESS = (
    "'cert_issue', 'cert_publish', 'cert_target', 'dns_profile_apply', 'cert_delete', "
    "'ndes_profile_apply'"
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
    op.execute(_constraints(OPERATIONS + ", 'cert_scep'", CLUSTERLESS + ", 'cert_scep'"))


def downgrade() -> None:
    #
    # Fails where a cert_scep job exists, for the reason 0026 gives.
    #
    op.execute(_constraints(OPERATIONS, CLUSTERLESS))
