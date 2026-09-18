"""Let the queue register and remove certificate receivers (B142).

Revision ID: 0032
Revises: 0031
"""

from __future__ import annotations

from alembic import op

revision = "0032"
down_revision = "0031"
branch_labels = None
depends_on = None

#
# `cert_receiver` is a certificate-scoped job like `cert_target`: no cluster,
# one at a time with the other certificate work, because the helper writes
# the registry and, for an sftp or an https receiver, sshd's or nginx's own
# configuration. The interface's receivers page queues it; the operator's
# `haproxy-cert-receiver` command is the same code without the queue.
#

OPERATIONS = (
    "'deploy', 'cert_deploy', 'revert', 'network_publish', 'objects_publish', "
    "'cert_issue', 'cert_publish', 'cert_target', 'dns_profile_apply', 'cert_delete', "
    "'ndes_profile_apply', 'cert_scep'"
)
CLUSTERLESS = (
    "'cert_issue', 'cert_publish', 'cert_target', 'dns_profile_apply', 'cert_delete', "
    "'ndes_profile_apply', 'cert_scep'"
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
    op.execute(_constraints(OPERATIONS + ", 'cert_receiver'", CLUSTERLESS + ", 'cert_receiver'"))


def downgrade() -> None:
    #
    # Fails where a cert_receiver job exists, for the reason 0026 gives.
    #
    op.execute(_constraints(OPERATIONS, CLUSTERLESS))
