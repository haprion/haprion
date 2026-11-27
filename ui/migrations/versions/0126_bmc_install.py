"""The `bmc_install` job: a certificate installed on its BMC now (B526, B536).

*Install now* on a certificate's BMC, and the install that saving a BMC target
starts, are jobs: the worker carries them over its socket to the root helper
that opens the account and talks to the BMC. The timer that installs on its own
is no job and is not in this table.

`job_operation_allowed` takes `bmc_install`. The constraint stays `not valid`,
as 0109 left it. And `job_cluster_presence` names it among the operations
queued with no cluster: a certificate's BMC is the manager's.

No table: what each BMC serves is the timer's state file, read with the
certificate listing the poller already caches.

Haprion 1.3.1's web, poller and worker never queue it, and its worker refuses
a `bmc_install` job as an operation it does not know.

Revision ID: 0126
Revises: 0125
"""

from __future__ import annotations

from alembic import op

revision = "0126"
down_revision = "0125"
branch_labels = None
depends_on = None

ROLLBACK_SAFE = True
ROLLBACK_SAFE_BECAUSE = (
    "it widens the job operations by one that 1.3.1's worker refuses, and adds nothing else"
)


def upgrade() -> None:
    op.execute("alter table public.job drop constraint job_operation_allowed")
    op.execute(
        "alter table public.job add constraint job_operation_allowed "
        "check ((operation = any (array["
        "'backup_run'::text, "
        "'backup_schedule'::text, "
        "'blocklist_apply'::text, "
        "'bmc_install'::text, "
        "'cert_delete'::text, "
        "'cert_deploy'::text, "
        "'cert_import'::text, "
        "'cert_issue'::text, "
        "'cert_publish'::text, "
        "'cert_receiver'::text, "
        "'cert_request'::text, "
        "'cert_scep'::text, "
        "'cert_target'::text, "
        "'changes_publish'::text, "
        "'cluster_define'::text, "
        "'cluster_node'::text, "
        "'deploy'::text, "
        "'dns_profile_apply'::text, "
        "'dynamic_unblock'::text, "
        "'ndes_profile_apply'::text, "
        "'node_restore'::text, "
        "'node_restore_discard'::text, "
        "'node_restore_prepare'::text, "
        "'node_restore_preview'::text, "
        "'node_restore_status'::text, "
        "'path_list_apply'::text, "
        "'revert'::text, "
        "'server_state'::text"
        "]))) not valid;"
    )
    op.execute("alter table public.job drop constraint job_cluster_presence")
    op.execute(
        "alter table public.job add constraint job_cluster_presence "
        "check (((operation = any (array["
        "'blocklist_apply'::text, "
        "'cert_issue'::text, "
        "'cert_publish'::text, "
        "'cert_target'::text, "
        "'dns_profile_apply'::text, "
        "'cert_delete'::text, "
        "'ndes_profile_apply'::text, "
        "'cert_scep'::text, "
        "'cert_receiver'::text, "
        "'cert_import'::text, "
        "'cert_request'::text, "
        "'path_list_apply'::text, "
        "'bmc_install'::text"
        "])) = (cluster is null)))"
    )
