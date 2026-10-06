"""A renamed backend's alias written by the worker, once the publish is done (B253, 2026-10-06).

0056 let the interface write `metric_backend_alias` when it queued a publish
that renamed a pool. A publish that was then refused or failed left the alias
behind, and a later backend given the new name would have drawn the old one's
readings - which were still arriving under the old name - as its own history.
The worker knows whether the publish was done, so it writes the alias, in the
transaction that finishes the job.

Additive only: the interface running when this migrates still writes from the
web (its grants stay until 0059 takes them back), and nothing it does breaks.

Revision ID: 0058
Revises: 0057
"""

from __future__ import annotations

from alembic import op

revision = "0058"
down_revision = "0057"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    grant select (cluster, old_name, new_name, renamed_at, reused_at)
        on metric_backend_alias to app_worker;
    grant insert (cluster, old_name, new_name) on metric_backend_alias to app_worker;
    grant update (new_name, renamed_at, reused_at) on metric_backend_alias to app_worker;
    """)


def downgrade() -> None:
    op.execute("revoke all on metric_backend_alias from app_worker;")
