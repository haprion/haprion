"""Which version of an external certificate was last taken out (26-10-18).

An external certificate (B255) is renewed on the manager and installed by hand,
so the registry row says when the version it holds has not been downloaded
since the renewal. The newest `certificate_export` or `certificate_download`
event per certificate answers it; this index keeps that read off the rest of
the audit trail, which grows with every job.

Revision ID: 0077
Revises: 0076
"""

from __future__ import annotations

from alembic import op

revision = "0077"
down_revision = "0076"
branch_labels = None
depends_on = None

ROLLBACK_SAFE = True
ROLLBACK_SAFE_BECAUSE = "adds one index; a UI from before never reads it"


def upgrade() -> None:
    op.execute(
        "create index audit_event_certificate_takeout_idx "
        "on audit_event ((detail->>'certificate'), id desc) "
        "where action in ('certificate_export', 'certificate_download');"
    )


def downgrade() -> None:
    op.execute("drop index audit_event_certificate_takeout_idx;")
