"""The web role reads the schema's revision, for /healthz (26-10-19).

`/healthz` says whether the interface can do its job, and an interface pointed
at an empty database, or at one older than its release accepts, cannot (B332).
The revision is one column of one row; reading it tells the web nothing about
the data.

Revision ID: 0078
Revises: 0077
"""

from __future__ import annotations

from alembic import op

revision = "0078"
down_revision = "0077"
branch_labels = None
depends_on = None

ROLLBACK_SAFE = True
ROLLBACK_SAFE_BECAUSE = "adds one column grant; a UI from before never reads it"


def upgrade() -> None:
    op.execute("grant select (version_num) on alembic_version to app_web;")


def downgrade() -> None:
    op.execute("revoke select (version_num) on alembic_version from app_web;")
