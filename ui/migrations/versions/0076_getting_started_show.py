"""The getting started list can be shown again after it was hidden (B316, 26-10-16).

0075 hid it for good, and *Hide* asked nothing: one press took the list away
with no way back. For seven days after it was hidden the dashboard offers it
again, and showing it removes the row - the same state as never hidden, so
hiding it again is recorded anew.

Revision ID: 0076
Revises: 0075
"""

from __future__ import annotations

from alembic import op

revision = "0076"
down_revision = "0075"
branch_labels = None
depends_on = None

ROLLBACK_SAFE = True
ROLLBACK_SAFE_BECAUSE = "adds one grant; a UI from before never deletes the row"


def upgrade() -> None:
    op.execute("grant delete on getting_started to app_web;")


def downgrade() -> None:
    op.execute("revoke delete on getting_started from app_web;")
