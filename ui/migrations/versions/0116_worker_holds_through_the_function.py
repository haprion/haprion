"""The worker holds jobs through the function alone, not through a column grant (B444).

Only `hold_jobs_queued_before` writes `job.held_since`. It is a definer
function, so it writes the column as the migration role and not as the worker,
and the worker's own `UPDATE (held_since)` grant has never been used. A role
holds what it uses: the grant is taken away, and a worker that reached for the
column directly - to hold, to release, or to move the time - is refused by the
database instead of allowed to. The function and the worker's right to execute
it are not touched, and what `held_since` means (the row waits for an
administrator's decision, `held_decision`) is as it was.

Haprion 0.99.13's worker never writes the column itself either: it holds
through the function, as this release's does, so a rollback to it over this
migration finds nothing it needs.

Revision ID: 0116
Revises: 0115
"""

from __future__ import annotations

from alembic import op

revision = "0116"
down_revision = "0115"
branch_labels = None
depends_on = None

ROLLBACK_SAFE = True
ROLLBACK_SAFE_BECAUSE = (
    "it only takes a grant away that 0.99.13's worker never used: it holds jobs through "
    "hold_jobs_queued_before, a definer function, and writes the column nowhere else"
)


def upgrade() -> None:
    op.execute("revoke update (held_since) on job from app_worker")
