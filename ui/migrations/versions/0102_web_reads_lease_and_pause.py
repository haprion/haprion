"""The web reads when a job's lease runs out and when a release's pause ends (26-10-29).

A worker that is stopped, hangs or keeps crashing leaves its job `running`,
and only a living worker settles it. The web could not tell that job from one
at work: *Jobs* drew it as running for good, and it silenced the row in *Needs
attention* about a worker that takes no job (review 26-10-29, Q01/R01). Jobs
held back by a release's pause were blamed on the worker the same way (Q06).

Column grants, and not a definer function that answers the question. Neither
value is a secret - `lease_until` says when a worker's claim on a job ends,
`paused_until` and `paused_by` when a release lets the queue go and which -
and a read of a column is less than running the owner's code: a definer
function is code with the migration role's rights, which must keep its
`search_path` locked and its grants to one role for as long as it exists. What
proves a claim is `claim_token`, which the web still cannot read, and nothing
here lets the web change a lease or the pause.

Revision ID: 0102
Revises: 0101
"""

from __future__ import annotations

from alembic import op

revision = "0102"
down_revision = "0101"
branch_labels = None
depends_on = None

ROLLBACK_SAFE = True
ROLLBACK_SAFE_BECAUSE = (
    "it only grants the web three columns it reads; a UI from before reads none of them"
)


def upgrade() -> None:
    op.execute("""
    grant select (lease_until) on table job to app_web;
    grant select (paused_until, paused_by) on table job_claim_gate to app_web;
    """)
