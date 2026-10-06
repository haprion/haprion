"""A pause on the worker's claims, for the moment a release restarts it (CR-12, 2026-10-06).

Activating a UI release restarts the worker, and a job it is running ends
with it - for a node restore or a backup, whose root helper carries on behind
its socket, as `unknown` for a run that changed a node. The release checked
once, before preparing, that none was running; the check and the restart were
minutes apart and a job could start in between (review 2026-10-04, CR-12).

One row says whether claims are paused and until when. The release sets it,
waits for the running jobs to finish, restarts the worker and clears it; the
claim reads it in the same statement that takes a job. `paused_until` rather
than a flag, so a release killed before it could clear the pause does not stop
the queue for good.

Revision ID: 0060
Revises: 0059
"""

from __future__ import annotations

from alembic import op

revision = "0060"
down_revision = "0059"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    create table job_claim_gate (
        only_row     boolean primary key default true check (only_row),
        paused_until timestamptz,
        paused_by    text check (paused_by is null or length(paused_by) <= 200)
    );
    insert into job_claim_gate (only_row) values (true);
    grant select (paused_until) on job_claim_gate to app_worker;
    """)


def downgrade() -> None:
    op.execute("drop table job_claim_gate;")
