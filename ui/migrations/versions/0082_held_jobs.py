"""A job from before the manager last started waits for a person (review 2026-10-20, R1; B343).

A manager restored from an image or a dump holds the jobs that were waiting at
that moment, and those ran then: a Drain since replaced by Ready would run
again, as a fresh request, if the backup were younger than the worker's two
hours. A marker kept on the manager cannot tell, since it is restored with
everything else; but a restored machine always boots. So the worker holds every
job that was queued before the machine's last boot, and an admin decides.

`held_since` is set by the worker - at its start, for what was queued before
the boot - or by `haprion-backup after-restore` after a dump was restored
without one. `held_decision` is the admin's answer, written by the web: `run`
lets the worker take the job (and lifts the two-hour rule, since a person has
now judged it), `discard` lets the worker end it as `blocked`. The web never
changes a job's state; the worker does, through its own claim.

Revision ID: 0082
Revises: 0081
"""

from __future__ import annotations

from alembic import op

revision = "0082"
down_revision = "0081"
branch_labels = None
depends_on = None

ROLLBACK_SAFE = True
ROLLBACK_SAFE_BECAUSE = (
    "adds three nullable job columns; a UI from before never reads them, and its worker takes "
    "a held job as it took every job before 0082"
)


def upgrade() -> None:
    op.execute("""
    alter table job
        add column held_since      timestamptz,
        add column held_decision   text,
        add column held_decided_by text,
        add constraint job_held_decision check (held_decision in ('run', 'discard')),
        --
        -- A decision is about a held job, and names who made it.
        --
        add constraint job_held_decision_needs_hold
            check (held_decision is null or held_since is not null),
        add constraint job_held_decided_by
            check ((held_decision is null) = (held_decided_by is null)
                   and char_length(held_decided_by) <= 64);

    grant select (held_since, held_decision, held_decided_by) on job to app_web, app_worker;
    grant update (held_since) on job to app_worker;
    grant update (held_decision, held_decided_by) on job to app_web;
    """)


def downgrade() -> None:
    op.execute("""
    revoke update (held_decision, held_decided_by) on job from app_web;
    revoke update (held_since) on job from app_worker;
    revoke select (held_since, held_decision, held_decided_by) on job from app_web, app_worker;
    alter table job
        drop column held_decided_by,
        drop column held_decision,
        drop column held_since;
    """)
