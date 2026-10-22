"""A held job's Run or Discard holds only until the next boot or restore (logic review 2026-10-22, L2).

0082 held every job queued before the machine's last boot, but only jobs not
held before: one held at an earlier boot and answered then kept its answer. A
job answered Run that was still running when a backup was taken came back
from that backup running, recovery put it in the queue again, and the worker
took it on the old answer - the one thing the hold was there to stop.

So a job held at an earlier boot is held again, and its answer is cleared: the
admin answers for this machine's life, not the backup's. The worker has never
been able to write the answer (0082 grants it to the web alone), and it is
not given that here; it gets one function, which can hold and clear, never
answer. `haprion-backup after-restore` calls the same function without a boot,
which holds every waiting or running job again.

Revision ID: 0085
Revises: 0084
"""

from __future__ import annotations

from alembic import op

revision = "0085"
down_revision = "0084"
branch_labels = None
depends_on = None

ROLLBACK_SAFE = True
ROLLBACK_SAFE_BECAUSE = (
    "adds one function; a UI from before never calls it, and its worker holds jobs with the "
    "column grant 0082 gave it, which stays"
)


def upgrade() -> None:
    op.execute("""
    create function hold_jobs_queued_before(boot timestamptz) returns setof bigint
    language sql security definer set search_path = pg_catalog, public as $$
        update job
           set held_since = statement_timestamp(), held_decision = null, held_decided_by = null
         where state in ('pending', 'running')
           and (boot is null or created_at < boot)
           and (held_since is null or boot is null or held_since < boot)
        returning id
    $$;
    revoke all on function hold_jobs_queued_before(timestamptz) from public;
    grant execute on function hold_jobs_queued_before(timestamptz) to app_worker;
    """)


def downgrade() -> None:
    op.execute("drop function hold_jobs_queued_before(timestamptz)")
