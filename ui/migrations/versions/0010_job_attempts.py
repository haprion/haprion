"""Count how many times a job has been picked up.

Phase 6's recovery may requeue a job whose worker died - but only an operation
proved not to have started, or proved safe to repeat. Even then it must not be
requeued forever: an operation that crashes the worker every time would be
retried without end, and the job history would fill with the same failure while
nothing said the system had given up.

So the claim counts itself. A first attempt that ends with an expired lease can
be requeued; a second one cannot, and is adjudicated as `unknown` instead - the
outcome the plan reserves for "nobody can say whether this took effect", which
is exactly true of a job that has already been taken twice and answered neither
time.

Counted on claim rather than on requeue, because what matters is how many times
a worker has held the job. A requeue that no worker ever picked up has cost
nothing and should not be held against it.

Revision ID: 0010
Revises: 0009
"""

from __future__ import annotations

from alembic import op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    --
    -- not-null with a default costs nothing here: no role may insert it, so
    -- every row gets the default including one inserted by a release that has
    -- never heard of the column.
    --
    alter table job add column attempts integer not null default 0;

    alter table job add constraint job_attempts_not_negative check (attempts >= 0);
    """)

    op.execute("""
    --
    -- The web role can see how many times an operation was attempted, because
    -- that is part of the history a reader is entitled to. It cannot change it:
    -- how often a job ran is something the worker observed, not something the
    -- caller may assert - the same split the rest of these grants follow.
    --
    grant select (attempts) on job to app_web, app_worker;
    grant update (attempts) on job to app_worker;

    --
    -- The recovery path reads the cached version listing to answer "did this
    -- request already record a version?". It reads the poller's answer rather
    -- than asking the cluster itself, because that needs no privilege the
    -- worker does not already have and its age is knowable: a listing observed
    -- before the lease expired describes the world while the operation may
    -- still have been running, and settles nothing.
    --
    grant select (cluster, observed_at, outcome, result, warnings, error, poll_error)
        on cluster_history to app_worker;
    """)


def downgrade() -> None:
    op.execute("""
    alter table job drop constraint if exists job_attempts_not_negative;
    alter table job drop column if exists attempts;
    """)
