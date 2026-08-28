"""The job queue, and the column grants that make a web intrusion bounded.

The web role may ask for an operation. It may not say that one ran, who ran it,
how it went, or when. That distinction is not a convention in the application -
it is which columns the role holds `insert` on, and it holds `insert` on three.

Everything else about a new job comes from a column default, which is the plan's
requirement stated as SQL: the database sets `pending`, the request ID and the
timestamps precisely so a compromised web process cannot choose them.

Revision ID: 0002
Revises: 0001
"""

from __future__ import annotations

from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    create table job (
        id           bigint generated always as identity primary key,

        --
        -- Set here, never received. The request ID is what answers "did this
        -- operation take effect?" after a crash, and an identifier the caller
        -- chooses is one the caller can reuse to make two operations look like
        -- one.
        --
        request_id   uuid not null default gen_random_uuid(),

        operation    text not null,
        cluster      text not null,
        payload      jsonb not null default '{}'::jsonb,

        --
        -- No payload hash column, deliberately.
        --
        -- The plan binds a request ID to operation + cluster + a canonical
        -- payload hash, and that binding is Phase 6's. Written here as a
        -- generated column it would have to be immutable, and the honest way to
        -- hash text - convert_to - is only stable, because it depends on the
        -- database encoding. PostgreSQL refuses it, correctly.
        --
        -- The ways around that are all worse than waiting: md5 is immutable but
        -- is not what you want a request identity to rest on, and a trigger puts
        -- the derivation somewhere nobody reading this table would look. So the
        -- column arrives with the migration that implements the binding, when
        -- its actual requirement is in hand - the same rule the grants follow.
        --

        state        text not null default 'pending',

        --
        -- The fencing token. Rotated every time the job is claimed, including
        -- when a lease expires and another worker takes over, so a worker that
        -- wakes from an expired lease finds its own writes refused by the
        -- database rather than by its own good manners.
        --
        claim_token  uuid,
        worker_id    text,
        lease_until  timestamptz,

        created_at   timestamptz not null default statement_timestamp(),
        started_at   timestamptz,
        finished_at  timestamptz,

        exit_code    smallint,
        outcome      text,
        result       jsonb,
        stderr_excerpt text,

        --
        -- An allowlist, not documentation. A web process that has been talked
        -- into queueing something else fails at the constraint, before a worker
        -- ever reads the row.
        --
        constraint job_operation_allowed
            check (operation in ('deploy', 'cert_deploy', 'revert')),
        constraint job_state_allowed
            check (state in ('pending', 'running', 'done', 'partial',
                             'failed', 'blocked', 'unknown')),
        constraint job_outcome_allowed
            check (outcome is null or outcome in ('done', 'partial', 'failed',
                                                  'blocked', 'unknown')),
        --
        -- A shape rather than a list, for the same reason as elsewhere: cluster
        -- IDs come from runtime configuration, and enumerating them here would
        -- make every new cluster a migration.
        --
        constraint job_cluster_shape
            check (cluster ~ '^[a-z0-9][a-z0-9_-]{0,31}$'),

        --
        -- A running job has a holder. Without this a row can sit in `running`
        -- with no lease, which no reclaim query will ever find.
        --
        constraint job_running_is_held
            check (state <> 'running'
                   or (claim_token is not null
                       and lease_until is not null
                       and worker_id is not null
                       and started_at is not null)),
        constraint job_finished_has_time
            check (state in ('pending', 'running') or finished_at is not null),

        --
        -- The contract's cap on persisted diagnostics, enforced where it cannot
        -- be forgotten. Redaction happens before the write; this is only the
        -- size.
        --
        constraint job_stderr_bounded
            check (stderr_excerpt is null or octet_length(stderr_excerpt) <= 65536)
    );

    create unique index job_request_id_key on job (request_id);

    --
    -- At most one job per cluster that has not finished. This is what makes a
    -- double-clicked button a conflict the database refuses rather than two
    -- rollouts of the same cluster - and it is a partial index, so finished
    -- jobs never collide with anything.
    --
    create unique index job_one_active_per_cluster on job (cluster)
        where state in ('pending', 'running');

    --
    -- The claim query orders by these two and takes one row. Deterministic
    -- ordering matters more than it looks: two workers scanning in different
    -- orders contend on different rows and both make progress slowly, and a
    -- reproduction of "which job ran first" becomes impossible.
    --
    create index job_claimable_idx on job (created_at, id) where state = 'pending';
    create index job_lease_idx on job (lease_until) where state = 'running';
    create index job_cluster_idx on job (cluster, created_at desc);
    """)

    op.execute("""
    --
    -- Three columns. The web role states what it wants done, to which cluster,
    -- with which parameters - and nothing about what happened. state,
    -- request_id and created_at come from defaults, so they are the database's
    -- answer rather than the caller's claim.
    --
    grant insert (operation, cluster, payload) on job to app_web;

    --
    -- No update, at all. A queued job is immutable to the role that queued it:
    -- there is no column it may revise, so there is no path from "I asked for
    -- this" to "this is what happened".
    --
    grant select (id, request_id, operation, cluster, payload, state,
                  created_at, started_at, finished_at, exit_code, outcome, result,
                  stderr_excerpt)
        on job to app_web;

    --
    -- The worker reads claim_token and lease_until because it names them in the
    -- WHERE clause of every write it makes, and PostgreSQL requires select on a
    -- column to filter on it. That the fencing check is expressible at all is
    -- the reason those columns exist.
    --
    grant select (id, request_id, operation, cluster, payload, state,
                  claim_token, worker_id, lease_until, created_at, started_at,
                  finished_at, exit_code, outcome, result, stderr_excerpt)
        on job to app_worker;

    grant update (state, claim_token, worker_id, lease_until, started_at, finished_at,
                  exit_code, outcome, result, stderr_excerpt)
        on job to app_worker;
    """)


def downgrade() -> None:
    op.execute("drop table if exists job;")
