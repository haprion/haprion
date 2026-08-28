"""Where the poller writes what the nodes said.

The interface must not reach a node to render a page. A read that happens while
somebody is looking at a screen is a read that fails while somebody is looking
at a screen - and node status takes seconds and can hang, which is a page that
hangs with it.

So one poller asks, on its own schedule, and writes the answer here. Everything
that renders reads this table and knows exactly how old the answer is, because
`observed_at` is written by the database rather than supplied.

The envelope is stored whole rather than unpacked into columns. It is the
engine's contract and it is versioned there; unpacking it here would make this
migration a second, quietly diverging definition of what a status result is.
Queries reach into the JSON, which PostgreSQL indexes perfectly well.

Revision ID: 0004
Revises: 0003
"""

from __future__ import annotations

from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    create table cluster_status (
        cluster      text primary key,
        observed_at  timestamptz not null default statement_timestamp(),
        --
        -- The envelope's own outcome, lifted out because every reader needs it
        -- and because a CHECK can then refuse a value the engine would never
        -- produce. The rest stays in the document.
        --
        outcome      text not null,
        result       jsonb not null,
        warnings     jsonb not null default '[]'::jsonb,
        error        jsonb,
        --
        -- What the poller could not do, as opposed to what the cluster said. A
        -- helper that refused to run and a cluster that is genuinely broken are
        -- different problems with different fixes, and a single "unavailable"
        -- would hide which one this is.
        --
        poll_error   text,

        constraint cluster_status_cluster_shape
            check (cluster ~ '^[a-z0-9][a-z0-9_-]{0,31}$'),
        constraint cluster_status_outcome_allowed
            check (outcome in ('done', 'partial', 'failed', 'unavailable'))
    );
    """)

    #
    # observed_at is moved forward by the database, not by the writer. The
    # poller holds no update on the column and could not set it if it wanted
    # to - which is the same rule the job table follows for `pending` and the
    # request id: whoever is being measured does not get to choose the clock.
    #
    # It matters here because the column is what a reader uses to decide whether
    # a status is worth trusting. A poller that could write it could report a
    # cluster it never reached as freshly observed.
    #
    op.execute("""
    create function cluster_status_observed_at() returns trigger
        language plpgsql as $$
    begin
        new.observed_at := statement_timestamp();
        return new;
    end;
    $$;

    create trigger cluster_status_observed_at
        before update on cluster_status
        for each row execute function cluster_status_observed_at();
    """)

    op.execute("""
    --
    -- The poller writes; the web role reads. Neither can do the other's half,
    -- and the poller holds no delete: a cluster that stops being polled leaves
    -- a visibly stale row rather than vanishing from the interface, which is
    -- the difference between "nobody has asked lately" and "this never existed".
    --
    grant insert (cluster, outcome, result, warnings, error, poll_error)
        on cluster_status to app_poller;
    grant update (outcome, result, warnings, error, poll_error)
        on cluster_status to app_poller;
    grant select (cluster, observed_at, outcome, result, warnings, error, poll_error)
        on cluster_status to app_poller, app_web;
    """)


def downgrade() -> None:
    op.execute("""
    drop table if exists cluster_status;
    drop function if exists cluster_status_observed_at();
    """)
