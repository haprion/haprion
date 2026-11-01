"""What publishing a cluster again would change is read and kept (0.99.11).

The poller asks the engine, per cluster, whether making the published version's
generated layer again with the installed product would change what the nodes
run. The answer is one row per cluster, replaced by the poller and read by the
web, in the shape of the other readings (`cluster_settings`): the row's
`outcome` says whether the reading was made, and `result` holds the engine's
answer, whose own `outcome` (unchanged, changed, refused, unpublished) the
pages read.

`result` is the engine's answer whole, with the difference in the shape of a
version's, so it is bounded: a node file's text is at most 256 KiB of the diff
and the objects are listed by name, and 8 MiB is far above both. An answer
larger than that is refused by the database and the earlier one stays.

Revision ID: 0112
Revises: 0111
"""

from __future__ import annotations

from alembic import op

revision = "0112"
down_revision = "0111"
branch_labels = None
depends_on = None

ROLLBACK_SAFE = True
ROLLBACK_SAFE_BECAUSE = "a new table that code from before never reads"


def upgrade() -> None:
    op.execute("""
    create table cluster_regeneration (
        cluster text primary key,
        observed_at timestamptz not null default statement_timestamp(),
        outcome text not null,
        result jsonb not null,
        warnings jsonb not null default '[]',
        error jsonb,
        poll_error text,
        constraint cluster_regeneration_cluster_shape check (cluster ~ '^[a-z][a-z0-9-]{0,62}$'),
        constraint cluster_regeneration_outcome_allowed
            check (outcome in ('done', 'failed', 'unavailable')),
        constraint cluster_regeneration_is_object check (jsonb_typeof(result) = 'object'),
        constraint cluster_regeneration_size check (octet_length(result::text) <= 8388608)
    );

    create function cluster_regeneration_observed_at() returns trigger
        language plpgsql
        as $$
        begin
            new.observed_at := statement_timestamp();
            return new;
        end;
        $$;
    create trigger cluster_regeneration_observed_at before update on cluster_regeneration
        for each row execute function cluster_regeneration_observed_at();

    grant select (cluster), insert (cluster) on cluster_regeneration to app_poller;
    grant select (cluster) on cluster_regeneration to app_web;
    grant select (observed_at) on cluster_regeneration to app_poller, app_web;
    grant select (outcome), insert (outcome), update (outcome) on cluster_regeneration to app_poller;
    grant select (outcome) on cluster_regeneration to app_web;
    grant select (result), insert (result), update (result) on cluster_regeneration to app_poller;
    grant select (result) on cluster_regeneration to app_web;
    grant select (warnings), insert (warnings), update (warnings) on cluster_regeneration to app_poller;
    grant select (warnings) on cluster_regeneration to app_web;
    grant select (error), insert (error), update (error) on cluster_regeneration to app_poller;
    grant select (error) on cluster_regeneration to app_web;
    grant select (poll_error), insert (poll_error), update (poll_error) on cluster_regeneration to app_poller;
    grant select (poll_error) on cluster_regeneration to app_web;
    """)
