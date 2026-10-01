"""What each version changed, as the poller fetched it once (B220, 2026-10-01).

A version is a commit, and its difference from the version before it never
changes once it exists. So the poller asks `haproxy-list-helper` for the diffs
of the versions it has none for yet, a few per pass, and keeps each answer here
for the Versions page to show. One row per cluster and commit; `insert ... on
conflict do nothing`, so the poller needs no update or delete privilege. Rows
for versions no longer in the history (after a history reset) are removed by
the retention command, which owns deletes.

Revision ID: 0046
Revises: 0045
"""

from __future__ import annotations

from alembic import op

revision = "0046"
down_revision = "0045"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    create table version_diff (
        cluster      text not null,
        commit       text not null,
        recorded_at  timestamptz not null default statement_timestamp(),
        diff         jsonb not null,

        primary key (cluster, commit),
        constraint version_diff_cluster_shape check (cluster ~ '^[a-z0-9][a-z0-9_-]{0,31}$'),
        constraint version_diff_commit_shape check (commit ~ '^[0-9a-f]{40,64}$'),
        constraint version_diff_is_object check (jsonb_typeof(diff) = 'object'),
        -- The engine bounds a diff at 256 KiB of patch text; this is the same
        -- bound with room for the JSON around it, so a row cannot grow past it.
        constraint version_diff_size check (octet_length(diff::text) <= 1048576)
    );

    grant insert (cluster, commit, diff) on version_diff to app_poller;
    grant select (cluster, commit, recorded_at, diff) on version_diff to app_poller, app_web;
    """)


def downgrade() -> None:
    op.execute("""
    drop table if exists version_diff;
    """)
