"""A renamed backend's earlier names, so its card keeps its history (2026-10-06).

Since B250 a pool's backend is named by the pool, so renaming the pool renames
the series HAProxy reports, and the card under the new name started empty while
the old name's rows sat unread. One row here says that `old_name`'s readings
belong to `new_name`'s card: written by the interface when it queues a publish
that renames a pool (or, by renaming an object, its redirects), because that is
the one moment both names are known. The job history cannot hold it - jobs are
kept seven days, a card reads thirty.

`reused_at` closes the old name: set when a later publish gives that name to a
backend again, so the newcomer's readings are not drawn into the renamed card.
The old name's rows count only before it.

A row per rename and no retention. A thousand renames are a few hundred
kilobytes, and a row whose old name has no readings left is simply read as
nothing.

Revision ID: 0056
Revises: 0055
"""

from __future__ import annotations

from alembic import op

revision = "0056"
down_revision = "0055"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    create table metric_backend_alias (
        cluster     text not null,
        old_name    text not null,
        new_name    text not null,
        renamed_at  timestamptz not null default statement_timestamp(),
        reused_at   timestamptz,

        constraint metric_backend_alias_cluster_shape
            check (cluster ~ '^[a-z0-9][a-z0-9_-]{0,31}$'),
        constraint metric_backend_alias_names
            check (length(old_name) between 1 and 128 and length(new_name) between 1 and 128
                   and old_name <> new_name),

        primary key (cluster, old_name)
    );

    grant select (cluster, old_name, new_name, renamed_at, reused_at) on metric_backend_alias to app_web;
    grant insert (cluster, old_name, new_name) on metric_backend_alias to app_web;
    grant update (new_name, renamed_at, reused_at) on metric_backend_alias to app_web;
    """)


def downgrade() -> None:
    op.execute("drop table if exists metric_backend_alias;")
