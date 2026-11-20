"""Protection review: what an admin accepted, and how the view is shown (B517, 12; B521).

`protection_review_ack` is one row per object an admin accepted on *Protection
review*: the weaknesses it had then, by their keys, and who accepted it when.
The row is accepted while it has no weakness the list does not hold; a new one
makes it a row to review again. *Undo* deletes the row, and so does the page
once the object is gone, so an object made again under the name starts afresh.

`protection_review_view` is the view's one row of shared choices: whether rows
with nothing to review are shown, and which clusters are hidden. Every reader
sees the same view; an admin changes it.

Both are the web's alone. Haprion 1.2.2's web, poller and worker never name
either table.

Revision ID: 0122
Revises: 0121
"""

from __future__ import annotations

from alembic import op

revision = "0122"
down_revision = "0121"
branch_labels = None
depends_on = None

ROLLBACK_SAFE = True
ROLLBACK_SAFE_BECAUSE = (
    "it adds two tables nothing in 1.2.2's web, poller or worker reads or writes"
)


def upgrade() -> None:
    op.execute(
        """
        create table public.protection_review_ack (
            cluster text not null
                constraint protection_review_ack_cluster_check
                check (char_length(cluster) between 1 and 64),
            subject text not null
                constraint protection_review_ack_subject_check
                check (char_length(subject) between 1 and 256),
            weaknesses text[] not null
                constraint protection_review_ack_weaknesses_check
                check (cardinality(weaknesses) between 1 and 32),
            accepted_by text not null
                constraint protection_review_ack_accepted_by_check
                check (char_length(accepted_by) between 1 and 64),
            accepted_at timestamp with time zone not null default statement_timestamp(),
            primary key (cluster, subject)
        )
        """
    )
    op.execute(
        "grant select (cluster, subject, weaknesses, accepted_by, accepted_at), "
        "insert (cluster, subject, weaknesses, accepted_by), "
        "update (weaknesses, accepted_by, accepted_at), delete "
        "on public.protection_review_ack to app_web"
    )
    op.execute(
        """
        create table public.protection_review_view (
            id boolean primary key default true
                constraint protection_review_view_one_row check (id),
            show_clean boolean not null default true,
            hidden_clusters text[] not null default '{}'
                constraint protection_review_view_hidden_clusters_check
                check (cardinality(hidden_clusters) <= 256),
            updated_by text not null
                constraint protection_review_view_updated_by_check
                check (char_length(updated_by) between 1 and 64),
            updated_at timestamp with time zone not null default statement_timestamp()
        )
        """
    )
    op.execute(
        "grant select (id, show_clean, hidden_clusters, updated_by, updated_at), "
        "insert (id, show_clean, hidden_clusters, updated_by), "
        "update (show_clean, hidden_clusters, updated_by, updated_at) "
        "on public.protection_review_view to app_web"
    )
