"""Whether a cluster's core/ or manual/ holds files written by hand that are not published (B529).

`cluster_handwritten` holds one row per cluster: the newest `handwritten`
reading the poller made through `haprion-readings-helper` - clean, pending with
the files, their difference and the fingerprint a publish names, or refused
with the reason. The poller writes it; the web reads it for *Needs attention*
and the page that publishes the files. The shape and the grants are
`cluster_regeneration`'s, the reading it sits beside.

Haprion 1.3.1's web, poller and worker never name the table.

Revision ID: 0124
Revises: 0123
"""

from __future__ import annotations

from alembic import op

revision = "0124"
down_revision = "0123"
branch_labels = None
depends_on = None

ROLLBACK_SAFE = True
ROLLBACK_SAFE_BECAUSE = "it adds a table nothing in 1.3.1's web, poller or worker reads or writes"

COLUMNS = ("cluster", "observed_at", "outcome", "result", "warnings", "error", "poll_error")
WRITTEN = ("cluster", "outcome", "result", "warnings", "error", "poll_error")
UPDATED = ("outcome", "result", "warnings", "error", "poll_error")


def upgrade() -> None:
    op.execute(
        """
        create function public.cluster_handwritten_observed_at() returns trigger
            language plpgsql
            as $$
            begin
                new.observed_at := statement_timestamp();
                return new;
            end;
            $$
        """
    )
    op.execute(
        """
        create table public.cluster_handwritten (
            cluster text primary key
                constraint cluster_handwritten_cluster_shape
                check (cluster ~ '^[a-z][a-z0-9-]{0,62}$'),
            observed_at timestamp with time zone default statement_timestamp() not null,
            outcome text not null
                constraint cluster_handwritten_outcome_allowed
                check (outcome in ('done', 'failed', 'unavailable')),
            result jsonb not null
                constraint cluster_handwritten_is_object check (jsonb_typeof(result) = 'object'),
            warnings jsonb default '[]'::jsonb not null,
            error jsonb,
            poll_error text,
            constraint cluster_handwritten_size check (octet_length(result::text) <= 8388608)
        )
        """
    )
    op.execute(
        "create trigger cluster_handwritten_observed_at before update on public.cluster_handwritten "
        "for each row execute function public.cluster_handwritten_observed_at()"
    )
    op.execute(
        f"grant select ({', '.join(COLUMNS)}), insert ({', '.join(WRITTEN)}), "
        f"update ({', '.join(UPDATED)}) on public.cluster_handwritten to app_poller"
    )
    op.execute(f"grant select ({', '.join(COLUMNS)}) on public.cluster_handwritten to app_web")
