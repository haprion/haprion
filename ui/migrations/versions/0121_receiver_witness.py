"""Where the receivers' fetches were read from, and since when (B498).

`receiver_witness` holds one row per source the poller reads a certificate
receiver's fetches from: `journal` (sshd's accepted logins, for rsync and sftp)
and `access_log` (nginx's receivers log, for https). A row says when the source
was first read successfully and when it was last. Without it a source that
could never be read, or that began after a copy was written, looked like a
receiver that had not fetched, and *Needs attention* listed every such
receiver for good. The poller writes a row for each source that answered and
moves only `read_at`; the web reads both columns.

Haprion 1.0.1's web, poller and worker never name the table.

Revision ID: 0121
Revises: 0120
"""

from __future__ import annotations

from alembic import op

revision = "0121"
down_revision = "0120"
branch_labels = None
depends_on = None

ROLLBACK_SAFE = True
ROLLBACK_SAFE_BECAUSE = "it adds a table nothing in 1.0.1's web, poller or worker reads or writes"


def upgrade() -> None:
    op.execute(
        """
        create table public.receiver_witness (
            source text primary key
                constraint receiver_witness_source_check
                check (source in ('journal', 'access_log')),
            first_read_at timestamp with time zone not null,
            read_at timestamp with time zone not null
        )
        """
    )
    op.execute(
        "grant select (source, first_read_at, read_at), "
        "insert (source, first_read_at, read_at), update (read_at) "
        "on public.receiver_witness to app_poller"
    )
    op.execute(
        "grant select (source, first_read_at, read_at) on public.receiver_witness to app_web"
    )
