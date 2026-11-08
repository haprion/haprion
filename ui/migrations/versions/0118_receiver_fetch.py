"""When each certificate receiver last fetched (B496, 10; B498).

`receiver_fetch` holds one row per receiver: the newest fetch the manager's own
logs have shown - sshd's accepted login of an rsync or sftp receiver's
account, or a `200` under an https receiver's `/certdist/<id>/` - and when the
poller recorded it. The poller reads it from the `receiver_fetches` reading
and only ever moves `fetched_at` forward: the logs rotate, and a fetch learnt
once is not forgotten because its log line is gone. The web reads both
columns for *Receivers*, the certificate list and *Needs attention*.

No row is removed with its receiver. A receiver is its fetching host, so one
registered again under the same name is the same host, and its last fetch is
still true.

Haprion 1.0.1's web, poller and worker never name the table.

Revision ID: 0118
Revises: 0117
"""

from __future__ import annotations

from alembic import op

revision = "0118"
down_revision = "0117"
branch_labels = None
depends_on = None

ROLLBACK_SAFE = True
ROLLBACK_SAFE_BECAUSE = "it adds a table nothing in 1.0.1's web, poller or worker reads or writes"


def upgrade() -> None:
    op.execute(
        """
        create table public.receiver_fetch (
            receiver text primary key
                constraint receiver_fetch_receiver_check
                check (char_length(receiver) between 1 and 253),
            fetched_at timestamp with time zone not null,
            seen_at timestamp with time zone not null
        )
        """
    )
    op.execute(
        "grant select (receiver, fetched_at, seen_at), insert (receiver, fetched_at, seen_at), "
        "update (fetched_at, seen_at) on public.receiver_fetch to app_poller"
    )
    op.execute("grant select (receiver, fetched_at, seen_at) on public.receiver_fetch to app_web")
