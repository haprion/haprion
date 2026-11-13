"""A blocklist's password or token has a revision of its own (B501).

`blocklist.revision` rises with every save, but the sealed box is written only
when the password or token is: a save that leaves the field empty keeps the
box, so the box is older than the row, and the apply helper, which refused a
box older than the job's revision, refused every such save (BL01).
`secret_revision` is the revision the box was last sealed at. The web sets it
when it seals and leaves it alone when it keeps the box; the worker hands it to
the helper, which requires the box to be at least that new and writes the
definition at the job's own revision. The helper also holds the box to the
source it was sealed for, so a URL changed while the box was kept is refused
there too (BL02); that binding is inside the box and needs no column.

The web writes the column and cannot read it back, as it cannot the box; the
worker reads it. A row made before this takes 1: its box, if older than the
binding, is refused by the helper with a sentence that says to type the
password or token again.

Haprion 1.0.1's web, poller and worker never name the table.

Revision ID: 0120
Revises: 0119
"""

from __future__ import annotations

from alembic import op

revision = "0120"
down_revision = "0119"
branch_labels = None
depends_on = None

ROLLBACK_SAFE = True
ROLLBACK_SAFE_BECAUSE = "it adds a column to a table nothing in 1.0.1's web, poller or worker names"


def upgrade() -> None:
    op.execute(
        "alter table public.blocklist add column secret_revision integer not null default 1 "
        "constraint blocklist_secret_revision_check check (secret_revision between 1 and 1000000)"
    )
    op.execute(
        "alter table public.blocklist add constraint blocklist_secret_revision_order "
        "check (secret_revision <= revision)"
    )
    op.execute("alter table public.blocklist alter column secret_revision drop default")
    op.execute(
        "grant insert (secret_revision), update (secret_revision) on public.blocklist to app_web"
    )
    op.execute("grant select (secret_revision) on public.blocklist to app_worker")
