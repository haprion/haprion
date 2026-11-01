"""A name typed at a failed sign-in is not kept when no account has it (0.99.11).

The user field of the sign-in form is sometimes where a password is typed. The
audit view shows such a row as *unknown user*, but the name was stored, and the
view's search, its *Who* filter and its sorting read the stored value: a reader
of the view could find the text out one character at a time. The row is now
written without the name, and `detail` says `unknown_user`; this blanks the
names already stored.

A failed sign-in keeps its actor when an account has the name (compared as the
account's own name is, lowercased). Nothing else in the record is touched.
`audit_event` is append-only for the application's roles; the migration runs as
the owner.

Revision ID: 0113
Revises: 0112
"""

from __future__ import annotations

from alembic import op

revision = "0113"
down_revision = "0112"
branch_labels = None
depends_on = None

ROLLBACK_SAFE = True
ROLLBACK_SAFE_BECAUSE = "code from before shows a row without an actor as a dash, and writes none of the rows it blanked"


def upgrade() -> None:
    op.execute("""
    update audit_event
       set actor = null,
           detail = detail || '{"unknown_user": true}'::jsonb
     where action = 'login_failed'
       and actor is not null
       and not exists (select 1 from app_user where username_normalised = lower(audit_event.actor));
    """)
