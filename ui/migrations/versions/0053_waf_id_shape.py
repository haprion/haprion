"""The WAF engine's transaction ID names the object, in the databases that already had 0052.

0052 was changed after it had been applied: the engine's ID became
`<object>.<uuid>` (B234), and the two shapes that check it were widened in the
migration itself to allow the dot and 96 characters. A database migrated with
the first version kept `^[A-Za-z0-9_-]{1,64}$`, and refused every record with
an ID - the collector's whole import failed on the first request an object with
the engine served (measured 26-10-03, production, from 19:44). A fresh
database already has the wide shapes from 0052; this sets them on both, so the
two kinds of database end up alike.

The collector imports in one transaction and keeps its place when it fails,
so what it could not import is imported once this has run.

An applied migration is never edited again; a change is a new one, like this.

Revision ID: 0053
Revises: 0052
"""

from __future__ import annotations

from alembic import op

revision = "0053"
down_revision = "0052"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    alter table waf_match
        drop constraint if exists waf_match_request_id_shape,
        add constraint waf_match_request_id_shape
            check (request_id ~ '^[A-Za-z0-9_.-]{1,96}$');

    alter table traffic_log
        drop constraint if exists traffic_log_waf_id_shape,
        add constraint traffic_log_waf_id_shape
            check (waf_id ~ '^([A-Za-z0-9_.-]{1,96})?$');
    """)


def downgrade() -> None:
    #
    # Nothing to undo. The narrow shape refuses the IDs the engine writes, and
    # rows that hold them cannot be put back under it; the wide shape is what
    # 0052 itself now creates, so leaving it is a database 0052 would make.
    #
    pass
