"""A DNS or NDES profile ID may hold `.` and `_` (B380, 26-10-28).

A profile is named after what it reaches - an NDES profile after its server,
`cs2.example.com` - and the ID names a file and is a command-line argument.
Neither `.` nor `_` needs quoting in a shell or harms the file name, and the
first character is still a letter or a digit, so `.` and `..` stay out. The two
checks are replaced; nothing else changes.

Revision ID: 0101
Revises: 0100
"""

from __future__ import annotations

from alembic import op

revision = "0101"
down_revision = "0100"
branch_labels = None
depends_on = None

ROLLBACK_SAFE = False
ROLLBACK_SAFE_BECAUSE = (
    "a profile named with a dot or an underscore is a row a UI from before refuses to read"
)


def upgrade() -> None:
    op.execute("""
    alter table dns_provider_profile drop constraint dns_provider_profile_id_shape;
    alter table dns_provider_profile add constraint dns_provider_profile_id_shape
        check (id ~ '^[a-z0-9][a-z0-9._-]{0,31}$');
    alter table ndes_provider_profile drop constraint ndes_provider_profile_id_shape;
    alter table ndes_provider_profile add constraint ndes_provider_profile_id_shape
        check (id ~ '^[a-z0-9][a-z0-9._-]{0,31}$');
    """)
