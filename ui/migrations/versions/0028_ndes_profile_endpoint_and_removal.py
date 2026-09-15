"""Show an NDES profile's endpoint, and let the queue remove a profile.

Revision ID: 0028
Revises: 0027
"""

from __future__ import annotations

from alembic import op

revision = "0028"
down_revision = "0027"
branch_labels = None
depends_on = None

#
# The endpoint is inside the sealed box, which is the right place for the
# helper to take it from: the box is what root opens and checks against the
# policy. It is also the one thing about a profile a reader wants to see in
# the list, and it is not a secret - so the web keeps a plain copy beside the
# box, written in the same statement. A row from before this revision has
# none; it shows as unknown until the profile is replaced.
#
# Removal follows the DNS profiles' shape: the helper removes the root-only
# record and the worker deletes the row for exactly that revision afterwards.
#


def upgrade() -> None:
    op.execute("""
    alter table ndes_provider_profile
        add column endpoint text not null default '',
        add constraint ndes_provider_profile_endpoint_shape
            check (endpoint = '' or (endpoint ~ '^https://' and char_length(endpoint) <= 2048));

    grant select (endpoint) on ndes_provider_profile to app_web;
    grant insert (endpoint) on ndes_provider_profile to app_web;
    grant update (endpoint) on ndes_provider_profile to app_web;
    grant delete on ndes_provider_profile to app_worker;
    """)


def downgrade() -> None:
    op.execute("""
    revoke delete on ndes_provider_profile from app_worker;
    alter table ndes_provider_profile drop column endpoint;
    """)
