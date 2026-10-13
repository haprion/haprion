"""Accounts through the provider come from its groups alone (B297, 26-10-13).

Sign-in through the provider always makes the account at first sign-in, with
the role its groups give; an admin no longer prepares one by name, and the
setting that made preparing necessary (`auto_create` off) is gone. Who may
sign in is decided in the provider's groups, in one place.

This removes the prepared accounts nobody has signed in as - they would hold
their name against the person's first sign-in - and turns `auto_create` on
where it was off. The column, and the web's grant to bind an account, stay
for now: the UI from before reads the one and a sign-in there may use the
other, so dropping them would make a rollback over this migration unsafe.
A later migration drops both.

`verified_revision` follows the revision the trigger raises, where it was
verified: Verify does not ask about `auto_create`, and sign-in through the
provider must stay on.

Revision ID: 0072
Revises: 0071
"""

from __future__ import annotations

from alembic import op

revision = "0072"
down_revision = "0071"
branch_labels = None
depends_on = None

ROLLBACK_SAFE = True
ROLLBACK_SAFE_BECAUSE = (
    "removes unbound prepared accounts and turns auto_create on; a UI from before reads the "
    "same columns and behaves as with auto_create on"
)


def upgrade() -> None:
    op.execute("""
    delete from app_user where source = 'oidc' and oidc_issuer is null;

    update oidc_provider
       set auto_create = true,
           verified_revision = case when verified_revision = revision
                                    then revision + 1 else verified_revision end
     where not auto_create;
    """)


def downgrade() -> None:
    #
    # Nothing to put back: the prepared accounts were never signed in as, and
    # a UI from before reads auto_create on as it was set before 0072.
    #
    pass
