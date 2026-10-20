"""The prepared account and its setting are gone from the schema (B297, 26-10-20).

0072 stopped preparing accounts by name and turned `auto_create` on, and kept
the column and the web's grant to bind an account for the UI from before it.
Nothing from 0072 on reads the one or uses the other: the provider's columns
the web selects and updates leave `auto_create` out, and an account through the
provider is inserted at its first sign-in, never bound afterwards. Both go.

The revision trigger names every column that raises the provider's revision,
so it is written again without `auto_create`; the change it measures is
otherwise the same.

A UI from before 0072 still reads `auto_create` and would fail over this, so
the declaration has a floor: safe for a UI at 0072 or later, and
`haprion-rollback` refuses an older one on this schema.

Revision ID: 0079
Revises: 0078
"""

from __future__ import annotations

from alembic import op

revision = "0079"
down_revision = "0078"
branch_labels = None
depends_on = None

ROLLBACK_SAFE = True
ROLLBACK_SAFE_FROM = "0072"
ROLLBACK_SAFE_BECAUSE = (
    "drops oidc_provider.auto_create and the web's update of an account's provider identity; "
    "no UI from 0072 on reads the one or uses the other"
)

TOUCH = """
create or replace function oidc_provider_touch() returns trigger
    language plpgsql as $$
begin
    new.updated_at := statement_timestamp();
    if (new.issuer, new.client_id, new.client_secret_sealed, new.key_id, new.auth_method,
        new.scopes, new.username_claim, new.groups_claim, new.admin_group, new.reader_group,
        {new}new.button_text, new.prompt_login, new.logout_mode, new.local_login,
        new.ca_pem)
       is distinct from
       (old.issuer, old.client_id, old.client_secret_sealed, old.key_id, old.auth_method,
        old.scopes, old.username_claim, old.groups_claim, old.admin_group, old.reader_group,
        {old}old.button_text, old.prompt_login, old.logout_mode, old.local_login,
        old.ca_pem) then
        new.revision := old.revision + 1;
    end if;
    return new;
end;
$$;
"""


def upgrade() -> None:
    op.execute(TOUCH.format(new="", old=""))
    op.execute("""
    revoke update (oidc_issuer, oidc_subject) on app_user from app_web;
    alter table oidc_provider drop column auto_create;
    """)


def downgrade() -> None:
    op.execute("""
    alter table oidc_provider add column auto_create boolean not null default true;
    grant select (auto_create), update (auto_create) on oidc_provider to app_web;
    grant update (oidc_issuer, oidc_subject) on app_user to app_web;
    """)
    op.execute(TOUCH.format(new="new.auto_create, ", old="old.auto_create, "))
