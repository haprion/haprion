"""An API token can be extended: the same secret, a new end date (B416, B417).

0107 fixed a token's life when it was made. A token that a script already
holds should not have to be replaced to live on, so the web may now move
`expires_at` - and only that. What it may not do is held here:

* **Every life is at most two years from the day it is made or extended.**
  `valid_from` is when the current life began: `created_at` for a token never
  extended, the extension's own moment after one. A trigger sets it from the
  database's clock, and the web has no grant to write it, so a token cannot be
  given a longer life than the table allows by choosing where it starts.
* **A revoked token is not extended, and a date already past is not a new
  date.** Revocation stays final; an extension that ends before it is made is
  refused rather than recorded as a token that never lived.

Revision ID: 0108
Revises: 0107
"""

from __future__ import annotations

from alembic import op

revision = "0108"
down_revision = "0107"
branch_labels = None
depends_on = None

ROLLBACK_SAFE = True
ROLLBACK_SAFE_BECAUSE = (
    "a column with a default, a constraint the old code's inserts also meet and a trigger on "
    "an update that code from before never makes; it names no new column"
)


def upgrade() -> None:
    op.execute("""
    alter table api_token
        add column valid_from timestamptz not null default statement_timestamp();
    update api_token set valid_from = created_at;

    alter table api_token drop constraint api_token_lifetime;
    alter table api_token add constraint api_token_lifetime
        check (expires_at > valid_from and expires_at <= valid_from + interval '2 years');

    create function api_token_extension() returns trigger
        language plpgsql
        as $$
        begin
            if old.revoked_at is not null then
                raise exception 'a revoked API token is not extended'
                    using errcode = 'check_violation';
            end if;
            if new.expires_at <= statement_timestamp() then
                raise exception 'an API token is extended to a date that has not passed'
                    using errcode = 'check_violation';
            end if;
            if old.expires_at > statement_timestamp() and new.expires_at <= old.expires_at then
                raise exception 'an API token in use is extended to a later date, never an earlier one'
                    using errcode = 'check_violation';
            end if;
            new.valid_from := statement_timestamp();
            return new;
        end;
        $$;
    create trigger api_token_extension before update of expires_at
        on api_token for each row execute function api_token_extension();

    grant select (valid_from) on api_token to app_web;
    grant update (expires_at) on api_token to app_web;
    """)
