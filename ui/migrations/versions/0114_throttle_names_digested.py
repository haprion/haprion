"""A name typed at a failed sign-in is kept as a digest when no account has it (0.99.11).

`login_attempt` counts attempts per typed name, and stored the name as typed.
The user field of the sign-in form is sometimes where a password is typed, so a
name nobody has is now kept only as a keyed digest: the count per typed name is
the same, and the text is not recoverable.

The key is one random value in `throttle_key`, which no application role can
read. `throttle_name(typed)` is a definer function the web may call: it returns
the account's own normalised name when an account has the typed one, and
otherwise `chr(31)` and 63 hex digits of `sha256(key || lower(typed))`. An
account name has no control characters, so a digest never equals one, and the
whole is 64 characters, which the table's check allows.

The rows already stored are rewritten the same way, with this key, so a name
nobody has keeps its count. A name an account has is left as it is.

Revision ID: 0114
Revises: 0113
"""

from __future__ import annotations

from alembic import op

revision = "0114"
down_revision = "0113"
branch_labels = None
depends_on = None

ROLLBACK_SAFE = True
ROLLBACK_SAFE_BECAUSE = "code from before writes and reads the name as typed, which counts as it did against the rows it wrote"


def upgrade() -> None:
    op.execute("""
    create table throttle_key (
        only_row boolean primary key default true,
        key bytea not null,
        constraint throttle_key_one_row check (only_row),
        constraint throttle_key_size check (octet_length(key) = 32)
    );
    insert into throttle_key (key)
        values (sha256(convert_to(gen_random_uuid()::text || gen_random_uuid()::text, 'UTF8')));

    create function throttle_name(typed text) returns text
        language sql stable security definer
        set search_path to 'pg_catalog', 'public'
        as $$
            select coalesce(
                (select u.username_normalised from app_user u
                  where u.username_normalised = lower(typed)),
                chr(31) || substr(encode(
                    sha256((select k.key from throttle_key k) || convert_to(lower(typed), 'UTF8')),
                    'hex'), 1, 63))
        $$;
    revoke all on function throttle_name(text) from public;
    grant execute on function throttle_name(text) to app_web;

    update login_attempt
       set username_normalised = throttle_name(username_normalised)
     where not exists (select 1 from app_user
                        where app_user.username_normalised = login_attempt.username_normalised);
    """)
