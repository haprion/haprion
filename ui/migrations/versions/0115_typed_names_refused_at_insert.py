"""A typed name nobody has is turned away at the insert, whatever code writes it (0.99.11).

0113 and 0114 keep a name typed at a failed sign-in out of `audit_event` and
`login_attempt`, but they rewrite what is stored and leave the writing to the
application. Both are `ROLLBACK_SAFE`, so a rollback to the release before keeps
the database at 0114 while that release writes the typed name as it always did,
and an upgrade afterwards does not run them again.

Two `before insert` triggers hold the rule instead. A `login_failed` row whose
actor no account has gets no actor and `unknown_user` in its detail, as the
application writes it. A `login_attempt` row whose name is not already a digest
(it does not start with `chr(31)`) is given as `throttle_name` makes it: the
account's own name when an account has it, otherwise the keyed digest. A row the
current code writes passes through unchanged.

The trigger functions are definers with a pinned search path, owned like
`throttle_name`; nobody but the owner may call them, and the tables' triggers
run them for every role that inserts.

Revision ID: 0115
Revises: 0114
"""

from __future__ import annotations

from alembic import op

revision = "0115"
down_revision = "0114"
branch_labels = None
depends_on = None

ROLLBACK_SAFE = True
ROLLBACK_SAFE_BECAUSE = "code from before writes the same columns, and the triggers only keep a name nobody has out of them"


def upgrade() -> None:
    op.execute("""
    create function audit_event_blank_unknown_actor() returns trigger
        language plpgsql security definer
        set search_path to 'pg_catalog', 'public'
        as $$
        begin
            if new.action = 'login_failed' and new.actor is not null
               and not exists (select 1 from app_user u
                                where u.username_normalised = lower(new.actor)) then
                new.actor := null;
                new.detail := new.detail || '{"unknown_user": true}'::jsonb;
            end if;
            return new;
        end
        $$;
    revoke all on function audit_event_blank_unknown_actor() from public;
    create trigger audit_event_blank_unknown_actor
        before insert on audit_event
        for each row execute function audit_event_blank_unknown_actor();

    create function login_attempt_digest_unknown_name() returns trigger
        language plpgsql security definer
        set search_path to 'pg_catalog', 'public'
        as $$
        begin
            if left(new.username_normalised, 1) <> chr(31) then
                new.username_normalised := throttle_name(new.username_normalised);
            end if;
            return new;
        end
        $$;
    revoke all on function login_attempt_digest_unknown_name() from public;
    create trigger login_attempt_digest_unknown_name
        before insert on login_attempt
        for each row execute function login_attempt_digest_unknown_name();
    """)
