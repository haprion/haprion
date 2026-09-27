"""Accounts from the web: the grants, the guard on the last admin, and unlocks.

0001 kept every write to `app_user` away from the application roles "until
there is an audited admin interface asking for it". This is that interface's
half in the database (Fas 13 part 2, B187). The rules it has to keep are
enforced here rather than trusted to the page:

* **Column grants, listed one by one**, as in 0001. The web role may create an
  account (name, hash, role) and change role, `disabled`, hash and time zone.
  It cannot delete an account, and it cannot set `created_at` or `updated_at`:
  the default and a trigger do, so an edit cannot be backdated.
* **The last active admin cannot be removed** - neither demoted nor disabled.
  A trigger refuses the change that would leave none, under a transaction lock
  so that two admins disabling each other at the same moment cannot both pass.
  It holds for `haproxy-ui-user` as well; the break-glass path there is `add`.
* **An unlock is a row added, not failures deleted.** `login_attempt` stays
  append-only - the web role still holds no delete on it - and the throttle
  counts failures since the latest of a success and an unlock. The record of
  what was tried survives the unlock.

The trade-off was accepted in B187: an intrusion *without* an admin session
cannot create an admin; one *with* it can, as it already can the rest.

Revision ID: 0039
Revises: 0038
"""

from __future__ import annotations

from alembic import op

revision = "0039"
down_revision = "0038"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    create function app_user_touch() returns trigger
        language plpgsql as $$
    begin
        new.updated_at := statement_timestamp();
        return new;
    end;
    $$;

    create trigger app_user_touch
        before update on app_user
        for each row execute function app_user_touch();

    --
    -- The lock is taken before the count, and the count is its own statement,
    -- so under read committed it sees what a concurrent change committed
    -- while this one waited. Without the lock, two transactions each
    -- disabling one of two admins would each still see the other active.
    --
    create function app_user_keep_an_admin() returns trigger
        language plpgsql as $$
    begin
        perform pg_advisory_xact_lock(hashtext('app_user_keep_an_admin'));
        if not exists (select 1 from app_user where role = 'admin' and not disabled) then
            raise exception 'the last active admin cannot be demoted or disabled'
                using errcode = 'check_violation';
        end if;
        return null;
    end;
    $$;

    create trigger app_user_keep_an_admin
        after update of role, disabled on app_user
        for each row
        when (old.role = 'admin' and not old.disabled
              and (new.role <> 'admin' or new.disabled))
        execute function app_user_keep_an_admin();

    --
    -- Per name, not per address: an unlock answers "let this person in
    -- again", from wherever they are. `actor` is who unlocked, which is what
    -- the audit event says too; the row is what the throttle reads.
    --
    create table login_unlock (
        id                  bigint generated always as identity primary key,
        at                  timestamptz not null default statement_timestamp(),
        username_normalised text not null,
        actor               text not null,

        constraint login_unlock_username_shape
            check (length(username_normalised) between 1 and 64),
        constraint login_unlock_actor_shape check (length(actor) between 1 and 64)
    );

    create index login_unlock_name_idx on login_unlock (username_normalised, at desc);
    """)

    op.execute("""
    grant select (created_at, updated_at) on app_user to app_web;
    grant insert (username, password_hash, role) on app_user to app_web;
    grant update (role, disabled, password_hash) on app_user to app_web;

    --
    -- Insert and select, as on login_attempt; `at` is not insertable.
    --
    grant insert (username_normalised, actor) on login_unlock to app_web;
    grant select (id, at, username_normalised, actor) on login_unlock to app_web;
    """)


def downgrade() -> None:
    # Unlock rows go; an account unlocked through a row may
    # read as throttled again until its window passes.
    op.execute("""
    revoke update (role, disabled, password_hash) on app_user from app_web;
    revoke insert (username, password_hash, role) on app_user from app_web;
    revoke select (created_at, updated_at) on app_user from app_web;
    drop table if exists login_unlock;
    drop trigger if exists app_user_keep_an_admin on app_user;
    drop function if exists app_user_keep_an_admin();
    drop trigger if exists app_user_touch on app_user;
    drop function if exists app_user_touch();
    """)
