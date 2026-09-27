"""Sign-in through an OpenID Connect provider, break-glass accounts, and deletion (Fas 13 part 4, B195-B199).

The database half of the design in the plan's §16.6, O1. Nothing here signs
anyone in; it is the shape the later parts write into, with the rules that must
hold whoever writes - the page, `haproxy-ui-user`, or a bug in either:

* **Two kinds of account.** `source` is `local` or `oidc`. A local account
  always has an Argon2id hash; an OIDC account never has one, so a password can
  never be the way into an account the provider owns, and a local account can
  never be left without one. An OIDC account is bound to its provider's
  (`oidc_issuer`, `oidc_subject`) - the name is for display and may change at
  the provider (B199). Until its first sign-in, an account prepared by an admin
  has neither.
* **Break-glass accounts** are local accounts marked to sign in with a password
  while sign-in through the provider is on (B195). While it is on, the last
  active break-glass admin can be neither demoted, disabled, unmarked nor
  deleted, and sign-in through the provider cannot be turned on without one:
  the provider may be the thing that is down.
* **Accounts can be deleted** (B197), by the web role as well. This is the one
  table where an application role holds `delete`; the others are cleaned by
  root through the migration role. The last active admin cannot be deleted, as
  it already cannot be demoted or disabled. Sessions go with the account; jobs
  and the audit trail carry the name as text and stay.
* **The provider** is one row. The web writes its settings and the sealed
  client secret, which it cannot open (B146's model; the helper can). A
  trigger raises `revision` whenever a setting changes, so a Verify recorded
  against one revision says nothing about the next, and the provider cannot be
  on unless the current revision is the verified one.
* **A sign-in in progress** is a row: `state`, `nonce` and the PKCE verifier,
  tied to the browser's pre-sign-in cookie by a hash, used once. The web marks
  it used; retention removes old rows.
* **A session may carry the provider's id_token**, only so that signing out
  can say who is leaving when the provider is asked to sign out too.

Revision ID: 0041
Revises: 0040
"""

from __future__ import annotations

from alembic import op

revision = "0041"
down_revision = "0040"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    alter table app_user
        add column source       text not null default 'local',
        add column break_glass  boolean not null default false,
        add column oidc_issuer  text,
        add column oidc_subject text,
        alter column password_hash drop not null,
        drop constraint app_user_hash_argon2id;

    alter table app_user
        add constraint app_user_source_allowed check (source in ('local', 'oidc')),
        --
        -- The hash follows the kind of account, both ways. `is not null` is
        -- spelled out: a check passes on null, and `like` against a missing
        -- hash is null, so without it a local account could have none.
        --
        add constraint app_user_hash_by_source check (
            (source = 'local' and password_hash is not null and password_hash like '$argon2id$%')
            or (source = 'oidc' and password_hash is null)),
        add constraint app_user_break_glass_local check (not break_glass or source = 'local'),
        --
        -- A local account has no provider identity; an OIDC account has both
        -- halves or, until its first sign-in, neither.
        --
        add constraint app_user_oidc_identity check (
            (oidc_issuer is null) = (oidc_subject is null)
            and (source = 'oidc' or oidc_issuer is null)),
        add constraint app_user_oidc_issuer_shape
            check (oidc_issuer is null or length(oidc_issuer) between 8 and 512),
        add constraint app_user_oidc_subject_shape
            check (oidc_subject is null or length(oidc_subject) between 1 and 255),
        add constraint app_user_oidc_identity_unique unique (oidc_issuer, oidc_subject);

    create table oidc_provider (
        singleton            boolean primary key default true,
        enabled              boolean not null default false,
        issuer               text,
        client_id            text,
        client_secret_sealed bytea,
        key_id               text,
        auth_method          text not null default 'client_secret_basic',
        scopes               text not null default 'openid profile email',
        username_claim       text not null default 'preferred_username',
        groups_claim         text not null default 'groups',
        admin_group          text,
        reader_group         text,
        auto_create          boolean not null default true,
        button_text          text not null default 'Sign in with SSO',
        prompt_login         boolean not null default false,
        logout_mode          text not null default 'app',
        local_login          text not null default 'break_glass_only',
        ca_pem               text,
        revision             integer not null default 0,
        verified_revision    integer,
        updated_at           timestamptz not null default statement_timestamp(),
        updated_by           text,

        constraint oidc_provider_singleton check (singleton),
        constraint oidc_provider_issuer_shape
            check (issuer is null or (issuer like 'https://%' and length(issuer) <= 512)),
        constraint oidc_provider_client_id_shape
            check (client_id is null or length(client_id) between 1 and 256),
        constraint oidc_provider_secret_shape
            check (client_secret_sealed is null or octet_length(client_secret_sealed) <= 4096),
        constraint oidc_provider_secret_keyed
            check ((client_secret_sealed is null) = (key_id is null)),
        constraint oidc_provider_key_id_shape
            check (key_id is null or length(key_id) between 1 and 128),
        constraint oidc_provider_auth_method
            check (auth_method in ('client_secret_basic', 'client_secret_post')),
        constraint oidc_provider_scopes_shape
            check (length(scopes) between 6 and 512 and scopes ~ '(^| )openid( |$)'),
        constraint oidc_provider_claim_shape
            check (length(username_claim) between 1 and 128 and length(groups_claim) between 1 and 128),
        constraint oidc_provider_group_shape check (
            (admin_group is null or length(admin_group) between 1 and 256)
            and (reader_group is null or length(reader_group) between 1 and 256)),
        constraint oidc_provider_button_shape check (length(button_text) between 1 and 64),
        constraint oidc_provider_logout_mode check (logout_mode in ('app', 'provider')),
        constraint oidc_provider_local_login check (local_login in ('all', 'break_glass_only')),
        constraint oidc_provider_ca_shape
            check (ca_pem is null or length(ca_pem) between 1 and 65536),
        constraint oidc_provider_updated_by_shape
            check (updated_by is null or length(updated_by) between 1 and 64),
        --
        -- On only when there is something complete to be on with, and only
        -- the revision that was verified.
        --
        constraint oidc_provider_enabled_complete check (
            not enabled
            or (issuer is not null and client_id is not null and client_secret_sealed is not null
                and (admin_group is not null or reader_group is not null)
                and verified_revision = revision))
    );

    insert into oidc_provider default values;

    --
    -- Any change to what the provider is or how it is asked raises the
    -- revision. `enabled`, `verified_revision` and the bookkeeping do not:
    -- recording a Verify must not undo itself.
    --
    create function oidc_provider_touch() returns trigger
        language plpgsql as $$
    begin
        new.updated_at := statement_timestamp();
        if (new.issuer, new.client_id, new.client_secret_sealed, new.key_id, new.auth_method,
            new.scopes, new.username_claim, new.groups_claim, new.admin_group, new.reader_group,
            new.auto_create, new.button_text, new.prompt_login, new.logout_mode, new.local_login,
            new.ca_pem)
           is distinct from
           (old.issuer, old.client_id, old.client_secret_sealed, old.key_id, old.auth_method,
            old.scopes, old.username_claim, old.groups_claim, old.admin_group, old.reader_group,
            old.auto_create, old.button_text, old.prompt_login, old.logout_mode, old.local_login,
            old.ca_pem) then
            new.revision := old.revision + 1;
        end if;
        return new;
    end;
    $$;

    create trigger oidc_provider_touch
        before update on oidc_provider
        for each row execute function oidc_provider_touch();

    --
    -- 0039's guard, widened: to deletion, and to the break-glass admin while
    -- sign-in through the provider is on. One function and one lock for both,
    -- so that a change to accounts and a change to the provider cannot pass
    -- each other.
    --
    create or replace function app_user_keep_an_admin() returns trigger
        language plpgsql as $$
    begin
        perform pg_advisory_xact_lock(hashtext('app_user_keep_an_admin'));
        if not exists (select 1 from app_user where role = 'admin' and not disabled) then
            raise exception 'the last active admin cannot be demoted, disabled or deleted'
                using errcode = 'check_violation';
        end if;
        if exists (select 1 from oidc_provider where enabled)
           and not exists (select 1 from app_user
                            where role = 'admin' and not disabled and break_glass) then
            raise exception 'sign-in through the provider is on and needs an active break-glass admin'
                using errcode = 'check_violation';
        end if;
        return null;
    end;
    $$;

    drop trigger app_user_keep_an_admin on app_user;

    create trigger app_user_keep_an_admin
        after update of role, disabled, break_glass on app_user
        for each row
        when (old.role = 'admin' and not old.disabled
              and (new.role <> 'admin' or new.disabled or (old.break_glass and not new.break_glass)))
        execute function app_user_keep_an_admin();

    create trigger app_user_keep_an_admin_on_delete
        after delete on app_user
        for each row
        when (old.role = 'admin' and not old.disabled)
        execute function app_user_keep_an_admin();

    create trigger oidc_provider_needs_break_glass
        after update of enabled on oidc_provider
        for each row
        when (new.enabled and not old.enabled)
        execute function app_user_keep_an_admin();

    create table oidc_login (
        state            text primary key,
        nonce            text not null,
        verifier         text not null,
        mode             text not null,
        pre_session_hash bytea not null,
        created_at       timestamptz not null default statement_timestamp(),
        used_at          timestamptz,

        constraint oidc_login_state_shape check (length(state) between 32 and 128),
        constraint oidc_login_nonce_shape check (length(nonce) between 32 and 128),
        --
        -- RFC 7636 4.1: 43 to 128 characters.
        --
        constraint oidc_login_verifier_shape check (length(verifier) between 43 and 128),
        constraint oidc_login_mode check (mode in ('sign_in', 'test')),
        constraint oidc_login_pre_session_shape check (octet_length(pre_session_hash) = 32)
    );

    create index oidc_login_created_idx on oidc_login (created_at);

    alter table app_session
        add column id_token text,
        add constraint app_session_id_token_shape
            check (id_token is null or length(id_token) between 1 and 16384);
    """)

    op.execute("""
    grant select (source, break_glass, oidc_issuer, oidc_subject) on app_user to app_web;
    grant insert (source, break_glass, oidc_issuer, oidc_subject) on app_user to app_web;
    grant update (break_glass, oidc_issuer, oidc_subject) on app_user to app_web;
    grant delete on app_user to app_web;

    grant select (enabled, issuer, client_id, client_secret_sealed, key_id, auth_method, scopes,
                  username_claim, groups_claim, admin_group, reader_group, auto_create, button_text,
                  prompt_login, logout_mode, local_login, ca_pem, revision, verified_revision,
                  updated_at, updated_by)
        on oidc_provider to app_web;
    grant update (enabled, issuer, client_id, client_secret_sealed, key_id, auth_method, scopes,
                  username_claim, groups_claim, admin_group, reader_group, auto_create, button_text,
                  prompt_login, logout_mode, local_login, ca_pem, verified_revision, updated_by)
        on oidc_provider to app_web;

    grant insert (state, nonce, verifier, mode, pre_session_hash) on oidc_login to app_web;
    grant select (state, nonce, verifier, mode, pre_session_hash, created_at, used_at)
        on oidc_login to app_web;
    grant update (used_at) on oidc_login to app_web;

    grant insert (id_token) on app_session to app_web;
    grant select (id_token) on app_session to app_web;
    """)


def downgrade() -> None:
    # An OIDC account has no password and cannot become a local one, so the
    # way back is refused while one exists rather than inventing a hash. Delete
    # them first (they sign in again after the upgrade).
    op.execute("""
    do $$
    declare
        names text;
    begin
        select string_agg(username, ', ' order by username) into names
          from app_user where source = 'oidc';
        if names is not null then
            raise exception 'delete the OIDC accounts before downgrading: %', names;
        end if;
    end;
    $$;

    revoke select (id_token) on app_session from app_web;
    revoke insert (id_token) on app_session from app_web;
    alter table app_session drop constraint if exists app_session_id_token_shape;
    alter table app_session drop column if exists id_token;

    drop table if exists oidc_login;

    drop trigger if exists oidc_provider_needs_break_glass on oidc_provider;
    drop trigger if exists app_user_keep_an_admin_on_delete on app_user;
    drop trigger if exists app_user_keep_an_admin on app_user;

    create or replace function app_user_keep_an_admin() returns trigger
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

    drop table if exists oidc_provider;
    drop function if exists oidc_provider_touch();

    revoke delete on app_user from app_web;
    revoke update (break_glass, oidc_issuer, oidc_subject) on app_user from app_web;
    revoke insert (source, break_glass, oidc_issuer, oidc_subject) on app_user from app_web;
    revoke select (source, break_glass, oidc_issuer, oidc_subject) on app_user from app_web;

    alter table app_user
        drop constraint if exists app_user_oidc_identity_unique,
        drop constraint if exists app_user_oidc_subject_shape,
        drop constraint if exists app_user_oidc_issuer_shape,
        drop constraint if exists app_user_oidc_identity,
        drop constraint if exists app_user_break_glass_local,
        drop constraint if exists app_user_hash_by_source,
        drop constraint if exists app_user_source_allowed;

    alter table app_user
        drop column oidc_subject,
        drop column oidc_issuer,
        drop column break_glass,
        drop column source,
        alter column password_hash set not null,
        add constraint app_user_hash_argon2id check (password_hash like '$argon2id$%');
    """)
