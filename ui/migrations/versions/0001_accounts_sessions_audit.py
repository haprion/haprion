"""Accounts, sessions and the audit trail.

The three tables that exist before any management operation does. Every grant is
here rather than in the installation, so a column's permissions are versioned
with the column and cannot drift from it.

Grants name the three contract roles - `app_web`, `app_worker`, `app_poller` -
and never a service account. Account names identify a real installation and this
repository is meant to be public; the installation connects whatever the
accounts are actually called to these roles.

Nothing is granted ahead of a feature. The web role reads accounts because it
authenticates people, and does not write them: creating and resetting an account
is a local root action until there is an audited admin interface asking for it.

Revision ID: 0001
Revises:
"""

from __future__ import annotations

from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    --
    -- Normalisation is a generated column rather than something the
    -- application does before it writes. Rate limiting and lookup both key on
    -- the normalised form, and two callers lowercasing "the same way" is how
    -- one of them eventually does not.
    --
    create table app_user (
        id                  bigint generated always as identity primary key,
        username            text not null,
        username_normalised text generated always as (lower(username)) stored,
        password_hash       text not null,
        role                text not null,
        disabled            boolean not null default false,
        created_at          timestamptz not null default statement_timestamp(),
        updated_at          timestamptz not null default statement_timestamp(),

        constraint app_user_username_shape check (length(username) between 1 and 64),
        constraint app_user_role_allowed   check (role in ('admin', 'reader')),
        --
        -- Argon2id, and the check is deliberately about the shape rather than
        -- the value: a row whose hash is a bcrypt string, or empty, is a
        -- migration mistake that must not become a login path.
        --
        constraint app_user_hash_argon2id  check (password_hash like '$argon2id$%')
    );

    create unique index app_user_username_key on app_user (username_normalised);

    --
    -- Only the hash of a session token is stored. The opaque token exists in
    -- the cookie and nowhere else, so a database dump - or this table read by
    -- anything - cannot be replayed as a login.
    --
    create table app_session (
        token_hash   bytea primary key,
        user_id      bigint not null references app_user (id) on delete cascade,
        created_at   timestamptz not null default statement_timestamp(),
        last_seen_at timestamptz not null default statement_timestamp(),
        expires_at   timestamptz not null,
        revoked_at   timestamptz,

        constraint app_session_hash_sha256 check (octet_length(token_hash) = 32),
        constraint app_session_expiry      check (expires_at > created_at)
    );

    create index app_session_user_idx on app_session (user_id);
    create index app_session_expiry_idx on app_session (expires_at);

    --
    -- Append-only, enforced by grant rather than by intention: no role is given
    -- update or delete, so a compromised web process can add to the record and
    -- cannot edit what is already in it. Retention is a later, deliberate root
    -- action, not something a running service can do.
    --
    create table audit_event (
        id         bigint generated always as identity primary key,
        at         timestamptz not null default statement_timestamp(),
        actor      text,
        action     text not null,
        cluster    text,
        request_id uuid,
        detail     jsonb not null default '{}'::jsonb,

        --
        -- A shape, not a list. Cluster IDs are loaded from runtime
        -- configuration, and enumerating them here would make every new cluster
        -- a migration.
        --
        constraint audit_event_cluster_shape
            check (cluster is null or cluster ~ '^[a-z0-9][a-z0-9_-]{0,31}$'),
        constraint audit_event_action_shape check (length(action) between 1 and 64)
    );

    create index audit_event_at_idx on audit_event (at desc);
    create index audit_event_cluster_idx on audit_event (cluster, at desc);
    create index audit_event_request_idx on audit_event (request_id);
    """)

    op.execute("""
    --
    -- Columns are listed one by one, including on tables where that is
    -- currently every column. A grant written as the whole table silently
    -- widens itself the next time somebody adds one.
    --
    grant select (id, username, username_normalised, password_hash, role, disabled)
        on app_user to app_web;

    grant select (token_hash, user_id, created_at, last_seen_at, expires_at, revoked_at)
        on app_session to app_web;
    --
    -- created_at and last_seen_at come from the column defaults, so the web
    -- role cannot backdate a session it just created.
    --
    grant insert (token_hash, user_id, expires_at) on app_session to app_web;
    grant update (last_seen_at, revoked_at) on app_session to app_web;

    grant insert (actor, action, cluster, request_id, detail) on audit_event
        to app_web, app_worker;
    grant select (id, at, actor, action, cluster, request_id, detail) on audit_event
        to app_web;
    """)


def downgrade() -> None:
    op.execute("""
    drop table if exists audit_event;
    drop table if exists app_session;
    drop table if exists app_user;
    """)
