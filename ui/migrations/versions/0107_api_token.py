"""API tokens: who may call `/api/v1/`, at which level, until when (B416).

A token is a random secret shown once; the table keeps its SHA-256, as
`app_session` does, so a dump of it is not a list of keys. What the web may
not do is held here rather than by the code that would otherwise have to
remember it:

* **The expiry is fixed when the token is made.** The web inserts it and has
  no grant to move it; the row's own date is the database's, so a token
  cannot be backdated into a longer life, and none lives past two years.
* **A revocation is final.** The web may set `revoked_at`, and a trigger
  refuses every later change to it or to who revoked.
* **A token in use is never deleted.** Only one revoked or expired may go;
  the audit record keeps what it did.

`clusters` empty is every cluster; `objects` names the objects a `block`
token may block on - at least one, as External blocking does - and is empty
for the other levels; `sources` empty is any address.

A web from before has no route that reads this table.

Revision ID: 0107
Revises: 0106
"""

from __future__ import annotations

from alembic import op

revision = "0107"
down_revision = "0106"
branch_labels = None
depends_on = None

ROLLBACK_SAFE = True
ROLLBACK_SAFE_BECAUSE = "a new table that code from before never reads"


def upgrade() -> None:
    op.execute("""
    create table api_token (
        id bigint generated always as identity primary key,
        name text not null,
        level text not null,
        clusters text[] not null default '{}',
        objects text[] not null default '{}',
        sources cidr[] not null default '{}',
        token_hash bytea not null,
        prefix text not null,
        created_at timestamptz not null default statement_timestamp(),
        created_by text not null,
        expires_at timestamptz not null,
        revoked_at timestamptz,
        revoked_by text,
        last_used_at timestamptz,
        last_used_from inet,
        constraint api_token_name_unique unique (name),
        constraint api_token_hash_unique unique (token_hash),
        constraint api_token_name_shape check (name ~ '^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$'),
        constraint api_token_level_allowed check (level in ('read', 'block', 'write')),
        constraint api_token_objects_only_to_block
            check (level = 'block' or cardinality(objects) = 0),
        constraint api_token_block_names_objects
            check (level <> 'block' or cardinality(objects) > 0),
        constraint api_token_hash_sha256 check (octet_length(token_hash) = 32),
        constraint api_token_prefix_shape check (prefix ~ '^hap_[A-Za-z0-9_-]{8}$'),
        constraint api_token_created_by_shape
            check (length(created_by) between 1 and 128),
        constraint api_token_lifetime
            check (expires_at > created_at and expires_at <= created_at + interval '2 years'),
        constraint api_token_revoked_by_whom
            check ((revoked_at is null) = (revoked_by is null)),
        constraint api_token_revoked_by_shape
            check (revoked_by is null or length(revoked_by) between 1 and 128)
    );

    create function api_token_revocation_is_final() returns trigger
        language plpgsql
        as $$
        begin
            if old.revoked_at is not null
               and (new.revoked_at is distinct from old.revoked_at
                    or new.revoked_by is distinct from old.revoked_by) then
                raise exception 'a revoked API token stays revoked'
                    using errcode = 'check_violation';
            end if;
            return new;
        end;
        $$;
    create trigger api_token_revocation_is_final before update of revoked_at, revoked_by
        on api_token for each row execute function api_token_revocation_is_final();

    create function api_token_delete_only_ended() returns trigger
        language plpgsql
        as $$
        begin
            if old.revoked_at is null and old.expires_at > statement_timestamp() then
                raise exception 'an API token in use is revoked before it is removed'
                    using errcode = 'check_violation';
            end if;
            return old;
        end;
        $$;
    create trigger api_token_delete_only_ended before delete
        on api_token for each row execute function api_token_delete_only_ended();

    grant select (id, name, level, clusters, objects, sources, token_hash, prefix, created_at,
                  created_by, expires_at, revoked_at, revoked_by, last_used_at, last_used_from)
        on api_token to app_web;
    grant insert (name, level, clusters, objects, sources, token_hash, prefix, created_by,
                  expires_at)
        on api_token to app_web;
    grant update (revoked_at, revoked_by, last_used_at, last_used_from) on api_token to app_web;
    grant delete on api_token to app_web;
    """)
