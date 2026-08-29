"""Bind a queued job to the request that asked for it.

Revision 0002 left this out on purpose and said why: the binding is Phase 6's,
and a column that hashes the payload cannot be a generated column because the
honest way to hash text depends on the database encoding. The requirement is in
hand now, so the derivation arrives with it.

Two columns, with different owners:

`payload_hash` is derived by the database and never received. It answers "is
this the same request as the one already queued?" without trusting the caller to
say so, which is the same reason `state` and `request_id` are defaults rather
than parameters.

`idempotency_key` is the one thing the caller does supply, because a retry is
only recognisable if the retrying side carries something with it. A browser
refresh, a double-click and a resubmitted form all carry the same key; a new
form carries a new one. The key names the *attempt*, so it cannot be used to
claim a `request_id`, which remains the database's own.

Revision ID: 0009
Revises: 0008
"""

from __future__ import annotations

from alembic import op

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    --
    -- Nullable, deliberately. The schema has to stay compatible with the
    -- application version before this one, and that version inserts three
    -- columns and knows nothing about a key. A not-null tightening belongs to a
    -- later migration, once no running release can insert without one - the
    -- expand half of expand/contract, not both halves in one release.
    --
    alter table job add column idempotency_key uuid;

    --
    -- Derived, so not-null costs nothing: the trigger fills it for every insert,
    -- including one from a release that has never heard of this column.
    --
    alter table job add column payload_hash bytea;

    --
    -- jsonb is already a normalised form - key order and whitespace are decided
    -- by the type, not by the sender - so its text rendering is the canonical
    -- form to hash. Written as a trigger rather than a generated column because
    -- convert_to is stable rather than immutable, which PostgreSQL refuses in a
    -- generated column and is right to refuse.
    --
    create function job_payload_hash() returns trigger
        language plpgsql as $$
    begin
        new.payload_hash := sha256(convert_to(new.payload::text, 'UTF8'));
        return new;
    end;
    $$;

    create trigger job_payload_hash
        before insert on job
        for each row execute function job_payload_hash();

    update job set payload_hash = sha256(convert_to(payload::text, 'UTF8'))
        where payload_hash is null;
    alter table job alter column payload_hash set not null;

    --
    -- One row per key. This is what turns a second submission into a conflict
    -- the database refuses rather than a second operation, and it is a unique
    -- index rather than a check in the application for the same reason the
    -- one-active-per-cluster index is: two web processes ask the question at the
    -- same moment, and only the database can answer it once.
    --
    -- Rows without a key never collide with each other, which is what keeps the
    -- nullable column above honest.
    --
    create unique index job_idempotency_key on job (idempotency_key)
        where idempotency_key is not null;
    """)

    op.execute("""
    --
    -- The caller supplies the key and nothing else new. It still cannot set the
    -- hash: that column is not in any grant, so a compromised web process can
    -- name an attempt but cannot describe what the attempt contains.
    --
    grant insert (idempotency_key) on job to app_web;
    grant select (idempotency_key, payload_hash) on job to app_web, app_worker;
    """)


def downgrade() -> None:
    op.execute("""
    drop trigger if exists job_payload_hash on job;
    drop function if exists job_payload_hash();
    drop index if exists job_idempotency_key;
    alter table job drop column if exists payload_hash;
    alter table job drop column if exists idempotency_key;
    """)
