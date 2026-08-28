"""Login attempts, so a guess costs something.

The phase gate asks for a rate limit per normalised username and client IP.
This is the table it counts.

It is **append-only by grant**, exactly like the audit trail, and that is the
whole design. A counter the web role could reset would be a lock whose key is
kept behind the door: a process that had been broken into would clear its own
failures and guess for as long as it liked. Here the web role can add an attempt
and read attempts, and cannot update or delete one - so a lockout survives the
process that is being locked out.

What it cannot do is defend against a compromised web process that stops asking
the question. Nothing at this layer can; the throttle raises the cost of
guessing a password from outside, and the privilege separation is what bounds
what an intrusion reaches. Two different jobs.

Retention is a deliberate root action rather than something a running service
can do, for the same reason the rows are immutable.

Revision ID: 0003
Revises: 0002
"""

from __future__ import annotations

from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    create table login_attempt (
        id                  bigint generated always as identity primary key,
        at                  timestamptz not null default statement_timestamp(),
        --
        -- The normalised form is stored, not the typed one. The lookup that
        -- finds the account and the count that throttles it must key on the
        -- same string, and "both sides lowercase it the same way" is a promise
        -- one side eventually breaks.
        --
        username_normalised text not null,
        --
        -- inet rather than text: an address that arrives in a shape PostgreSQL
        -- will not accept is a bug in whatever parsed the forwarded header, and
        -- it should fail here rather than quietly become its own bucket.
        --
        client_ip           inet not null,
        succeeded           boolean not null,

        constraint login_attempt_username_shape
            check (length(username_normalised) between 1 and 64)
    );

    --
    -- The index the throttle query uses, in the order it uses it: the pair
    -- first, newest attempts last, so a lookup reads a short range rather than
    -- the whole history of one busy account.
    --
    create index login_attempt_pair_idx
        on login_attempt (username_normalised, client_ip, at desc);
    create index login_attempt_at_idx on login_attempt (at desc);
    """)

    op.execute("""
    --
    -- Insert and select. No update, no delete: the append-only property is the
    -- point, and a grant is the only place it cannot be forgotten.
    --
    -- `at` is not insertable, so an attempt cannot be recorded as older than it
    -- is - which would otherwise slide it out of the throttle window.
    --
    grant insert (username_normalised, client_ip, succeeded) on login_attempt to app_web;
    grant select (id, at, username_normalised, client_ip, succeeded) on login_attempt to app_web;
    """)


def downgrade() -> None:
    op.execute("drop table if exists login_attempt;")
