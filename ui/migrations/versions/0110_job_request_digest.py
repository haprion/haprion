"""A job remembers the request that queued it, not only the payload it built (B416, review 26-11-01).

An `Idempotency-Key` names a call. The API builds most payloads from the state
at the time of the call - the saved changes, the version head, the registry -
so after the job has run, the same call builds another payload and the
payload's hash no longer says "this is the retry". The digest of the request
itself (caller, method, route, path parameters, body) is stored beside the key:
the same key with the same digest is the job already queued, whatever the state
has become since; the same key with another digest is a key used for another
change.

Null for every job the pages and the engine queue, and for every job from
before: they keep the payload comparison. The web may write and read the column
and nothing else may change it.

Revision ID: 0110
Revises: 0109
"""

from __future__ import annotations

from alembic import op

revision = "0110"
down_revision = "0109"
branch_labels = None
depends_on = None

ROLLBACK_SAFE = True
ROLLBACK_SAFE_BECAUSE = "a nullable column that code from before neither names nor reads"


def upgrade() -> None:
    op.execute("""
    alter table job add column request_digest bytea;
    alter table job add constraint job_request_digest_sha256
        check (request_digest is null or octet_length(request_digest) = 32);

    grant select (request_digest), insert (request_digest) on job to app_web;
    """)
