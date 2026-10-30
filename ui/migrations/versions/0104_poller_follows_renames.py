"""The poller records the backend renames of a publish the web did not make (B411, 26-10-30).

`haprion-objects apply` publishes through the engine, which never touches the
interface's database, so only the poller sees that the configuration changed:
it compares the objects it read before with the ones it reads now and writes
down the renames, as the worker does for a web publish (B253). It is granted
what `record_backend_renames` does and nothing more: it reads the pairs, adds
one, changes where a pair points and closes a name given out again.

A UI from before never uses the grants, so it runs over this schema as before.

Revision ID: 0104
Revises: 0103
"""

from __future__ import annotations

from alembic import op

revision = "0104"
down_revision = "0103"
branch_labels = None
depends_on = None

ROLLBACK_SAFE = True
ROLLBACK_SAFE_BECAUSE = (
    "it only grants the poller columns of one table; a UI from before never touches them"
)


def upgrade() -> None:
    op.execute("""
    grant select (cluster, old_name, new_name, renamed_at, reused_at)
        on table metric_backend_alias to app_poller;
    grant insert (cluster, old_name, new_name) on table metric_backend_alias to app_poller;
    grant update (new_name, renamed_at, reused_at) on table metric_backend_alias to app_poller;
    """)
