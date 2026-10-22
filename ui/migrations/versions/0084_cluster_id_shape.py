"""A cluster column holds the engine's cluster ID (2026-10-22).

Every table's cluster CHECK said `^[a-z0-9][a-z0-9_-]{0,31}$`, the UI's own
pattern, while the engine accepts `^[a-z][a-z0-9-]{0,62}$` (`haprion.config`,
`common.schema.json`). A cluster the engine created with an ID of 33 to 63
characters could not be cached, queued or audited; the UI's config refused it
too. The UI now imports the engine's pattern, and each CHECK is replaced with
it. Nothing stored is lost: every ID came from the engine, which never made one
that starts with a digit or holds an underscore.

The partitioned tables (`traffic_log`, `waf_match` and the metric tables)
take the constraint on the parent, which carries it to every partition, and
a day's new partition is made with `partition of`, which inherits it.

A new CHECK reads every row it covers, under the table's lock. Measured
2026-10-22 on fabricated rows in a disposable cluster: the whole upgrade over
5 million `traffic_log` rows in 4.9 s, about a second a million - some 15 s for
a week of 2 million a day, the heaviest load D1 measured.

Revision ID: 0084
Revises: 0083
"""

from __future__ import annotations

from alembic import op

revision = "0084"
down_revision = "0083"
branch_labels = None
depends_on = None

ROLLBACK_SAFE = True
ROLLBACK_SAFE_BECAUSE = (
    "accepts every cluster ID the engine makes, which is every one a UI from before can write; "
    "an older UI refuses the longer ones in its own config before it reaches the database"
)

ENGINE = "^[a-z][a-z0-9-]{0,62}$"
BEFORE = "^[a-z0-9][a-z0-9_-]{0,31}$"
#
# (table, whether the column may be empty), each with `<table>_cluster_shape`.
#
TABLES = (
    ("audit_event", True),
    ("job", True),
    ("cluster_status", False),
    ("cluster_inventory", False),
    ("cluster_history", False),
    ("cluster_backups", False),
    ("cluster_certificates", False),
    ("cluster_network", False),
    ("cluster_objects", False),
    ("cluster_settings", False),
    ("cluster_change", False),
    ("cluster_pass", False),
    ("proxy_draft", False),
    ("version_diff", False),
    ("search_entry", False),
    ("metric_frontend", False),
    ("metric_backend_member", False),
    ("metric_backend_hour", False),
    ("metric_backend_alias", False),
    ("traffic_log", False),
    ("waf_match", False),
)


def _replace(pattern: str) -> None:
    for table, nullable in TABLES:
        shape = f"cluster ~ '{pattern}'"
        if nullable:
            shape = f"cluster is null or {shape}"
        op.execute(
            f"alter table {table} drop constraint {table}_cluster_shape, "
            f"add constraint {table}_cluster_shape check ({shape})"
        )


def upgrade() -> None:
    _replace(ENGINE)


def downgrade() -> None:
    _replace(BEFORE)
