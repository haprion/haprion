"""Make one poll one instant, rather than one instant per row.

Revision ID: 0019
Revises: 0018
"""

from __future__ import annotations

from alembic import op

revision = "0019"
down_revision = "0018"
branch_labels = None
depends_on = None

TABLES = ("metric_listener", "metric_pool_member")


def upgrade() -> None:
    #
    # Measured on the first release that wrote samples: two rows of one poll
    # arrived at ...795255 and ...795310. `statement_timestamp()` advances
    # between statements, and `executemany` sends one statement per row - so a
    # poll's rows were spread across microseconds rather than sharing a moment.
    #
    # Nothing was wrong with the data. It matters because of what a sample is:
    # the rows of one poll are one reading of one cluster, and a later
    # aggregation that groups them by time should not have to carry a tolerance
    # to put them back together. `transaction_timestamp()` is stable for the
    # whole transaction, and the sample write is one transaction by design.
    #
    # The caches keep `statement_timestamp()` deliberately. There the question
    # is "when was this row written", each write is its own statement, and a
    # value that stayed fixed across a longer transaction would report a
    # freshness the reading does not have.
    #
    for table in TABLES:
        op.execute(f"""
        alter table {table}
            alter column observed_at set default transaction_timestamp();
        """)


def downgrade() -> None:
    for table in TABLES:
        op.execute(f"""
        alter table {table}
            alter column observed_at set default statement_timestamp();
        """)
