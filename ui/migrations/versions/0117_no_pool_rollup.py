"""The hourly pool rollup and its boundary are taken away: nothing reads them (B451).

`haprion-retention` copied one reading per pool member and hour into
`metric_backend_hour` every night and kept it for a year, with
`metric_rollup_state` saying how far it had come. The interface never read it:
the metrics cards take their long windows from the hourly sums of stored
differences (`metric_backend_hour_delta`, 0055, kept 31 days) and their last
week from the raw samples. The rollup also held the raw pool samples back from
retention until it had gone past them. Taken away: the table and its monthly
partitions, the boundary table, and `metric_month_partition`, which only made
the rollup's partitions.

Haprion 0.99.13's web, poller and worker never touch these tables. The only
code of its that did is `haprion-retention` and `03-verify`, which the
haprion-ui package installs outside the release directory, and a rollback moves
only the release: they stay as the installed package wrote them, without the
rollup.

Revision ID: 0117
Revises: 0116
"""

from __future__ import annotations

from alembic import op

revision = "0117"
down_revision = "0116"
branch_labels = None
depends_on = None

ROLLBACK_SAFE = True
ROLLBACK_SAFE_BECAUSE = (
    "it takes away tables nothing in 0.99.13's web, poller or worker reads or writes; its "
    "retention and 03-verify, the only code that did, are installed with the package and "
    "stay as the package wrote them over a rollback"
)


def upgrade() -> None:
    op.execute("drop table metric_backend_hour")
    op.execute("drop table metric_rollup_state")
    op.execute("drop function metric_month_partition(text, date)")
