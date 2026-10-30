"""An acknowledgement holds the severity and the label the row was given for (B406, 26-10-30).

A row of *Needs attention* that becomes worse - a certificate that was a
warning and has expired, a node that was short of counters and is now silent -
is shown again, and acknowledging one receiver of a forwarding node leaves the
node's other receivers shown. So what an acknowledgement names is more than
(kind, cluster, subject): `severity` is what the row was acknowledged as, and
`variant` the label a node row carried (empty for a row with none).

Both are part of the key. The rows already stored get the empty severity, which
no row of the list has, so they hold nothing: the list shows the row again and
the next read of it forgets the stale acknowledgement.

A UI from before inserts without the two columns and reads three, so it runs
over this schema as before; the web is granted the new columns as it has the
others, and nothing more.

Revision ID: 0103
Revises: 0102
"""

from __future__ import annotations

from alembic import op

revision = "0103"
down_revision = "0102"
branch_labels = None
depends_on = None

ROLLBACK_SAFE = True
ROLLBACK_SAFE_BECAUSE = (
    "it only adds two defaulted columns to the key: a UI from before inserts and deletes "
    "acknowledgements by its three columns, which the defaults complete"
)


def upgrade() -> None:
    op.execute("""
    alter table attention_ack add column severity text not null default '';
    alter table attention_ack add column variant text not null default '';
    alter table attention_ack add constraint attention_ack_severity_check
        check (length(severity) <= 16);
    alter table attention_ack add constraint attention_ack_variant_check
        check (length(variant) <= 128);
    alter table attention_ack drop constraint attention_ack_pkey;
    alter table attention_ack add constraint attention_ack_pkey
        primary key (kind, cluster, subject, severity, variant);
    grant select (severity, variant), insert (severity, variant) on table attention_ack to app_web;
    """)
