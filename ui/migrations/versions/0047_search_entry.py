"""What the header's search finds, one row per value (B222, 2026-10-01).

The poller turns each reading - objects, network, certificates, node status,
the cluster list - into the values somebody might search for and replaces that
source's rows for that cluster in one transaction. The rows are derived and
rebuilt every pass, so nothing in them is the only copy of anything.

That is why this is the first table the poller may delete from, and the only
one: replacing a source's rows is a delete and an insert, and a removed object
or cluster that stayed in the search would be a result pointing at nothing.
The web reads, and nothing else writes.

`pg_trgm` indexes the values for substring search - a part of an address or a
hostname, which a full-text index splits into words and cannot find. Platform
step 2 installs it for the traffic log; `if not exists` here only matters for a
database made without that step, where the migration role may create it as the
database's owner because the extension is trusted. The downgrade leaves it: the
traffic log's indexes depend on it.

Revision ID: 0047
Revises: 0046
"""

from __future__ import annotations

from alembic import op

revision = "0047"
down_revision = "0046"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    create extension if not exists pg_trgm;

    create table search_entry (
        cluster     text not null,
        source      text not null,
        kind        text not null,
        title       text not null,
        label       text not null default '',
        value       text not null,
        href        text not null,
        admin_only  boolean not null default false,

        constraint search_entry_cluster_shape check (cluster ~ '^[a-z0-9][a-z0-9_-]{0,31}$'),
        constraint search_entry_source_allowed
            check (source in ('objects', 'network', 'cert_list', 'status', 'cluster_list')),
        constraint search_entry_kind_allowed
            check (kind in ('proxy', 'address', 'certificate', 'cluster')),
        constraint search_entry_title_size check (length(title) between 1 and 255),
        constraint search_entry_label_size check (length(label) <= 64),
        constraint search_entry_value_size check (length(value) between 1 and 512),
        -- A path inside this interface, never an address elsewhere.
        constraint search_entry_href_local check (href ~ '^/[^/]' or href = '/')
    );

    create index search_entry_value on search_entry using gin (lower(value) gin_trgm_ops);
    create index search_entry_reading on search_entry (cluster, source);

    grant insert (cluster, source, kind, title, label, value, href, admin_only)
       on search_entry to app_poller;
    grant select (cluster, source, kind, title, label, value, href, admin_only)
       on search_entry to app_poller, app_web;
    grant delete on search_entry to app_poller;
    """)


def downgrade() -> None:
    op.execute("""
    drop table if exists search_entry;
    """)
