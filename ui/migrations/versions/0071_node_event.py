"""What the nodes did on their own: *Events → Nodes* (26-10-12).

`node_event` is one row per change the poller saw between two status readings
- a server down or back up, the VIP moving, a node that stopped answering or
answers again - kept 90 days by `haprion-retention`. `node_event_state` is
the last state per cluster, kind and subject that a reading is compared with:
a row per server, node and VIP, replaced on every reading, so a comparison
never reads the events back.

The poller writes both and reads the state; the web reads the events.

Revision ID: 0071
Revises: 0070
"""

from __future__ import annotations

from alembic import op

revision = "0071"
down_revision = "0070"
branch_labels = None
depends_on = None

ROLLBACK_SAFE = True
ROLLBACK_SAFE_BECAUSE = "adds two tables; a UI from before neither reads nor writes them"


def upgrade() -> None:
    op.execute("""
    create table node_event (
        id       bigint generated always as identity primary key,
        at       timestamptz not null default transaction_timestamp(),
        cluster  text not null,
        node     text not null,
        event    text not null check (
                     event in ('server_down', 'server_up', 'vip_moved', 'node_silent', 'node_back')
                 ),
        subject  text not null,
        detail   jsonb not null default '{}'::jsonb
    );
    create index node_event_at on node_event (at desc, id desc);
    create index node_event_cluster_at on node_event (cluster, at desc);

    create table node_event_state (
        cluster  text not null,
        kind     text not null check (kind in ('server', 'vip', 'node')),
        subject  text not null,
        value    text not null,
        primary key (cluster, kind, subject)
    );

    grant select (cluster, kind, subject, value) on node_event_state to app_poller;
    grant insert (cluster, kind, subject, value) on node_event_state to app_poller;
    grant update (value) on node_event_state to app_poller;
    grant delete on node_event_state to app_poller;
    grant insert (at, cluster, node, event, subject, detail) on node_event to app_poller;
    grant select (id, at, cluster, node, event, subject, detail) on node_event to app_web;
    """)


def downgrade() -> None:
    op.execute("drop table if exists node_event_state; drop table if exists node_event;")
