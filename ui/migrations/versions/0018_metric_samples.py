"""Store what each listener and each pool member counted, as measured.

Revision ID: 0018
Revises: 0017
"""

from __future__ import annotations

from alembic import op

revision = "0018"
down_revision = "0017"
branch_labels = None
depends_on = None

#
# HAProxy's own `show stat` column names, the same list the node script reads
# and for the same reason: `stot` and `hrsp_5xx` can be looked up in HAProxy's
# documentation, `sessions_total` cannot. One list for both tables even though
# a listener has no `econ` and a member no `req_tot` on most rows - HAProxy
# decides which apply, a column that stays null costs nothing, and a column
# that turns out to be filled later would otherwise cost a migration.
#
# Every one is nullable, and that is load-bearing. Null means the column does
# not apply to this row or the node did not report it; zero means the thing was
# counted and came out zero. A listener that received nothing and a listener
# nobody asked must not arrive as the same number.
#
COUNTERS = (
    "scur",
    "stot",
    "bin",
    "bout",
    "req_tot",
    "qcur",
    "ereq",
    "econ",
    "eresp",
    "dreq",
    "dresp",
    "wretr",
    "wredis",
    "hrsp_2xx",
    "hrsp_3xx",
    "hrsp_4xx",
    "hrsp_5xx",
)

_COLUMNS = "".join(f"        {name} bigint,\n" for name in COUNTERS)
_GRANTABLE = ", ".join(COUNTERS)


def upgrade() -> None:
    #
    # Two tables rather than one, because the two answers have different scope
    # and B94 is about exactly that. A listener's counters are a fact about the
    # node - every node has listeners, and a standby's zero is a real zero. A
    # pool member's verdict is a fact about the VIP owner: the generated
    # backend carries `source <the VIP's address>`, only the keepalived master
    # holds that address, and the standby's health check is answered to
    # somebody else. Its `DOWN` is not a measurement, so it is not stored as
    # one.
    #
    # `owns_vip` is carried on the listener sample rather than looked up later.
    # Ownership moves on failover, and a row that recorded who held the address
    # at the time it was taken stays true; a join against today's owner would
    # rewrite history every time keepalived moves.
    #
    # Counters are stored cumulative, exactly as the node reported them, with
    # the runtime's `uptime_sec` beside them. Deltas and reload detection are
    # derived from that on read - a reload resets the counters and the uptime
    # together, so the pair carries what a difference alone cannot. Storing a
    # delta computed at write would mean storing something the node never said.
    #
    op.execute(f"""
    create table metric_listener (
        cluster      text not null,
        node         text not null,
        frontend     text not null,
        observed_at  timestamptz not null default statement_timestamp(),
        owns_vip     boolean,
        uptime_sec   bigint,
        status       text,
{_COLUMNS}
        constraint metric_listener_cluster_shape
            check (cluster ~ '^[a-z0-9][a-z0-9_-]{{0,31}}$'),

        primary key (cluster, node, frontend, observed_at)
    ) partition by range (observed_at);

    create table metric_pool_member (
        cluster      text not null,
        node         text not null,
        backend      text not null,
        member       text not null,
        observed_at  timestamptz not null default statement_timestamp(),
        uptime_sec   bigint,
        status       text,
        check_status text,
        check_code   text,
{_COLUMNS}
        constraint metric_pool_member_cluster_shape
            check (cluster ~ '^[a-z0-9][a-z0-9_-]{{0,31}}$'),

        primary key (cluster, node, backend, member, observed_at)
    ) partition by range (observed_at);
    """)

    #
    # No default partition, deliberately. A default would absorb a row whose
    # day was never created and hide the fact that partition maintenance had
    # stopped; it also blocks adding the partition that row belonged in. An
    # insert with nowhere to go fails loudly instead, which is why the horizon
    # is measured in months - see B93.
    #
    # The table name is checked against the two that exist rather than quoted
    # and trusted. Only root reaches this, so it is not a boundary against an
    # attacker; it is a boundary against a typo creating `metric_lisener_...`
    # that nothing would ever write to and nobody would notice.
    #
    op.execute("""
    create function metric_partition(table_name text, day date)
        returns text language plpgsql as $$
    declare
        partition text;
    begin
        if table_name not in ('metric_listener', 'metric_pool_member') then
            raise exception 'not a metric table: %', table_name;
        end if;

        partition := format('%s_%s', table_name, to_char(day, 'YYYYMMDD'));

        execute format(
            'create table if not exists %I partition of %I for values from (%L) to (%L)',
            partition, table_name, day, day + 1
        );
        return partition;
    end;
    $$;
    """)

    #
    # The poller writes and the web role reads, as with every cache. Neither
    # `observed_at` nor the primary key's own defaults are in the write grant:
    # the timestamp comes from `statement_timestamp()`, so every row of one
    # poll shares it and none can be backdated into looking fresh.
    #
    # Nobody is granted `delete`. Removing rows is the retention command's
    # work, as the migration role, for the same reason it already prunes the
    # job table: an application process must not be able to remove the record
    # of what it did.
    #
    op.execute(f"""
    grant insert (cluster, node, frontend, owns_vip, uptime_sec, status, {_GRANTABLE})
        on metric_listener to app_poller;
    grant select (cluster, node, frontend, observed_at, owns_vip, uptime_sec, status, {_GRANTABLE})
        on metric_listener to app_poller, app_web;

    grant insert (cluster, node, backend, member, uptime_sec, status,
                  check_status, check_code, {_GRANTABLE})
        on metric_pool_member to app_poller;
    grant select (cluster, node, backend, member, observed_at, uptime_sec, status,
                  check_status, check_code, {_GRANTABLE})
        on metric_pool_member to app_poller, app_web;
    """)


def downgrade() -> None:
    op.execute("""
    drop table if exists metric_listener;
    drop table if exists metric_pool_member;
    drop function if exists metric_partition(text, date);
    """)
