"""The WAF page's findings counted as the matches arrive, not when the page opens.

The page groups a week of `waf_match` per cluster, object, rule and field, with
three distinct counts in each group. Measured 26-10-04 in production: 220 ms of
the page's 240, for 96 091 rows that one load test had written - and an attack
writes exactly as many, on the day the page is wanted.

Two small tables hold the same answer in advance, one row per rule and field
and hour and path, and one per rule and field and hour and client. Every
figure the page shows stays exact:

- requests: a request has one path and one hour, and the engine logs a rule
  once per request (no repeat among the 96 091 measured rows), so the counts
  add up across hours and imports;
- clients and paths: still counted distinct, over these rows;
- the matched value: the newest, kept beside the time it was seen.

A statement trigger keeps them current. Its transition table holds the rows
an import actually added - a repeat that `waf_match_ignore_duplicate` turned
away is not in it - so a collector reading again from its checkpoint counts
nothing twice (proven on PostgreSQL 18.6 before this was written). The
collector is not changed and needs no grant: the function runs as its owner.

The tables are not partitioned on purpose. A trigger that could meet a day
without a partition could fail an import the collector makes today; these
cannot. The retention command deletes hours past the traffic window.

Revision ID: 0054
Revises: 0053
"""

from __future__ import annotations

from alembic import op

revision = "0054"
down_revision = "0053"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    create table waf_finding_path (
        cluster    text not null,
        object     text not null,
        rule_id    integer not null,
        field      text not null,
        hour       timestamptz not null,
        path       text not null,
        requests   integer not null,
        last_seen  timestamptz not null,
        matched    text not null,
        primary key (cluster, object, rule_id, field, hour, path)
    );

    create table waf_finding_client (
        cluster    text not null,
        object     text not null,
        rule_id    integer not null,
        field      text not null,
        hour       timestamptz not null,
        client     text not null,
        primary key (cluster, object, rule_id, field, hour, client)
    );

    -- The page asks for an hour onward; retention removes what is before one.
    create index waf_finding_path_hour on waf_finding_path (hour);
    create index waf_finding_client_hour on waf_finding_client (hour);

    create function waf_finding_add()
        returns trigger
        language plpgsql
        security definer
        set search_path = pg_catalog, public
    as $$
    begin
        insert into waf_finding_path as kept
               (cluster, object, rule_id, field, hour, path, requests, last_seen, matched)
        select cluster, object, rule_id, field, date_trunc('hour', occurred_at, 'UTC'), path,
               count(distinct request_id), max(occurred_at),
               (array_agg(matched order by occurred_at desc))[1]
          from added
         group by 1, 2, 3, 4, 5, 6
        on conflict (cluster, object, rule_id, field, hour, path) do update
           set requests = kept.requests + excluded.requests,
               matched = case when excluded.last_seen >= kept.last_seen
                              then excluded.matched else kept.matched end,
               last_seen = greatest(kept.last_seen, excluded.last_seen);

        insert into waf_finding_client (cluster, object, rule_id, field, hour, client)
        select distinct cluster, object, rule_id, field,
               date_trunc('hour', occurred_at, 'UTC'), client
          from added
        on conflict do nothing;
        return null;
    end;
    $$;
    revoke all on function waf_finding_add() from public;

    create trigger waf_finding_add
        after insert on waf_match
        referencing new table as added
        for each statement execute function waf_finding_add();

    -- What is already there, counted once.
    insert into waf_finding_path
           (cluster, object, rule_id, field, hour, path, requests, last_seen, matched)
    select cluster, object, rule_id, field, date_trunc('hour', occurred_at, 'UTC'), path,
           count(distinct request_id), max(occurred_at),
           (array_agg(matched order by occurred_at desc))[1]
      from waf_match
     group by 1, 2, 3, 4, 5, 6;

    insert into waf_finding_client (cluster, object, rule_id, field, hour, client)
    select distinct cluster, object, rule_id, field, date_trunc('hour', occurred_at, 'UTC'), client
      from waf_match;

    grant select (
        cluster, object, rule_id, field, hour, path, requests, last_seen, matched
    ) on waf_finding_path to app_web;
    grant select (cluster, object, rule_id, field, hour, client)
        on waf_finding_client to app_web;
    """)


def downgrade() -> None:
    op.execute("""
    drop trigger if exists waf_finding_add on waf_match;
    drop function if exists waf_finding_add();
    drop table if exists waf_finding_client;
    drop table if exists waf_finding_path;
    """)
