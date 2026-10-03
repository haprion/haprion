"""What the WAF engine matched, rule by rule, and the request it belongs to (Fas 21, B234).

`waf_match` holds one row per rule the engine matched on a request, read from
the engine's own log on each node (its journal namespace): which object, which
rule, which part of the request (`field`, as the rule set names it -
`ARGS:q`, `REQUEST_HEADERS:User-Agent` - or empty where the rule names none),
and the matched value itself. B234 reverses 0051's choice not to keep the
value: the WAF page is where a false alarm is told from an attack, and the
value is what tells them apart. It is the requester's own text, so it is
bounded here and shown escaped.

`request_id` is the engine's transaction ID. The engine hands the same ID back
to HAProxy as `txn.coraza.id`, which the traffic record carries as `waf_id` -
the join between a request and what was found in it, with no `unique-id` in
the configuration (measured 26-10-03).

Daily partitions and duplicate handling as `traffic_log` (0030): the collector
re-reads from a checkpoint, and `event_id` is what makes a repeat harmless.
The retention command keeps the horizon and drops whole days, with the traffic
log's window. Nothing writes the table yet.

Revision ID: 0052
Revises: 0051
"""

from __future__ import annotations

from alembic import op

revision = "0052"
down_revision = "0051"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    create table waf_match (
        event_id     bytea not null,
        cluster      text not null,
        node         text not null,
        occurred_at  timestamptz not null,
        request_id   text not null,
        object       text not null,
        rule_id      integer not null,
        field        text not null default '',
        matched      text not null default '',
        path         text not null default '',
        client       text not null default '',
        inserted_at  timestamptz not null default statement_timestamp(),

        constraint waf_match_cluster_shape
            check (cluster ~ '^[a-z0-9][a-z0-9_-]{0,31}$'),
        constraint waf_match_node_shape
            check (node ~ '^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$'),
        constraint waf_match_event_id_shape check (octet_length(event_id) = 32),
        constraint waf_match_request_id_shape check (request_id ~ '^[A-Za-z0-9_-]{1,64}$'),
        constraint waf_match_object_shape check (object ~ '^[a-z][a-z0-9_-]{0,39}$'),
        constraint waf_match_rule_id_range check (rule_id between 1 and 999999),
        constraint waf_match_field_form
            check (char_length(field) <= 256 and field !~ '[[:cntrl:]]'),
        constraint waf_match_matched_bound check (char_length(matched) <= 1024),
        constraint waf_match_path_bound check (char_length(path) <= 2048),
        constraint waf_match_client_bound check (char_length(client) <= 64),

        primary key (occurred_at, event_id)
    ) partition by range (occurred_at);

    create function waf_match_partition(day date)
        returns text language plpgsql as $$
    declare
        partition text := format('waf_match_%s', to_char(day, 'YYYYMMDD'));
    begin
        execute format(
            'create table if not exists %I partition of waf_match '
            'for values from (%L) to (%L)',
            partition, day, day + 1
        );
        -- The Requests view asks for one request's matches.
        execute format(
            'create index if not exists %I on %I (cluster, request_id)',
            partition || '_request', partition
        );
        return partition;
    end;
    $$;

    select waf_match_partition(day::date)
      from generate_series(current_date - 6, current_date + 7, interval '1 day') as day;

    create function waf_match_ignore_duplicate()
        returns trigger
        language plpgsql
        security definer
        set search_path = pg_catalog, public
    as $$
    begin
        if exists (
            select 1 from waf_match
             where occurred_at = new.occurred_at and event_id = new.event_id
        ) then
            return null;
        end if;
        return new;
    end;
    $$;

    create trigger waf_match_duplicate
        before insert on waf_match
        for each row execute function waf_match_ignore_duplicate();
    revoke all on function waf_match_ignore_duplicate() from public;

    grant insert (
        event_id, cluster, node, occurred_at, request_id, object, rule_id,
        field, matched, path, client
    ) on waf_match to app_collector;
    grant select (
        cluster, node, occurred_at, request_id, object, rule_id, field, matched,
        path, client
    ) on waf_match to app_web;

    alter table traffic_log
        add column waf_id text not null default '',
        add constraint traffic_log_waf_id_shape
            check (waf_id ~ '^([A-Za-z0-9_-]{1,64})?$');

    grant insert (waf_id) on traffic_log to app_collector;
    grant select (waf_id) on traffic_log to app_web;
    """)


def downgrade() -> None:
    op.execute("""
    alter table traffic_log
        drop constraint traffic_log_waf_id_shape,
        drop column waf_id;

    drop table if exists waf_match;
    drop function if exists waf_match_partition(date);
    drop function if exists waf_match_ignore_duplicate();
    """)
