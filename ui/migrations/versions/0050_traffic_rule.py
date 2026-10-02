"""Which access rule a request met, on its traffic record (Fas 21, B227).

`rule` holds the name of the rule and what it did - `block-admin:log` or
`block-admin:deny` - and is empty when none matched, which is what HAProxy
writes for an unset variable (measured in 3.4.6, 2026-10-02). The record stays
in the traffic log either way: a refused request is still a request, and a
log that left it out would misstate the traffic a site received.

Empty rather than null so that the collector writes what the record says
without a case of its own, and so that an older collector, which knows nothing
of the field, fills the column with the same "no rule" its default gives.
Adding a column with a constant default rewrites no partition.

The WAF page asks for the few records with a rule out of a day of many, so
each day's partition gets a partial index on them; the partition function
creates it for the days to come, and this migration for the days already
there.

Revision ID: 0050
Revises: 0049
"""

from __future__ import annotations

from alembic import op

revision = "0050"
down_revision = "0049"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    alter table traffic_log
        add column rule text not null default '',
        add constraint traffic_log_rule_length check (char_length(rule) <= 160);

    -- The roles are granted column by column (0030): a new column is
    -- invisible to both until it is named.
    grant insert (rule) on traffic_log to app_collector;
    grant select (rule) on traffic_log to app_web;

    create or replace function traffic_log_partition(day date)
        returns text language plpgsql as $$
    declare
        partition text := format('traffic_log_%s', to_char(day, 'YYYYMMDD'));
    begin
        execute format(
            'create table if not exists %I partition of traffic_log '
            'for values from (%L) to (%L)',
            partition, day, day + 1
        );
        execute format(
            'create index if not exists %I on %I using gin '
            '((host || '' '' || path || '' '' || backend) gin_trgm_ops)',
            partition || '_search', partition
        );
        execute format(
            'create index if not exists %I on %I (occurred_at) where rule <> ''''',
            partition || '_rule', partition
        );
        return partition;
    end;
    $$;

    do $$
    declare
        name text;
    begin
        for name in
            select child.relname
              from pg_inherits
              join pg_class child on child.oid = pg_inherits.inhrelid
              join pg_class parent on parent.oid = pg_inherits.inhparent
             where parent.relname = 'traffic_log'
        loop
            execute format(
                'create index if not exists %I on %I (occurred_at) where rule <> ''''',
                name || '_rule', name
            );
        end loop;
    end;
    $$;
    """)


def downgrade() -> None:
    op.execute("""
    create or replace function traffic_log_partition(day date)
        returns text language plpgsql as $$
    declare
        partition text := format('traffic_log_%s', to_char(day, 'YYYYMMDD'));
    begin
        execute format(
            'create table if not exists %I partition of traffic_log '
            'for values from (%L) to (%L)',
            partition, day, day + 1
        );
        execute format(
            'create index if not exists %I on %I using gin '
            '((host || '' '' || path || '' '' || backend) gin_trgm_ops)',
            partition || '_search', partition
        );
        return partition;
    end;
    $$;

    alter table traffic_log
        drop constraint traffic_log_rule_length,
        drop column rule;
    """)
