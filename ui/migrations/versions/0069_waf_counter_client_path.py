"""The path a counted client was let through on, for an exception's own figures (review 26-10-11).

An exception's counter is numbered by its place among the object's exceptions
on the same rule (B273), so removing one moves the next into its number - and
the page then showed the removed one's week under the one that stayed. The
page now counts only within what each exception covers: its field, and its
paths where it names any. The requests already carry the path
(`waf_finding_path`); the clients did not, so they could not be narrowed.

Only a counter's rows carry it (an ID below 900000): the findings count
clients per field and would only grow. What the counters already rolled up is
counted again from `waf_match`, which keeps the same window.

Revision ID: 0069
Revises: 0068
"""

from __future__ import annotations

from alembic import op

revision = "0069"
down_revision = "0068"
branch_labels = None
depends_on = None

ROLLBACK_SAFE = True
ROLLBACK_SAFE_BECAUSE = (
    "adds a column with a default to a rollup a UI from before reads by naming its columns; "
    "a counter's client counted on two paths is counted once by its distinct count"
)

ROLLUP_PATHS = """
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
"""

#
# A counter is any ID below the rule set's 900000 (B273).
#
CLIENTS_WITH_PATH = """
    insert into waf_finding_client (cluster, object, rule_id, field, hour, client, path)
    select distinct cluster, object, rule_id, field,
           date_trunc('hour', occurred_at, 'UTC'), client,
           case when rule_id < 900000 then path else '' end
      from added
    on conflict do nothing;
"""

CLIENTS_WITHOUT_PATH = """
    insert into waf_finding_client (cluster, object, rule_id, field, hour, client)
    select distinct cluster, object, rule_id, field,
           date_trunc('hour', occurred_at, 'UTC'), client
      from added
    on conflict do nothing;
"""


def _function(clients: str) -> str:
    return (
        "create or replace function waf_finding_add() returns trigger language plpgsql "
        "security definer set search_path = pg_catalog, public as $$ begin "
        + ROLLUP_PATHS
        + clients
        + " return null; end; $$; revoke all on function waf_finding_add() from public;"
    )


def upgrade() -> None:
    op.execute(
        """
        alter table waf_finding_client add column path text not null default '';
        alter table waf_finding_client drop constraint waf_finding_client_pkey;
        alter table waf_finding_client
            add primary key (cluster, object, rule_id, field, hour, client, path);
        """
    )
    op.execute(_function(CLIENTS_WITH_PATH))
    op.execute(
        """
        delete from waf_finding_client where rule_id < 900000;
        insert into waf_finding_client (cluster, object, rule_id, field, hour, client, path)
        select distinct cluster, object, rule_id, field, date_trunc('hour', occurred_at, 'UTC'),
               client, path
          from waf_match
         where rule_id < 900000
        on conflict do nothing;
        grant select (path) on waf_finding_client to app_web;
        """
    )


def downgrade() -> None:
    op.execute("revoke select (path) on waf_finding_client from app_web;")
    op.execute(_function(CLIENTS_WITHOUT_PATH))
    op.execute(
        """
        delete from waf_finding_client
         where (cluster, object, rule_id, field, hour, client, path) not in (
               select cluster, object, rule_id, field, hour, client, min(path)
                 from waf_finding_client
                group by cluster, object, rule_id, field, hour, client);
        alter table waf_finding_client drop constraint waf_finding_client_pkey;
        alter table waf_finding_client drop column path;
        alter table waf_finding_client
            add primary key (cluster, object, rule_id, field, hour, client);
        """
    )
