"""What the WAF engine found, on the traffic record, and its switch (Fas 21, B231, B233).

`waf_rules` holds the CRS rules the engine matched, as it reports them in
`txn.coraza.rule_ids`: six-digit IDs, comma-separated, attack rules only.
`waf_score` is the request's inbound anomaly score. Both are what the engine
said and nothing more - the matched value, the attacker's own text, is not
kept (B233). The rule's description is looked up from the installed CRS when
a page shows it.

Empty and zero rather than null, as `rule` (0050): a collector that knows
nothing of the fields writes "nothing found", and a constant default rewrites
no partition. Whether a request met a rule at all is still `rule`
(`crs:log`/`crs:deny`), which the WAF page's partial index already covers.

`waf_engine` is the fifth switch: whether the interface offers the engine on
an object. Off to begin with. Unlike `advanced_config`, the web refuses to
turn it off while an object uses the engine (B231) - that is the web's rule,
not this table's.

Revision ID: 0051
Revises: 0050
"""

from __future__ import annotations

from alembic import op

revision = "0051"
down_revision = "0050"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    alter table traffic_log
        add column waf_rules text not null default '',
        add column waf_score integer not null default 0,
        add constraint traffic_log_waf_rules_form
            check (char_length(waf_rules) <= 1024 and waf_rules ~ '^([0-9]{6}(,[0-9]{6})*)?$'),
        add constraint traffic_log_waf_score_range check (waf_score between 0 and 100000);

    -- The roles are granted column by column (0030): a new column is
    -- invisible to both until it is named.
    grant insert (waf_rules, waf_score) on traffic_log to app_collector;
    grant select (waf_rules, waf_score) on traffic_log to app_web;

    alter table feature_switch
        drop constraint feature_switch_name,
        add constraint feature_switch_name
            check (name in ('cert_receivers', 'node_backups', 'cluster_colours',
                            'advanced_config', 'waf_engine'));

    insert into feature_switch (name, enabled) values ('waf_engine', false);
    """)


def downgrade() -> None:
    op.execute("""
    delete from feature_switch where name = 'waf_engine';

    alter table feature_switch
        drop constraint feature_switch_name,
        add constraint feature_switch_name
            check (name in ('cert_receivers', 'node_backups', 'cluster_colours',
                            'advanced_config'));

    alter table traffic_log
        drop constraint traffic_log_waf_score_range,
        drop constraint traffic_log_waf_rules_form,
        drop column waf_score,
        drop column waf_rules;
    """)
