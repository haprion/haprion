"""Feature switches: two capabilities an installation may turn off (Fas 13 part 3, B193).

Two rows, both on to begin with, and never more than the check allows:

* `cert_receivers` - certificate publication to receivers outside the
  clusters. Off hides it from the interface; receivers already registered go
  on getting renewed certificates.
* `node_backups` - node backups and restore. Off also stops every cluster's
  backup timer, through the schedule job the page already queues, and keeps
  the schedules it stopped in `remembered` so that on starts exactly those
  again. Archives are never touched.

The web role may read the rows and flip them; it cannot add or remove one,
rename one, or set `updated_at`, which a trigger sets. Nobody else reads them:
the switches live in the interface, and the worker only runs the jobs the web
queues.

Revision ID: 0040
Revises: 0039
"""

from __future__ import annotations

from alembic import op

revision = "0040"
down_revision = "0039"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    create table feature_switch (
        name        text primary key,
        enabled     boolean not null default true,
        remembered  jsonb not null default '{}'::jsonb,
        updated_at  timestamptz not null default statement_timestamp(),
        updated_by  text,

        constraint feature_switch_name check (name in ('cert_receivers', 'node_backups')),
        constraint feature_switch_remembered_object check (jsonb_typeof(remembered) = 'object'),
        constraint feature_switch_updated_by_shape
            check (updated_by is null or length(updated_by) between 1 and 64)
    );

    insert into feature_switch (name) values ('cert_receivers'), ('node_backups');

    create function feature_switch_touch() returns trigger
        language plpgsql as $$
    begin
        new.updated_at := statement_timestamp();
        return new;
    end;
    $$;

    create trigger feature_switch_touch
        before update on feature_switch
        for each row execute function feature_switch_touch();
    """)

    op.execute("""
    grant select (name, enabled, remembered, updated_at, updated_by) on feature_switch to app_web;
    grant update (enabled, remembered, updated_by) on feature_switch to app_web;
    """)


def downgrade() -> None:
    # The switches go, and with them what they remembered. A backup timer
    # a switch stopped stays stopped: turn it on per cluster with Enabled.
    op.execute("""
    drop table if exists feature_switch;
    drop function if exists feature_switch_touch();
    """)
