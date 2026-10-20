"""Whether a newer release exists, as the poller last heard it from GitHub (B334, B342, 26-10-20).

`update_check` is the sixth switch, off on every installation including those
that have one already: it is the one thing the application fetches from the
internet while it runs, and that is somebody's decision.

One row at most, written by the poller and read by the web. `latest_tag` and
`latest_url` are the last answer GitHub gave and stay when a later ask fails,
so a header that said a release exists goes on saying it; `checked_at` is when
that answer came. `failing_since` is the first failure after it, cleared by the
next answer, and `attempted_at` the last ask of either kind - what spaces the
asks an hour apart while GitHub does not answer.

Revision ID: 0081
Revises: 0080
"""

from __future__ import annotations

from alembic import op

revision = "0081"
down_revision = "0080"
branch_labels = None
depends_on = None

ROLLBACK_SAFE = True
ROLLBACK_SAFE_BECAUSE = (
    "adds one switch row and one table; a UI from before reads only the switches it knows "
    "and never the table"
)


def upgrade() -> None:
    op.execute("""
    alter table feature_switch
        drop constraint feature_switch_name,
        add constraint feature_switch_name
            check (name in ('cert_receivers', 'node_backups', 'cluster_colours',
                            'advanced_config', 'waf_engine', 'update_check'));

    insert into feature_switch (name, enabled) values ('update_check', false);

    create table update_check (
        only_row       boolean primary key default true check (only_row),
        latest_tag     text check (latest_tag ~ '^v[0-9]{1,4}\\.[0-9]{1,4}\\.[0-9]{1,4}$'),
        --
        -- The release's own page on the project's repository, never another
        -- address: the header links to it.
        --
        latest_url     text check (
            latest_url ~ '^https://github\\.com/haprion/haprion/releases/tag/v[0-9.]{5,14}$'
        ),
        checked_at     timestamptz,
        attempted_at   timestamptz not null,
        failing_since  timestamptz,
        error          text check (char_length(error) <= 300),
        constraint update_check_answer_whole
            check ((latest_tag is null) = (latest_url is null)
                   and (latest_tag is null) = (checked_at is null))
    );

    --
    -- The poller asks whether the switch is on, and keeps the row. The web
    -- reads it; nothing else touches it.
    --
    grant select (name, enabled) on feature_switch to app_poller;
    grant select (only_row, latest_tag, latest_url, checked_at, attempted_at, failing_since, error)
        on update_check to app_poller;
    grant insert (latest_tag, latest_url, checked_at, attempted_at, failing_since, error)
        on update_check to app_poller;
    grant update (latest_tag, latest_url, checked_at, attempted_at, failing_since, error)
        on update_check to app_poller;
    grant select (latest_tag, latest_url, checked_at, attempted_at, failing_since)
        on update_check to app_web;
    """)


def downgrade() -> None:
    op.execute("""
    drop table if exists update_check;
    revoke select (name, enabled) on feature_switch from app_poller;
    delete from feature_switch where name = 'update_check';

    alter table feature_switch
        drop constraint feature_switch_name,
        add constraint feature_switch_name
            check (name in ('cert_receivers', 'node_backups', 'cluster_colours',
                            'advanced_config', 'waf_engine'));
    """)
