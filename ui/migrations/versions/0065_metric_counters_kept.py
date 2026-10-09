"""A reload that keeps HAProxy's counters is no longer read as a restart (N3, 2026-10-09).

With `shm-stats-file` HAProxy keeps frontend and server counters in a file
across a reload and finds each object again by its GUID. `Uptime_sec` starts
from nought on every reload all the same - measured on 3.4.6, 46 to 2 - and
0048's rule reads a falling uptime as "the process is new and its counters
started again", storing the whole counter as the difference. With the counters
kept, every deploy would then count again all the traffic since the node last
really restarted.

So each sample says whether its counters were kept, and the rule asks it:

* `counters_kept` - written by the poller from what the node reports
  (`runtime.shared_counters`: the running release names the file and the
  worker has it mapped). True for a frontend or a server on such a node; false
  for a pool's own row, which carries no GUID while HAProxy alternates
  backends between two slots (`guid.py`); null where nothing was reported -
  dnsdist, IPVS, a node or poller from before this.
* `restarted` - the uptime fell, and either the counters were not kept or one
  of them went down. The second half is a real stop and start: HAProxy
  releases the file when properly stopped, and the counters begin again even
  though the file is named. Null `counters_kept` is today's rule exactly.

Everything downstream reads `restarted` and `delta_*` as before, so the hourly
sums (0055) and the cards need nothing. Rows already stored are left as they
are: none was written with counters kept.

Both row functions are replaced whole, with the counters they cover today:
0048's for frontends, and for backends 0057's with 0061's syslog counters.

Revision ID: 0065
Revises: 0064
"""

from __future__ import annotations

from alembic import op

revision = "0065"
down_revision = "0064"
branch_labels = None
depends_on = None

ROLLBACK_SAFE = True
ROLLBACK_SAFE_BECAUSE = (
    "adds one nullable column per sample table and replaces two trigger functions; a poller "
    "from before leaves the column null, which the new functions read as the old rule"
)

#
# 0048's counters, as that migration names them; 0057's and 0061's added to the
# backend rows. A test holds these against those migrations.
#
HAPROXY_COUNTERS = (
    "req_tot",
    "hrsp_2xx",
    "hrsp_3xx",
    "hrsp_4xx",
    "hrsp_5xx",
    "econ",
    "wretr",
    "bin",
    "bout",
)
DNS_COUNTERS = ("dns_queries", "dns_tcp", "dns_refused", "dns_answered")
SYSLOG_COUNTERS = ("syslog_messages", "syslog_bytes")
MEMBER_COUNTERS = (*HAPROXY_COUNTERS, *DNS_COUNTERS, *SYSLOG_COUNTERS)

LOOKBACK = "31 days"


def _assign(names: tuple[str, ...]) -> str:
    """0048's rule for one stored difference, per counter - unchanged."""

    return "\n".join(
        f"        new.delta_{name} := case when previous.{name} is null "
        f"or new.{name} is null then null when new.restarted then new.{name} "
        f"when new.{name} < previous.{name} then null "
        f"else new.{name} - previous.{name} end;"
        for name in names
    )


def _restarted(names: tuple[str, ...], kept: bool) -> str:
    """Whether the counters began again, the rule this migration is for."""

    if not kept:
        return "coalesce(new.uptime_sec < previous.uptime_sec, false)"
    fell = " or ".join(f"coalesce(new.{name} < previous.{name}, false)" for name in names)
    return (
        "coalesce(new.uptime_sec < previous.uptime_sec, false)\n"
        "            and (not coalesce(new.counters_kept, false)\n"
        f"                 or {fell})"
    )


def _frontend(kept: bool) -> str:
    names = HAPROXY_COUNTERS
    return f"""
    create or replace function metric_frontend_delta() returns trigger
        language plpgsql
        set search_path = pg_catalog, public
    as $$
    declare
        previous record;
    begin
        if new.owns_vip is not true then
            new.previous_at := null;
            new.restarted := null;
            return new;
        end if;
        select observed_at, uptime_sec, {", ".join(names)}
          into previous
          from metric_frontend
         where cluster = new.cluster and node = new.node and frontend = new.frontend
           and owns_vip
           and observed_at < new.observed_at
           and observed_at >= new.observed_at - interval '{LOOKBACK}'
         order by observed_at desc
         limit 1;
        if not found then
            new.previous_at := null;
            new.restarted := null;
            return new;
        end if;
        new.previous_at := previous.observed_at;
        new.restarted := {_restarted(names, kept)};
{_assign(names)}
        return new;
    end;
    $$;
    """  # noqa: S608 - every value interpolated here is a constant of this module


def _member(kept: bool) -> str:
    names = MEMBER_COUNTERS
    return f"""
    create or replace function metric_backend_member_delta() returns trigger
        language plpgsql
        set search_path = pg_catalog, public
    as $$
    declare
        previous record;
    begin
        select observed_at, uptime_sec, {", ".join(names)}
          into previous
          from metric_backend_member
         where cluster = new.cluster and node = new.node
           and backend = new.backend and member = new.member
           and observed_at < new.observed_at
           and observed_at >= new.observed_at - interval '{LOOKBACK}'
         order by observed_at desc
         limit 1;
        if not found then
            new.previous_at := null;
            new.restarted := null;
            return new;
        end if;
        new.previous_at := previous.observed_at;
        new.restarted := {_restarted(names, kept)};
{_assign(names)}
        return new;
    end;
    $$;
    """  # noqa: S608 - every value interpolated here is a constant of this module


def upgrade() -> None:
    op.execute("""
    alter table metric_frontend add column counters_kept boolean;
    alter table metric_backend_member add column counters_kept boolean;
    grant insert (counters_kept) on metric_frontend to app_poller;
    grant insert (counters_kept) on metric_backend_member to app_poller;
    """)
    op.execute(_frontend(kept=True))
    op.execute(_member(kept=True))


def downgrade() -> None:
    op.execute(_frontend(kept=False))
    op.execute(_member(kept=False))
    op.execute("""
    alter table metric_frontend drop column if exists counters_kept;
    alter table metric_backend_member drop column if exists counters_kept;
    """)
