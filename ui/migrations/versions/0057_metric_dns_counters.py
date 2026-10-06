"""dnsdist's counters beside HAProxy's in the backend rows (Fas 19a B4, 2026-10-06).

A dns object is served by dnsdist rather than HAProxy (B249), and its card
shows what a resolver is asked about: queries, answered, refused, unanswered
and how many came over TCP, and per server queries, answered and latency. None
of HAProxy's counters means any of those, so they are columns of their own
rather than HAProxy's renamed.

They go into `metric_backend_member` because a dns pool has the shape the table
already keeps. The pool's own row is `BACKEND` - what the listener was asked,
refused and answered - and each server a row of its own, both from the node
holding the address, as for HAProxy. So retention, the hourly sums (0055),
the pairing of samples (0048), the newest-poll listing and the earlier names of
a renamed pool (0056) hold for them without a second copy of any of it.

* `dns_queries`, `dns_tcp`, `dns_refused`, `dns_answered` - cumulative, like
  HAProxy's, and differenced by 0048's trigger, which is replaced here with the
  longer list. Unanswered is not stored: it is asked less refused less
  answered, worked out from the sums.
* `dns_latency_us` - dnsdist's running average for one server, a reading and
  not a counter, so it is kept as read and never differenced. The hourly sums
  carry its total and how many readings made it, so an hour's average is one
  division away.

The uptime on a dns row is dnsdist's, which restarts whenever its
configuration changes and apart from HAProxy; 0048's rule reads it per row, so
a restart of one is never read as a restart of the other.

No row is filled in: no dns row exists before this migration.

Revision ID: 0057
Revises: 0056
"""

from __future__ import annotations

from alembic import op

revision = "0057"
down_revision = "0056"
branch_labels = None
depends_on = None

#
# 0048's counters, as that migration names them; a test holds the two equal.
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
COUNTERS = (*HAPROXY_COUNTERS, *DNS_COUNTERS)
LATENCY = "dns_latency_us"

LOOKBACK = "31 days"
HOUR = "date_trunc('hour', observed_at, 'UTC')"
SPAN = "extract(epoch from observed_at - previous_at)"
KEYS = ("cluster", "backend", "member")


def _assign(names: tuple[str, ...]) -> str:
    """0048's rule for one stored difference, per counter."""

    return "\n".join(
        f"        new.delta_{name} := case when previous.{name} is null "
        f"or new.{name} is null then null when new.restarted then new.{name} "
        f"when new.{name} < previous.{name} then null "
        f"else new.{name} - previous.{name} end;"
        for name in names
    )


def _member_delta(names: tuple[str, ...]) -> str:
    """0048's row trigger function for the backend rows, over these counters."""

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
        new.restarted := coalesce(new.uptime_sec < previous.uptime_sec, false);
{_assign(names)}
        return new;
    end;
    $$;
    """  # noqa: S608 - every value interpolated here is a constant of this module


def _value_columns(names: tuple[str, ...], latency: bool) -> str:
    return ", ".join(
        [
            "first_previous_at",
            "last_observed_at",
            "restarted",
            "samples",
            "span_sec",
            "span_clean_sec",
        ]
        + [f"delta_{name}, span_{name}_sec" for name in names]
        + ([f"{LATENCY}_sum", f"{LATENCY}_samples"] if latency else [])
    )


def _sums(names: tuple[str, ...], latency: bool) -> str:
    return ",\n               ".join(
        [
            "min(previous_at)",
            "max(observed_at)",
            "bool_or(restarted)",
            "count(*)",
            f"sum({SPAN})",
            f"coalesce(sum({SPAN}) filter (where not restarted), 0)",
        ]
        + [
            f"sum(delta_{name}), coalesce(sum({SPAN}) filter "
            f"(where delta_{name} is not null and not restarted), 0)"
            for name in names
        ]
        + ([f"coalesce(sum({LATENCY}), 0)", f"count({LATENCY})"] if latency else [])
    )


def _merge(names: tuple[str, ...], latency: bool) -> str:
    deltas = ",\n               ".join(
        [
            f"delta_{name} = case when kept.delta_{name} is null then excluded.delta_{name} "
            f"when excluded.delta_{name} is null then kept.delta_{name} "
            f"else kept.delta_{name} + excluded.delta_{name} end,\n"
            f"               span_{name}_sec = kept.span_{name}_sec + excluded.span_{name}_sec"
            for name in names
        ]
        + (
            [
                f"{LATENCY}_sum = kept.{LATENCY}_sum + excluded.{LATENCY}_sum",
                f"{LATENCY}_samples = kept.{LATENCY}_samples + excluded.{LATENCY}_samples",
            ]
            if latency
            else []
        )
    )
    return f"""
        on conflict ({", ".join(KEYS)}, node, hour, crossing) do update
           set first_previous_at = least(kept.first_previous_at, excluded.first_previous_at),
               last_observed_at = greatest(kept.last_observed_at, excluded.last_observed_at),
               restarted = kept.restarted or excluded.restarted,
               samples = kept.samples + excluded.samples,
               span_sec = kept.span_sec + excluded.span_sec,
               span_clean_sec = kept.span_clean_sec + excluded.span_clean_sec,
               {deltas}"""  # noqa: S608 - every value interpolated here is a constant of this module


def _hour_add(names: tuple[str, ...], latency: bool) -> str:
    """0055's statement trigger function for the backend hours, over these counters."""

    key_list = ", ".join(KEYS)
    group = ", ".join(str(index) for index in range(1, len(KEYS) + 4))
    return f"""
    create or replace function metric_backend_hour_delta_add()
        returns trigger
        language plpgsql
        security definer
        set search_path = pg_catalog, public
    as $$
    begin
        insert into metric_backend_hour_delta as kept
               ({key_list}, node, hour, crossing, {_value_columns(names, latency)})
        select {key_list}, node, {HOUR}, previous_at < {HOUR},
               {_sums(names, latency)}
          from added
         where previous_at is not null
         group by {group}
        {_merge(names, latency)};
        return null;
    end;
    $$;
    revoke all on function metric_backend_hour_delta_add() from public;
    """  # noqa: S608 - every value interpolated here is a constant of this module


def upgrade() -> None:
    raw = ",\n        ".join(
        [f"add column {name} bigint" for name in (*DNS_COUNTERS, LATENCY)]
        + [f"add column delta_{name} bigint" for name in DNS_COUNTERS]
    )
    hours = ",\n        ".join(
        [
            f"add column delta_{name} bigint,\n        "
            f"add column span_{name}_sec numeric not null default 0"
            for name in DNS_COUNTERS
        ]
        + [
            f"add column {LATENCY}_sum numeric not null default 0",
            f"add column {LATENCY}_samples integer not null default 0",
        ]
    )
    #
    # The columns first, then the functions that name them, in one transaction:
    # the poller's next insert waits for the lock and meets both.
    #
    op.execute(f"""
    alter table metric_backend_member
        {raw};
    alter table metric_backend_hour_delta
        {hours};
    """)
    op.execute(_member_delta(COUNTERS))
    op.execute(_hour_add(COUNTERS, latency=True))

    dns = ", ".join((*DNS_COUNTERS, LATENCY))
    deltas = ", ".join(f"delta_{name}" for name in DNS_COUNTERS)
    hour_columns = ", ".join(
        [f"delta_{name}, span_{name}_sec" for name in DNS_COUNTERS]
        + [f"{LATENCY}_sum", f"{LATENCY}_samples"]
    )
    #
    # The poller writes the readings and its trigger reads the previous ones;
    # the interface reads them and their differences. Nobody writes a
    # difference: the trigger does, as 0048 says.
    #
    op.execute(f"""
    grant insert ({dns}) on metric_backend_member to app_poller;
    grant select ({dns}) on metric_backend_member to app_poller;
    grant select ({dns}, {deltas}) on metric_backend_member to app_web;
    grant select ({hour_columns}) on metric_backend_hour_delta to app_web;
    """)


def downgrade() -> None:
    op.execute(_member_delta(HAPROXY_COUNTERS))
    op.execute(_hour_add(HAPROXY_COUNTERS, latency=False))
    raw = ", ".join(
        [f"drop column if exists {name}" for name in (*DNS_COUNTERS, LATENCY)]
        + [f"drop column if exists delta_{name}" for name in DNS_COUNTERS]
    )
    hours = ", ".join(
        [
            f"drop column if exists delta_{name}, drop column if exists span_{name}_sec"
            for name in DNS_COUNTERS
        ]
        + [f"drop column if exists {LATENCY}_sum", f"drop column if exists {LATENCY}_samples"]
    )
    op.execute(f"""
    alter table metric_backend_member {raw};
    alter table metric_backend_hour_delta {hours};
    """)
