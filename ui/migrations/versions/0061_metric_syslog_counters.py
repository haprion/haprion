"""IPVS's counters for a syslog pool beside HAProxy's and dnsdist's (Fas 19b B3, 2026-10-08).

A syslog object is forwarded by the kernel's IPVS rather than HAProxy (B256),
and its card shows what arrived: messages and bytes, per pool and per
receiver. Each message is one datagram scheduled on its own (`ops`), so the
kernel's packets in are the messages; nothing travels back.

They go into `metric_backend_member` for the reason dnsdist's did (0057): a
syslog pool has the shape the table already keeps - the pool's own row
`BACKEND` from the virtual server, a row per receiver, from the node holding
the address - and retention, the hourly sums (0055), the pairing of samples
(0048), the newest-poll listing and a renamed pool's earlier names (0056)
then hold without a copy.

* `syslog_messages`, `syslog_bytes` - cumulative, differenced by 0048's
  trigger, which is replaced here with the longer list - 0057's own
  functions, over 0057's counters and these, so the three cannot drift.

IPVS reports no uptime. A receiver keepalived took out and put back starts
counting from nought while its virtual server does not, so a counter that
falls is read as 0048's rule reads one: no difference for that interval,
rather than a negative one or a restart guessed at.

No row is filled in: no syslog row exists before this migration.

Revision ID: 0061
Revises: 0060
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

from alembic import op

revision = "0061"
down_revision = "0060"
branch_labels = None
depends_on = None

SYSLOG_COUNTERS = ("syslog_messages", "syslog_bytes")


def _dns_counters() -> ModuleType:
    """0057 itself, frozen by digest (`migrations/frozen.sha256`): its trigger SQL, as 0059 reads it."""

    path = Path(__file__).with_name("0057_metric_dns_counters.py")
    spec = importlib.util.spec_from_file_location("migration_0057", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot read {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def upgrade() -> None:
    earlier = _dns_counters()
    counters = (*earlier.COUNTERS, *SYSLOG_COUNTERS)
    raw = ",\n        ".join(
        [f"add column {name} bigint" for name in SYSLOG_COUNTERS]
        + [f"add column delta_{name} bigint" for name in SYSLOG_COUNTERS]
    )
    hours = ",\n        ".join(
        f"add column delta_{name} bigint,\n        "
        f"add column span_{name}_sec numeric not null default 0"
        for name in SYSLOG_COUNTERS
    )
    #
    # The columns first, then the functions that name them, in one
    # transaction, as 0057 did: the poller's next insert meets both.
    #
    op.execute(f"""
    alter table metric_backend_member
        {raw};
    alter table metric_backend_hour_delta
        {hours};
    """)
    op.execute(earlier._member_delta(counters))
    op.execute(earlier._hour_add(counters, latency=False))

    readings = ", ".join(SYSLOG_COUNTERS)
    deltas = ", ".join(f"delta_{name}" for name in SYSLOG_COUNTERS)
    hour_columns = ", ".join(f"delta_{name}, span_{name}_sec" for name in SYSLOG_COUNTERS)
    op.execute(f"""
    grant insert ({readings}) on metric_backend_member to app_poller;
    grant select ({readings}) on metric_backend_member to app_poller;
    grant select ({readings}, {deltas}) on metric_backend_member to app_web;
    grant select ({hour_columns}) on metric_backend_hour_delta to app_web;
    """)


def downgrade() -> None:
    earlier = _dns_counters()
    op.execute(earlier._member_delta(earlier.COUNTERS))
    op.execute(earlier._hour_add(earlier.COUNTERS, latency=False))
    raw = ", ".join(
        [f"drop column if exists {name}" for name in SYSLOG_COUNTERS]
        + [f"drop column if exists delta_{name}" for name in SYSLOG_COUNTERS]
    )
    hours = ", ".join(
        f"drop column if exists delta_{name}, drop column if exists span_{name}_sec"
        for name in SYSLOG_COUNTERS
    )
    op.execute(f"""
    alter table metric_backend_member {raw};
    alter table metric_backend_hour_delta {hours};
    """)
