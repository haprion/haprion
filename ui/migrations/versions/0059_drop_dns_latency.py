"""dnsdist's latency out, and the alias table's writes left to the worker (B253, 2026-10-06).

0057 kept a dns server's latency, dnsdist's running average, beside its
counters and summed it per hour. Nothing has read it since the server table
went (26-10-06), and the reading starts at nought whenever dnsdist does, so the
review decided to drop it (F4); Prometheus reads dnsdist's own figure. 0058
stopped the interface writing it; this takes the columns away, and first the
hourly trigger that names them - 0057's function over the same counters
without the latency, so the two cannot drift.

0058 gave the worker the right to record a pool's rename once the publish is
done (F2). The web kept its own until the release that stopped using it was
running; this takes it back, and the web reads the table and nothing more.

Revision ID: 0059
Revises: 0058
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

from alembic import op

revision = "0059"
down_revision = "0058"
branch_labels = None
depends_on = None


def _dns_counters() -> ModuleType:
    """0057 itself, frozen by digest (`migrations/frozen.sha256`): its trigger SQL, read once."""

    path = Path(__file__).with_name("0057_metric_dns_counters.py")
    spec = importlib.util.spec_from_file_location("migration_0057", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot read {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def upgrade() -> None:
    earlier = _dns_counters()
    latency = earlier.LATENCY
    op.execute(earlier._hour_add(earlier.COUNTERS, latency=False))
    op.execute(f"""
    alter table metric_backend_member drop column {latency};
    alter table metric_backend_hour_delta
        drop column {latency}_sum,
        drop column {latency}_samples;
    revoke insert, update on metric_backend_alias from app_web;
    """)


def downgrade() -> None:
    earlier = _dns_counters()
    latency = earlier.LATENCY
    op.execute(f"""
    alter table metric_backend_member add column {latency} bigint;
    alter table metric_backend_hour_delta
        add column {latency}_sum numeric not null default 0,
        add column {latency}_samples integer not null default 0;
    grant insert ({latency}) on metric_backend_member to app_poller;
    grant select ({latency}) on metric_backend_member to app_poller, app_web;
    grant select ({latency}_sum, {latency}_samples) on metric_backend_hour_delta to app_web;
    grant insert (cluster, old_name, new_name) on metric_backend_alias to app_web;
    grant update (new_name, renamed_at, reused_at) on metric_backend_alias to app_web;
    """)
    op.execute(earlier._hour_add(earlier.COUNTERS, latency=True))
