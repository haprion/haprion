"""The poller: ask the clusters how they are, so no page view has to.

A read that happens while somebody is looking at a screen is a read that fails
while somebody is looking at a screen. Reaching a node takes seconds and can
hang, so the interface never does it: one poller asks on a schedule and writes
the answer to a table, and everything that renders reads that table and states
how old the answer is.

**It reaches nothing privately.** The engine's configuration, the status
identity's key and the published release tree are all out of this account's
reach by design. The poller runs the same privileged helper the command line
runs, through one exact sudoers rule, and builds the request with the engine's
own code rather than a second copy of it - so the interface and the command line
cannot come to disagree about what was asked.

**One poller, enforced by the database.** A session-scoped advisory lock is held
for the process's life. A second poller finds the lock taken and exits rather
than doubling the load on every node and racing the first one's writes. The lock
is released by the server when the connection dies, including when the process
is killed without cleanup - which is exactly the case a lock file gets wrong.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from haproxy_mgmt.cli.inventory import run_inventory_helper
from haproxy_mgmt.cli.status import run_status_helper
from haproxy_mgmt.envelope import new_request_id

from haproxy_ui import db
from haproxy_ui.config import DEFAULT_CONFIG_PATH, Config
from haproxy_ui.config import load as load_config
from haproxy_ui.service import StopRequest

logger = logging.getLogger("haproxy_ui.poller")

#
# An arbitrary constant, and it only has to be stable and unlikely to collide
# with another application's advisory locks in the same database. Nothing else
# in this installation takes one.
#
POLLER_LOCK_KEY = 0x48415052

#
# Enough of stderr to recognise the failure, not enough to put a helper's entire
# output in a row that is read on every page view.
#
MAX_ERROR_BYTES = 2000

type RunHelper = Callable[[str, str], Any]


def _excerpt(text: str) -> str:
    text = text.strip()
    return text if len(text) <= MAX_ERROR_BYTES else text[:MAX_ERROR_BYTES] + " […]"


def poll_cluster(
    cluster: str,
    run_helper: RunHelper = run_status_helper,
    *,
    operation: str = "status",
) -> dict[str, Any]:
    """Ask one cluster, and turn every way that can go wrong into a row.

    Never raises. A poller that dies on one unreachable cluster stops reporting
    the others, and the others are usually the ones that are fine - which is
    information somebody is waiting for.

    The two failure kinds are kept apart. `poll_error` means this process could
    not get an answer: sudo refused, the helper is missing, the output was not
    JSON. An `outcome` of failed or partial means the cluster answered and the
    answer is bad news. Collapsing them would hide which one to go and fix.
    """

    try:
        completed = run_helper(cluster, new_request_id())
    except Exception as exc:  # noqa: BLE001 - any failure to run the helper is one row
        return {
            "outcome": "unavailable",
            "result": {},
            "poll_error": f"could not run the {operation} helper: {exc}",
        }

    try:
        envelope = json.loads(completed.stdout)
    except (json.JSONDecodeError, TypeError):
        return {
            "outcome": "unavailable",
            "result": {},
            "poll_error": _excerpt(
                f"the helper returned exit {completed.returncode} and no usable JSON. "
                f"stderr: {completed.stderr}"
            ),
        }

    if not isinstance(envelope, dict) or envelope.get("operation") != operation:
        return {
            "outcome": "unavailable",
            "result": {},
            "poll_error": f"the helper returned JSON that is not a result envelope for {operation}",
        }

    outcome = envelope.get("outcome")
    expected_outcomes = (
        ("done", "partial", "failed") if operation == "status" else ("done", "failed")
    )
    if outcome not in expected_outcomes:
        return {
            "outcome": "unavailable",
            "result": {},
            "poll_error": f"the helper reported an unknown outcome: {outcome!r}",
        }

    return {
        "outcome": outcome,
        "result": envelope.get("result") or {},
        "warnings": envelope.get("warnings") or [],
        "error": envelope.get("error"),
        "poll_error": None,
    }


def poll_once(
    pool: Any,
    config: Config,
    run_helper: RunHelper = run_status_helper,
    inventory_helper: RunHelper = run_inventory_helper,
) -> int:
    """One pass over every configured cluster. Returns how many answered well.

    Each cluster is written in its own transaction. A pass that fails halfway
    then leaves the clusters it did reach updated, rather than discarding good
    readings because a later one went wrong.
    """

    healthy = 0
    for cluster in config.clusters:
        reading = poll_cluster(cluster, run_helper)
        with pool.connection() as connection:
            db.record_cluster_status(
                connection,
                cluster=cluster,
                outcome=reading["outcome"],
                result=reading["result"],
                warnings=reading.get("warnings"),
                error=reading.get("error"),
                poll_error=reading.get("poll_error"),
            )
            connection.commit()
        inventory = poll_cluster(cluster, inventory_helper, operation="inventory")
        with pool.connection() as connection:
            db.record_cluster_inventory(
                connection,
                cluster=cluster,
                outcome=inventory["outcome"],
                result=inventory["result"],
                warnings=inventory.get("warnings"),
                error=inventory.get("error"),
                poll_error=inventory.get("poll_error"),
            )
            connection.commit()
        if reading["outcome"] == "done":
            healthy += 1
        else:
            logger.warning(
                "cluster %s: %s%s",
                cluster,
                reading["outcome"],
                f" ({reading['poll_error']})" if reading.get("poll_error") else "",
            )
        if inventory["outcome"] != "done":
            logger.warning(
                "cluster %s inventory: %s%s",
                cluster,
                inventory["outcome"],
                f" ({inventory['poll_error']})" if inventory.get("poll_error") else "",
            )
    return healthy


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(format="%(levelname)s %(message)s", level=logging.INFO)
    path = Path(os.environ.get("HAPROXY_UI_CONFIG", str(DEFAULT_CONFIG_PATH)))
    config = load_config(path)

    if not config.clusters:
        logger.error("no clusters are configured; there is nothing to poll")
        return 78

    pool = db.pool(config.database, min_size=1, max_size=2)
    pool.open(wait=True, timeout=10)
    try:
        #
        # The lock is taken on a connection held for the whole run, outside the
        # pool. A pooled connection would be returned between passes, and a
        # session-scoped lock goes back with it.
        #
        with db.pool(config.database, min_size=1, max_size=1) as lock_pool:
            lock_pool.open(wait=True, timeout=10)
            with lock_pool.connection() as lock_connection:
                identity, database = db.connected_identity(lock_connection)
                if not db.try_singleton_lock(lock_connection, POLLER_LOCK_KEY):
                    logger.error("another poller holds the lock on %s; exiting", database)
                    return 75
                logger.info(
                    "polling %d cluster(s) every %ds as %s on %s",
                    len(config.clusters),
                    config.poller.interval_seconds,
                    identity,
                    database,
                )

                #
                # A pass is finished before the process leaves. Killing a poller
                # mid-write would corrupt nothing - each write is one
                # transaction - but finishing means no row is left looking stale
                # for no reason.
                #
                stopping = StopRequest(what="after this pass")
                while not stopping.requested():
                    healthy = poll_once(pool, config)
                    logger.info("%d/%d cluster(s) fully current", healthy, len(config.clusters))
                    stopping.sleep(config.poller.interval_seconds)
    finally:
        pool.close()
    return 0


def _entry() -> None:  # pragma: no cover - console script shim
    sys.exit(main())


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
