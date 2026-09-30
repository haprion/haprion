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
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from haproxy_mgmt.cli.cert_list import run_cert_list_helper
from haproxy_mgmt.cli.cluster_list_helper import run_cluster_list_helper
from haproxy_mgmt.cli.cluster_settings import run_settings_helper
from haproxy_mgmt.cli.inventory import run_inventory_helper
from haproxy_mgmt.cli.list import run_list_helper
from haproxy_mgmt.cli.list_backups import run_list_backups_helper
from haproxy_mgmt.cli.network import run_network_helper
from haproxy_mgmt.cli.objects import run_objects_helper
from haproxy_mgmt.cli.status import run_status_helper
from haproxy_mgmt.envelope import new_request_id
from haproxy_mgmt.version_history import MAX_LIST_LIMIT

from haproxy_ui import db, service
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
type Recorder = Callable[..., None]


@dataclass(frozen=True, slots=True)
class Source:
    """One read the poller makes, and where the answer is written.

    Listed rather than written out per source, because every source is the same
    three steps - run one helper, judge one envelope, replace one row - and a
    fourth copy of those steps is a fourth place for them to drift.
    """

    operation: str
    run: RunHelper
    record: Recorder
    #
    # Partial is allowed only where the read has more than one place to fail.
    # Status reaches two nodes and one of them can answer; a backup listing
    # reads one directory per node and one of them can be missing. An inventory,
    # a version listing, a certificate listing and a network description are
    # each read in one place, so a partial outcome from those would mean the
    # helper is doing something it should not.
    #
    partial_ok: bool = False
    #
    # A second write from the same reading, where one exists. The cache answers
    # what is true now and is replaced; a sample answers what was true then and
    # is appended. Asking the nodes twice to get both would double the load on
    # every node to produce two readings of the same moment that could disagree.
    #
    # It is a separate field rather than something `record` does, because the
    # two writes must not share a transaction: a sample that cannot be written
    # is a gap in a graph, and a cache row that is not written is a dashboard
    # that says the cluster is stale. The second must not be caused by the
    # first. See the phase gate: missing stats data does not affect
    # reachability.
    #
    sample: Callable[..., int] | None = None


def _list_every_version(cluster: str, request_id: str) -> Any:
    """Every version up to the helper's ceiling, not the terminal's ten.

    The Versions page pages through them in the browser (Fas 14 point 8), so a
    version older than the tenth is on the page rather than only in git.
    """

    return run_list_helper(cluster, request_id, limit=MAX_LIST_LIMIT)


def _list_every_backup(cluster: str, request_id: str) -> Any:
    """Every archive the manager keeps for this cluster, not the command line's default.

    The archive list is where a restore is chosen from, and the retention is
    set per cluster from 1 to 365. A fixed page-sized limit here would make the
    older archives exist on disk and nowhere on the page; the page pages them
    instead.
    """

    return run_list_backups_helper(cluster, request_id, None)


SOURCES: tuple[Source, ...] = (
    Source(
        "status",
        run_status_helper,
        db.record_cluster_status,
        partial_ok=True,
        sample=db.record_metric_samples,
    ),
    Source("inventory", run_inventory_helper, db.record_cluster_inventory),
    Source("list", _list_every_version, db.record_cluster_history),
    Source("list_backups", _list_every_backup, db.record_cluster_backups, partial_ok=True),
    Source("cert_list", run_cert_list_helper, db.record_cluster_certificates),
    Source("network", run_network_helper, db.record_cluster_network),
    Source("cluster_settings", run_settings_helper, db.record_cluster_settings),
    #
    # The objects as they are written, which the inventory cannot answer for:
    # it parses published configuration, and an edit is made against the source
    # that produced it.
    #
    Source("objects", run_objects_helper, db.record_cluster_objects),
)


def _excerpt(text: str) -> str:
    text = text.strip()
    return text if len(text) <= MAX_ERROR_BYTES else text[:MAX_ERROR_BYTES] + " […]"


def poll_cluster(
    cluster: str,
    run_helper: RunHelper = run_status_helper,
    *,
    operation: str = "status",
    partial_ok: bool | None = None,
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
    accept_partial = operation == "status" if partial_ok is None else partial_ok
    expected_outcomes = ("done", "partial", "failed") if accept_partial else ("done", "failed")
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


def _sample(pool: Any, source: Source, *, cluster: str, result: Mapping[str, Any]) -> None:
    """Write this reading's samples, and never let that failure reach the poll.

    A partial reading is sampled too: the nodes that answered are exactly the
    measurement worth keeping on a day when one did not.

    Every failure is swallowed to a log line, and the reason is the phase gate -
    missing stats data must not affect reachability. The likeliest failure is a
    day with no partition, which is a maintenance problem to go and fix and not
    a reason for the dashboard to stop saying which nodes are up.
    """

    if source.sample is None or not result:
        return
    try:
        with pool.connection() as connection:
            written = source.sample(connection, cluster=cluster, result=result)
            connection.commit()
    except Exception as exc:  # noqa: BLE001 - a sample is never worth a failed pass
        logger.warning("cluster %s samples not written: %s", cluster, exc)
        return
    logger.debug("cluster %s: %d sample row(s)", cluster, written)


def read_cluster_list(
    run: Callable[[str], Any] = run_cluster_list_helper,
) -> tuple[str, ...] | None:
    """Which clusters exist, from the cluster file; None when that cannot be said.

    None is not "no clusters". It is a helper that could not be run or did not
    answer, and the caller keeps polling the clusters it already knew rather
    than emptying every page because one read failed.
    """

    try:
        completed = run(new_request_id())
        envelope = json.loads(completed.stdout)
    except Exception as exc:  # noqa: BLE001 - any failure is "not known this pass"
        logger.warning("the cluster list could not be read: %s", exc)
        return None
    result = envelope.get("result") if isinstance(envelope, dict) else None
    if (
        not isinstance(envelope, dict)
        or envelope.get("operation") != "cluster_list"
        or envelope.get("outcome") != "done"
        or not isinstance(result, dict)
        or not isinstance(result.get("clusters"), list)
    ):
        logger.warning("the cluster list helper did not answer with a list")
        return None
    names = tuple(
        str(entry["id"])
        for entry in result["clusters"]
        if isinstance(entry, dict) and isinstance(entry.get("id"), str)
    )
    return names or None


def poll_once(
    pool: Any,
    config: Config,
    sources: tuple[Source, ...] = SOURCES,
    *,
    clusters: tuple[str, ...] | None = None,
) -> int:
    """One pass over every configured cluster. Returns how many answered well.

    Each source of each cluster is written in its own transaction. A pass that
    fails halfway then leaves what it did read updated, rather than discarding
    good readings because a later one went wrong.

    The count returned is the status source only. It is what "fully current"
    means to an operator watching the log; a cluster whose nodes are healthy
    while its listing could not be read is a smaller problem, and it is logged
    as its own line rather than folded into that number.
    """

    healthy = 0
    for cluster in clusters if clusters is not None else config.clusters:
        for source in sources:
            reading = poll_cluster(
                cluster, source.run, operation=source.operation, partial_ok=source.partial_ok
            )
            with pool.connection() as connection:
                source.record(
                    connection,
                    cluster=cluster,
                    outcome=reading["outcome"],
                    result=reading["result"],
                    warnings=reading.get("warnings"),
                    error=reading.get("error"),
                    poll_error=reading.get("poll_error"),
                )
                connection.commit()
            _sample(pool, source, cluster=cluster, result=reading["result"])
            if reading["outcome"] == "done":
                if source.operation == "status":
                    healthy += 1
                continue
            logger.warning(
                "cluster %s %s: %s%s",
                cluster,
                source.operation,
                reading["outcome"],
                f" ({reading['poll_error']})" if reading.get("poll_error") else "",
            )
    return healthy


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(format="%(levelname)s %(message)s", level=logging.INFO)
    path = Path(os.environ.get("HAPROXY_UI_CONFIG", str(DEFAULT_CONFIG_PATH)))
    config = load_config(path)

    #
    # The cluster file decides which clusters exist (B206); `ui.toml`'s list is
    # the fallback while the list helper cannot be read, and the only list
    # before it was installed.
    #
    known = read_cluster_list() or config.clusters
    if not known:
        logger.error("no clusters are configured; there is nothing to poll")
        return 78

    pool = db.pool(config.database, min_size=1, max_size=2)
    pool.open(wait=True, timeout=10)
    #
    # Its own connection, held for the process's life, for the same reason the
    # worker's listener has one: the pool exists for short queries, and lending
    # one out permanently leaves it a size smaller than it says it is.
    #
    listener = db.listener(config.database, db.CLUSTER_CHANNEL)
    try:
        #
        # The lock is taken on its own autocommit connection, held for the whole
        # run and never pooled. Two things would otherwise take it away: a pooled
        # connection is returned between passes, and a session-scoped lock goes
        # back with it - and a lock taken in transaction mode leaves an open
        # transaction that `idle_in_transaction_session_timeout` closes ten
        # seconds later, releasing the lock while this process keeps polling.
        #
        with db.lock_session(config.database) as lock_connection:
            identity, database = db.connected_identity(lock_connection)
            if not db.try_singleton_lock(lock_connection, POLLER_LOCK_KEY):
                logger.error("another poller holds the lock on %s; exiting", database)
                return 75
            logger.info(
                "polling %d cluster(s) every %ds as %s on %s",
                len(known),
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
                listed = read_cluster_list()
                if listed is not None:
                    if listed != known:
                        logger.info("the cluster list changed: %s", ", ".join(listed))
                    known = listed
                    with pool.connection() as connection:
                        db.record_cluster_list(connection, known)
                        connection.commit()
                healthy = poll_once(pool, config, clusters=known)
                logger.info("%d/%d cluster(s) fully current", healthy, len(known))
                #
                # Woken by a finished job as well as by the clock. A publish
                # that changed a cluster used to sit invisible until the next
                # tick, so a page said "observed just now" about a reading taken
                # before the change it was being consulted about.
                #
                service.sleep_until_notified(stopping, listener, config.poller.interval_seconds)
    finally:
        listener.close()
        pool.close()
    return 0


def _entry() -> None:  # pragma: no cover - console script shim
    sys.exit(main())


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
