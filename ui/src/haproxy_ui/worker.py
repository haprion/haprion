"""The worker: the only identity that may turn a queued job into an operation.

Nothing here claims a job yet, and that is the phase 4 design rather than an
unfinished edge. Management writes are switched off until the phase that turns
them on, so the worker is installed, running and provably unable to act - which
is a stronger statement than not installing it, because it is the state a
rollback returns to.

Why the worker exists at all, when the web process could call the same commands:
it could not. The web identity holds no sudo rule, no membership of the
management group, and no path to a key. A web intrusion can therefore ask for
one of the operations the web role is allowed to queue - that is what makes the
interface work - and cannot choose the command, the arguments, the cluster's
lock, or what the result says happened.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

from haproxy_ui import db
from haproxy_ui.config import DEFAULT_CONFIG_PATH
from haproxy_ui.config import load as load_config
from haproxy_ui.service import StopRequest

logger = logging.getLogger("haproxy_ui.worker")

IDLE_SECONDS = 30


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(format="%(levelname)s %(message)s", level=logging.INFO)
    path = Path(os.environ.get("HAPROXY_UI_CONFIG", str(DEFAULT_CONFIG_PATH)))
    config = load_config(path)

    pool = db.pool(config.database, min_size=1, max_size=2)
    pool.open(wait=True, timeout=10)
    try:
        with pool.connection() as connection:
            identity, database = db.connected_identity(connection)
        #
        # Reported rather than assumed, on every start. Peer authentication
        # means the role is decided by the kernel, and a worker running as the
        # wrong role looks exactly like one running correctly until something is
        # denied - or, worse, allowed.
        #
        logger.info("worker running as %s on %s", identity, database)

        if not config.management_writes:
            #
            # Said once and then quiet. A line every thirty seconds saying
            # nothing happened is a log nobody reads, and this state is normal
            # for the whole of phase 4.
            #
            logger.info(
                "management writes are disabled; no job will be claimed. "
                "This is the phase 4 state, and switching it off is the "
                "documented rollback for the write path."
            )

        stopping = StopRequest(what="worker")
        while not stopping.requested():
            if config.management_writes:
                #
                # Deliberately a refusal rather than a partial implementation.
                # The claim, the lease and the fenced writes exist now as
                # `db.claim_job`, `db.renew_lease` and `db.finish_job` - what is
                # missing is the half that runs the command: a subprocess in its
                # own process group, with a timeout and an aborted run when the
                # lease is lost. A worker that claims before it can execute is a
                # worker that takes a job it cannot finish or report, which is
                # worse than one that has not started.
                #
                logger.error(
                    "management writes are enabled but the claim path is not built yet. "
                    "Turn management_writes off until the phase that implements it."
                )
                return 78
            stopping.sleep(IDLE_SECONDS)
    finally:
        pool.close()
    return 0


def _entry() -> None:  # pragma: no cover - console script shim
    sys.exit(main())


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
