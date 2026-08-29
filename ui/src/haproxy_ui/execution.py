"""Running one operation, and stopping it when this worker is no longer allowed to.

Three things have to be true at once while a job runs, and each of them is a way
the naive version goes wrong:

The command must be stoppable as a whole. A deploy reaches nodes over SSH, so
killing the process the worker started can leave its children running - and a
child that keeps writing after the job has been handed to another worker is
exactly the double write the fencing token exists to prevent. The command is
therefore started in its own session, and stopped by signalling the group.

The lease must keep being renewed while the work goes on, because a lease that
expires under a healthy worker hands its job to a second one. Renewal happens
here, between checks, rather than in the operation's own code.

And a lost lease must end the run. Not finish it, not report it - end it. The
worker that lost the lease no longer owns the job, and the database will refuse
its writes anyway; continuing only burns the cluster's lock for longer.
"""

from __future__ import annotations

import logging
import os
import signal
import subprocess  # noqa: S404 - running one fixed command is this module's purpose
import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

logger = logging.getLogger("haproxy_ui.execution")

type Ending = Literal["finished", "timeout", "lease_lost"]

#
# How often the loop wakes to renew the lease and look at the process. Short
# enough that a lost lease is noticed while the operation is still running, long
# enough that a slow deploy does not spend its time asking the database how it
# is doing.
#
TICK_SECONDS = 5.0

#
# The grace between asking the process group to stop and insisting. A deploy
# that is interrupted mid-step should get the chance to leave the node in a
# state it chose rather than one the kernel chose.
#
GRACE_SECONDS = 10.0

#
# Everything the command is allowed to inherit. Passed explicitly rather than
# filtered, so a variable that appears in the worker's environment later does not
# silently become part of an operation's.
#
ENVIRONMENT_KEYS = ("PATH", "LANG", "LC_ALL", "TZ")


@dataclass(frozen=True, slots=True)
class Completed:
    """How the run ended, and what it said.

    `ending` is deliberately separate from `exit_code`. A command killed for a
    lost lease may still exit 0 on its way out, and reading that as success would
    record a result this worker is not entitled to record.
    """

    ending: Ending
    exit_code: int | None
    stdout: str
    stderr: str


def _environment() -> dict[str, str]:
    return {key: os.environ[key] for key in ENVIRONMENT_KEYS if key in os.environ}


def _stop(process: subprocess.Popen[str]) -> None:
    """Stop the whole group, politely and then not.

    `os.killpg` on the child's own group, which exists because the process was
    started in a new session. Signalling the process alone would leave an SSH
    child holding the far end of the operation.
    """

    try:
        group = os.getpgid(process.pid)
    except ProcessLookupError:  # pragma: no cover - it exited between checks
        return

    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(group, sig)
        except ProcessLookupError:  # pragma: no cover - the group is already gone
            return
        try:
            process.wait(timeout=GRACE_SECONDS if sig == signal.SIGTERM else GRACE_SECONDS)
            return
        except subprocess.TimeoutExpired:
            logger.warning("the operation did not stop on %s; escalating", sig.name)


def run(
    argv: Sequence[str],
    *,
    request: str,
    timeout_seconds: float,
    still_ours: Callable[[], bool],
    environment: Mapping[str, str] | None = None,
) -> Completed:
    """Run one command to completion, or stop it and say why.

    `still_ours` is asked on every tick and is where the lease is renewed. It
    returns False the moment this worker stops holding the job, and the run ends
    there.

    No shell, an argv array, and an environment built by name. The request goes
    in on stdin the way every helper in this system takes it, so the command line
    carries no operation-specific values at all - there is nothing in it for a
    payload to influence.
    """

    process = subprocess.Popen(  # noqa: S603 - argv array, fixed program, no shell
        list(argv),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=dict(environment) if environment is not None else _environment(),
        #
        # The reason the group exists. Also detaches the command from the
        # worker's terminal signals, so a Ctrl-C in a development shell does not
        # reach a running deploy sideways.
        #
        start_new_session=True,
    )

    #
    # communicate() in its own thread rather than reading the pipes here. Reading
    # them by hand while also polling is where output-heavy commands deadlock: a
    # full pipe blocks the child, and the loop is busy waiting for a child that
    # is waiting for the loop.
    #
    captured: dict[str, str] = {}

    def drain() -> None:
        out, err = process.communicate(input=request)
        captured["stdout"], captured["stderr"] = out, err

    reader = threading.Thread(target=drain, name="operation-output", daemon=True)
    reader.start()

    waited = 0.0
    ending: Ending = "finished"
    while True:
        reader.join(timeout=TICK_SECONDS)
        if not reader.is_alive():
            break
        waited += TICK_SECONDS
        if not still_ours():
            logger.error("the lease was lost while the operation was running; stopping it")
            ending = "lease_lost"
            break
        if waited >= timeout_seconds:
            logger.error("the operation passed its timeout of %ss; stopping it", timeout_seconds)
            ending = "timeout"
            break

    if ending != "finished":
        _stop(process)
        #
        # Joined after the kill, so the output produced before it is not thrown
        # away. A timed-out deploy's last lines are usually the interesting ones.
        #
        reader.join(timeout=GRACE_SECONDS)

    return Completed(
        ending=ending,
        exit_code=process.returncode,
        stdout=captured.get("stdout", ""),
        stderr=captured.get("stderr", ""),
    )
