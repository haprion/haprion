"""Stopping a long-running service the way systemd asks it to.

Shared by the worker and the poller because both have the same shape: a loop
that leaves between one round and the next. systemd stops the whole unit, so a
root helper under the worker ends with it; the job it was running is then left
to recovery after the restart, not written with an end it did not have.

The state is behind a method rather than an attribute for a reason that is not
style. A signal handler mutates it, which no type checker can see, so a loop
written as `while not stopping.stop` reads to mypy as a condition that never
changes - and everything after the first check inside it becomes unreachable
code that is never checked. A call cannot be narrowed that way, so the loop body
stays under analysis.
"""

from __future__ import annotations

import logging
import signal

logger = logging.getLogger("haprion_ui.service")


class StopRequest:
    """True once systemd has asked this process to stop."""

    def __init__(self, *, what: str) -> None:
        self._requested = False
        self._what = what
        signal.signal(signal.SIGTERM, self._handle)
        signal.signal(signal.SIGINT, self._handle)

    def _handle(self, *_: object) -> None:
        logger.info("stopping %s", self._what)
        self._requested = True

    def requested(self) -> bool:
        return self._requested

    def sleep(self, seconds: int) -> None:
        """Wait, but stop waiting the moment a stop is asked for.

        A second at a time rather than one long call. systemd waits for a
        service to go, and one that always takes its full interval to stop
        teaches everyone that a restart is slow.
        """

        import time

        for _ in range(seconds):
            if self._requested:
                return
            time.sleep(1)


def sleep_until_notified(stopping: StopRequest, listener: object, seconds: int) -> None:
    """Wait for a notification, the interval, or a stop - whichever is first.

    A function rather than a method on `StopRequest`, and both arguments
    duck-typed, because this module is the one the worker and the poller share
    and it has no business knowing what a database connection is. What it needs
    is something with `notifies`; psycopg's connection is the only thing that
    has ever been passed.

    A second at a time, for the same reason `StopRequest.sleep` is: systemd
    waits for a service to go, and one that always takes its full interval to
    stop teaches everyone that a restart is slow.

    The notification is a hint and never an instruction. It carries no payload
    and is not trusted to mean anything in particular - it only ends the wait
    early, and the pass that follows asks the database what is actually there.
    So a lost notification costs latency and nothing else: the interval still
    expires, and the loop still asks. That is what keeps this an optimisation
    rather than a second source of truth.
    """

    for _ in range(seconds):
        if stopping.requested():
            return
        for _notification in listener.notifies(timeout=1.0, stop_after=1):  # type: ignore[attr-defined]
            return
