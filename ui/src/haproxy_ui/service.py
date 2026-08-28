"""Stopping a long-running service the way systemd asks it to.

Shared by the worker and the poller because both have the same shape: a loop
that should finish what it is doing and then leave, rather than being killed
partway through and restarted into whatever state that left.

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

logger = logging.getLogger("haproxy_ui.service")


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
