"""What a node's log forwarding queues mean (B289), for the status command and the interface.

The node reports, per external receiver, the lines queued in memory and on disk
and the lines dropped in the last hour because the queue was full
(`haprion-node-status`, `log_forwarding`). This is the one reading of those
figures: the terminal's status line and the dashboard's attention list both
come from here, so they cannot disagree about when a receiver is in trouble.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal

#
# A queue that keeps up holds next to nothing; one that holds this many lines
# has a receiver that is away or slower than the traffic - about ten seconds
# of the 1 000 requests a second a single-core node handles comfortably. Not
# yet a loss: the queue on disk holds some 1.3 million lines per GiB.
#
QUEUE_WARNING = 10_000
#
# impstats writes once a minute; five missed minutes is an rsyslog that has
# stopped writing them, and then the queue figures are old news.
#
STATS_STALE_SECONDS = 300


@dataclass(frozen=True, slots=True)
class Problem:
    severity: Literal["critical", "warning"]
    receiver: str
    message: str


def _receivers(forwarding: object) -> list[Mapping[str, Any]]:
    if not isinstance(forwarding, Mapping):
        return []
    receivers = forwarding.get("receivers")
    if not isinstance(receivers, list):
        return []
    return [item for item in receivers if isinstance(item, Mapping)]


def _count(value: int) -> str:
    return f"{value:,}".replace(",", " ")


def unreached(receiver: Mapping[str, Any]) -> str | None:
    """Why the node's rsyslog last failed to reach this receiver, while that is news.

    The node reads it from rsyslog's own journal lines (`Connection refused`,
    `Connection timed out`) and leaves it out once the receiver resumed.
    """

    error = receiver.get("last_error")
    if not isinstance(error, Mapping):
        return None
    reason = error.get("reason")
    return reason if isinstance(reason, str) and reason else None


def problems(forwarding: object) -> list[Problem]:
    """What is wrong with a node's forwarding, worst first; empty when nothing is."""

    found: list[Problem] = []
    receivers = _receivers(forwarding)
    if not receivers or not isinstance(forwarding, Mapping):
        return found
    age = forwarding.get("stats_age_sec")
    for receiver in receivers:
        name = str(receiver.get("name", ""))
        dropped = receiver.get("dropped_last_hour")
        if isinstance(dropped, int) and dropped > 0:
            found.append(
                Problem(
                    "critical",
                    name,
                    f"traffic log to {name}: {_count(dropped)} lines dropped in the last hour",
                )
            )
        queued = receiver.get("queued")
        if isinstance(queued, int) and queued >= QUEUE_WARNING:
            reason = unreached(receiver)
            found.append(
                Problem(
                    "warning",
                    name,
                    f"traffic log to {name}: {_count(queued)} lines queued"
                    + (f" ({reason})" if reason else ""),
                )
            )
    if age is None or (isinstance(age, int) and age > STATS_STALE_SECONDS):
        found.append(
            Problem(
                "warning",
                "",
                "traffic log forwarding: rsyslog has written no queue statistics"
                + ("" if age is None else f" for {age // 60} min"),
            )
        )
    order = {"critical": 0, "warning": 1}
    return sorted(found, key=lambda problem: order[problem.severity])


def status_line(forwarding: object) -> str | None:
    """One line for the terminal: each receiver and its queue. None when nothing is forwarded."""

    receivers = _receivers(forwarding)
    if not receivers:
        return None
    parts = []
    for receiver in receivers:
        queued = receiver.get("queued")
        dropped = receiver.get("dropped_last_hour")
        part = f"{receiver.get('name')} " + (
            "queue unknown" if not isinstance(queued, int) else f"{_count(queued)} queued"
        )
        if isinstance(dropped, int) and dropped > 0:
            part += f", {_count(dropped)} DROPPED in the last hour"
        reason = unreached(receiver)
        if reason:
            part += f", not reached: {reason}"
        parts.append(part)
    return "; ".join(parts)
