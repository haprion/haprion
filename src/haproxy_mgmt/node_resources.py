"""A node's CPU and memory, as the status command and the dashboard show them (B239).

The node reports counters and sizes, never percentages: CPU use is a rate, and
a rate needs two readings. One reading gives memory and the load average; the
CPU share needs the previous reading as well, which only a reader that keeps
one - the poller - has. Both readers work the figures out here, so the status
command and the dashboard cannot disagree about the same node.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

#
# A node at or above this share of CPU or memory is marked on the dashboard
# (B239). Chosen as the point where a node with one CPU and one gigabyte has
# little left for a burst; not a measured threshold.
#
HIGH_PERCENT = 85


def _counters(resources: Any) -> tuple[int, int] | None:
    if not isinstance(resources, Mapping):
        return None
    cpu = resources.get("cpu")
    if not isinstance(cpu, Mapping):
        return None
    total, idle = cpu.get("total"), cpu.get("idle")
    if not isinstance(total, int) or not isinstance(idle, int) or isinstance(total, bool):
        return None
    return total, idle


def memory_percent(resources: Any) -> int | None:
    """Used memory as a whole percentage: what is not available to a new process."""

    if not isinstance(resources, Mapping):
        return None
    memory = resources.get("memory")
    if not isinstance(memory, Mapping):
        return None
    total, available = memory.get("total_kb"), memory.get("available_kb")
    if not isinstance(total, int) or not isinstance(available, int) or total <= 0:
        return None
    return max(0, min(100, round(100 * (total - available) / total)))


def cpu_percent(previous: Any, current: Any) -> int | None:
    """The CPU share used between two readings of the same node, as a whole percentage.

    None when either reading lacks counters, or when the counters did not move
    forward - a node restarted in between starts its counters again, and a
    difference across a restart describes nothing.
    """

    before, after = _counters(previous), _counters(current)
    if before is None or after is None:
        return None
    elapsed = after[0] - before[0]
    idle = after[1] - before[1]
    if elapsed <= 0 or idle < 0 or idle > elapsed:
        return None
    return max(0, min(100, round(100 * (elapsed - idle) / elapsed)))


def memory_line(resources: Any) -> str:
    """`35 % used (311 of 889 MB)`, for the status command."""

    share = memory_percent(resources)
    if share is None:
        return "unknown"
    memory = resources["memory"]
    total = memory["total_kb"]
    used = total - memory["available_kb"]
    return f"{share} % used ({used // 1024} of {total // 1024} MB)"


def load_line(resources: Any) -> str:
    """`0.08 on 1 CPU, last minute`, for the status command.

    The status command reads a node once, so it shows the load average, which
    the kernel already averages, rather than a CPU share it cannot work out.
    """

    if not isinstance(resources, Mapping):
        return "unknown"
    load, cpus = resources.get("load"), resources.get("cpus")
    shown = (
        f"{load:.2f}" if isinstance(load, int | float) and not isinstance(load, bool) else "unknown"
    )
    count = f"{cpus} CPU" if isinstance(cpus, int) and cpus == 1 else f"{cpus or '?'} CPUs"
    return f"{shown} on {count}, last minute"
