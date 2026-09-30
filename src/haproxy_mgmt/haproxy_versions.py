"""Which nodes run an older HAProxy than they should (Fas 16 punkt 3b).

Two rules, both from the manual's *Keeping HAProxy current*: a cluster's nodes
run one version, and the management host - whose `haproxy -c` validates every
candidate - is upgraded last, so it is never newer than a node. A validator
newer than a node can accept a directive that node then refuses.

The versions compared are what each node's running process reports on its
runtime socket and what `haproxy -v` names on this host, compared by their
upstream part (`3.4.6` of `3.4.6-1ppa1~resolute`). One implementation, read
by `haproxy-status` and the dashboard alike.
"""

from __future__ import annotations

import re
from collections.abc import Mapping

UPSTREAM = re.compile(r"\d+(?:\.\d+)*")

__all__ = ["notes", "upstream"]


def upstream(version: object) -> str | None:
    """The upstream release a package version names, or None."""

    if not isinstance(version, str):
        return None
    found = UPSTREAM.match(version.strip())
    return found.group(0) if found else None


def _key(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def notes(running: Mapping[str, object], validator: object = None) -> dict[str, str]:
    """A sentence per node that is behind, keyed by node name; nodes that are fine are absent.

    `running` is each node's runtime version, as the status reports it. A node
    whose version is unknown is not judged: an unreachable node is already
    reported for what it is.
    """

    known = {name: found for name, value in running.items() if (found := upstream(value))}
    if not known:
        return {}
    newest = max(known.values(), key=_key)
    checked = upstream(validator)
    said: dict[str, str] = {}
    for name, version in known.items():
        if _key(version) < _key(newest):
            said[name] = f"Behind {newest}"
        elif checked is not None and _key(checked) > _key(version):
            said[name] = f"Manager validates with {checked}"
    return said
