"""The manager's certificate reading (B304), from tests that describe the registry.

Most certificate tests describe the registry where it travelled until
26-10-14: inside a cluster's listing, built with `with_registry`. The engine
now answers it for the manager, and the interface reads it only from there.
`manager_of` turns such a description into that reading, so a test keeps
saying what the registry holds while the page reads it the real way.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from haprion_ui.db import ManagerCertificates


def manager_of(readings: Iterable[Any]) -> ManagerCertificates | None:
    """The newest registry the readings describe, as the manager's reading."""

    newest: Any = None
    for reading in readings:
        result = getattr(reading, "result", None)
        if not isinstance(result, Mapping) or not isinstance(result.get("registry"), Mapping):
            continue
        if newest is None or reading.observed_at > newest.observed_at:
            newest = reading
    if newest is None:
        return None
    registry = dict(newest.result["registry"])
    return ManagerCertificates(
        observed_at=newest.observed_at,
        outcome="done",
        result={"interface_served": registry.get("interface_served"), "registry": registry},
        warnings=[],
        error=None,
        poll_error=None,
    )
