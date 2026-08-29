"""Visual identity helpers for cluster-specific, non-semantic UI details."""

from __future__ import annotations

from hashlib import sha256

ACCENT_COUNT = 2


def accent_index(cluster: str) -> int:
    """Return a stable visual accent index without assigning operational meaning."""
    return sha256(cluster.encode("utf-8")).digest()[0] % ACCENT_COUNT
