"""Visual identity helpers for cluster-specific, non-semantic UI details."""

from __future__ import annotations

from hashlib import sha256

#
# Four markers, and they are shapes rather than colours: a solid, a dashed, a
# double and a dotted left rule, all drawn in one neutral ink. A colour here
# would have to be defended against the status palette forever - green, amber,
# blue and red already mean something - and four attempts at a colour pair each
# ended up either too similar to tell apart or reading as a status. A shape
# carries the same amount of identity, survives a dark theme unchanged, and is
# still distinguishable to a reader who cannot separate the hues.
#
ACCENT_COUNT = 4


def accent_index(cluster: str) -> int:
    """Return a stable visual marker index without assigning operational meaning."""
    return sha256(cluster.encode("utf-8")).digest()[0] % ACCENT_COUNT
