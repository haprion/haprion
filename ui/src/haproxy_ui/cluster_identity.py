"""Visual identity helpers for cluster-specific, non-semantic UI details."""

from __future__ import annotations

from hashlib import sha256

#
# Four markers, drawn as a low-chroma tint behind the cluster name. Colour is
# what makes the marker work: it is read before the name is, which is the whole
# point of it - the name is adjacent everywhere, but a name has to be read.
#
# Four earlier colour pairs were rejected, and the lesson was not "no colour".
# They differed in hue at nearly the same lightness, on a 4px rule, all of them
# crowded into the narrow gap between blue and red. These are spread around the
# circle and neighbours differ in lightness too. What keeps them from reading as
# a status is chroma, not hue: every status colour here is vivid, so a muted
# plate does not compete with one.
#
# Four is a ceiling, not a budget. Pure lightness separates three, maybe four;
# hue and lightness together stretch to six before a reader starts looking
# twice, and a marker that has to be studied is not doing its job. Cluster five
# repeats cluster one.
#
ACCENT_COUNT = 4


def accent_index(cluster: str) -> int:
    """Return a stable visual marker index without assigning operational meaning."""
    return sha256(cluster.encode("utf-8")).digest()[0] % ACCENT_COUNT
