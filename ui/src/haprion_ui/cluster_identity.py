"""Visual identity helpers for cluster-specific, non-semantic UI details."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from contextvars import ContextVar
from types import MappingProxyType

#
# Six markers, drawn as a low-chroma rule down the left edge. Colour is what
# makes the marker work: it is read before the name is, which is the whole
# point of it - the name is adjacent everywhere, but a name has to be read.
#
# Six is a ceiling, not a budget (B204). Eight muted colours were tried twice
# and failed by eye: on a 5px rule the eye separates mostly by lightness, so
# pairs a full colour distance apart still read as one. Six hues at least 45
# degrees apart, each at its own lightness, held. What keeps them from reading
# as a status is chroma, not hue: every status colour here is vivid, so a muted
# rule does not compete with one.
#
# They are handed out in the order the cluster file lists the clusters (B206) - the order the
# dashboard draws them in - not by a hash of the name, which could give the
# first two clusters one colour. A seventh cluster does not get the first one's
# again: a marker that has to be doubted is worse than none, so the first six
# clusters keep their colours and the seventh and later have none (B410; B204
# switched all of them off). The name stands beside the card either way. A
# cluster the list does not name has none either.
#
ACCENT_COUNT = 6

_ORDER: ContextVar[Mapping[str, int]] = ContextVar("cluster_accents", default=MappingProxyType({}))


def read_in(clusters: Iterable[str], *, on: bool) -> None:
    """Take this request's clusters, in the installation's order, and the switch."""

    listed = tuple(clusters)[:ACCENT_COUNT]
    _ORDER.set(
        MappingProxyType({cluster: index for index, cluster in enumerate(listed)})
        if on
        else MappingProxyType({})
    )


def accent_index(cluster: str) -> int | None:
    """This cluster's marker, or None when it is not to have one."""

    return _ORDER.get().get(cluster)


def accent_class(index: int | None) -> str:
    """The class that draws the marker, for a template; empty without one."""

    return "" if index is None else f"cluster-accent-{index}"
