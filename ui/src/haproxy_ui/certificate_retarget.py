"""Publish to… and Remove from…: the two target pages, what they offer and what they queue.

The registry says where each certificate goes; these pages change that for a
selection at once (asked for 2026-09-15: "I sent 30 certificates to the wrong
cluster and want to clean up", and "how do I publish one to the other
cluster?"). The engine takes one delta for the whole selection - add these
targets, or remove them - and applies it per certificate to whatever the
registry holds when the job runs, so the page does not have to know a
certificate's current targets exactly; it only has to say which ones exist.

What is this side's to refuse
-----------------------------
The same one thing the deletion page refuses: a draft that names the
certificate in a cluster it is being removed from. A draft lives in this
database and nowhere the helper can see; publishing it after the removal
would fail on a file that used to be there. Everything else - a committed
object in that cluster, the cluster's default or last certificate, an
unknown target - is the helper's to refuse, and arrives on the job's rows.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from haproxy_mgmt.config import CERTIFICATE_ID, CLUSTER_ID, RECEIVER_ID

from haproxy_ui.certificate_delete import draft_references
from haproxy_ui.certificates import RegistryCertificateView
from haproxy_ui.db import ProxyDraft
from haproxy_ui.operations import MAX_DELETE_BATCH

ACTIONS: Mapping[str, str] = {"add": "Publish to", "remove": "Remove from"}


class SelectionProblem(Exception):
    """The selection as a whole cannot become a job; the page says why."""


@dataclass(frozen=True, slots=True)
class Row:
    """One chosen certificate as the page draws it."""

    identifier: str
    source_label: str
    clusters: tuple[str, ...]
    receivers: tuple[str, ...]
    drafts: tuple[str, ...] = ()
    """`cluster/object` rows of live drafts naming it; a removal from that cluster is refused."""

    @property
    def targets(self) -> tuple[str, ...]:
        return tuple(f"{name} (cluster)" for name in self.clusters) + tuple(
            f"{name} (receiver)" for name in self.receivers
        )


@dataclass(frozen=True, slots=True)
class Choice:
    """One target the page offers, and how many of the selection already have it."""

    name: str
    kind: str
    holding: int


@dataclass(frozen=True, slots=True)
class Selection:
    action: str
    rows: tuple[Row, ...]
    choices: tuple[Choice, ...]

    @property
    def identifiers(self) -> tuple[str, ...]:
        return tuple(row.identifier for row in self.rows)

    @property
    def label(self) -> str:
        return ACTIONS[self.action]


def selection(
    action: str,
    chosen: Sequence[str],
    registry: Mapping[str, RegistryCertificateView],
    clusters: Sequence[str],
    receivers: Sequence[str],
    drafts: Iterable[ProxyDraft],
) -> Selection:
    """The rows and the offered targets, in the order the registry lists them.

    For an add, every cluster and receiver that exists is offered; for a
    remove, only the ones some chosen certificate is actually on. A target
    every chosen certificate already has (add) or none has (remove) is not
    offered - the job would report it unchanged, and the page can say so
    without asking.
    """

    if action not in ACTIONS:
        raise SelectionProblem("Unknown action.")
    ids = tuple(dict.fromkeys(item.strip() for item in chosen if item.strip()))
    if not ids:
        raise SelectionProblem("Nothing is selected.")
    if any(not CERTIFICATE_ID.fullmatch(item) for item in ids):
        raise SelectionProblem("The selection contains something that is not a certificate ID.")
    if len(ids) > MAX_DELETE_BATCH:
        raise SelectionProblem(
            f"At most {MAX_DELETE_BATCH} certificates go in one job. Select fewer and run it twice."
        )
    missing = [identifier for identifier in ids if identifier not in registry]
    if missing:
        raise SelectionProblem("Not in the registry: " + ", ".join(missing) + ".")
    referenced = draft_references(drafts, ids)
    rows = tuple(
        Row(
            identifier,
            registry[identifier].source_label,
            tuple(t.name for t in registry[identifier].targets if t.kind == "cluster"),
            tuple(t.name for t in registry[identifier].targets if t.kind == "receiver"),
            referenced.get(identifier, ()),
        )
        for identifier in registry
        if identifier in ids
    )
    choices: list[Choice] = []
    for kind, names in (("cluster", clusters), ("receiver", receivers)):
        for name in names:
            holding = sum(
                1 for row in rows if name in (row.clusters if kind == "cluster" else row.receivers)
            )
            if action == "add" and holding == len(rows):
                continue
            if action == "remove" and holding == 0:
                continue
            choices.append(Choice(name, kind, holding))
    return Selection(action, rows, tuple(choices))


def payload(picked: Selection, clusters: Sequence[str], receivers: Sequence[str]) -> dict[str, Any]:
    """The job's payload for the targets ticked on the page: only offered ones count."""

    offered_clusters = {c.name for c in picked.choices if c.kind == "cluster"}
    offered_receivers = {c.name for c in picked.choices if c.kind == "receiver"}
    chosen_clusters = tuple(
        name
        for name in dict.fromkeys(clusters)
        if CLUSTER_ID.fullmatch(name) and name in offered_clusters
    )
    chosen_receivers = tuple(
        name
        for name in dict.fromkeys(receivers)
        if RECEIVER_ID.fullmatch(name) and name in offered_receivers
    )
    if not chosen_clusters and not chosen_receivers:
        raise SelectionProblem("Choose at least one target.")
    body: dict[str, Any] = {
        "certificates": list(picked.identifiers),
        "action": picked.action,
        "clusters": list(chosen_clusters),
        "receivers": list(chosen_receivers),
    }
    return body
