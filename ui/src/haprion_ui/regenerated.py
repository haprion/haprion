"""What publishing a cluster again would change, as the page draws it (0.99.11).

The engine's answer is kept by the poller in `cluster_regeneration`; nothing
here compares anything. It only turns the stored answer into the words, the
per-object list and the diff the page shows, and says plainly when there is
nothing to show.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from haprion import proxy_model
from haprion.config import CLUSTER_ID
from haprion_ui import attention, version_changes
from haprion_ui.db import ClusterRegeneration

#
# What a part of an object is called where an operator reads it.
#
PARTS = {
    "backends": "backends",
    "routing": "routing",
    "listener": "listener",
    "certificate": "certificate",
}
CHANGES = {"changed": "Changed", "absent": "No longer generated"}


@dataclass(frozen=True, slots=True)
class ObjectChange:
    name: str
    change: str
    parts: str
    #
    # The object's page, which every role may open; none for a name that is no
    # object's (the reading is the engine's text, and a link is built from
    # names the pages accept only).
    #
    link: str = ""


@dataclass(frozen=True, slots=True)
class Regenerated:
    """One cluster's answer: `state` is what the page leads with."""

    cluster: str
    #
    # changed, refused, unchanged, unpublished; failed - the reading was tried and
    # could not be made (`message` says why); or unread - none was tried yet.
    #
    state: str
    fingerprint: str
    published_commit: str
    installed_version: str
    message: str
    causes: tuple[str, ...]
    objects: tuple[ObjectChange, ...]
    files_changed: int
    changes: version_changes.ChangesView | None
    observed_at: Any


def _failure(row: ClusterRegeneration) -> str:
    """Why the reading could not be made, in the words the poller kept."""

    said = row.error.get("message") if isinstance(row.error, Mapping) else None
    return _text(said) or _text(row.poll_error) or "The helper did not answer."


def _text(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _object_link(cluster: str, name: str) -> str:
    if CLUSTER_ID.fullmatch(cluster) and proxy_model.NAME.fullmatch(name):
        return f"/proxies/{cluster}/{name}"
    return ""


def build(cluster: str, row: ClusterRegeneration | None) -> Regenerated:
    """The page's view of the stored reading; `unread` when none was made, `failed` when it could not be."""

    result = row.result if row is not None and row.outcome == "done" else {}
    outcome = _text(result.get("outcome"))
    state = outcome if outcome in {"changed", "refused", "unchanged", "unpublished"} else "unread"
    message = _text(result.get("message"))
    if row is not None and row.outcome != "done":
        state, message = "failed", _failure(row)
    causes = tuple(
        said
        for cause in result.get("causes") or ()
        if isinstance(cause, Mapping) and (said := attention.regeneration_cause(cause))
    )
    objects = tuple(
        ObjectChange(
            name=_text(entry.get("name")),
            change=CHANGES.get(_text(entry.get("change")), _text(entry.get("change"))),
            parts=", ".join(PARTS.get(part, str(part)) for part in entry.get("parts") or ()),
            link=_object_link(cluster, _text(entry.get("name"))),
        )
        for entry in result.get("objects") or ()
        if isinstance(entry, Mapping) and _text(entry.get("name"))
    )
    files = result.get("files_changed")
    diff = result.get("diff")
    return Regenerated(
        cluster=cluster,
        state=state,
        fingerprint=_text(result.get("fingerprint")),
        published_commit=_text(result.get("published_commit")),
        installed_version=_text(result.get("installed_version")),
        message=message,
        causes=causes,
        objects=objects,
        files_changed=files if isinstance(files, int) and not isinstance(files, bool) else 0,
        changes=version_changes.build(diff) if isinstance(diff, Mapping) else None,
        observed_at=row.observed_at if row is not None else None,
    )
