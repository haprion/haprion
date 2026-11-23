"""The files changed by hand in core/ and manual/, as the page draws them (B529).

The engine's reading is kept by the poller in `cluster_handwritten`; nothing
here reads a file or compares one. It turns the stored answer into the files,
the difference and the comment the page offers, and says plainly when there
is nothing to publish.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from haprion_ui import attention, version_changes
from haprion_ui.db import ClusterHandwritten

#
# The version's comment when the page is opened: what it publishes, by name.
#
COMMENT = "Handwritten changes: "
KINDS = {"new": "New", "changed": "Changed", "deleted": "Deleted"}


@dataclass(frozen=True, slots=True)
class Handwritten:
    """One cluster's reading: `state` is what the page leads with."""

    cluster: str
    #
    # pending, refused, clean; failed - the reading was tried and could not be
    # made (`message` says why); or unread - none was tried yet.
    #
    state: str
    head: str
    fingerprint: str
    files: tuple[tuple[str, str], ...]
    message: str
    comment: str
    changes: version_changes.ChangesView | None
    observed_at: Any


def _text(value: Any) -> str:
    return value if isinstance(value, str) else ""


def build(cluster: str, row: ClusterHandwritten | None) -> Handwritten:
    """The page's view of the stored reading; `unread` when none was made, `failed` when it could not be."""

    result = row.result if row is not None and row.outcome == "done" else {}
    state = _text(result.get("state"))
    state = state if state in {"pending", "refused", "clean"} else "unread"
    message = _text(result.get("message"))
    if row is not None and row.outcome != "done":
        said = row.error.get("message") if isinstance(row.error, Mapping) else None
        state = "failed"
        message = _text(said) or _text(row.poll_error) or "The helper did not answer."
    files = tuple(
        (_text(item.get("path")), KINDS.get(_text(item.get("kind")), _text(item.get("kind"))))
        for item in result.get("pending") or ()
        if isinstance(item, Mapping) and _text(item.get("path"))
    )
    diff = result.get("diff")
    return Handwritten(
        cluster=cluster,
        state=state,
        head=_text(result.get("head")),
        fingerprint=_text(result.get("fingerprint")),
        files=files,
        message=message,
        comment=COMMENT + attention.handwritten_files(result) if files else "",
        changes=version_changes.build(diff) if isinstance(diff, Mapping) else None,
        observed_at=row.observed_at if row is not None else None,
    )
