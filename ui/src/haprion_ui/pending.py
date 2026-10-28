"""What waits to be published: a cluster's package of saved changes (K01, review 2026-10-28).

The dashboard's count and the publish dialog's list come from here: every
saved object, network and settings change not yet in a published version,
the backends a publish renames, the servers held in drain or maintenance, and
the key that makes a second click on Publish the same request as the first.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
from typing import Any
from uuid import UUID, uuid5

from fastapi import Request
from haprion.cli import changes_publish
from haprion.config import ConfigError
from haprion.managed_network import load_document as load_network_document
from haprion.managed_network import location as network_location
from haprion.objects import objects_result
from haprion.proxy_model import (
    ModelError,
    load_proxy,
)

from haprion_ui import (
    db,
    health,
    held_servers,
    metrics,
    network,
    objects,
)
from haprion_ui.config import Config
from haprion_ui.editor_flow import (
    EditorState,
    editor_state,
    object_moved,
    proxy_path,
    removal_bookkeeping,
    state_reading,
)
from haprion_ui.reading import (
    NETWORK_SOURCE,
    OBJECTS_SOURCE,
    read_source,
)
from haprion_ui.saved_work import (
    objects_reading_of,
    reading_heads,
    settled_changes,
    settled_drafts,
)


@dataclass(frozen=True, slots=True)
class PendingRow:
    """One saved change waiting for the next publish, as the Versions page lists it."""

    kind: str
    name: str
    what: str
    updated_by: str
    updated_at: datetime
    link: str
    #
    # Published as it is, it could put back what a newer version changed, so
    # the package is refused until it is saved again over what is there now
    # (B257). Since 0080 that is a row whose object was changed after it was
    # written (`moved`); a row from before can only say it was saved against
    # a version that is no longer the newest.
    #
    stale: bool
    moved: bool = False
    #
    # What a saved network description changes and who it reaches (B277):
    # one line per VIP, source or group, under the row.
    #
    details: tuple[network.NetworkChange, ...] = ()


@dataclass(frozen=True, slots=True)
class Package:
    """A cluster's saved changes, and the publish that would carry them (B257)."""

    cluster: str
    head: str | None
    rows: tuple[PendingRow, ...]
    payload: dict[str, Any]
    problem: str
    #
    # A network description or settings whose reading stands at another
    # version than the objects': the package waits for the poller, and the
    # Versions page asks for itself again until it has (review 26-10-24, 12-14).
    #
    lagging: tuple[str, ...] = ()

    @property
    def identity(self) -> str:
        """The list as it was shown, as one value the publish form carries back (R1, 2026-10-08).

        The version it was saved against, and every saved row and document by
        its identity and revision: a row saved in another tab, saved again or
        removed since the page was drawn gives another value, while the head
        alone stays the same until something is published. Revisions and not
        content, as the clearing reads them, so the value says nothing a
        reader of the page could not already see.
        """

        def carried(key: str) -> list[list[Any]]:
            entries = self.payload.get(key) or []
            return sorted([entry["id"], entry["revision"]] for entry in entries)

        shown = {
            "cluster": self.cluster,
            "head": self.head,
            "drafts": carried("drafts"),
            "changes": carried("changes"),
        }
        encoded = json.dumps(shown, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


def held_server_counts(
    request: Request, config: Config, clusters: Iterable[str], status_rows: Iterable[Any]
) -> dict[str, held_servers.HeldServers]:
    """Each cluster's servers in drain or maintenance, by object.

    The objects are read only for a cluster where a node holds a server: telling
    a pool's owner needs them, and at ten thousand objects that read is the
    cost of the whole dashboard (2026-10-01) for a line that is usually absent.
    """

    rows = list(status_rows)
    held = {
        cluster: found
        for cluster in clusters
        if (found := held_servers.held_backends(rows, cluster=cluster))
    }
    if not held:
        return {}
    _, object_rows = read_source(request, config, OBJECTS_SOURCE)
    stored = {reading.cluster: reading for reading in object_rows}
    counted = {
        cluster: held_servers.by_object(
            found, health.backend_owners(objects.cluster_object_views(stored.get(cluster)))
        )
        for cluster, found in held.items()
    }
    return {cluster: found for cluster, found in counted.items() if found is not None}


def pending_count(request: Request, config: Config, cluster: str) -> int:
    """How many saved changes one cluster has, each cleared once its publish is read (B257)."""

    _, object_rows = read_source(request, config, OBJECTS_SOURCE, cluster=cluster)
    objects_row = next((row for row in object_rows if row.cluster == cluster), None)
    heads = reading_heads(request, config, cluster)
    with request.app.state.pool.connection() as connection:
        saved = [
            row
            for row in settled_drafts(connection, cluster, objects_reading_of(objects_row))
            if row.stage == db.SAVED
        ]
        changes = settled_changes(connection, cluster, heads)
    return len(saved) + len(changes)


def pending_package(request: Request, config: Config, cluster: str) -> Package:
    """Everything saved for one cluster, as rows and as one `changes_publish` payload.

    Drafts are not part of it: they are unfinished. A saved row whose base is
    not the newest version makes the whole package wait, and says which; the
    objects' bookkeeping (removed backends, renamed pools) is what one
    object's publish carried, for every object at once.
    """

    state = editor_state(request, config, cluster)
    head = state.commit
    heads = reading_heads(request, config, cluster)
    with request.app.state.pool.connection() as connection:
        saved = [
            row
            for row in settled_drafts(connection, cluster, state_reading(state))
            if row.stage == db.SAVED
        ]
        changes = settled_changes(connection, cluster, heads)
    rows: list[PendingRow] = []
    objects: dict[str, str | None] = {}
    published = {view.name for view in state.stored}
    for row in saved:
        moved = object_moved(state, row)
        objects[row.object_id] = None if row.deleted else row.yaml
        if row.replaces and not row.deleted:
            objects.setdefault(row.replaces, None)
        rows.append(
            PendingRow(
                kind="object",
                name=row.object_id,
                what=(
                    "Removal"
                    if row.deleted
                    else f"Renamed from {row.replaces}"
                    if row.replaces
                    else "Changed"
                    if row.object_id in published
                    else "New"
                ),
                updated_by=row.updated_by,
                updated_at=row.updated_at,
                link=proxy_path(cluster, row.object_id, "edit"),
                stale=moved or (row.base_document is None and row.base_hash != head),
                moved=moved,
            )
        )
    #
    # A network description or settings saved over its own page's reading,
    # which another helper run makes than the objects' (review 26-10-08, F3).
    # While that reading stands at another version than the objects', the save
    # cannot be told stale from current, and the package waits for it rather
    # than send somebody to save again over the same lagging page.
    #
    lagging: list[str] = []
    for kind, label, link in (
        ("network", "Network description", "/network"),
        ("settings", "Logs & metrics", f"/settings/clusters/{cluster}"),
    ):
        change = changes.get(kind)
        if change is not None:
            if heads.get(kind) != head:
                lagging.append(label)
            rows.append(
                PendingRow(
                    kind=kind,
                    name=label,
                    #
                    # Every object's lines are the cluster's settings; said,
                    # since the row names no object (B277).
                    #
                    what=(
                        "Changed · applies to every proxy on the cluster"
                        if kind == "settings"
                        else "Changed"
                    ),
                    updated_by=change.updated_by,
                    updated_at=change.updated_at,
                    link=link,
                    stale=heads.get(kind) == head and change.base_hash != head,
                    details=(
                        _network_changes(request, config, cluster, change.document, state, saved)
                        if kind == "network"
                        else ()
                    ),
                )
            )
    payload: dict[str, Any] = {"expected_head": head or ""}
    if objects:
        payload["objects"] = objects
        payload["drafts"] = [{"id": str(row.id), "revision": row.revision} for row in saved]
        payload.update(removal_bookkeeping(state.stored, objects))
        renamed: dict[str, str] = {}
        introduced: list[str] = []
        for row in saved:
            if row.deleted:
                continue
            more, new = _backend_renames(
                state.stored, row.object_id, row.yaml, row.replaces or row.object_id
            )
            renamed.update(more)
            introduced.extend(name for name in new if name not in introduced)
        if renamed or introduced:
            payload["backend_renames"] = {"renamed": renamed, "introduced": introduced}
    for kind in ("network", "settings"):
        if kind in changes:
            payload[kind] = changes[kind].document
    if changes:
        payload["changes"] = [
            {"id": str(change.id), "revision": change.revision}
            for change in sorted(changes.values(), key=lambda change: change.kind)
        ]
    stale = [row.name for row in rows if row.stale and not row.moved]
    changed = [row.name for row in rows if row.moved]
    problem = (
        "The stored proxies have not been read yet."
        if head is None
        else f"{', '.join(changed)} {'was' if len(changed) == 1 else 'were'} changed by a "
        f"publish after the changes were saved. Open {'it' if len(changed) == 1 else 'each'} "
        "to save over that or discard the changes."
        if changed
        else f"{', '.join(stale)} {'was' if len(stale) == 1 else 'were'} saved against an "
        "older version. Open and save again before publishing."
        if stale
        else f"{' and '.join(lagging)} {'is' if len(lagging) == 1 else 'are'} still being read "
        "at the newest version. Publishing opens again within a minute."
        if lagging
        else f"{len(objects)} proxies; at most {changes_publish.MAX_OBJECTS} go in one publish."
        if len(objects) > changes_publish.MAX_OBJECTS
        else ""
    )
    return Package(
        cluster=cluster,
        head=head,
        rows=tuple(rows),
        payload=payload,
        problem=problem,
        lagging=tuple(lagging),
    )


def _network_changes(
    request: Request,
    config: Config,
    cluster: str,
    document: str,
    state: EditorState,
    saved_objects: Sequence[Any],
) -> tuple[network.NetworkChange, ...]:
    """What the saved network description changes against the published one (B277).

    Read against the cluster's own reading, which is the published
    description. Its users are the objects as this publish leaves them: the
    published ones with the saved ones in their place, read by the engine's
    own object listing against the saved description - so an object moved off
    a removed VIP in the same publish is not said to block it (26-10-11).
    Nothing when either cannot be read: a line that guessed would be worse
    than none.
    """

    _, rows = read_source(request, config, NETWORK_SOURCE, cluster=cluster)
    reading = next((row for row in rows if row.cluster == cluster), None)
    if reading is None or reading.outcome != "done" or not isinstance(reading.result, Mapping):
        return ()
    saved = network.result_from_document(document, reading.result)
    if saved is None:
        return ()
    documents = {view.name: view.document for view in state.stored}
    for row in saved_objects:
        if row.replaces and row.replaces != row.object_id:
            documents.pop(row.replaces, None)
        if row.deleted:
            documents.pop(row.object_id, None)
        else:
            documents[row.object_id] = row.yaml
    ownership = reading.result.get("ownership_vip")
    try:
        parsed = load_network_document(
            document.encode("utf-8"),
            ownership_vip=str(ownership) if ownership else "",
            location=network_location(),
        )
    except ConfigError:
        return ()
    listed: Any = objects_result(
        {f"managed/proxies/{name}.yaml": text.encode("utf-8") for name, text in documents.items()},
        None if not documents else "0" * 40,
        network=parsed,
    )["objects"]
    after = [view for view in map(objects.object_view, listed) if view is not None]
    return network.changes(reading.result, saved, network.usage(after))


def _backend_renames(
    stored: Sequence[objects.ObjectView], name: str, document: str, before_name: str
) -> tuple[dict[str, str], list[str]]:
    """What a publish renames, and what names it brings into use (`metrics.renamed_backends`).

    Nothing without the stored objects to compare with: every name would look
    new, and closing them all would cut the history of backends that were
    never renamed.
    """

    if not stored:
        return {}, []
    views = {view.name: view for view in stored}
    try:
        after = load_proxy(name, document.encode())
    except ModelError:
        return {}, []
    previous = views.get(before_name)
    before = None
    if previous is not None:
        try:
            before = load_proxy(before_name, previous.document.encode())
        except ModelError:
            before = None
    return metrics.renamed_backends(before, after)


#
# Fixed, and never regenerated. It turns a publish's identity - the cluster, the
# object and the draft revision being published - into the idempotency key the
# job table compares against, so a double-click or a refresh is the same request
# rather than a second publish of the same work.
#
PUBLISH_NAMESPACE = UUID("6f1d5f8e-1a2b-4c3d-8e9f-0a1b2c3d4e5f")


def publish_key(cluster: str, operation: str, payload: Mapping[str, Any], *, drawn: UUID) -> UUID:
    """The idempotency key one request is asked under: the form's key and a digest of the request.

    Derived from everything the job will carry, and that is the whole point.
    The queue treats a repeated key as a retry only when the payload hashes the
    same, so a key covering less than the payload can be handed two different
    requests - and it answers the second with "already asked for with different
    content", permanently, for a publish somebody is looking at.

    That is what happened. The key was derived from cluster, object and
    document while the payload also carried `expected_head`, so the same
    document published again after the tree had moved was one key with two
    contents and could never be published again.

    Deriving it from the payload makes the two agree by construction rather
    than by remembering to add each new field here. A double-click is the same
    request because it is the same bytes; anything else is another request.

    And `drawn`, the key the form was drawn with, as every other form carries.
    A publish that failed, or was blocked by a locked cluster, kept its job row
    and so its key: the same list and comment sent again - from a page drawn
    afresh, after the cause was fixed - was answered with the old job and
    "Publishing..." while nothing was queued (review 2026-10-22, 1B-1).
    """

    #
    # Sorted keys, because a mapping's order is not part of what was asked and
    # two orderings of one request must not be two requests.
    #
    body = json.dumps(
        {"cluster": cluster, "operation": operation, "payload": payload, "drawn": str(drawn)},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return uuid5(PUBLISH_NAMESPACE, sha256(body.encode("utf-8")).hexdigest())
