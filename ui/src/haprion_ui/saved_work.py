"""Saved work as the pages show it: drafts and saved changes settled against what was published (K01, review 2026-10-28).

An object's draft and saved layers live in the database until a publish
records them in a version; the poller's reading of the cluster's repository
says when that happened. What is settled here is which rows are still work,
which a publish has taken, and which a newer draft or change has replaced -
kept, never refused.
"""

from __future__ import annotations

import re
from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from fastapi import Request

from haprion_ui import (
    db,
    jobs,
    network,
    objects,
)
from haprion_ui.config import Config
from haprion_ui.reading import (
    NETWORK_SOURCE,
    SETTINGS_SOURCE,
    read_source,
)

#
# A commit as a form carries it, checked before it reaches a column that
# would refuse it with a database error instead of a sentence.
#
COMMIT_ID = re.compile(r"[0-9a-f]{40}")


@dataclass(frozen=True, slots=True)
class ObjectsReading:
    """What the objects cache holds for one cluster: the names, and the commit read."""

    names: Collection[str]
    commit: str | None = None


def objects_reading_of(row: Any, names: Collection[str] | None = None) -> ObjectsReading:
    """One cluster's objects cache row as `_reflects` reads it; `names` overrides the row's."""

    result = getattr(row, "result", None)
    commit = result.get("commit") if isinstance(result, Mapping) else None
    if names is None:
        names = {view.name for view in objects.cluster_object_views(row)} if row else set()
    return ObjectsReading(names, commit if isinstance(commit, str) and commit else None)


@dataclass(frozen=True, slots=True)
class DraftPublish:
    """A finished publish of one draft revision: the commit it was made against, and
    whether it changed anything."""

    base: str
    changed: bool | None


def _published_drafts(
    connection: Any, cluster: str, drafts: Iterable[db.ProxyDraft]
) -> dict[tuple[str, int], DraftPublish]:
    """Which draft revisions a finished publish has already carried away.

    Named by identity - the draft's own id and the revision that was published -
    and never by what the document says. Content matched a draft that had been
    edited back to a text published earlier, which is somebody deliberately
    reverting, and it deleted their work as though it were finished.

    Asked about these drafts and no others (CR-04): the newest twenty jobs were
    the evidence until 2026-10-06, and twenty later jobs made published work look
    unpublished.
    """

    ids = {str(draft.id) for draft in drafts if draft.id is not None}
    settled: dict[tuple[str, int], DraftPublish] = {}
    for job in db.draft_publishes(connection, cluster=cluster, draft_ids=ids):
        payload = job.payload if isinstance(job.payload, Mapping) else {}
        base = payload.get("expected_head")
        #
        # Every publish is queued with the commit it was made against; a job
        # without one is no evidence, and its row stays for the operator.
        #
        if not isinstance(base, str) or not base:
            continue
        changed = _publish_changed(job.result)
        for identity, revision in _carried(payload, "drafts"):
            settled.setdefault(
                (identity, revision),
                DraftPublish(base, changed if isinstance(changed, bool) else None),
            )
    return settled


def _publish_changed(result: Any) -> bool | None:
    """Whether a finished publish recorded a new version: the helper's `result.changed`.

    Read from inside the envelope, where the helper writes it. It was read from
    the envelope's top level until 2026-10-08, where it never is - so a publish
    that changed nothing kept its draft until some later commit moved the
    cache, and the tests built their jobs in the same wrong shape. A publish
    followed by a deploy in one job (B257) keeps its own answer under `publish`.
    """

    envelope = jobs.publish_answer(result)
    body = envelope.get("result") if envelope is not None else None
    changed = body.get("changed") if isinstance(body, Mapping) else None
    return changed if isinstance(changed, bool) else None


def _carried(payload: Mapping[str, Any], key: str) -> list[tuple[str, int]]:
    """The saved rows a publish of saved changes carried, under `drafts` or `changes` (B257)."""

    listed = payload.get(key)
    entries = listed if isinstance(listed, list) else []
    return [
        (entry["id"], entry["revision"])
        for entry in entries
        if isinstance(entry, Mapping)
        and isinstance(entry.get("id"), str)
        and isinstance(entry.get("revision"), int)
    ]


def _reflects(draft: db.ProxyDraft, publish: DraftPublish, reading: ObjectsReading) -> bool:
    """Whether the objects cache has caught up with what this draft published.

    A publish finishes before the poller reads the repository again, so between
    the two there is a stretch where the job is done and the cache still shows
    the object as it was. Clearing the draft on the job alone made the row
    vanish for that stretch, and in the editor it opened the old document in
    place of the published one (review 2026-10-04, CR-03).

    Decided by the commit. The publish was made against the commit the cache
    showed when it was queued, and the repository only moves forward, so a
    cache that has read any other commit has read this publish or a later one.
    A cache still at that commit has not - unless the publish changed nothing,
    and then presence is all there is to wait for: a new object, or a removal.
    """

    if reading.commit is None:
        return False
    if reading.commit != publish.base:
        return True
    if publish.changed is not False:
        return False
    return (
        (draft.object_id not in reading.names)
        if draft.deleted
        else (draft.object_id in reading.names)
    )


@dataclass(frozen=True, slots=True)
class ObjectWork:
    """What one object has besides its stored document (B257).

    A draft is unfinished and never published; a saved change goes out with
    the next publish. Both may exist - a draft started on top of a saved
    change - and what the editor opens is the top one.
    """

    draft: db.ProxyDraft | None = None
    saved: db.ProxyDraft | None = None

    @property
    def top(self) -> db.ProxyDraft | None:
        return self.draft or self.saved


def _settled_row(
    connection: Any, cluster: str, row: db.ProxyDraft, reading: ObjectsReading
) -> db.ProxyDraft | None:
    """One row, cleared away if its own publish has finished and can be read."""

    if not _shown_rows(connection, cluster, (row,), reading):
        #
        # Unpublished, or published and the cache has not caught up. The row
        # is the only thing that can carry the object until it does.
        #
        return row
    if not _discard_shown(connection, cluster, row):
        return db.read_draft(connection, cluster, row.object_id, row.stage)
    connection.commit()
    return None


def _shown_rows(
    connection: Any, cluster: str, rows: Sequence[db.ProxyDraft], reading: ObjectsReading
) -> set[tuple[str, str]]:
    """The rows - by object and stage - whose own publish is done and the reading shows.

    The one rule for clearing an object's draft or saved change, asked of one
    row by the editor and of a cluster's rows by the listings (review 26-10-08,
    F5): written twice, a fix to one copy left the other behind.
    """

    settled = _published_drafts(connection, cluster, rows)
    return {
        (row.object_id, row.stage)
        for row in rows
        if (publish := settled.get((str(row.id), row.revision))) is not None
        and _reflects(row, publish, reading)
    }


def _discard_shown(connection: Any, cluster: str, row: db.ProxyDraft) -> bool:
    """Delete one row its publish has carried; False when it was saved again since it was read.

    That row is the newer one and stays. The conflict is not caught by
    rolling back: it is a delete that matched no row, not a failed statement,
    so the transaction is still good - and a rollback would throw away the
    deletes a caller clearing several rows has already made. Uncaught, it took
    the whole listing down with it, a 500 for a tidying step that was allowed
    to change nothing.
    """

    try:
        db.discard_draft(
            connection,
            cluster=cluster,
            object_id=row.object_id,
            expected_revision=row.revision,
            stage=row.stage,
        )
    except db.DraftConflict:
        return False
    return True


def settled_work(
    connection: Any, cluster: str, object_id: str, reading: ObjectsReading
) -> ObjectWork:
    """One object's draft and saved change, each cleared away once its publish can be read.

    The editor reads this rather than the rows directly, and that is the case
    that matters most: the editor opens the top row in preference to the
    stored object, so a stale one would hand somebody their pre-publish copy
    of a document they have already published - and the next save would write
    it back.
    """

    rows = {
        stage: row
        for stage in (db.DRAFT, db.SAVED)
        if (row := db.read_draft(connection, cluster, object_id, stage)) is not None
    }
    settled = {
        stage: _settled_row(connection, cluster, row, reading) for stage, row in rows.items()
    }
    return ObjectWork(draft=settled.get(db.DRAFT), saved=settled.get(db.SAVED))


def settled_draft(
    connection: Any, cluster: str, object_id: str, reading: ObjectsReading
) -> db.ProxyDraft | None:
    """The top of one object's work: its draft, else its saved change, else None."""

    return settled_work(connection, cluster, object_id, reading).top


def top_layers(rows: Iterable[db.ProxyDraft]) -> list[db.ProxyDraft]:
    """One row per object, the one the editor would open: the draft over a saved change."""

    top: dict[str, db.ProxyDraft] = {}
    for row in rows:
        if row.object_id not in top or row.stage == db.DRAFT:
            top[row.object_id] = row
    return [top[name] for name in sorted(top)]


def settled_changes(
    connection: Any, cluster: str, heads: Mapping[str, str | None]
) -> dict[str, db.ClusterChange]:
    """This cluster's saved network and settings, each cleared once its own reading shows it (B257).

    `heads` holds the commit each kind's reading stands at - the network page's
    and the settings page's, the readings the document is drawn over. A kind
    not named there is kept as it is. Shown means the reading stands at the
    commit the publish recorded, or at a later version by the cached listing.
    Not "at another commit than the publish's base": the network, the settings
    and the objects are read by separate helper runs, and a reading that lags
    stands at an older commit than the base the package was published against
    (review 26-10-08, F3). A publish that changed nothing recorded the commit
    that was already there, so a reading at it has shown it.
    """

    changes = db.cluster_changes(connection, cluster)
    if not changes:
        return changes
    recorded: dict[tuple[str, int], tuple[str, int | None]] = {}
    ids = {str(change.id) for change in changes.values()}
    for job in db.change_publishes(connection, cluster=cluster, change_ids=ids):
        payload = job.payload if isinstance(job.payload, Mapping) else {}
        answer = _publish_recorded(job.result)
        if answer is None:
            continue
        for identity, revision in _carried(payload, "changes"):
            recorded.setdefault((identity, revision), answer)
    versions: dict[str, int] | None = None
    kept = dict(changes)
    for kind, change in changes.items():
        answer = recorded.get((str(change.id), change.revision))
        head = heads.get(kind)
        if answer is None or head is None:
            continue
        commit, version = answer
        if head != commit:
            if versions is None:
                versions = _listed_versions(connection, cluster)
            shown = versions.get(head)
            if shown is None or version is None or shown <= version:
                continue
        try:
            db.discard_cluster_change(
                connection, cluster=cluster, kind=kind, expected_revision=change.revision
            )
        except db.DraftConflict:
            #
            # Saved again between the read and the delete: that one is newer
            # and stays. No rollback, for the reason `_discard_shown` gives.
            #
            continue
        del kept[kind]
    connection.commit()
    return kept


def _publish_recorded(result: Any) -> tuple[str, int | None] | None:
    """The commit and version a finished publish recorded, from inside its envelope."""

    envelope = jobs.publish_answer(result)
    body = envelope.get("result") if envelope is not None else None
    if not isinstance(body, Mapping):
        return None
    commit, version = body.get("hash"), body.get("version")
    if not isinstance(commit, str) or not COMMIT_ID.fullmatch(commit):
        return None
    return commit, version if isinstance(version, int) and not isinstance(version, bool) else None


def _listed_versions(connection: Any, cluster: str) -> dict[str, int]:
    """Commit to version number, from the cluster's cached version listing."""

    history = db.cluster_history(connection, cluster)
    entries = history.result.get("versions") if history is not None else None
    numbers: dict[str, int] = {}
    for entry in entries if isinstance(entries, list) else ():
        if not isinstance(entry, Mapping):
            continue
        commit, number = entry.get("hash"), entry.get("version")
        if isinstance(commit, str) and isinstance(number, int) and not isinstance(number, bool):
            numbers[commit] = number
    return numbers


def reading_heads(request: Request, config: Config, cluster: str) -> dict[str, str | None]:
    """The commit the network and the settings readings of one cluster stand at."""

    _, network_rows = read_source(request, config, NETWORK_SOURCE, cluster=cluster)
    _, settings_rows = read_source(request, config, SETTINGS_SOURCE)
    return {
        "network": reading_head(next((r for r in network_rows if r.cluster == cluster), None)),
        "settings": reading_head(
            next((r for r in settings_rows if r.cluster == cluster and r.outcome == "done"), None)
        ),
    }


def reading_head(row: Any) -> str | None:
    result = getattr(row, "result", None)
    head = result.get("head") if isinstance(result, Mapping) else None
    return head if isinstance(head, str) and head else None


def saved_network_rows(
    connection: Any, rows: Sequence[db.ClusterNetwork]
) -> tuple[list[db.ClusterNetwork], dict[str, db.ClusterChange]]:
    """The network readings with each cluster's saved description over them, and those saves."""

    saved: dict[str, db.ClusterChange] = {}
    for row in rows:
        change = settled_changes(connection, row.cluster, {"network": reading_head(row)}).get(
            "network"
        )
        if change is not None:
            saved[row.cluster] = change
    return (
        network.with_saved(rows, {cluster: change.document for cluster, change in saved.items()}),
        saved,
    )


def settled_drafts(connection: Any, cluster: str, reading: ObjectsReading) -> list[db.ProxyDraft]:
    """This cluster's drafts, with the ones already published cleared away.

    Published work is not a draft any more. Left behind it is worse than untidy:
    the editor opens the draft in preference to the stored object, so a stale
    row would hand somebody yesterday's copy of a document they published.

    Done here and not in the worker because only the web role may touch this
    table - the privilege split keeps the worker out of it on purpose, and it
    publishes from the job payload rather than from the row. So the clearing
    happens the next time the interface reads, which is a write during a read
    and deliberately a narrow one: it deletes nothing but a draft whose own
    publish is recorded as done.
    """

    drafts = db.cluster_drafts(connection, cluster)
    published = _shown_rows(connection, cluster, drafts, reading)
    if not published:
        return drafts
    #
    # Counted rather than assumed, because the rows returned below have to
    # match what the table now holds.
    #
    kept = {
        (draft.object_id, draft.stage)
        for draft in drafts
        if (draft.object_id, draft.stage) in published
        and not _discard_shown(connection, cluster, draft)
    }
    connection.commit()
    return [
        draft
        for draft in drafts
        if (key := (draft.object_id, draft.stage)) not in published or key in kept
    ]
