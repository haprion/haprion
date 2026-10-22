"""Saved changes: proxy drafts and cluster changes waiting to be published."""

from __future__ import annotations

from collections.abc import Collection
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

import psycopg
from psycopg import Connection
from psycopg.rows import class_row

from haprion_ui.db.jobs import Job


@dataclass(frozen=True, slots=True)
class ProxyDraft:
    """One object being edited, and what it was edited against.

    `base_hash` is the commit the draft was derived from; a publish compares
    its snapshot to it, so a draft made against a tree that has since moved is
    refused rather than applied to something else. `revision` is the database's
    own counter, raised by a trigger on every write, and it is what tells two
    tabs apart.

    `deleted` means the draft asks for the object to be *removed* when it is
    published. It is not a discarded draft - discarding one deletes the row,
    because an abandoned edit should leave nothing behind to be mistaken for a
    decision.
    """

    cluster: str
    object_id: str
    yaml: str
    base_version: int | None
    base_hash: str
    revision: int
    updated_by: str
    updated_at: datetime
    deleted: bool
    #
    # Set by the database and never by the caller. A draft is deleted once its
    # publish is done, so the next edit of the same object starts again at
    # revision 1 under the same key - and this is what tells the two apart. The
    # job that publishes a draft names it, and the row that appears afterwards
    # is visibly not the row that was published.
    #
    id: UUID | None = None
    #
    # B257: a *draft* is unfinished and never published; a *saved* change goes
    # out with the next publish. One of each may exist for an object - a draft
    # on top of a saved change - and the stage is part of the key.
    #
    stage: str = "draft"
    #
    # The published name this object takes the place of, for a rename. Kept on
    # the row so the publish that carries it removes the old name as well,
    # whenever that publish happens.
    #
    replaces: str | None = None
    #
    # The object as it was published when this row was written (0080): its
    # document, or empty where nothing of that name was published. What tells
    # a draft whose object moved from one the cluster merely moved past. None
    # on rows from before, which only `base_hash` can judge.
    #
    base_document: str | None = None


DRAFT = "draft"


SAVED = "saved"


class DraftConflict(Exception):
    """Somebody else wrote this draft since it was read.

    The revision the caller carried is not the one in the table. Refused rather
    than merged: the two edits are both somebody's intention, and picking one
    silently is how the other disappears without anyone noticing.
    """


def cluster_drafts(connection: Connection[Any], cluster: str) -> list[ProxyDraft]:
    """Every draft and saved change for one cluster, in the order a listing shows objects."""

    with connection.cursor(row_factory=class_row(ProxyDraft)) as cursor:
        cursor.execute(
            "select id, cluster, object_id, yaml, base_version, base_hash, revision, "
            "       updated_by, updated_at, deleted, stage, replaces, base_document "
            "  from proxy_draft "
            " where cluster = %(cluster)s "
            " order by object_id, stage",
            {"cluster": cluster},
        )
        return cursor.fetchall()


def live_drafts(connection: Connection[Any]) -> list[ProxyDraft]:
    """Every draft and saved change in every cluster that still asks for an object to exist.

    A row marked `deleted` asks for its object to go and names nothing a
    deletion has to respect, so it is left out here rather than filtered by
    every caller.
    """

    with connection.cursor(row_factory=class_row(ProxyDraft)) as cursor:
        cursor.execute(
            "select id, cluster, object_id, yaml, base_version, base_hash, revision, "
            "       updated_by, updated_at, deleted, stage, replaces, base_document "
            "  from proxy_draft "
            " where not deleted "
            " order by cluster, object_id, stage"
        )
        return cursor.fetchall()


def read_draft(
    connection: Connection[Any], cluster: str, object_id: str, stage: str = DRAFT
) -> ProxyDraft | None:
    """One draft or saved change, or None where the object has none of that stage."""

    with connection.cursor(row_factory=class_row(ProxyDraft)) as cursor:
        cursor.execute(
            "select id, cluster, object_id, yaml, base_version, base_hash, revision, "
            "       updated_by, updated_at, deleted, stage, replaces, base_document "
            "  from proxy_draft "
            " where cluster = %(cluster)s and object_id = %(object_id)s "
            "   and stage = %(stage)s",
            {"cluster": cluster, "object_id": object_id, "stage": stage},
        )
        return cursor.fetchone()


def save_draft(
    connection: Connection[Any],
    *,
    cluster: str,
    object_id: str,
    yaml: str,
    base_version: int | None,
    base_hash: str,
    updated_by: str,
    base_document: str | None,
    deleted: bool = False,
    replaces: str | None = None,
    expected_revision: int | None,
) -> ProxyDraft:
    """Create or replace one draft, refusing a write the caller did not see.

    A draft only: a saved change is written by `save_change`, which also
    takes the draft it was finished from out of the way.

    `expected_revision` is None for a draft that should not exist yet and the
    revision the caller read for one that should. Both are enforced by the
    statement rather than by a check-then-write: a read followed by a write is
    two moments, and the interesting case is precisely somebody writing between
    them.

    The insert therefore carries `on conflict do nothing` and the update
    carries the revision in its `where`, so a row that changed underneath
    matches nothing and comes back as a conflict instead of an overwrite.
    """

    values = {
        "cluster": cluster,
        "object_id": object_id,
        "yaml": yaml,
        "base_version": base_version,
        "base_hash": base_hash,
        "updated_by": updated_by,
        "deleted": deleted,
        "replaces": replaces,
        "base_document": base_document,
        "revision": expected_revision,
    }
    with connection.transaction(), connection.cursor(row_factory=class_row(ProxyDraft)) as cursor:
        if expected_revision is None:
            cursor.execute(
                "insert into proxy_draft "
                "       (cluster, object_id, yaml, base_version, base_hash, updated_by, deleted, "
                "        replaces, base_document, stage) "
                "values (%(cluster)s, %(object_id)s, %(yaml)s, %(base_version)s, "
                "        %(base_hash)s, %(updated_by)s, %(deleted)s, %(replaces)s, "
                "        %(base_document)s, 'draft') "
                "on conflict do nothing "
                "returning id, cluster, object_id, yaml, base_version, base_hash, revision, "
                "          updated_by, updated_at, deleted, stage, replaces, base_document",
                values,
            )
        else:
            cursor.execute(
                "update proxy_draft "
                "   set yaml = %(yaml)s, base_version = %(base_version)s, "
                "       base_hash = %(base_hash)s, updated_by = %(updated_by)s, "
                "       deleted = %(deleted)s, replaces = %(replaces)s, "
                "       base_document = %(base_document)s "
                " where cluster = %(cluster)s and object_id = %(object_id)s "
                "   and stage = 'draft' and revision = %(revision)s "
                "returning id, cluster, object_id, yaml, base_version, base_hash, revision, "
                "          updated_by, updated_at, deleted, stage, replaces, base_document",
                values,
            )
        row = cursor.fetchone()
        if row is None:
            raise DraftConflict(
                f"the draft for {object_id} changed since it was read; reload it and try again"
            )
        return row


def save_change(
    connection: Connection[Any],
    *,
    cluster: str,
    object_id: str,
    new_object_id: str | None = None,
    yaml: str,
    base_version: int | None,
    base_hash: str,
    updated_by: str,
    base_document: str | None,
    deleted: bool = False,
    replaces: str | None = None,
    saved_revision: int | None,
    draft_revision: int | None,
) -> ProxyDraft:
    """Write one object's saved change, and drop the draft it was finished from (B257).

    One transaction, so a conflict on any part leaves all of it as it was:
    the draft the person was looking at is removed (`draft_revision`, None
    when there is none), and the saved change is written - inserted when
    `saved_revision` is None, updated at that revision otherwise. A rename
    moves the saved row's key to `new_object_id`; a name already taken fails
    on the key rather than on a check that raced.

    Each part is held to the revision the caller read, as `save_draft` holds
    its one row, and for the same reason.
    """

    target = new_object_id or object_id
    values = {
        "cluster": cluster,
        "object_id": object_id,
        "target": target,
        "yaml": yaml,
        "base_version": base_version,
        "base_hash": base_hash,
        "updated_by": updated_by,
        "deleted": deleted,
        "replaces": replaces,
        "base_document": base_document,
        "saved_revision": saved_revision,
        "draft_revision": draft_revision,
    }
    stale = f"the changes to {object_id} changed since they were read; reload and try again"
    with connection.transaction(), connection.cursor(row_factory=class_row(ProxyDraft)) as cursor:
        if draft_revision is not None:
            cursor.execute(
                "delete from proxy_draft "
                " where cluster = %(cluster)s and object_id = %(object_id)s "
                "   and stage = 'draft' and revision = %(draft_revision)s",
                values,
            )
            if cursor.rowcount == 0:
                raise DraftConflict(stale)
        try:
            if saved_revision is None:
                cursor.execute(
                    "insert into proxy_draft "
                    "       (cluster, object_id, yaml, base_version, base_hash, updated_by, "
                    "        deleted, replaces, base_document, stage) "
                    "values (%(cluster)s, %(target)s, %(yaml)s, %(base_version)s, "
                    "        %(base_hash)s, %(updated_by)s, %(deleted)s, %(replaces)s, "
                    "        %(base_document)s, 'saved') "
                    "on conflict do nothing "
                    "returning id, cluster, object_id, yaml, base_version, base_hash, revision, "
                    "          updated_by, updated_at, deleted, stage, replaces, base_document",
                    values,
                )
            else:
                cursor.execute(
                    "update proxy_draft "
                    "   set object_id = %(target)s, yaml = %(yaml)s, "
                    "       base_version = %(base_version)s, base_hash = %(base_hash)s, "
                    "       updated_by = %(updated_by)s, deleted = %(deleted)s, "
                    "       replaces = %(replaces)s, base_document = %(base_document)s "
                    " where cluster = %(cluster)s and object_id = %(object_id)s "
                    "   and stage = 'saved' and revision = %(saved_revision)s "
                    "returning id, cluster, object_id, yaml, base_version, base_hash, revision, "
                    "          updated_by, updated_at, deleted, stage, replaces, base_document",
                    values,
                )
        except psycopg.errors.UniqueViolation as clash:
            raise DraftConflict(
                f"{target} already has saved changes in this cluster; "
                f"the rename would replace somebody's work"
            ) from clash
        row = cursor.fetchone()
        if row is None:
            raise DraftConflict(
                f"{target} already has saved changes in this cluster"
                if saved_revision is None and target != object_id
                else stale
            )
        return row


def rename_draft(
    connection: Connection[Any],
    *,
    cluster: str,
    object_id: str,
    new_object_id: str,
    yaml: str,
    base_version: int | None,
    base_hash: str,
    updated_by: str,
    base_document: str | None,
    replaces: str | None = None,
    expected_revision: int,
) -> ProxyDraft:
    """Move one draft to another name, as a change of its key.

    A rename is not a new draft and a removal of the old one. Written that way
    it is two writes, and `save_draft` commits its own transaction - so a
    conflict on the second left the first standing and the person had two
    drafts where they had made one, which is precisely how this was found.

    One statement instead. The stage is part of the key, so the move either
    happens or does not, and a name already taken fails on the key rather
    than on a check that raced. The row keeps its `id`: it is the same piece
    of work, and the publish that eventually carries it should be able to
    say so.
    """

    values = {
        "cluster": cluster,
        "object_id": object_id,
        "new_object_id": new_object_id,
        "yaml": yaml,
        "base_version": base_version,
        "base_hash": base_hash,
        "updated_by": updated_by,
        "replaces": replaces,
        "base_document": base_document,
        "revision": expected_revision,
    }
    with connection.transaction(), connection.cursor(row_factory=class_row(ProxyDraft)) as cursor:
        try:
            cursor.execute(
                "update proxy_draft "
                "   set object_id = %(new_object_id)s, yaml = %(yaml)s, "
                "       base_version = %(base_version)s, base_hash = %(base_hash)s, "
                "       updated_by = %(updated_by)s, replaces = %(replaces)s, "
                "       base_document = %(base_document)s "
                " where cluster = %(cluster)s and object_id = %(object_id)s "
                "   and stage = 'draft' and revision = %(revision)s "
                "returning id, cluster, object_id, yaml, base_version, base_hash, revision, "
                "          updated_by, updated_at, deleted, stage, replaces, base_document",
                values,
            )
        except psycopg.errors.UniqueViolation as clash:
            raise DraftConflict(
                f"{new_object_id} already has a draft in this cluster; "
                f"the rename would replace somebody's work"
            ) from clash
        row = cursor.fetchone()
        if row is None:
            raise DraftConflict(
                f"the draft for {object_id} changed since it was read; reload it and try again"
            )
        return row


def discard_draft(
    connection: Connection[Any],
    *,
    cluster: str,
    object_id: str,
    expected_revision: int,
    stage: str = DRAFT,
) -> None:
    """Throw one draft or saved change away, and only the revision the caller was looking at.

    A real delete rather than a flag. An abandoned edit that stayed in the table
    would be indistinguishable from a decision to remove the object, which is
    what `deleted` means and what this is not.
    """

    with connection.cursor() as cursor:
        cursor.execute(
            "delete from proxy_draft "
            " where cluster = %(cluster)s and object_id = %(object_id)s "
            "   and stage = %(stage)s and revision = %(revision)s",
            {
                "cluster": cluster,
                "object_id": object_id,
                "stage": stage,
                "revision": expected_revision,
            },
        )
        if cursor.rowcount == 0:
            raise DraftConflict(
                f"the saved changes to {object_id} changed since they were read; "
                "reload them and try again"
                if stage == SAVED
                else f"the draft for {object_id} changed since it was read; reload it and try again"
            )


@dataclass(frozen=True, slots=True)
class ClusterChange:
    """A cluster's saved network description or settings, before a publish (B257).

    The whole document, saved the way a proxy object's change is: written
    here, published with the next publish, and cleared once that publish can
    be read.
    """

    cluster: str
    kind: str
    document: str
    base_hash: str
    revision: int
    updated_by: str
    updated_at: datetime
    id: UUID


CHANGE_KINDS = ("network", "settings")


def cluster_changes(connection: Connection[Any], cluster: str) -> dict[str, ClusterChange]:
    """This cluster's saved network description and settings, by kind."""

    with connection.cursor(row_factory=class_row(ClusterChange)) as cursor:
        cursor.execute(
            "select cluster, kind, document, base_hash, revision, updated_by, updated_at, id "
            "  from cluster_change "
            " where cluster = %(cluster)s",
            {"cluster": cluster},
        )
        return {row.kind: row for row in cursor.fetchall()}


def save_cluster_change(
    connection: Connection[Any],
    *,
    cluster: str,
    kind: str,
    document: str,
    base_hash: str,
    updated_by: str,
    expected_revision: int | None,
) -> ClusterChange:
    """Create or replace one saved document, refusing a write the caller did not see.

    The same rule as `save_draft`: None for a document that should not exist
    yet, the revision read for one that should, both enforced by the statement.
    """

    values = {
        "cluster": cluster,
        "kind": kind,
        "document": document,
        "base_hash": base_hash,
        "updated_by": updated_by,
        "revision": expected_revision,
    }
    with (
        connection.transaction(),
        connection.cursor(row_factory=class_row(ClusterChange)) as cursor,
    ):
        if expected_revision is None:
            cursor.execute(
                "insert into cluster_change (cluster, kind, document, base_hash, updated_by) "
                "values (%(cluster)s, %(kind)s, %(document)s, %(base_hash)s, %(updated_by)s) "
                "on conflict do nothing "
                "returning cluster, kind, document, base_hash, revision, updated_by, "
                "          updated_at, id",
                values,
            )
        else:
            cursor.execute(
                "update cluster_change "
                "   set document = %(document)s, base_hash = %(base_hash)s, "
                "       updated_by = %(updated_by)s "
                " where cluster = %(cluster)s and kind = %(kind)s "
                "   and revision = %(revision)s "
                "returning cluster, kind, document, base_hash, revision, updated_by, "
                "          updated_at, id",
                values,
            )
        row = cursor.fetchone()
        if row is None:
            raise DraftConflict(
                f"the saved {kind} of {cluster} changed since it was read; reload and try again"
            )
        return row


def discard_cluster_change(
    connection: Connection[Any], *, cluster: str, kind: str, expected_revision: int
) -> None:
    """Throw one saved document away, and only the revision the caller was looking at."""

    with connection.cursor() as cursor:
        cursor.execute(
            "delete from cluster_change "
            " where cluster = %(cluster)s and kind = %(kind)s and revision = %(revision)s",
            {"cluster": cluster, "kind": kind, "revision": expected_revision},
        )
        if cursor.rowcount == 0:
            raise DraftConflict(
                f"the saved {kind} of {cluster} changed since it was read; reload and try again"
            )


def change_publishes(
    connection: Connection[Any], *, cluster: str, change_ids: Collection[str]
) -> list[Job]:
    """The finished publishes of these saved documents, asked by their ids.

    The same evidence `draft_publishes` reads for a proxy object, under the
    payload's `change` - or in the `changes` of a publish of saved changes.
    Retention keeps these rows while their change exists.
    """

    if not change_ids:
        return []
    with connection.cursor(row_factory=class_row(Job)) as cursor:
        cursor.execute(
            "select id, request_id, operation, cluster, payload, state, created_at, "
            "       started_at, finished_at, exit_code, outcome, result, stderr_excerpt, "
            "       idempotency_key, attempts "
            "  from job "
            " where (state = 'done' or result->'publish'->>'outcome' = 'done') "
            "   and cluster = %(cluster)s "
            "   and ((operation in ('network_publish', 'cluster_settings_publish') "
            "         and payload->'change'->>'id' = any(%(ids)s)) "
            "        or (operation = 'changes_publish' "
            "            and exists (select 1 "
            "                          from jsonb_array_elements(payload->'changes') as entry "
            "                         where entry->>'id' = any(%(ids)s)))) "
            " order by created_at desc, id desc",
            {"cluster": cluster, "ids": sorted(change_ids)},
        )
        return cursor.fetchall()
