"""The shared version-history read model, in the frozen `list` result shape.

`haprion-list` prints this for a human and the interface's helper returns it as
JSON, so both are built here rather than assembled twice. Two readers of the same
history that count or label versions differently would disagree about what
"version 7" means - and the number is not stored anywhere, it is counted, which
makes an independent second implementation the easiest kind of drift to
introduce and the hardest to notice.

The shape is `schemas/v1/haprion-list.schema.json`, frozen in phase 0. `current`
there means the newest saved version - what a publish would build on - and is a
separate question from which version the nodes are running. The published
release is reported alongside it, under keys the schema allows, so a reader can
tell "saved" from "live" without either fact being renamed.

What is deliberately not here: any file the repository's work tree holds. The
listing is saved history, and the published release is read from the RELEASE
stamp, so an unpublished draft can never be shown as live.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime

from haprion.deploy_plan import ReleaseTarget
from haprion.version_history import LIST_LIMIT, VersionSummary


def _version_document(entry: VersionSummary, newest: int | None) -> dict[str, object]:
    return {
        "version": entry.version,
        "hash": entry.commit,
        "created_at": entry.created_at,
        "comment": entry.comment,
        "current": entry.version == newest,
        #
        # Additive within v1, which allows unknown fields. This is the half of
        # the completion evidence that survives a crash: after a restart, "did
        # this request already record a version?" is answered by reading the
        # listing rather than by guessing from the configuration's content.
        #
        "request_id": entry.request_id,
        #
        # Who asked for the version (B207), from its `Requested-By` trailer;
        # null for everything recorded before it. Additive within v1.
        #
        "requested_by": entry.requested_by,
    }


def history_result(
    versions: Sequence[VersionSummary],
    target: ReleaseTarget | None,
    *,
    generated_at: datetime | None = None,
    limit: int = LIST_LIMIT,
) -> dict[str, object]:
    """The recent versions of one cluster, and which of them is published.

    `total_versions` is not counted again. The newest version's number *is* the
    depth of the history - that is how the listing is numbered - so taking it
    from the top row is exact and saves a second walk of the same history.

    `unpublished` counts versions saved after the published one, which is the
    question an operator is actually asking: is anything waiting to go out. It
    is derived here so no reader has to know how versions are ordered.

    A published release that is not in the listing leaves `unpublished` null
    rather than zero. The honest answer is that this listing cannot say - the
    release is older than the versions shown, or the history has been reset -
    and zero would be the reassuring guess.

    The published version is matched by hash, never by number: after a history
    reset an old number can name a different commit, while the hash is what the
    nodes were actually given.
    """

    timestamp = generated_at or datetime.now(UTC)
    newest = versions[0].version if versions else None
    documents = [_version_document(entry, newest) for entry in versions]

    unpublished: int | None = None
    if target is not None:
        for offset, entry in enumerate(versions):
            if entry.commit == target.hash:
                unpublished = offset
                break
    elif documents:
        #
        # Nothing published: every saved version is waiting, truthfully only up
        # to the listing limit, which `truncated` states.
        #
        unpublished = len(documents)

    return {
        "current_version": newest,
        "total_versions": newest or 0,
        "versions": documents,
        "published_version": target.version if target is not None else None,
        "published_hash": target.hash if target is not None else None,
        "unpublished": unpublished,
        "truncated": len(documents) >= limit,
        "generated_at": timestamp.isoformat().replace("+00:00", "Z"),
    }


def summary_line(result: Mapping[str, object]) -> str:
    """One sentence about publication state, for a human reading the listing."""

    unpublished = result.get("unpublished")
    if result.get("published_version") is None:
        return "No version has been published yet."
    if unpublished == 0:
        return f"Version {result['published_version']} is published and is the newest saved."
    if isinstance(unpublished, int):
        return (
            f"Version {result['published_version']} is published; "
            f"{unpublished} newer version(s) are saved but not published."
        )
    return f"Version {result['published_version']} is published; it is older than this listing."
