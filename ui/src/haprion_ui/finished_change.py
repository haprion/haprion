"""One change to a stored object, saved as finished work for the next publish (B257).

Made outside the editor: a WAF exception from a finding (B234), and a
blocklist added under *Denied* (B496, 13). Made on the object's saved change,
or on the stored object when it has none, and never on a draft somebody has
not finished - an object with one is said and left as it is. The change is
held to the model before it is kept, and the cluster's other saved changes
are held while it is written, as the editor's own save does.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any
from uuid import uuid4

from fastapi import Request
from haprion.proxy_model import ModelError, load_written

from haprion_ui import db
from haprion_ui import editor as editor_module
from haprion_ui.db import AuthenticatedSession
from haprion_ui.editor_flow import EditorState, carried_base, hold_cluster_changes, state_reading
from haprion_ui.saved_work import settled_work


def save(
    request: Request,
    session: AuthenticatedSession,
    state: EditorState,
    *,
    name: str,
    change: Callable[[str], str],
    detail: dict[str, Any],
) -> str | None:
    """Apply one change to the object's saved change or stored document; the problem, or None."""

    cluster = state.cluster
    stored = next((view for view in state.stored if view.name == name), None)
    with request.app.state.pool.connection() as connection:
        work = settled_work(connection, cluster, name, state_reading(state))
    if work.draft is not None:
        return f"{name} has a draft. Save or discard it in the editor first."
    draft = work.saved
    if draft is not None and draft.deleted:
        return f"The saved changes remove {name}."
    base = draft.yaml if draft is not None else (stored.document if stored is not None else "")
    if not base or state.commit is None:
        return "The stored proxies have not been read yet."
    try:
        document = change(base)
        load_written(name, document.encode())
    except (ValueError, ModelError) as exc:
        return str(exc)
    if editor_module.unchanged(document, base):
        return None
    with request.app.state.pool.connection() as connection:
        try:
            hold_cluster_changes(
                connection,
                state,
                cluster=cluster,
                key=name,
                target=name,
                replaces=draft.replaces if draft is not None else None,
            )
            saved = db.save_change(
                connection,
                cluster=cluster,
                object_id=name,
                yaml=document,
                base_version=state.base_version,
                base_hash=state.commit,
                updated_by=session.username,
                base_document=carried_base(state, name, draft),
                replaces=draft.replaces if draft is not None else None,
                saved_revision=draft.revision if draft is not None else None,
                draft_revision=None,
            )
        except db.DraftConflict as conflict:
            connection.rollback()
            return f"{conflict}. Reload the page and try again."
        db.record_audit_event(
            connection,
            actor=session.username,
            action="save_change",
            cluster=cluster,
            request_id=uuid4(),
            detail={"object": name, "revision": saved.revision, **detail},
        )
        connection.commit()
    return None
