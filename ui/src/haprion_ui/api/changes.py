"""Changing objects: saved changes, publishing, and going back to a version (B416, release 3).

An object written through the API is the page's *Save*: a saved change that
waits for the next publish, written by the web as the editor writes it (same
validation, same revision rules, same pending-changes model), answered with
the change. Publishing and going back are jobs, as the pages queue them.

* **The body is the document.** An object as the engine reads it: JSON or
  YAML, which is the same thing to the engine, whatever the `Content-Type`.
* **Nothing is lost silently.** A change somebody saved in the interface is
  not overwritten by a create; a replace is held to the revision the caller
  names in `If-Match`, and to the draft nobody has finished (the editor's own
  rule: finish or discard it there). A removal is held to the same two, and to
  a change somebody else saved unless `If-Match` names its revision.
* **The switches are the page's.** *Advanced config* and *WAF engine* off:
  a document may not change the object's advanced text or start the engine on
  it, as the page's form and dialog do not offer either (review 26-11-01, a-P3-3).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from haprion import digits, dnsdist_config, proxy_model, resolve_socket
from haprion.proxy_model import ModelError
from haprion.version_history import comment_problem
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from haprion_ui import db, features, history
from haprion_ui import editor as editor_module
from haprion_ui.api import contract, writing
from haprion_ui.api.answers import Refusal, answer
from haprion_ui.api.caller import Caller, in_scope, needs
from haprion_ui.editor_flow import (
    EditorState,
    editor_state,
    save_object_change,
    save_removal,
    state_reading,
    unresolved_servers,
)
from haprion_ui.pending import pending_package, publish_payload
from haprion_ui.preview import Preview
from haprion_ui.reading import HISTORY_SOURCE, listed_clusters, read_source
from haprion_ui.saved_work import ObjectWork, settled_work

router = APIRouter(tags=["changes"])

#
# What the engine reads of one object; a body longer than that is no object.
#
MAX_DOCUMENT = proxy_model.MAX_MODEL_BYTES

NOT_FOUND = Refusal(404, "not_found", "No such cluster or object.")

#
# What a version says when the caller gives no comment: the comment is the
# version's, and the page will not publish without one.
#
DEFAULT_COMMENT = "Published through the API."


class PublishBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    comment: str = Field(default="", max_length=4096)
    #
    # *Publish & deploy*, as the Proxies page's button queues it; false is the
    # Versions page's *Publish*, which leaves the deploy to a later call.
    #
    deploy: bool = Field(default=True, strict=True)


class RevertBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int = Field(ge=1, strict=True)


def _json[T: BaseModel](body: bytes, model: type[T], *, empty_ok: bool = False) -> T:
    """A JSON body as `model`, whatever the `Content-Type` (curl's `-d` sends a form's).

    Which field, never the value, as the API's own handler says it.
    """

    if empty_ok and not body.strip():
        return model()
    try:
        return model.model_validate_json(body)
    except ValidationError as refused:
        fields = sorted(
            {".".join(str(part) for part in error["loc"]) or "body" for error in refused.errors()}
        )
        raise _bad(f"Not valid: {', '.join(fields)}.") from None


def _iso(moment: datetime) -> str:
    return moment.astimezone(UTC).isoformat()


def _writes_on(request: Request) -> None:
    if not request.app.state.config.management_writes:
        raise writing.WRITES_OFF


def _requested_by(caller: Caller) -> str:
    """The name a version records for the token, as the history names the actor.

    The commit trailer holds sixty-four characters; a token name may use them
    all. Cut here rather than refused by the helper after the cluster's lock
    was taken - the audit row beside the job has the whole of it.
    """

    return caller.trailer_actor


async def document_body(
    request: Request,
    caller: Caller = Depends(needs("write")),  # noqa: B008
) -> bytes:
    """The request's body, read up to what an object may be, once the token is judged.

    The caller is a dependency of this one so that no route can read a body
    for a call without a valid token: that call is a `401`, not a `413`
    (review 26-11-01, b-P3-8).
    """

    del caller
    received = bytearray()
    async for chunk in request.stream():
        received += chunk
        if len(received) > MAX_DOCUMENT:
            raise Refusal(
                413,
                "too_large",
                f"An object is at most {MAX_DOCUMENT // 1024} KiB.",
            )
    return bytes(received)


def document_text(body: bytes) -> str:
    """The body as the YAML text the engine reads; JSON is written out as YAML first.

    A body that is not JSON is left as it came, and the engine says what is
    wrong with it: flow-style YAML begins with a brace too.
    """

    try:
        text = body.decode("utf-8")
    except UnicodeError:
        raise Refusal(400, "bad_input", "The document is not UTF-8 text.") from None
    if text.lstrip().startswith("{"):
        try:
            loaded = json.loads(text)
        except ValueError:
            return text
        if isinstance(loaded, dict):
            return proxy_model.dump_document(loaded)
    return text


def _bad(message: str) -> Refusal:
    return Refusal(400, "bad_input", message)


def _usable_name(name: object) -> str:
    if not isinstance(name, str) or not proxy_model.NAME.fullmatch(name):
        said = (
            f"{name} is not a usable proxy name - {proxy_model.name_refusal(name)}; "
            if (isinstance(name, str))
            else "The document needs a name; "
        )
        raise _bad(f"{said}use {proxy_model.NAME_RULE}.")
    return name


def _protocol_of(text: str, name: str) -> str | None:
    try:
        data = proxy_model.read_document(name, text.encode())
    except ModelError:
        return None
    listen = data.get("listen")
    protocol = listen.get("protocol") if isinstance(listen, dict) else None
    return protocol if isinstance(protocol, str) else None


def _read(name: str, text: str | None) -> dict[str, Any]:
    if text is None:
        return {}
    try:
        return proxy_model.read_document(name, text.encode())
    except ModelError:
        return {}


def _inspects(name: str, text: str | None) -> bool:
    if text is None:
        return False
    try:
        return proxy_model.load_proxy(name, text.encode()).inspected is not None
    except (ModelError, UnicodeError):
        return False


def held_to_switches(request: Request, name: str, document: str, base: str | None) -> None:
    """A document the switches would not have the page write is a `400`, as it is on the page.

    The page offers neither the advanced text nor the WAF engine while its
    switch is off: what the object already has stays, and cannot be changed or
    started. `base` is the object as it stands - the saved change, else the
    published one, else None for a new object.
    """

    with request.app.state.pool.connection() as connection:
        features.read_in(db.feature_switches(connection))
    if not features.is_on(features.ADVANCED_CONFIG) and _read(name, document).get(
        "advanced"
    ) != _read(name, base).get("advanced"):
        raise _bad(
            "Advanced config is switched off on this installation, so an object's advanced "
            "config cannot be changed."
        )
    if (
        not features.is_on(features.WAF_ENGINE)
        and _inspects(name, document)
        and not _inspects(name, base)
    ):
        raise _bad(
            "The WAF engine is switched off on this installation, so an object cannot start "
            "using it."
        )


def checked_document(state: EditorState, name: str, text: str) -> tuple[str, Preview]:
    """The document as the editor would store it, and what the editor's check says of it.

    A document the engine cannot read as an object is refused, as the editor
    refuses to save it. One that does not fit the cluster is saved all the
    same, as a draft is, and the answer says why it does not fit.
    """

    try:
        document = dnsdist_config.with_addresses(name, text, resolve_socket.lookup)
    except ModelError:
        # Not an object at all; the check says why.
        document = text
    except ValueError as refused:
        raise _bad(str(refused)) from None
    preview = editor_module.check_document(name, document, state.choices)
    if preview.about_the_object:
        raise _bad(preview.problem or "The document is not an object.")
    return document, preview


def _check(request: Request, preview: Preview, name: str, text: str) -> dict[str, Any]:
    """What the answer says of how the object fits its cluster, and which server names do not resolve."""

    del request
    warnings = []
    if _protocol_of(preview.document, name) != "dns":
        warnings = unresolved_servers(name, preview.document)
    return {
        # None where the cluster is not described well enough to judge by.
        "fits": True if preview.beside_others else (False if preview.problem else None),
        "problem": preview.problem,
        "warnings": warnings,
    }


def _saved(
    saved: db.ProxyDraft | None, name: str, *, changed: bool, removal: bool, check: Any
) -> dict[str, Any]:
    return {
        "object": name,
        "stage": "saved",
        "removal": removal,
        "changed": changed,
        "revision": saved.revision if saved is not None else None,
        "updated_by": saved.updated_by if saved is not None else None,
        "updated_at": _iso(saved.updated_at) if saved is not None else None,
        "check": check,
    }


def _state(request: Request, cluster: str) -> EditorState:
    try:
        state = editor_state(request, request.app.state.config, cluster)
    except HTTPException:
        # A cluster that is not listed, as every route says it.
        raise NOT_FOUND from None
    if state.commit is None:
        raise Refusal(
            409,
            "conflict",
            "The stored proxies have not been read yet, so there is no base to change them against.",
        )
    return state


def _written(
    request: Request,
    caller: Caller,
    cluster: str,
    name: str,
    *,
    state: EditorState,
    work: ObjectWork,
    save: Any,
    detail: dict[str, Any],
    action: str = "save_change",
) -> db.ProxyDraft:
    """Write one saved change and its audit row in one transaction; a lost race is a `409`."""

    with request.app.state.pool.connection() as connection:
        writing.still_valid(connection, request, caller)
        try:
            saved: db.ProxyDraft = save(connection)
        except db.DraftConflict as conflict:
            connection.rollback()
            raise Refusal(409, "conflict", f"{conflict}.") from None
        db.record_audit_event(
            connection,
            actor=caller.actor,
            action=action,
            cluster=cluster,
            request_id=uuid4(),
            detail={"object": name, "revision": saved.revision, "via": "api", **detail},
        )
        connection.commit()
    return saved


@router.post(
    "/clusters/{cluster}/objects",
    name="object_create",
    status_code=201,
    responses=contract.responses("object_create", status=201),
)
def object_create(
    request: Request,
    cluster: str,
    caller: Caller = Depends(needs("write")),  # noqa: B008
    body: bytes = Depends(document_body),
) -> JSONResponse:
    """Save a new object from its document, for the next publish."""

    in_scope(caller, cluster)
    _writes_on(request)
    text = document_text(body)
    try:
        data = proxy_model.read_document("object", text.encode())
    except ModelError as refused:
        raise _bad(str(refused)) from None
    name = _usable_name(data.get("name"))
    in_scope(caller, cluster, name)
    state = _state(request, cluster)
    document, preview = checked_document(state, name, text)
    held_to_switches(request, name, document, None)
    with request.app.state.pool.connection() as connection:
        work = settled_work(connection, cluster, name, state_reading(state))
    if any(view.name == name for view in state.stored):
        raise Refusal(409, "conflict", "A proxy of that name already exists in this cluster.")
    saved_here = work.saved
    # The same document again is a retry whose answer was lost: nothing more to save.
    if (
        work.draft is None
        and saved_here is not None
        and not saved_here.deleted
        and editor_module.unchanged(document, saved_here.yaml)
    ):
        response = answer(
            request,
            _saved(
                saved_here,
                name,
                changed=False,
                removal=False,
                check=_check(request, preview, name, text),
            ),
            cluster=cluster,
            status=201,
        )
        response.headers["Location"] = f"/api/v1/clusters/{cluster}/objects/{name}"
        return response
    if work.top is not None:
        raise Refusal(
            409,
            "conflict",
            f"{name} already has a draft or saved changes in this cluster; replace it instead.",
        )
    saved = _written(
        request,
        caller,
        cluster,
        name,
        state=state,
        work=work,
        save=lambda connection: save_object_change(
            connection,
            state,
            cluster=cluster,
            object_id=name,
            document=document,
            updated_by=caller.actor,
            saved_revision=None,
            draft_revision=None,
        ),
        detail={"stage": "saved"},
    )
    response = answer(
        request,
        _saved(
            saved, name, changed=True, removal=False, check=_check(request, preview, name, text)
        ),
        cluster=cluster,
        status=201,
    )
    response.headers["Location"] = f"/api/v1/clusters/{cluster}/objects/{name}"
    return response


def _revision(request: Request) -> int | None:
    """The revision named in `If-Match` (quoted or not), or None without the header.

    0 says "nothing is saved yet": a revision starts at 1.
    """

    value = request.headers.get("If-Match", "").strip().removeprefix("W/").strip('"')
    if not request.headers.get("If-Match"):
        return None
    if not digits.is_digits(value):
        raise _bad(
            "If-Match holds the revision of the saved change, a whole number; 0 means nothing is saved."
        )
    return int(value)


def _not_at(name: str, held: int | None, saved: db.ProxyDraft | None) -> bool:
    """Whether `If-Match` names another revision than the saved change's (0 where none is saved)."""

    return held is not None and held != (saved.revision if saved is not None else 0)


@router.put(
    "/clusters/{cluster}/objects/{name}",
    name="object_replace",
    responses=contract.responses("object_replace"),
)
def object_replace(
    request: Request,
    cluster: str,
    name: str,
    caller: Caller = Depends(needs("write")),  # noqa: B008
    body: bytes = Depends(document_body),
) -> JSONResponse:
    """Replace an object's saved change, or save one over the object as published."""

    in_scope(caller, cluster, name)
    _writes_on(request)
    held = _revision(request)
    text = document_text(body)
    state = _state(request, cluster)
    stored = next((view for view in state.stored if view.name == name), None)
    with request.app.state.pool.connection() as connection:
        work = settled_work(connection, cluster, name, state_reading(state))
    if stored is None and work.saved is None:
        raise NOT_FOUND
    document, preview = checked_document(state, name, text)
    saved = work.saved
    held_to_switches(
        request,
        name,
        document,
        saved.yaml
        if saved is not None and not saved.deleted
        else stored.document
        if stored
        else None,
    )
    check = _check(request, preview, name, text)
    if work.draft is not None:
        raise Refusal(
            409,
            "conflict",
            f"{name} has a draft. Save or discard it in the editor first.",
        )
    if _not_at(name, held, saved):
        raise Refusal(
            409,
            "conflict",
            f"The saved changes to {name} are not at revision {held}; read them again.",
        )
    # Saying what is already there is nothing to save: a retry, or a pipeline run twice.
    if (
        saved is None and stored is not None and editor_module.unchanged(document, stored.document)
    ) or (
        saved is not None and not saved.deleted and editor_module.unchanged(document, saved.yaml)
    ):
        return answer(
            request,
            _saved(saved, name, changed=False, removal=False, check=check),
            cluster=cluster,
        )
    revision = saved.revision if saved is not None else None
    replaces = saved.replaces if saved is not None else None
    written = _written(
        request,
        caller,
        cluster,
        name,
        state=state,
        work=work,
        save=lambda connection: save_object_change(
            connection,
            state,
            cluster=cluster,
            object_id=name,
            document=document,
            updated_by=caller.actor,
            replaces=replaces,
            saved_revision=revision,
            draft_revision=None,
        ),
        detail={"stage": "saved"},
    )
    return answer(
        request,
        _saved(written, name, changed=True, removal=False, check=check),
        cluster=cluster,
    )


@router.delete(
    "/clusters/{cluster}/objects/{name}",
    name="object_remove",
    responses=contract.responses("object_remove"),
)
def object_remove(
    request: Request,
    cluster: str,
    name: str,
    caller: Caller = Depends(needs("write")),  # noqa: B008
) -> JSONResponse:
    """Save the removal of a published object, for the next publish.

    Held to what a replace is held to: a draft somebody is editing is not
    taken away, and neither is a change somebody else saved unless `If-Match`
    names its revision (review 26-11-01, a-P2-3).
    """

    in_scope(caller, cluster, name)
    _writes_on(request)
    held = _revision(request)
    state = _state(request, cluster)
    stored = next((view for view in state.stored if view.name == name), None)
    if stored is None:
        raise NOT_FOUND
    with request.app.state.pool.connection() as connection:
        work = settled_work(connection, cluster, name, state_reading(state))
    if work.draft is not None:
        raise Refusal(
            409,
            "conflict",
            f"{name} has a draft. Save or discard it in the editor first.",
        )
    if _not_at(name, held, work.saved):
        raise Refusal(
            409,
            "conflict",
            f"The saved changes to {name} are not at revision {held}; read them again.",
        )
    if work.saved is not None and held is None and work.saved.updated_by != caller.actor:
        raise Refusal(
            409,
            "conflict",
            f"{name} has changes saved by {work.saved.updated_by}. Name their revision "
            f"({work.saved.revision}) in If-Match to remove it all the same.",
        )
    saved = _written(
        request,
        caller,
        cluster,
        name,
        state=state,
        work=work,
        save=lambda connection: save_removal(
            connection,
            state,
            stored,
            cluster=cluster,
            existing=work,
            updated_by=caller.actor,
        ),
        detail={"removed": True},
    )
    return answer(
        request,
        _saved(saved, name, changed=True, removal=True, check=None),
        cluster=cluster,
    )


@router.post(
    "/clusters/{cluster}/publish",
    name="cluster_publish",
    status_code=202,
    responses=contract.responses("cluster_publish", status=202),
)
def cluster_publish(
    request: Request,
    cluster: str,
    caller: Caller = Depends(needs("write")),  # noqa: B008
    body: bytes = Depends(document_body),
) -> JSONResponse:
    """Publish everything saved for the cluster as one version (Publish & deploy)."""

    in_scope(caller, cluster)
    _writes_on(request)
    writing.idempotency_key(request)
    asked = _json(body, PublishBody, empty_ok=True)
    if (again := writing.replayed(request, caller, asked)) is not None:
        return again
    config = request.app.state.config
    if cluster not in listed_clusters(request, config):
        raise NOT_FOUND
    package = pending_package(request, config, cluster)
    if package.problem:
        raise Refusal(409, "conflict", package.problem)
    if not package.rows:
        raise Refusal(409, "nothing_to_publish", "Nothing is saved to publish.")
    comment = asked.comment.strip() or DEFAULT_COMMENT
    problem = comment_problem(comment)
    if problem:
        raise _bad(f"The comment {problem}.")
    return writing.queue(
        request,
        caller,
        operation="changes_publish",
        cluster=cluster,
        payload=publish_payload(
            package, comment=comment, requested_by=_requested_by(caller), deploy=asked.deploy
        ),
        detail={"changes": [row.name for row in package.rows]},
        body=asked,
    )


@router.post(
    "/clusters/{cluster}/revert",
    name="cluster_revert",
    status_code=202,
    responses=contract.responses("cluster_revert", status=202),
)
def cluster_revert(
    request: Request,
    cluster: str,
    body: bytes = Depends(document_body),
    caller: Caller = Depends(needs("write")),  # noqa: B008
) -> JSONResponse:
    """Publish an earlier version again (the Versions page's *Publish this version*)."""

    in_scope(caller, cluster)
    _writes_on(request)
    writing.idempotency_key(request)
    asked = _json(body, RevertBody)
    if (again := writing.replayed(request, caller, asked)) is not None:
        return again
    config = request.app.state.config
    clusters, history_rows = read_source(request, config, HISTORY_SOURCE)
    if cluster not in clusters:
        raise NOT_FOUND
    overview = history.build_history_overview(
        clusters, history_rows, stale_after=config.poller.stale_after
    )
    view = next((view for view in overview.clusters if view.cluster == cluster), None)
    version = next(
        (version for version in view.versions if version.number == asked.version)
        if view is not None
        else iter(()),
        None,
    )
    if view is None or version is None:
        raise Refusal(404, "not_found", "No such version of this cluster.")
    if version.published:
        raise Refusal(409, "conflict", f"Version {version.number} is the one published.")
    return writing.queue(
        request,
        caller,
        operation="revert",
        cluster=cluster,
        payload=history.revert_payload(
            version=version.number,
            expected_commit=version.expected_commit,
            requested_by=_requested_by(caller),
            expected_head=view.head_commit,
        ),
        detail={"version": version.number},
        body=asked,
    )
