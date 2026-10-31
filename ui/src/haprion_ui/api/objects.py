"""Objects, their documents and history: what the Proxies page lists, read through the page's own listing."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse
from haprion.proxy_model import ModelError, load_proxy, read_document

from haprion_ui import db, history, objects, server_card
from haprion_ui.api.answers import Refusal, answer
from haprion_ui.api.caller import Caller, in_scope, needs
from haprion_ui.health import ObjectHealth
from haprion_ui.jobs import InFlight
from haprion_ui.object_reading import read_object
from haprion_ui.pages.proxies import proxy_listing
from haprion_ui.proxies import ProxyView
from haprion_ui.reading import HISTORY_SOURCE, listed_clusters, read_source

router = APIRouter(tags=["objects"])

#
# The most one answer lists. A cluster can hold thousands of objects; the
# caller pages through them with `offset`.
#
OBJECT_LIMIT = 200
OBJECT_LIMIT_MAX = 1000
VERSION_LIMIT = 50
VERSION_LIMIT_MAX = 200

NOT_FOUND = Refusal(404, "not_found", "No such cluster or object.")


def _iso(moment: datetime | None) -> str | None:
    return moment.astimezone(UTC).isoformat() if moment is not None else None


def _plain(value: Any) -> Any:
    """A parsed document as JSON holds it: YAML also reads dates, which JSON has no type for."""

    if isinstance(value, dict):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_plain(item) for item in value]
    if value is None or isinstance(value, bool | int | float | str):
        return value
    return value.isoformat() if hasattr(value, "isoformat") else str(value)


def _health(lamp: ObjectHealth | None) -> dict[str, Any] | None:
    if lamp is None:
        return None
    return {
        "tone": lamp.tone,
        "label": lamp.label,
        "detail": lamp.detail,
        "up": lamp.up,
        "total": lamp.total,
    }


def _draft(draft: db.ProxyDraft | None) -> dict[str, Any] | None:
    if draft is None:
        return None
    return {
        # "saved" is waiting for a publish; "draft" is still being edited.
        "stage": draft.stage,
        "removal": draft.deleted,
        "replaces": draft.replaces or None,
        "updated_by": draft.updated_by,
        "updated_at": _iso(draft.updated_at),
    }


def _publishing(running: InFlight | None) -> dict[str, Any] | None:
    if running is None:
        return None
    return {"label": running.label, "job": running.job}


def _written(
    listed: objects.ListedObject,
    *,
    lamp: ObjectHealth | None,
    draft: db.ProxyDraft | None,
    running: InFlight | None,
    refused: str | None,
    reconfigured: bool,
    unforwarded: bool,
) -> dict[str, Any]:
    #
    # The Proxies page's order of precedence for the badge in the protocol
    # cell, less the draft, which is its own field here.
    #
    if not listed.readable:
        state = "unreadable"
    elif listed.protocol == "syslog" and unforwarded:
        state = "include_missing"
    elif not listed.serving:
        state = "inactive"
    elif reconfigured:
        state = "reconfigured"
    else:
        state = "serving"
    at = listed.addresses
    return {
        "name": listed.name,
        "managed": True,
        "protocol": listed.protocol,
        "state": state,
        "serving": listed.serving,
        "readable": listed.readable,
        "problem": listed.problem,
        "hostnames": list(listed.hostnames),
        "ports": list(listed.ports),
        # A tcp, dns or syslog object's servers as the listing writes them.
        "servers": list(listed.servers),
        "backend_count": listed.backend_count,
        "redirect_http": listed.redirect_http,
        "vip": (
            {
                "name": at.vip_name,
                "address": at.vip.address or None,
                "is_default": at.vip_is_default,
            }
            if at is not None
            else None
        ),
        "source_address": (at.source.address or None) if at is not None and at.source else None,
        "health": _health(lamp),
        "draft": _draft(draft),
        "publishing": _publishing(running),
        "publish_refused": refused,
    }


def _other(**fields: Any) -> dict[str, Any]:
    """An entry that is not a stored object, in the same shape."""

    entry: dict[str, Any] = {
        "name": None,
        "managed": True,
        "protocol": None,
        "state": None,
        "serving": None,
        "readable": None,
        "problem": None,
        "hostnames": [],
        "ports": [],
        "servers": [],
        "backend_count": None,
        "redirect_http": None,
        "vip": None,
        "source_address": None,
        "health": None,
        "draft": None,
        "publishing": None,
        "publish_refused": None,
    }
    entry.update(fields)
    return entry


def _unmanaged(proxy: ProxyView) -> dict[str, Any]:
    return _other(
        name=proxy.name,
        managed=False,
        protocol=proxy.protocol,
        state="serving" if proxy.enabled else "disabled",
        serving=proxy.enabled,
        hostnames=list(proxy.hostnames),
        ports=list(proxy.ports),
        backend_count=proxy.backend_count,
    )


def object_entries(listing: dict[str, Any], cluster: str) -> list[dict[str, Any]]:
    """Every row the Proxies page draws for one cluster, by name.

    A stored object, a draft that is stored nowhere yet, an object a published
    removal has not yet taken off the nodes, and what the platform did not
    write: the page's four kinds of row.
    """

    drafts = {draft.object_id: draft for draft in listing["drafts"].get(cluster, ())}
    publishing = listing["publishing"].get(cluster, {})
    refused = listing["failed"].get(cluster, {})
    lamps = listing["health"].get(cluster, {})
    #
    # A cluster that is not behind has nothing to reconfigure: the page shows
    # the badge only where the nodes are on an older release.
    #
    reconfigured = (
        listing["reconfigured"].get(cluster, frozenset())
        if (cluster in listing["behind"])
        else frozenset()
    )
    unforwarded = bool(listing["unforwarded"].get(cluster))
    entries = [
        _written(
            listed,
            lamp=lamps.get(listed.name),
            draft=drafts.get(listed.name),
            running=publishing.get(listed.name),
            refused=refused.get(listed.name),
            reconfigured=listed.name in reconfigured,
            unforwarded=unforwarded,
        )
        for listed in listing["listed"].get(cluster, ())
    ]
    stored = {entry["name"] for entry in entries}
    entries += [
        _other(
            name=name,
            state="draft",
            draft=_draft(draft),
            publishing=_publishing(publishing.get(name)),
            publish_refused=refused.get(name),
        )
        for name, draft in drafts.items()
        if name not in stored
    ]
    entries += [
        _other(name=name, state="removal_pending") for name in listing["removed"].get(cluster, ())
    ]
    entries += [_unmanaged(proxy) for proxy in listing["unmanaged"].get(cluster, ())]
    return sorted(entries, key=lambda entry: entry["name"])


def _as_admin(caller: Caller) -> bool:
    """Whether the token is given what the pages give an admin and not a reader.

    A `read` token sees what a reader sees (B416); a `write` token is the
    admin's level. The object's document and its drafts are an admin's
    (B68): the YAML names certificates and backend addresses.
    """

    return caller.issued.level == "write"


def _listing(request: Request, cluster: str, caller: Caller) -> list[dict[str, Any]]:
    config = request.app.state.config
    if cluster not in listed_clusters(request, config):
        raise NOT_FOUND
    role = "admin" if _as_admin(caller) else "reader"
    listing = proxy_listing(request, config, role, {}, only=cluster)
    return object_entries(listing, cluster)


@router.get("/clusters/{cluster}/objects", name="object_list")
def object_list(
    request: Request,
    cluster: str,
    caller: Caller = Depends(needs("read")),  # noqa: B008
    limit: int = Query(OBJECT_LIMIT, ge=1, le=OBJECT_LIMIT_MAX),
    offset: int = Query(0, ge=0),
) -> JSONResponse:
    in_scope(caller, cluster)
    entries = _listing(request, cluster, caller)
    shown = entries[offset : offset + limit]
    return answer(
        request,
        {
            "objects": shown,
            "total": len(entries),
            "offset": offset,
            "limit": limit,
            "truncated": offset + limit < len(entries),
        },
        cluster=cluster,
    )


def _state_of(cell: server_card.Cell) -> tuple[str, bool]:
    """A node's word for a server as `ready`, `drain` or `maintenance`, and whether it was lost.

    The card has one label for the two things a node says - held or not, and
    what the check found - and a held server shows only the first; the check
    is the `detail`.
    """

    label = cell.label
    lost = label.endswith(" LOST")
    word = label.removesuffix(" LOST")
    if word == "DRAIN":
        return "drain", lost
    if word == "MAINT":
        return "maintenance", lost
    return ("unknown" if label == "—" else "ready"), False


def _server_states(card: server_card.ServerCard | None) -> dict[str, Any] | None:
    if card is None:
        return None
    servers = []
    for row in card.rows:
        pool, _, address = row.target.partition("/")
        nodes = []
        for node, cell in zip(card.nodes, row.cells, strict=True):
            state, lost = _state_of(cell)
            nodes.append(
                {
                    "node": node,
                    "state": state,
                    "lost": lost,
                    "label": cell.label,
                    "tone": cell.tone,
                    "detail": cell.title or None,
                }
            )
        servers.append(
            {
                "pool": pool,
                "address": address,
                "backup": row.backup,
                "weight": row.weight,
                "sessions": row.sessions,
                "nodes": nodes,
            }
        )
    return {
        # False: the nodes do not run this version of the object yet, so no node's word is given.
        "current": card.current,
        "observed_at": _iso(card.observed_at),
        "servers": servers,
    }


def _definition(document: str) -> Any:
    try:
        return _plain(read_document("object", document.encode()))
    except (ModelError, ValueError, UnicodeError):
        return None


@router.get("/clusters/{cluster}/objects/{name}", name="object_show")
def object_show(
    request: Request,
    cluster: str,
    name: str,
    caller: Caller = Depends(needs("read")),  # noqa: B008
) -> JSONResponse:
    in_scope(caller, cluster, name)
    entries = {entry["name"]: entry for entry in _listing(request, cluster, caller)}
    entry = entries.get(name)
    if entry is None:
        raise NOT_FOUND
    config = request.app.state.config
    reading = read_object(request, config, listed_clusters(request, config), cluster, name)
    detail = reading.detail
    stored = detail.stored
    states = None
    if stored is not None:
        try:
            proxy = load_proxy(name, stored.document.encode())
        except ModelError:
            proxy = None
        if proxy is not None:
            states = server_card.build(
                proxy,
                reading.status_rows,
                cluster=cluster,
                current=detail.publication is not None and detail.publication.tone == "healthy",
                sourced=reading.written is not None and reading.written.sourced,
            )
    if entry["vip"] is None and detail.vip is not None:
        # The cluster's default address, for an object that names none.
        entry["vip"] = {
            "name": detail.vip,
            "address": detail.vip_address,
            "is_default": detail.vip_is_default,
        }
    publication = detail.publication
    document = stored.document if stored is not None and _as_admin(caller) else None
    return answer(
        request,
        {
            **entry,
            "document": document,
            "definition": _definition(document) if document is not None else None,
            "publication": (
                {
                    "label": publication.label,
                    "detail": publication.detail,
                    "tone": publication.tone,
                    "version": publication.version,
                }
                if publication is not None
                else None
            ),
            "commit": detail.commit,
            "observed_at": _iso(detail.observed_at),
            "stale": detail.stale,
            "server_states": _server_states(states),
        },
        cluster=cluster,
    )


@router.get("/clusters/{cluster}/objects/{name}/history", name="object_history")
def object_history(
    request: Request,
    cluster: str,
    name: str,
    caller: Caller = Depends(needs("read")),  # noqa: B008
    limit: int = Query(VERSION_LIMIT, ge=1, le=VERSION_LIMIT_MAX),
) -> JSONResponse:
    """The cluster's versions, newest first: a version holds every object, so this is the one history."""

    in_scope(caller, cluster, name)
    if name not in {entry["name"] for entry in _listing(request, cluster, caller)}:
        raise NOT_FOUND
    config = request.app.state.config
    clusters, history_rows = read_source(request, config, HISTORY_SOURCE)
    overview = history.build_history_overview(
        clusters, history_rows, stale_after=config.poller.stale_after
    )
    view = next((view for view in overview.clusters if view.cluster == cluster), None)
    versions = view.versions if view is not None else ()
    return answer(
        request,
        {
            "versions": [
                {
                    "version": version.number,
                    "saved_by": None if version.requested_by == "—" else version.requested_by,
                    "saved_at": version.saved_at,
                    "comment": version.written_comment,
                    "published": version.published,
                    "current": version.current,
                }
                for version in versions[:limit]
            ],
            "published_version": view.target_version if view is not None else None,
            "total": view.total if view is not None else 0,
            "limit": limit,
            "truncated": (view is not None and view.truncated) or len(versions) > limit,
        },
        cluster=cluster,
    )
