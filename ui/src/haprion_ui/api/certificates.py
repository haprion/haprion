"""Certificates: where they are deployed, and issuing, renewing, retargeting and deleting them.

A change is the job the Certificates page queues, with the payload the page
builds (`certificate_form`, `certificate_renew`, `certificate_retarget`), run
by the same worker; no private key passes through the API, so an import, an
upload and a signing request stay in the interface.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Annotated, Any, Literal
from uuid import uuid4

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse
from haprion.cert_issue import IssueError, parse_domain
from haprion.config import CERTIFICATE_ID
from pydantic import BaseModel, ConfigDict, Field

from haprion_ui import (
    api_tokens,
    certificate_delete,
    certificate_form,
    certificate_renew,
    certificate_retarget,
    db,
    features,
    operations,
)
from haprion_ui.api import contract, writing
from haprion_ui.api.answers import Refusal, answer
from haprion_ui.api.caller import Caller, in_scope, needs
from haprion_ui.certificate_reading import certificate_choices, registry_views
from haprion_ui.certificates import (
    CertificateOverview,
    CertificateView,
    RegistryCertificateView,
    TargetView,
)
from haprion_ui.reading import listed_clusters
from haprion_ui.sorting import tone_rank
from haprion_ui.views import read_certificate_overview

router = APIRouter(tags=["certificates"])

# A registry holds tens of certificates; the limit is for the day it holds thousands.
DEFAULT_LIMIT = 200
MAX_LIMIT = 1000


def _iso(moment: datetime | None) -> str | None:
    return moment.astimezone(UTC).isoformat() if moment is not None else None


def _target(target: TargetView) -> dict[str, Any]:
    return {
        "name": target.name,
        "kind": target.kind,
        "published_at": _iso(target.published_at),
        "current": target.current,
    }


def _certificate(entry: RegistryCertificateView, caller: Caller, now: datetime) -> dict[str, Any]:
    #
    # A token limited to some clusters is told about those clusters only: the
    # others, and the receivers, which belong to no cluster, are not its to see.
    #
    limited = bool(caller.issued.clusters)
    targets = [
        target
        for target in entry.targets
        if not limited
        or (target.kind == "cluster" and api_tokens.covers(caller.issued, target.name))
    ]
    state = (entry.state_label, entry.state_detail, entry.state_tone)
    needs_publish = entry.needs_publish
    if limited:
        #
        # The combined State counts the receivers and the other clusters'
        # nodes. A limited token gets the worst of its own clusters' States,
        # and whether a publish is due as the clusters see it, not the receivers.
        #
        state = min(
            (
                (own.label, own.detail, own.tone)
                for own in entry.cluster_states
                if api_tokens.covers(caller.issued, own.cluster)
            ),
            key=lambda each: tone_rank(each[2]),
            default=state,
        )
        needs_publish = entry.cluster_needs_publish
    left = entry.expires_at - now if entry.expires_at is not None else None
    return {
        "id": entry.identifier,
        "common_name": entry.common_name,
        "names": list(entry.sans),
        "issuer": entry.issuer if entry.readable else None,
        "source": entry.source_kind,
        "lifecycle": entry.lifecycle,
        "readable": entry.readable,
        "problem": entry.problem,
        "not_after": _iso(entry.expires_at),
        "days_left": left.days if left is not None else None,
        "expired": left is not None and left.total_seconds() <= 0,
        "expiry_state": entry.tone,
        "state": {"label": state[0], "detail": state[1], "tone": state[2]},
        "needs_publish": needs_publish,
        "targets": [_target(target) for target in targets],
    }


def _from_clusters(
    overview: CertificateOverview, caller: Caller, now: datetime
) -> tuple[list[dict[str, Any]], bool]:
    """What the clusters' own listings say they serve, where there is no registry to read.

    The Certificates page and Needs attention do the same: with no registry
    the listings are the only word. A certificate is one row however many of
    the token's clusters serve it, with the worst of their states. Whether any of the token's clusters is unread
    or stale comes with them.
    """

    found: dict[str, list[CertificateView]] = {}
    clusters: dict[str, list[str]] = {}
    unread = False
    for cluster in overview.clusters:
        if not cluster.configured or not api_tokens.covers(caller.issued, cluster.cluster):
            continue
        unread = unread or cluster.stale or cluster.observed_at is None
        for view in cluster.certificates:
            if view.referenced:
                found.setdefault(view.identifier, []).append(view)
                clusters.setdefault(view.identifier, []).append(cluster.cluster)
    rows = []
    for identifier, views in sorted(found.items()):
        first = views[0]
        worst = min(views, key=lambda each: tone_rank(each.state_tone))
        left = first.expires_at - now if first.expires_at is not None else None
        rows.append(
            {
                "id": identifier,
                "common_name": first.common_name,
                "names": list(first.sans),
                "issuer": first.issuer if first.usable else None,
                "source": "unknown",
                "lifecycle": first.lifecycle
                if first.lifecycle in {"acme", "static"}
                else "unknown",
                "readable": first.usable,
                "problem": first.problem,
                "not_after": _iso(first.expires_at),
                "days_left": left.days if left is not None else None,
                "expired": left is not None and left.total_seconds() <= 0,
                "expiry_state": first.tone,
                "state": {
                    "label": worst.state_label,
                    "detail": worst.state_detail,
                    "tone": worst.state_tone,
                },
                "needs_publish": False,
                "targets": [
                    {"name": name, "kind": "cluster", "published_at": None, "current": None}
                    for name in clusters[identifier]
                ],
            }
        )
    return rows, unread


def visible(entry: RegistryCertificateView, caller: Caller) -> bool:
    """Whether the token may see a certificate: one deployed to a cluster it covers.

    A limited token sees nothing that is deployed only elsewhere or nowhere;
    an unlimited one sees everything.
    """

    if not caller.issued.clusters:
        return True
    return any(
        target.kind == "cluster" and api_tokens.covers(caller.issued, target.name)
        for target in entry.targets
    )


@router.get(
    "/certificates", name="certificate_list", responses=contract.responses("certificate_list")
)
def certificate_list(
    request: Request,
    limit: int = Query(DEFAULT_LIMIT, ge=1, le=MAX_LIMIT),
    caller: Caller = Depends(needs("read")),  # noqa: B008
) -> JSONResponse:
    """The registry as the Certificates page lists it, within the token's clusters."""

    overview, _, _ = read_certificate_overview(request.app.state.config, request)
    registry = overview.registry
    now = datetime.now(UTC)
    #
    # "No certificates" is only said of a registry that was read. Without one
    # the answer is what the clusters list, as on the page, and it says which.
    #
    if registry is not None:
        shown = [
            _certificate(entry, caller, now)
            for entry in registry.certificates
            if visible(entry, caller)
        ]
        stale = registry.stale
    else:
        shown, unread = _from_clusters(overview, caller, now)
        stale = unread or overview.registry_state == "unreadable"
    return answer(
        request,
        {
            "certificates": shown[:limit],
            "count": len(shown),
            "truncated": len(shown) > limit,
            "registry": overview.registry_state,
            "observed_at": _iso(overview.registry_observed_at),
            "stale": stale,
        },
    )


# - Changes ----------------------------------------------------------------

NOT_FOUND = Refusal(404, "not_found", "No such certificate.")

#
# Receivers belong to no cluster, so a token limited to clusters has none to
# name. One answer whether or not the receiver exists, so it learns nothing.
#
CLUSTERS_ONLY = Refusal(
    403,
    "forbidden",
    "A token limited to some clusters publishes to those clusters only, and to no receiver.",
)
BY_FILE = (
    "This certificate is renewed with a file, and a private key does not go through the API; "
    "upload it under Certificates in the interface."
)

Name = Annotated[str, Field(max_length=255)]


class IssueBody(BaseModel):
    """The *New certificate* form's fields."""

    model_config = ConfigDict(extra="forbid")

    domain: Name
    method: Annotated[str, Field(max_length=16)]
    clusters: list[Name] = Field(default_factory=list, max_length=100)
    receivers: list[Name] = Field(default_factory=list, max_length=100)
    formats: dict[Name, Name] = Field(default_factory=dict, max_length=100)
    dns_profile: Annotated[str, Field(max_length=32)] = ""
    ndes_profile: Annotated[str, Field(max_length=32)] = ""
    exportable: bool = False


class TargetsBody(BaseModel):
    """*Publish to…* (`add`) or *Remove from…* (`remove`) for one certificate."""

    model_config = ConfigDict(extra="forbid")

    action: Literal["add", "remove"]
    clusters: list[Name] = Field(default_factory=list, max_length=100)
    receivers: list[Name] = Field(default_factory=list, max_length=100)
    formats: dict[Name, Name] = Field(default_factory=dict, max_length=100)


def touchable(entry: RegistryCertificateView, caller: Caller) -> bool:
    """Whether the token may change a certificate: every place it goes is a cluster the token covers.

    Stricter than `visible`: renewing or deleting a certificate also renews
    or removes it where it is deployed to another cluster, or to a receiver.
    """

    if not caller.issued.clusters:
        return True
    return bool(entry.targets) and all(
        target.kind == "cluster" and api_tokens.covers(caller.issued, target.name)
        for target in entry.targets
    )


def _own(
    registry: Mapping[str, RegistryCertificateView], certificate_id: str, caller: Caller
) -> RegistryCertificateView:
    """The registry's row, or the same 404 whether it is missing or the token's to leave alone."""

    entry = registry.get(certificate_id) if CERTIFICATE_ID.fullmatch(certificate_id) else None
    if entry is None or not touchable(entry, caller):
        raise NOT_FOUND
    return entry


def _ready(
    request: Request,
    caller: Caller,
    clusters: Sequence[str] = (),
    body: BaseModel | None = None,
) -> JSONResponse | None:
    """What is refused before anything is read - writes off, no key, a cluster out of scope - or the answer to a retry.

    Writes switched off comes first, as for every change (review 26-11-01,
    a-P3-8). A call this key already queued is answered with its job before the
    registry is read: what the registry says has changed once the job ran.
    """

    if not request.app.state.config.management_writes:
        raise writing.WRITES_OFF
    writing.idempotency_key(request)
    for cluster in clusters:
        in_scope(caller, cluster)
    return writing.replayed(request, caller, body)


def _only_clusters(caller: Caller, receivers: Sequence[str]) -> None:
    if receivers and caller.issued.clusters:
        raise CLUSTERS_ONLY


def _read_switches(request: Request) -> None:
    """The feature switches for this request: the pages read them in their middleware."""

    with request.app.state.pool.connection() as connection:
        features.read_in(db.feature_switches(connection))


def _formats(formats: Mapping[str, str]) -> tuple[str, ...]:
    """The page's `<receiver>=<format>` fields."""

    return tuple(f"{receiver}={form}" for receiver, form in formats.items())


def _queue(
    request: Request,
    caller: Caller,
    *,
    operation: str,
    payload: Mapping[str, Any],
    detail: Mapping[str, Any],
    body: BaseModel | None = None,
) -> JSONResponse:
    return writing.queue(
        request,
        caller,
        operation=operation,
        cluster=None,
        payload=payload,
        detail=detail,
        body=body,
    )


def _live_drafts(request: Request) -> list[db.ProxyDraft]:
    clusters = listed_clusters(request, request.app.state.config)  # before the connection is taken
    with request.app.state.pool.connection() as connection:
        return db.live_drafts(connection, clusters)


@router.post(
    "/certificates",
    name="certificate_issue",
    status_code=202,
    responses=contract.responses("certificate_issue", status=202),
)
def certificate_issue(
    request: Request,
    body: IssueBody,
    caller: Caller = Depends(needs("write")),  # noqa: B008
) -> JSONResponse:
    """Issue a certificate from a CA the manager talks to (ACME or NDES), as *New certificate* does."""

    if (again := _ready(request, caller, body.clusters, body)) is not None:
        return again
    _only_clusters(caller, body.receivers)
    if body.exportable and caller.issued.clusters:
        raise CLUSTERS_ONLY
    if body.method == certificate_form.CSR_METHOD:
        raise Refusal(
            400,
            "bad_input",
            "A signing request is made in the interface; its certificate comes back as a file.",
        )
    _read_switches(request)
    if body.exportable and not features.is_on(features.CERT_RECEIVERS):
        raise Refusal(400, "bad_input", "Certificates for other hosts are switched off.")
    choices = certificate_choices(request, request.app.state.config)
    form = certificate_form.IssueForm(
        domain=body.domain,
        method=body.method,
        dns_profile=body.dns_profile,
        ndes_profile=body.ndes_profile,
        clusters=tuple(body.clusters),
        receivers=tuple(body.receivers),
        formats=_formats(body.formats),
        exportable=body.exportable,
    )
    try:
        name, _, _ = parse_domain(certificate_form.normalise(form).domain)
    except IssueError:
        name = ""
    if name and name in (*choices.registered, *choices.waiting):
        raise Refusal(
            409,
            "already_exists",
            "A certificate with this name is already in the registry; to send it elsewhere, "
            "set its targets.",
        )
    try:
        payload = certificate_form.payload_from_form(form, choices)
    except certificate_form.FormProblem as problem:
        raise Refusal(400, "bad_input", str(problem)) from None
    return _queue(
        request,
        caller,
        operation=certificate_form.operation_of(form),
        payload=payload,
        detail={"certificate": name},
        body=body,
    )


@router.post(
    "/certificates/{certificate_id}/renew",
    name="certificate_renew",
    status_code=202,
    responses=contract.responses("certificate_renew", status=202),
)
def certificate_renewal(
    request: Request,
    certificate_id: str,
    caller: Caller = Depends(needs("write")),  # noqa: B008
) -> JSONResponse:
    """Renew a certificate the way its source is made: certbot again, or the NDES enrollment again."""

    if (again := _ready(request, caller)) is not None:
        return again
    registry = registry_views(request, request.app.state.config)
    entry = _own(registry, certificate_id, caller)
    if entry.placeholder:
        raise NOT_FOUND
    try:
        renewal = certificate_renew.selection((certificate_id,), registry)
        if renewal.way in ("upload", "signed"):
            raise certificate_renew.SelectionProblem(BY_FILE)
        operation, payload = certificate_renew.payload(renewal)
    except certificate_renew.SelectionProblem as refused:
        raise Refusal(409, "cannot_renew", str(refused)) from None
    return _queue(
        request,
        caller,
        operation=operation,
        payload=payload,
        detail={"certificate": certificate_id, "renew": True},
    )


@router.put(
    "/certificates/{certificate_id}/targets",
    name="certificate_targets",
    status_code=202,
    responses=contract.responses("certificate_targets", status=202),
)
def certificate_targets(
    request: Request,
    certificate_id: str,
    body: TargetsBody,
    caller: Caller = Depends(needs("write")),  # noqa: B008
) -> JSONResponse:
    """Publish a certificate to more places, or take it from some, as *Publish to…* and *Remove from…*."""

    if (again := _ready(request, caller, body.clusters, body)) is not None:
        return again
    _only_clusters(caller, body.receivers)
    config = request.app.state.config
    entry = _own(registry_views(request, config), certificate_id, caller)
    if body.action == "remove" and body.formats:
        raise Refusal(400, "bad_input", "A removal does not take formats.")
    if not body.clusters and not body.receivers:
        raise Refusal(400, "bad_input", "Name at least one cluster or receiver.")
    _read_switches(request)
    choices = certificate_choices(request, config)
    if not set(body.clusters) <= set(choices.clusters) or not set(body.receivers) <= set(
        choices.receivers
    ):
        raise Refusal(400, "bad_input", "Each target must be a cluster or receiver that exists.")
    drafts = _live_drafts(request)
    try:
        picked = certificate_retarget.selection(
            body.action,
            (certificate_id,),
            {certificate_id: entry},
            choices.clusters,
            choices.receivers,
            drafts,
        )
        offered = {(choice.kind, choice.name) for choice in picked.offered}
        wanted = {("cluster", name) for name in body.clusters} | {
            ("receiver", name) for name in body.receivers
        }
        if offered.isdisjoint(wanted):
            raise Refusal(
                409,
                "no_change",
                "The certificate is already published to these places."
                if body.action == "add"
                else "The certificate is not published to these places.",
            )
        payload = certificate_retarget.payload(
            picked, tuple(body.clusters), tuple(body.receivers), _formats(body.formats)
        )
    except certificate_retarget.SelectionProblem as refused:
        raise Refusal(400, "bad_input", str(refused)) from None
    _refuse_drafts(payload, drafts)
    return _queue(
        request,
        caller,
        operation="cert_target",
        payload=payload,
        detail={"certificate": certificate_id, "action": body.action},
        body=body,
    )


def _refuse_drafts(payload: Mapping[str, Any], drafts: Sequence[db.ProxyDraft]) -> None:
    """A removal from a cluster is refused while a draft there names the certificate, as the page refuses it.

    `writing.queue` checks the payload's shape; the drafts live in this
    database and are the page's own question to ask before it queues. The
    message names only the clusters of the payload, which the token covers.
    """

    try:
        operations.prepare(
            operation="cert_target",
            cluster=None,
            request_id=uuid4(),
            payload=payload,
            draft_references=lambda ids: certificate_delete.draft_references(drafts, ids),
        )
    except operations.BadPayload as refused:
        message = str(refused)
        raise Refusal(409, "in_use", message[:1].upper() + message[1:] + ".") from None


@router.delete(
    "/certificates/{certificate_id}",
    name="certificate_delete",
    status_code=202,
    responses=contract.responses("certificate_delete", status=202),
)
def certificate_removal(
    request: Request,
    certificate_id: str,
    caller: Caller = Depends(needs("write")),  # noqa: B008
) -> JSONResponse:
    """Delete a certificate, refused while a draft names it as the page refuses; the nodes' own refusals come on the job."""

    if (again := _ready(request, caller)) is not None:
        return again
    _own(registry_views(request, request.app.state.config), certificate_id, caller)
    named = certificate_delete.draft_references(_live_drafts(request), (certificate_id,))
    if named:
        #
        # The drafts of clusters the token does not cover are not named to it.
        #
        shown = [
            row
            for row in named[certificate_id]
            if api_tokens.covers(caller.issued, row.split("/")[0])
        ]
        raise Refusal(
            409,
            "in_use",
            "A draft still names it" + (": " + ", ".join(shown) if shown else "") + ".",
        )
    return _queue(
        request,
        caller,
        operation="cert_delete",
        payload={"certificates": [certificate_id]},
        detail={"certificate": certificate_id},
    )
