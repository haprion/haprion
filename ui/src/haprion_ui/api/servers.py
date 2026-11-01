"""Servers and deployment: drain, maintenance and ready, a deploy, and the health check's test (B416, release 3)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from haprion.proxy_model import NAME
from haprion.server_state import MAX_SERVERS
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError

from haprion_ui import editor_flow, job_payloads, probe
from haprion_ui.api import contract, writing
from haprion_ui.api.answers import Refusal, answer
from haprion_ui.api.caller import Caller, in_scope, needs
from haprion_ui.preview import Unexpressible
from haprion_ui.reading import STATUS_SOURCE, listed_clusters, read_source
from haprion_ui.saved_work import settled_work

router = APIRouter(tags=["servers"])

NOT_FOUND = Refusal(404, "not_found", "No such cluster or object.")

#
# The words a caller uses for a state; the job carries the node helper's own
# (`server_state.STATES`), as the object page's buttons send them.
#
STATES = {"drain": "drain", "maintenance": "maint", "ready": "ready"}


class ServersBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    servers: Annotated[
        list[Annotated[str, StringConstraints(min_length=1, max_length=job_payloads.SERVER_LINE)]],
        Field(min_length=1, max_length=MAX_SERVERS),
    ]
    state: Literal["drain", "maintenance", "ready"]


class DeployBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_version: Annotated[int | None, Field(ge=1)] = None


def _iso(moment: datetime | None) -> str | None:
    return moment.astimezone(UTC).isoformat() if moment is not None else None


def _listed(request: Request, cluster: str) -> None:
    if cluster not in listed_clusters(request, request.app.state.config):
        raise NOT_FOUND


@router.post(
    "/clusters/{cluster}/objects/{name}/servers",
    name="object_servers",
    status_code=202,
    responses=contract.responses("object_servers", status=202),
)
def object_servers(
    request: Request,
    cluster: str,
    name: str,
    body: ServersBody,
    caller: Caller = Depends(needs("write")),  # noqa: B008
) -> JSONResponse:
    """Drain, maintenance or ready for servers of the object: the buttons of its Servers card.

    The helper finds every server in the object's newest version again before
    a node is asked, so what is checked here is the shape only, as the page
    checks it.
    """

    in_scope(caller, cluster, name)
    if not request.app.state.config.management_writes:
        raise writing.WRITES_OFF
    if (again := writing.replayed(request, caller, body)) is not None:
        return again
    _listed(request, cluster)
    if not NAME.fullmatch(name):
        raise NOT_FOUND
    chosen = job_payloads.chosen_servers(body.servers)
    state = STATES[body.state]
    return writing.queue(
        request,
        caller,
        operation="server_state",
        cluster=cluster,
        payload=job_payloads.server_state(name, chosen, state),
        detail={"object": name, "state": state, "servers": chosen},
        body=body,
    )


@router.post(
    "/clusters/{cluster}/deploy",
    name="cluster_deploy",
    status_code=202,
    responses=contract.responses("cluster_deploy", status=202),
)
def cluster_deploy(
    request: Request,
    cluster: str,
    caller: Caller = Depends(needs("write")),  # noqa: B008
    body: DeployBody | None = None,
) -> JSONResponse:
    """Deploy the published configuration to the nodes: the dashboard's *Deploy configuration*.

    `expected_version` binds the deploy to the version the caller saw, as the
    button does; the helper deploys that one or refuses.
    """

    in_scope(caller, cluster)
    if not request.app.state.config.management_writes:
        raise writing.WRITES_OFF
    asked = body if body is not None else DeployBody()
    if (again := writing.replayed(request, caller, asked)) is not None:
        return again
    _listed(request, cluster)
    version = body.expected_version if body is not None else None
    return writing.queue(
        request,
        caller,
        operation="deploy",
        cluster=cluster,
        payload=job_payloads.deploy(allow_vip_unknown=False, expected_version=version),
        detail={"expected_version": version} if version is not None else None,
        body=asked,
    )


def _opened(source: str, networks: Any) -> tuple[dict[str, Any] | None, str | None]:
    """The editor's fields for the document, or the sentence the editor says when it cannot open it."""

    try:
        return editor_flow.form_fields(source, networks), None
    except Unexpressible as exc:
        return None, str(exc)
    except ValidationError as exc:
        return None, ".".join(str(part) for part in exc.errors()[0]["loc"])


def _result(
    name: str, document: str, report: probe.ProbeReport, held_by: tuple[str, ...]
) -> dict[str, Any]:
    return {
        "object": name,
        "document": document,
        "ran": report.ran,
        "problem": report.problem,
        "source": report.source or None,
        "complete": report.ran and report.complete,
        "caveats": list(report.caveats),
        "failing": report.failing,
        "tested_at": _iso(report.tested_at),
        "held_by": list(held_by),
        "nodes": [
            {
                "node": node.node,
                "reachable": node.reachable,
                "error": node.error,
                "source_held": node.source_held,
                "results": [
                    {
                        "host": row.host,
                        "port": row.port,
                        "ok": row.ok,
                        "status": row.status,
                        "error": row.error,
                        "ms": row.ms,
                        "summary": row.phrase,
                    }
                    for row in node.results
                ],
            }
            for node in report.nodes
        ],
    }


@router.post(
    "/clusters/{cluster}/objects/{name}/health-check",
    name="object_health_check",
    responses=contract.responses("object_health_check"),
)
def object_health_check(
    request: Request,
    cluster: str,
    name: str,
    caller: Caller = Depends(needs("write")),  # noqa: B008
) -> JSONResponse:
    """The object form's *Test health check*: the nodes try the check, now, and the answer is in this call.

    The object as the editor would open it: its draft or saved change over the
    stored one. A real connection to every server is made from the nodes, which
    is why this is a write; nothing is changed and no job is queued.
    """

    in_scope(caller, cluster, name)
    config = request.app.state.config
    if not config.management_writes:
        raise writing.WRITES_OFF
    _listed(request, cluster)
    if not NAME.fullmatch(name):
        raise NOT_FOUND
    state = editor_flow.editor_state(request, config, cluster)
    with request.app.state.pool.connection() as connection:
        top = settled_work(connection, cluster, name, editor_flow.state_reading(state)).top
    stored = next((view for view in state.stored if view.name == name), None)
    if top is not None and not top.deleted:
        source, document = top.yaml, top.stage
    elif stored is not None:
        source, document = stored.document, "published"
    else:
        raise NOT_FOUND
    fields, problem = _opened(source, state.choices.networks)
    if fields is None:
        report = probe.ProbeReport(
            ran=False,
            source="",
            nodes=(),
            problem=f"This object cannot be opened by the editor, so its check cannot be run: {problem}",
        )
        return answer(request, _result(name, document, report, ()), cluster=cluster)
    _, status_rows = read_source(request, config, STATUS_SOURCE)
    backend = editor_flow.object_backend(status_rows, state, stored, fields, name)
    report = editor_flow.probe_report(state, fields, backend)
    return answer(request, _result(name, document, report, backend.held_by), cluster=cluster)
