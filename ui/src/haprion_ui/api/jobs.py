"""Jobs, to follow what a change is doing."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Path, Query, Request
from fastapi.responses import JSONResponse

from haprion_ui import api_tokens, db, jobs
from haprion_ui.api import contract
from haprion_ui.api.answers import Refusal, answer
from haprion_ui.api.caller import Caller, in_scope, needs
from haprion_ui.reading import listed_clusters

router = APIRouter(tags=["jobs"])

DEFAULT_LIMIT = 50
MAXIMUM_LIMIT = 500
LARGEST_ID = 2**63 - 1  # the column is a bigint; a larger number is no job

State = Literal["pending", "running", "done", "partial", "blocked", "failed", "unknown"]

NOT_FOUND = Refusal(404, "not_found", "No such job.")


def _iso(moment: datetime | None) -> str | None:
    return None if moment is None else moment.astimezone(UTC).isoformat()


def _entitled(caller: Caller) -> bool:
    """Whether the token may be given the helper's own sentences.

    The Jobs page gives them to every signed-in role, so a `read` token and a
    `write` token are given them alike; the helper's raw stderr is never part
    of the API.
    """

    return api_tokens.reads_everything(caller.issued.level)


def _summary(job: db.Job, view: jobs.JobView, actor: str | None) -> dict[str, Any]:
    return {
        "id": job.id,
        "operation": job.operation,
        "label": view.operation,
        "cluster": job.cluster,
        "state": job.state,
        "state_label": view.state_label,
        "outcome": job.outcome,
        "finished": job.state not in {"pending", "running"},
        "held": view.held,
        "queued_at": _iso(job.created_at),
        "started_at": _iso(job.started_at),
        "finished_at": _iso(job.finished_at),
        "actor": actor or None,
        "subjects": [name for name in jobs.subjects(job) if name],
        "error_code": view.error_code,
        "error_message": view.error_message,
    }


def _overview(
    request: Request,
    rows: list[db.Job],
    caller: Caller,
    *,
    awaiting: frozenset[str] = frozenset(),
) -> list[jobs.JobView]:
    #
    # `judged` empty: it only feeds the page's "need review" count, which
    # nothing here reads.
    #
    return list(
        jobs.build_job_overview(
            rows,
            awaiting=awaiting,
            sentences=_entitled(caller),
            judged=[],
            writes=request.app.state.config.management_writes,
        ).jobs
    )


@router.get("/jobs", name="job_list", responses=contract.responses("job_list"))
def job_list(
    request: Request,
    cluster: str | None = None,
    state: State | None = None,
    limit: Annotated[int, Query(ge=1, le=MAXIMUM_LIMIT)] = DEFAULT_LIMIT,
    caller: Caller = Depends(needs("read")),  # noqa: B008
) -> JSONResponse:
    """The newest jobs, as the Jobs page lists them, newest first."""

    if cluster is not None:
        in_scope(caller, cluster)
        scope: list[str] | None = [cluster]
        listed = cluster in listed_clusters(request, request.app.state.config)
    else:
        # A token limited to clusters has no part in a job that has none, but
        # the ones it queued itself (a certificate's): it must be able to follow them.
        scope = caller.issued.clusters or None
        listed = True
    with request.app.state.pool.connection() as connection:
        #
        # A removed cluster's jobs stay in the history, so a name the
        # installation no longer lists is real if it has any; a mistyped one
        # would otherwise be "no failures" for good.
        #
        if not listed and not db.listed_jobs(connection, clusters=scope, state=None, limit=1):
            raise Refusal(404, "not_found", "No such cluster or object.")
        #
        # One more than asked, which is how a cut list is told from a full one.
        #
        rows = db.listed_jobs(
            connection,
            clusters=scope,
            state=state,
            limit=limit + 1,
            clusterless_by=caller.actor if scope and cluster is None else None,
        )
        truncated = len(rows) > limit
        rows = rows[:limit]
        actors = db.requested_by(connection, [row.request_id for row in rows])
    views = _overview(request, rows, caller)
    return answer(
        request,
        {
            "jobs": [
                _summary(row, view, actors.get(row.request_id))
                for row, view in zip(rows, views, strict=True)
            ],
            "limit": limit,
            "truncated": truncated,
        },
        cluster=cluster,
    )


@router.get("/jobs/{job_id}", name="job_show", responses=contract.responses("job_show"))
def job_show(
    request: Request,
    job_id: Annotated[int, Path(ge=1, le=LARGEST_ID)],
    caller: Caller = Depends(needs("read")),  # noqa: B008
) -> JSONResponse:
    """One job with its steps: enough to tell running, done, partial and failed apart."""

    with request.app.state.pool.connection() as connection:
        job = db.job_by_id(connection, job_id)
        if job is None:
            raise NOT_FOUND
        actors = db.requested_by(connection, [job.request_id])
        #
        # A job outside the token's scope is answered as one that is not
        # there; a job with no cluster is outside every limited token's but the
        # one that queued it (review 26-11-01, a-P2-2).
        #
        if (
            job.cluster is None
            and caller.issued.clusters
            and actors.get(job.request_id) != caller.actor
        ) or (job.cluster is not None and not api_tokens.covers(caller.issued, job.cluster)):
            raise NOT_FOUND
        #
        # The page captions a follow-up on the newest job that owes one, so a
        # job is read among its cluster's newest and not alone; one older than
        # that window is history and carries no caption.
        #
        window = [] if job.cluster is None else db.recent_jobs(connection, cluster=job.cluster)
        awaiting = frozenset[str]()
        if any(row.id == job.id for row in window):
            awaiting = jobs.awaiting_deployment(db.cluster_statuses(connection))
        else:
            window = [job]
    views = _overview(request, window, caller, awaiting=awaiting)
    view = next(v for row, v in zip(window, views, strict=True) if row.id == job.id)
    keyed = jobs.keyed_states(job)
    result = _summary(job, view, actors.get(job.request_id))
    result.update(
        {
            "exit_code": job.exit_code,
            "exit_meaning": view.exit_meaning,
            "waiting_for": jobs.waiting_for(job),
            "follow_up": view.follow_up,
            "next_command": view.next_command,
            "warning_codes": [code for code in view.warning_codes.split(", ") if code],
            "warning_message": view.warning_message,
            "note": view.note,
            "step_states": [
                {"step": step, "state": state} for step, state in jobs.step_states(job)
            ],
            "keyed_states": [
                {"step": step, "subject": subject or None, "state": state}
                for step, subject, state in keyed
            ],
            "step_note": jobs.step_note(job),
            "distribution_note": jobs.distribution_note(job),
        }
    )
    return answer(request, result, cluster=job.cluster)
