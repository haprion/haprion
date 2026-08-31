"""The safe, reader-visible projection of queued management jobs.

The job table is an operation record, not a way to control an operation.  It
deliberately leaves out claim tokens, idempotency keys, payload internals and
raw stderr: none answers the question a reader has after pressing a button,
and several would make an implementation detail into part of the UI contract.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal

from haproxy_ui.dashboard import relative_age
from haproxy_ui.db import ClusterStatus, Job

type Tone = Literal["healthy", "warning", "critical", "info", "unknown"]


@dataclass(frozen=True, slots=True)
class JobView:
    id: int
    operation: str
    cluster: str
    state: str
    state_label: str
    tone: Tone
    requested: str
    requested_iso: str
    started: str
    finished: str
    outcome: str
    exit_code: str
    #
    # What is still owed after a job that succeeded. A revert publishes but does
    # not roll out, so a job that reads `Completed` can leave the nodes on the
    # previous version - which is the one case where the state column alone is
    # actively misleading. The helper answers this in its result; until it was
    # projected here it was answered to nobody.
    #
    follow_up: str | None = None
    next_command: str | None = None


@dataclass(frozen=True, slots=True)
class JobOverview:
    jobs: tuple[JobView, ...]
    active_count: int
    attention_count: int
    completed_count: int


def _stamp(moment: datetime | None, now: datetime) -> str:
    return "—" if moment is None else relative_age(moment, now)


def _state(state: str) -> tuple[str, Tone]:
    """Turn database state into the small vocabulary the screen promises."""

    labels: dict[str, tuple[str, Tone]] = {
        "pending": ("Queued", "info"),
        "running": ("Running", "info"),
        "done": ("Completed", "healthy"),
        "partial": ("Completed with gaps", "warning"),
        "blocked": ("Blocked", "warning"),
        "failed": ("Failed", "critical"),
        "unknown": ("Outcome unknown", "critical"),
    }
    return labels.get(state, ("Unknown", "unknown"))


def _operation(value: str) -> str:
    return {
        "deploy": "Deploy configuration",
        "cert_deploy": "Deploy certificates",
        "revert": "Publish reverted version",
    }.get(value, value.replace("_", " ").capitalize())


def awaiting_deployment(statuses: list[ClusterStatus]) -> frozenset[str]:
    """Clusters whose newest reading says they are not on their target.

    Read defensively, like everything else that comes out of a stored helper
    document: a reading that is missing, malformed or simply unknown is not
    evidence that a cluster is behind, and a job should not be captioned on a
    guess.
    """

    pending = set()
    for status in statuses:
        summary = status.result.get("summary") if isinstance(status.result, dict) else None
        if isinstance(summary, dict) and summary.get("release_state") not in {
            "converged",
            None,
        }:
            pending.add(status.cluster)
    return frozenset(pending)


def _owes_deployment(job: Job) -> tuple[bool, str | None]:
    """Whether this job recorded that a deploy was still owed when it ran.

    Read defensively. The document is written by a privileged helper and stored
    as it arrived, so this asks it questions rather than assuming its shape.
    """

    envelope = job.result
    if not isinstance(envelope, dict):
        return False, None
    body = envelope.get("result")
    if not isinstance(body, dict) or body.get("deployment_required") is not True:
        return False, None

    command = body.get("next_command")
    return True, command if isinstance(command, str) and command else None


def _view(job: Job, now: datetime, *, follow_up: str | None, next_command: str | None) -> JobView:
    label, tone = _state(job.state)
    return JobView(
        id=job.id,
        operation=_operation(job.operation),
        cluster=job.cluster,
        state=job.state,
        state_label=label,
        tone=tone,
        requested=_stamp(job.created_at, now),
        requested_iso=job.created_at.astimezone(UTC).isoformat(),
        started=_stamp(job.started_at, now),
        finished=_stamp(job.finished_at, now),
        outcome=job.outcome.replace("_", " ") if job.outcome else "—",
        exit_code="—" if job.exit_code is None else str(job.exit_code),
        follow_up=follow_up,
        next_command=next_command,
    )


def build_job_overview(
    rows: list[Job],
    *,
    now: datetime | None = None,
    awaiting: frozenset[str] = frozenset(),
) -> JobOverview:
    """Build one bounded, newest-first operation history from database rows.

    `awaiting` is what keeps the follow-up line honest. A job's result records
    what was still owed **when it ran**, which for anything but the newest such
    job is a statement about a moment that has passed - job 15 published, job 16
    deployed it, and captioning job 15 with "the nodes still run the previous
    version" was wrong within the hour. Found on 2026-08-31 by a reader looking
    at the page rather than at the row.

    So two things have to hold: the cluster has to be behind its target now, and
    this has to be the newest job that left it that way. Anything older is
    history, and history does not need a caption telling the reader to act.
    """

    current = now or datetime.now(UTC)
    captioned: set[str] = set()
    views = []
    for job in rows:
        owes, command = _owes_deployment(job)
        show = owes and job.cluster in awaiting and job.cluster not in captioned
        if show:
            captioned.add(job.cluster)
        views.append(
            _view(
                job,
                current,
                follow_up=(
                    f"Published, not deployed. The nodes still run the previous version "
                    f"until {job.cluster} is deployed."
                    if show
                    else None
                ),
                next_command=command if show else None,
            )
        )
    jobs = tuple(views)
    return JobOverview(
        jobs=jobs,
        active_count=sum(job.state in {"pending", "running"} for job in jobs),
        attention_count=sum(
            job.state in {"partial", "blocked", "failed", "unknown"} for job in jobs
        ),
        completed_count=sum(job.state == "done" for job in jobs),
    )
