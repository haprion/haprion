"""The safe, reader-visible projection of queued management jobs.

The job table is an operation record, not a way to control an operation.  It
deliberately leaves out claim tokens, idempotency keys and payload internals:
none answers the question a reader has after pressing a button, and several
would make an implementation detail into part of the UI contract.

Two things a failure needs are here, and both were missing until 2026-08-31.

The **error code** is the stable, environment-independent string the helper
blamed. The worker already keeps it in the audit trail because it is the one
part of a failure a person can act on months later - it simply never reached a
page, so `failed / exit 65` was the whole of what a reader was told, and a
locked cluster, a moved target and a refused validation looked identical.

The **diagnostics** are the operation's redacted stderr, and they are shown to
an admin only. The frozen contract says raw stderr is never returned to a
*reader role*; hiding it from everyone was a habit rather than a decision, and
the cost of that habit fell on the one person who had to open an SSH session at
every failure. See B44.
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
    exit_meaning: str
    #
    # What is still owed after a job that succeeded. A revert publishes but does
    # not roll out, so a job that reads `Completed` can leave the nodes on the
    # previous version - which is the one case where the state column alone is
    # actively misleading. The helper answers this in its result; until it was
    # projected here it was answered to nobody.
    #
    follow_up: str | None = None
    next_command: str | None = None
    #
    # Verbatim, never translated. A table mapping codes to friendlier sentences
    # would be a second place that has to stay in step with the contract - the
    # same drift `EXIT_MEANINGS` already documents one instance of - and the
    # code says more to somebody with proxy experience than a paraphrase would.
    #
    error_code: str | None = None
    #
    # Admin only, and empty for everyone else. Not merely hidden in the
    # template: the projection never carries it, so a role that may not see it
    # cannot be shown it by a later change to a page.
    #
    diagnostics: str | None = None


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


#
# The states that mean "this did not work". Both the follow-up row under a job
# and the "Need review" tally read it, so the two cannot drift into disagreeing
# about what counts as a bad ending.
#
ATTENTION = frozenset({"partial", "blocked", "failed", "unknown"})


def _error_code(job: Job) -> str | None:
    """The stable code this job's result blamed, or nothing.

    Read defensively for the same reason `_owes_deployment` is: the document
    was written by a privileged helper and stored as it arrived, so this asks
    it questions rather than assuming its shape.
    """

    envelope = job.result
    if not isinstance(envelope, dict):
        return None
    error = envelope.get("error")
    if not isinstance(error, dict):
        return None
    code = error.get("code")
    return code if isinstance(code, str) and code else None


def _view(
    job: Job,
    now: datetime,
    *,
    follow_up: str | None,
    next_command: str | None,
    diagnostics: bool,
) -> JobView:
    label, tone = _state(job.state)
    ended_badly = job.state in ATTENTION
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
        exit_meaning=_exit_meaning(job.exit_code),
        follow_up=follow_up,
        next_command=next_command,
        error_code=_error_code(job) if ended_badly else None,
        #
        # Only for a job that ended badly. A successful operation's stderr is
        # progress output, and putting a diagnostics panel under every green
        # row would bury the ones that mean something.
        #
        diagnostics=(job.stderr_excerpt or None) if diagnostics and ended_badly else None,
    )


#
# What the number in the exit column means. It is shown because a maintainer
# reading a bad job wants the precise code, and explained because everyone else
# is being shown an implementation detail of a command they did not run.
#
# Two of these are worth knowing about: 65 and 75 both mean "refused", because
# the engine has two constants named for blocking with different values. That is
# the engine's to reconcile, not this table's to hide.
#
EXIT_MEANINGS = {
    0: "Finished.",
    64: "The request itself was not valid.",
    65: "Refused before anything was changed.",
    68: "No usable status could be read from the cluster.",
    69: "Finished with nodes left unverified.",
    75: "Refused: the target had moved, or the cluster was locked.",
}


def _exit_meaning(code: int | None) -> str:
    if code is None:
        return "The job recorded no exit code."
    if code < 0:
        return f"Stopped by signal {-code}."
    return EXIT_MEANINGS.get(code, f"The command exited with {code}.")


def _unresolved(rows: list[Job]) -> int:
    """Clusters whose newest finished job ended badly.

    Not a tally of every bad outcome in the list. That number only ever grows,
    cannot be cleared, and answers no question a reader can act on - a failure
    from yesterday that a later run replaced is history, not work. Asked on the
    page as "what needs review?", the honest answer is: the clusters where the
    last thing we did did not work.

    A queued or running job is skipped rather than counted, and the cluster is
    then judged on the newest job that did finish. So a re-run in flight neither
    clears the warning nor replaces it: what is still known about that cluster
    is that the last completed attempt failed, and it stays known until an
    attempt completes differently.

    That is deliberate, and it is the opposite of what this docstring claimed
    until 2026-08-31, when the code review measured the function against its own
    description. Counting only finished jobs and then letting a running one
    silence the tally would let an operation in progress hide a warning, which
    is the wrong direction to be wrong in.
    """

    latest: dict[str, str] = {}
    for job in rows:
        if job.cluster not in latest and job.state not in {"pending", "running"}:
            latest[job.cluster] = job.state
    return sum(state in ATTENTION for state in latest.values())


def build_job_overview(
    rows: list[Job],
    *,
    now: datetime | None = None,
    awaiting: frozenset[str] = frozenset(),
    diagnostics: bool = False,
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

    `diagnostics` says whether the caller is entitled to the operations' stderr.
    It defaults to false, so a page that forgets to ask the question gets the
    reader-safe projection rather than the privileged one.
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
                diagnostics=diagnostics,
            )
        )
    jobs = tuple(views)
    return JobOverview(
        jobs=jobs,
        active_count=sum(job.state in {"pending", "running"} for job in jobs),
        attention_count=_unresolved(rows),
        completed_count=sum(job.state == "done" for job in jobs),
    )
