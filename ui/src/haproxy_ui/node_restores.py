"""Restoring a node from its archive: the form that starts a run, and the run's page.

Nothing new is stored for a restore. A run is the three jobs that carry its ID
in their payload (B175) - prepare, preview, run - and the page is drawn from
those rows alone, so what it says is what the helper answered and nothing a
second table could disagree with. The steps a person takes between the jobs
(pasting a line on the target, reading its fingerprint, typing the node's name)
happen on the page, and each one queues the next job.

The parameters are checked by the root helper's own `validate`, the one the
command line uses too, so this form cannot accept what the helper refuses.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from haproxy_mgmt import node_restore, restore_agent
from haproxy_mgmt.cli import node_restore_helper
from haproxy_mgmt.cli.node_restore_helper import PREPARE, PREVIEW, RUN

from .db import Job
from .jobs import RUNNING_LABELS

OPERATIONS = (PREPARE, PREVIEW, RUN)
MODES = ("new_vm", "test")
ACTIVE_STATES = frozenset({"pending", "running"})


class RestoreProblem(ValueError):
    """What was entered cannot start or continue a restore; safe to show."""


def new_run_id() -> str:
    """The engine's own run ID, chosen here so the page exists before its first job."""

    return node_restore.new_run_id()


def prepare_payload(
    *,
    run: str,
    node: str,
    archive: str,
    target: str,
    mode: str,
    test_hostname: str,
    test_address: str,
    test_vip: str,
    archives: Iterable[tuple[str, str]],
) -> dict[str, Any]:
    """The `node_restore_prepare` payload, or a sentence saying why not.

    `archives` is what the backup listing holds for this cluster, as
    (node, version) pairs: an archive this page has not been shown is not one
    it will ask the helper for, even though the helper would refuse it too.
    """

    if (node, archive) not in set(archives):
        raise RestoreProblem("That archive is not in this cluster's backup listing.")
    if mode not in MODES:
        raise RestoreProblem("Choose a new VM or a test restore.")
    test = (
        {
            "hostname": test_hostname.strip(),
            "address": test_address.strip(),
            "vip": test_vip.strip(),
        }
        if mode == "test"
        else None
    )
    payload: dict[str, Any] = {
        "run": run,
        "node": node,
        "archive": archive,
        "target": target.strip(),
        "test": test,
    }
    _checked(PREPARE, payload)
    return payload


def preview_payload(run: str, fingerprint: str) -> dict[str, Any]:
    payload = {"run": run, "fingerprint": node_restore_helper.fingerprint_in(fingerprint)}
    _checked(PREVIEW, payload)
    return payload


def run_payload(run: str, confirm: str, expected: str) -> dict[str, Any]:
    """Typing the node's name is the confirmation, and it must be the name in the plan."""

    if confirm.strip() != expected:
        raise RestoreProblem(f"Type {expected} to restore this node.")
    payload = {"run": run, "confirm": confirm.strip()}
    _checked(RUN, payload)
    return payload


def _checked(operation: str, payload: Mapping[str, Any]) -> None:
    try:
        node_restore_helper.validate(operation, payload)
    except node_restore_helper.ParameterProblem as exc:
        # The helper's sentences name a field, never what was typed into it.
        raise RestoreProblem(f"{str(exc)[:1].upper()}{str(exc)[1:]}.") from exc


@dataclass(frozen=True, slots=True)
class RestoreJob:
    id: int
    operation: str
    state: str


@dataclass(frozen=True, slots=True)
class RestoreRun:
    """One run as its jobs tell it.

    `stage` is what the page asks for next:

    ``working``            a job is queued or running; the page refreshes
    ``prepare_failed``     the run was never created on the manager
    ``fingerprint``        paste the line on the target, then enter its fingerprint
    ``confirm``            the preview found no problems; type the node's name
    ``done``               restored
    ``failed``             the run stopped after writing; `rolled_back` says whether
                           the network was put back
    """

    run: str
    cluster: str
    node: str
    archive: str
    target: str
    mode: str
    profile: Mapping[str, Any] | None
    stage: str
    working: str
    paste: str
    plan: Mapping[str, Any] | None
    target_facts: Mapping[str, Any] | None
    problems: tuple[str, ...]
    error: str
    confirm_name: str
    rolled_back: bool
    failed_stage: str
    result: Mapping[str, Any] | None
    warnings: tuple[str, ...]
    jobs: tuple[RestoreJob, ...]

    @property
    def active(self) -> bool:
        return self.stage == "working"


def _body(job: Job) -> Mapping[str, Any]:
    envelope = job.result if isinstance(job.result, dict) else {}
    body = envelope.get("result")
    return body if isinstance(body, dict) else {}


def _error(job: Job) -> str:
    envelope = job.result if isinstance(job.result, dict) else {}
    error = envelope.get("error")
    if isinstance(error, dict) and isinstance(error.get("message"), str):
        return str(error["message"])
    if job.stderr_excerpt:
        return job.stderr_excerpt.strip().splitlines()[-1]
    return "The helper gave no reason."


def _strings(value: Any) -> tuple[str, ...]:
    return tuple(item for item in value if isinstance(item, str)) if isinstance(value, list) else ()


def _warnings(body: Mapping[str, Any]) -> tuple[str, ...]:
    """Every session's warnings, in the order the sessions ran."""

    sessions = body.get("sessions")
    if not isinstance(sessions, dict):
        return ()
    return tuple(
        warning
        for name in ("apply", "network", "finish")
        if isinstance(sessions.get(name), dict)
        for warning in _strings(sessions[name].get("warnings"))
    )


def run_view(run: str, rows: Sequence[Job]) -> RestoreRun | None:
    """The run's state from its jobs, oldest first, or None when it has none."""

    jobs = sorted(
        (job for job in rows if job.operation in OPERATIONS and job.payload.get("run") == run),
        key=lambda job: job.id,
    )
    prepared = next((job for job in jobs if job.operation == PREPARE), None)
    if prepared is None:
        return None
    asked = prepared.payload
    test = asked.get("test")
    previews = [job for job in jobs if job.operation == PREVIEW and _body(job).get("plan")]
    preview = _body(previews[-1]) if previews else {}
    plan = preview.get("plan") if isinstance(preview.get("plan"), dict) else None

    stage, working, error = "fingerprint", "", ""
    problems: tuple[str, ...] = ()
    rolled_back, failed_stage, result = False, "", None
    latest = jobs[-1]
    if latest.state in ACTIVE_STATES:
        stage = "working"
        working = RUNNING_LABELS.get(latest.operation, latest.operation)
    elif latest.operation == PREPARE and latest.state != "done":
        stage, error = "prepare_failed", _error(latest)
    elif latest.operation == PREVIEW:
        if latest.state == "done":
            stage = "confirm"
        else:
            #
            # Blocked with a plan: the target was reached and something in it
            # stops the restore - shown with the plan. Without one the
            # fingerprint did not match, or the target was not reached.
            #
            error = _error(latest)
            problems = _strings(_body(latest).get("problems"))
    elif latest.operation == RUN:
        body = _body(latest)
        if latest.state == "done":
            stage, result = "done", body
        elif latest.state == "blocked":
            #
            # Refused before anything was written: the plan changed after the
            # preview, or the confirmation did not match. Preview again.
            #
            error = _error(latest)
        else:
            stage, error, result = "failed", _error(latest), body
            rolled_back = body.get("rolled_back") is True
            failed_stage = str(body.get("stage") or "")

    target_facts = preview.get("target") if isinstance(preview.get("target"), dict) else None
    return RestoreRun(
        run=run,
        cluster=prepared.cluster or "",
        node=str(asked.get("node", "")),
        archive=str(asked.get("archive", "")),
        target=str(asked.get("target", "")),
        mode="test" if isinstance(test, dict) else "new_vm",
        profile=test if isinstance(test, dict) else None,
        stage=stage,
        working=working,
        paste=str(_body(prepared).get("paste") or ""),
        plan=plan,
        target_facts=target_facts,
        problems=problems,
        error=error,
        confirm_name=str(plan.get("hostname", "")) if plan else "",
        rolled_back=rolled_back,
        failed_stage=failed_stage,
        result=result,
        warnings=_warnings(result) if result else (),
        jobs=tuple(RestoreJob(job.id, job.operation, job.state) for job in jobs),
    )


def step_states(restore: RestoreRun) -> dict[str, str]:
    """Where each of the three steps stands: done, current, failed or waiting."""

    order = ("prepare", "preview", "run")
    if restore.stage == "working":
        latest = restore.jobs[-1].operation
        at = {PREPARE: 0, PREVIEW: 1, RUN: 2}[latest]
        return {
            name: "done" if index < at else "current" if index == at else "waiting"
            for index, name in enumerate(order)
        }
    return {
        "prepare_failed": {"prepare": "failed", "preview": "waiting", "run": "waiting"},
        "fingerprint": {"prepare": "done", "preview": "current", "run": "waiting"},
        "confirm": {"prepare": "done", "preview": "done", "run": "current"},
        "done": {"prepare": "done", "preview": "done", "run": "done"},
        "failed": {"prepare": "done", "preview": "done", "run": "failed"},
    }[restore.stage]


def usable_run(run: str) -> bool:
    """A run ID in a URL is held to the pattern the run directory is."""

    return restore_agent.RUN_ID.fullmatch(run) is not None


#
# What the backup page says about a run, by the stage its page is at. The run's
# page is where anything is done; this is a line that leads there.
#
STAGE_LABELS: dict[str, tuple[str, str]] = {
    "working": ("Running", "info"),
    "prepare_failed": ("Not prepared", "critical"),
    "fingerprint": ("Waiting for the fingerprint", "warning"),
    "confirm": ("Waiting for confirmation", "warning"),
    "done": ("Restored", "healthy"),
    "failed": ("Failed", "critical"),
}
RECENT_PER_CLUSTER = 5


@dataclass(frozen=True, slots=True)
class RecentRun:
    run: str
    node: str
    mode: str
    started: str
    started_iso: str
    label: str
    tone: str


def recent_runs(
    rows: Iterable[Job], *, shown: Callable[[datetime], datetime]
) -> dict[str, tuple[RecentRun, ...]]:
    """The newest runs per cluster, newest first, each read the way its own page reads it.

    `rows` may hold the same job more than once (three queries, one per
    operation); a job is counted once. The job table keeps a week of rows, so
    this is a week of runs at most.
    """

    unique = {job.id: job for job in rows if job.operation in OPERATIONS}
    by_run: dict[str, list[Job]] = {}
    for job in unique.values():
        run = job.payload.get("run")
        if isinstance(run, str) and usable_run(run):
            by_run.setdefault(run, []).append(job)
    views = []
    for run, jobs in by_run.items():
        restore = run_view(run, jobs)
        if restore is None:
            continue
        first = min(jobs, key=lambda job: job.id)
        views.append((first.created_at, first.id, restore))
    views.sort(key=lambda item: (item[0], item[1]), reverse=True)
    recent: dict[str, list[RecentRun]] = {}
    for created, _id, restore in views:
        listed = recent.setdefault(restore.cluster, [])
        if len(listed) >= RECENT_PER_CLUSTER:
            continue
        label, tone = STAGE_LABELS[restore.stage]
        if restore.stage == "failed" and restore.rolled_back:
            label = "Failed · rolled back"
        listed.append(
            RecentRun(
                run=restore.run,
                node=restore.node,
                mode="test" if restore.mode == "test" else "as the node",
                started=shown(created).strftime("%Y-%m-%d %H:%M"),
                started_iso=created.astimezone(UTC).isoformat(),
                label=label,
                tone=tone,
            )
        )
    return {cluster: tuple(runs) for cluster, runs in recent.items()}
