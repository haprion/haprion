"""Restoring a node from its archive: the form that starts a run, and the run's page.

Nothing new is stored for a restore. A run is the jobs that carry its ID in
their payload (B175) - prepare, preview, run, and discard (B182) - and the page is drawn from
those rows alone, so what it says is what the helper answered and nothing a
second table could disagree with. The steps a person takes between the jobs
(pasting a line on the target, reading its fingerprint, typing the node's name)
happen on the page, and each one queues the next job.

The parameters are checked by the root helper's own `validate`, the one the
command line uses too, so this form cannot accept what the helper refuses.

A run has an hour from prepare to run (B182), read from the engine's own
constant: past it the page says so and takes nothing more, the backup page
stops listing it, and the helper refuses it and removes its key. Nobody has to
click anything for that - the hour is a rule both ends read, not a job.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from haproxy_mgmt import node_restore, restore_agent
from haproxy_mgmt.cli import node_restore_helper
from haproxy_mgmt.cli.node_restore_helper import DISCARD, PREPARE, PREVIEW, RUN

from .db import Job
from .jobs import RUNNING_LABELS

OPERATIONS = (PREPARE, PREVIEW, RUN, DISCARD)
MODES = ("new_vm", "test")
ACTIVE_STATES = frozenset({"pending", "running"})
EXPIRES_AFTER = timedelta(seconds=node_restore.START_WINDOW)
#
# What Discard is offered for: every stage but one that is working, one that
# restored the node, and one already discarded.
#
DISCARDABLE = frozenset({"prepare_failed", "fingerprint", "confirm", "failed", "expired"})


class RestoreProblem(ValueError):
    """What was entered cannot start or continue a restore; safe to show."""


def _resolve(host: str) -> str:
    try:
        found = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
    except (OSError, UnicodeError):
        return ""
    return str(found[0][4][0]) if found else ""


def node_address(
    statuses: Iterable[Any],
    cluster: str,
    node: str,
    *,
    resolve: Callable[[str], str] = _resolve,
) -> str:
    """The node's own IPv4 address, to fill in the form's target; empty when not known.

    Read from the poller's reading of the cluster - the name status and deploy
    reach the node by - and looked up when it is a name. Only a suggestion: a
    restore as the node itself is held to the archive's address and host key
    by the preview, whatever is typed here.
    """

    for status in statuses:
        if getattr(status, "cluster", None) != cluster or not isinstance(status.result, dict):
            continue
        for entry in status.result.get("nodes", []):
            if isinstance(entry, dict) and entry.get("name") == node:
                host = str(entry.get("mgmt_host") or "")
                try:
                    return str(ipaddress.IPv4Address(host))
                except ValueError:
                    return resolve(host) if host else ""
    return ""


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
        raise RestoreProblem("Choose the node or a test restore.")
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
    """Empty is allowed: the node itself is known by its archived host key (B184)."""

    payload = {"run": run, "fingerprint": node_restore_helper.fingerprint_in(fingerprint)}
    _checked(PREVIEW, payload)
    return payload


def discard_payload(run: str) -> dict[str, Any]:
    payload = {"run": run}
    _checked(DISCARD, payload)
    return payload


def run_payload(
    run: str,
    confirm: str,
    expected: str,
    *,
    overwrite: bool = False,
    backup_failed_ok: bool = False,
    break_traffic: bool = False,
) -> dict[str, Any]:
    """Typing the node's name is the confirmation, and it must be the name in the plan.

    An overwrite (B172) passes on the two ticks the helper itself holds it to,
    shown only when its preview found the need: going on without a backup, and
    breaking live traffic. The name is the confirmation; there is no third tick.
    """

    if confirm.strip() != expected:
        raise RestoreProblem(f"Type {expected} to restore this node.")
    payload: dict[str, Any] = {"run": run, "confirm": confirm.strip()}
    if overwrite:
        payload.update(backup_failed_ok=backup_failed_ok, break_traffic=break_traffic)
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
    ``expired``            waited for a fingerprint or a confirmation past its hour
    ``discarded``          given up with Discard; its key is gone
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
    # The manager's node bundle the preview found (B180): root and commit.
    node_bundle: Mapping[str, Any] | None = None
    # Accounts and groups whose number on the VM differs from the archive's (B181).
    renumbered: tuple[str, ...] = ()
    # When the prepare job was queued, and when the hour to start the run ends (B182).
    prepared_at: datetime | None = None
    # An overwrite's backup and pair, as its preview read them (B172, B183).
    overwrite: Mapping[str, Any] | None = None

    @property
    def backup_failed(self) -> bool:
        return self.overwrite is not None and self.overwrite.get("backup") != "done"

    @property
    def traffic_at_risk(self) -> bool:
        """The node may hold the VIP and its neighbour could not take it."""

        return (
            self.overwrite is not None
            and self.overwrite.get("vip_owner") is not False
            and not self.overwrite.get("neighbour_healthy")
        )

    @property
    def active(self) -> bool:
        return self.stage == "working"

    @property
    def discardable(self) -> bool:
        return self.stage in DISCARDABLE

    @property
    def expires_at(self) -> datetime | None:
        return None if self.prepared_at is None else self.prepared_at + EXPIRES_AFTER


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
        for name in ("apply", "network", "finish", "rollback")
        if isinstance(sessions.get(name), dict)
        for warning in _strings(sessions[name].get("warnings"))
    )


def run_view(run: str, rows: Sequence[Job], *, now: datetime | None = None) -> RestoreRun | None:
    """The run's state from its jobs, oldest first, or None when it has none.

    `now` decides whether a run waiting on its operator has expired; without it
    the hour is not judged, which is what a test of the steps alone wants.
    """

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
    latest = [job for job in jobs if job.operation != DISCARD][-1]
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

    if (
        now is not None
        and stage in {"fingerprint", "confirm"}
        and now - prepared.created_at > EXPIRES_AFTER
    ):
        stage, error, problems = "expired", "", ()
    discards = [job for job in jobs if job.operation == DISCARD]
    if discards and stage != "working":
        #
        # A discard is read last and over whatever the steps left: done, the run
        # is given up; still queued, it is working; refused, the stage stands
        # with the reason beside it.
        #
        discard = discards[-1]
        if discard.state in ACTIVE_STATES:
            stage, working = "working", RUNNING_LABELS.get(DISCARD, DISCARD)
        elif discard.state == "done":
            stage, error, problems = "discarded", "", ()
        else:
            error = _error(discard)

    target_facts = preview.get("target") if isinstance(preview.get("target"), dict) else None
    return RestoreRun(
        run=run,
        cluster=prepared.cluster or "",
        node=str(asked.get("node", "")),
        archive=str(asked.get("archive", "")),
        target=str(asked.get("target", "")),
        # As the node, the preview decides: over the node itself or a VM in its place (B184).
        mode="test"
        if isinstance(test, dict)
        else "overwrite"
        if plan is not None and plan.get("mode") == "overwrite"
        else "new_vm",
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
        node_bundle=preview.get("node_bundle")
        if isinstance(preview.get("node_bundle"), dict)
        else None,
        renumbered=_strings(preview.get("renumbered")),
        prepared_at=prepared.created_at,
        overwrite=preview.get("overwrite") if isinstance(preview.get("overwrite"), dict) else None,
    )


def step_states(restore: RestoreRun) -> dict[str, str]:
    """Where each of the three steps stands: done, current, failed or waiting."""

    order = ("prepare", "preview", "run")
    if restore.stage == "working" and restore.jobs[-1].operation != DISCARD:
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
        # Given up, past its hour, or being discarded: the steps not taken stay grey.
        "expired": {"prepare": "done", "preview": "waiting", "run": "waiting"},
        "discarded": {"prepare": "done", "preview": "waiting", "run": "waiting"},
        "working": {"prepare": "done", "preview": "waiting", "run": "waiting"},
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
    "expired": ("Expired", "unknown"),
    "discarded": ("Discarded", "unknown"),
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
    discardable: bool = False


def recent_runs(
    rows: Iterable[Job], *, shown: Callable[[datetime], datetime], now: datetime
) -> dict[str, tuple[RecentRun, ...]]:
    """The runs that still ask something of somebody, per cluster, newest first.

    A restored run is history: the audit trail and the jobs page keep it. What
    the backup page lists is a run left waiting for its fingerprint or its
    confirmation, one still running, and one that stopped - each the way its
    own page reads it, and each a way back to that page. Only within the run's
    hour (B182): past it a run is started again, not finished, so it leaves the
    list by itself - unless a job of it is still working. A discarded run goes
    at once.

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
        restore = run_view(run, jobs, now=now)
        if restore is None or restore.stage in {"done", "discarded", "expired"}:
            continue
        if not restore.active and restore.expires_at is not None and now > restore.expires_at:
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
                mode={"test": "test", "overwrite": "over the node"}.get(
                    restore.mode, "as the node"
                ),
                started=shown(created).strftime("%Y-%m-%d %H:%M"),
                started_iso=created.astimezone(UTC).isoformat(),
                label=label,
                tone=tone,
                discardable=restore.discardable,
            )
        )
    return {cluster: tuple(runs) for cluster, runs in recent.items()}
