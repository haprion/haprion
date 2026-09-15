"""What the queue is doing to a registered certificate, for the State column.

A deletion is a job, and until 2026-09-15 the page after confirming one was
the jobs page: the listing had no way to say "being deleted" about a row
that the registry still held. Now it does. The newest `cert_delete` job that
names a certificate decides what its State cell says while the row is still
listed: the job is running, it is done and the poller has not yet re-read
the registry, or it ended badly and the row is still here for a reason the
cell can give.

Read from the same recent jobs the dashboard reads; nothing is queried for
this. The listing itself is a cached reading, so a certificate the helper
removed stays in the table until the next poll - which is why "Deleted" is
a state here at all, and why the page refreshes itself while any of these
states is in effect.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from haproxy_ui.db import Job

#
# How long a finished deletion's verdict stays in the cell. A failure from
# last week is history, and the jobs page keeps it; the State column is for
# what the operator just did.
#
VERDICT_LIFETIME = timedelta(hours=1)


@dataclass(frozen=True, slots=True)
class DeletionState:
    label: str
    detail: str
    tone: str
    #
    # Whether the page should refresh itself: the state is going to change
    # without anybody pressing anything.
    #
    active: bool


def deletion_states(
    jobs: Iterable[Job], *, now: datetime | None = None
) -> dict[str, DeletionState]:
    """Per certificate, what its newest `cert_delete` job says, if it says anything."""

    moment = now or datetime.now(UTC)
    states: dict[str, DeletionState] = {}
    for job in jobs:
        if job.operation == "cert_scep":
            identifier = job.payload.get("id")
            if isinstance(identifier, str) and identifier not in states:
                state = _enrollment_state_of(job, moment)
                if state is not None:
                    states[identifier] = state
            continue
        if job.operation != "cert_delete":
            continue
        named = job.payload.get("certificates")
        if not isinstance(named, list):
            continue
        for identifier in named:
            if not isinstance(identifier, str) or identifier in states:
                continue
            state = _state_of(job, identifier, moment)
            if state is not None:
                states[identifier] = state
    return states


def _enrollment_state_of(job: Job, now: datetime) -> DeletionState | None:
    """An NDES enrollment in flight or just failed; the listing says the rest.

    A pending request and an issued certificate are both facts the listing
    helper reads from the manager itself (`request_state`, the material), so
    only the running job and a fresh failure are overlays here.
    """

    if job.state in {"pending", "running"}:
        return DeletionState("Enrolling", "The CA is being asked for the certificate", "info", True)
    if job.finished_at is not None and now - job.finished_at > VERDICT_LIFETIME:
        return None
    if job.state == "failed":
        result = job.result if isinstance(job.result, Mapping) else {}
        error = result.get("error") if isinstance(result.get("error"), Mapping) else {}
        message = error.get("message") if isinstance(error, Mapping) else None
        return DeletionState(
            "Enrollment failed",
            message if isinstance(message, str) and message else "The enrollment job failed",
            "critical",
            False,
        )
    return None


def _state_of(job: Job, identifier: str, now: datetime) -> DeletionState | None:
    if job.state in {"pending", "running"}:
        return DeletionState("Deleting", "A deletion job is running", "info", True)
    if job.finished_at is not None and now - job.finished_at > VERDICT_LIFETIME:
        return None
    result = job.result if isinstance(job.result, Mapping) else {}
    if job.state == "failed":
        error = result.get("error") if isinstance(result.get("error"), Mapping) else {}
        message = error.get("message") if isinstance(error, Mapping) else None
        return DeletionState(
            "Delete failed",
            message if isinstance(message, str) and message else "The deletion job failed",
            "critical",
            False,
        )
    row = _row(result, identifier)
    outcome = row.get("state") if row else None
    if outcome == "removed":
        return DeletionState(
            "Deleted", "Removed; the listing drops it at the next poll", "info", True
        )
    if outcome == "refused":
        return DeletionState("Delete refused", _reason(row), "critical", False)
    if outcome == "incomplete":
        return DeletionState("Delete incomplete", _reason(row), "warning", False)
    return None


def _row(result: Mapping[str, Any], identifier: str) -> Mapping[str, Any] | None:
    rows = result.get("certificates")
    if not isinstance(rows, list):
        return None
    for row in rows:
        if isinstance(row, Mapping) and row.get("certificate") == identifier:
            return row
    return None


def _reason(row: Mapping[str, Any] | None) -> str:
    reason = row.get("reason") if row else None
    return reason if isinstance(reason, str) and reason else "See the jobs page"
