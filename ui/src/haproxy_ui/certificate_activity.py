"""What the queue is doing to a certificate, for the State column.

A deletion is a job, and until 2026-09-15 the page after confirming one was
the jobs page: the listing had no way to say "being deleted" about a row
that the registry still held. Now it does. The newest `cert_delete` job that
names a certificate decides what its State cell says while the row is still
listed: the job is running, it is done and the poller has not yet re-read
the registry, or it ended badly and the row is still here for a reason the
cell can give.

A request is a job too, and the same day the page after asking for one was
also the jobs page - "jobs is where you look when something failed or takes
long", not where a person expects to land after pressing a button. So a
`cert_issue` or `cert_scep` in flight is a row here before the registry has
one: the name typed, the targets chosen, and "Requesting" where the state
goes; when it fails, the CA's own words in the same cell for an hour.

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

from haproxy_mgmt.cert_issue import IssueError, parse_domain

from haproxy_ui.db import Job

#
# How long a finished deletion's verdict stays in the cell. A failure from
# last week is history, and the jobs page keeps it; the State column is for
# what the operator just did.
#
VERDICT_LIFETIME = timedelta(hours=1)


@dataclass(frozen=True, slots=True)
class Placeholder:
    """A row for a certificate the registry does not list yet.

    Drawn from the request's own payload, because that is all there is: the
    listing is a cached reading and the material does not exist until the
    CA answers.
    """

    source_label: str
    lifecycle: str
    wildcard: bool
    sans: tuple[str, ...]
    clusters: tuple[str, ...]
    receivers: tuple[str, ...]


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
    #
    # What to draw when no registry row carries this identifier. A request
    # that has not been answered has no row of its own; a deletion always
    # had one.
    #
    placeholder: Placeholder | None = None
    #
    # True for a state that only fills a gap: once the registry lists the
    # certificate, the row's own reading is the truth and this overlay is
    # not drawn over it. A finished request is one; a running one is not,
    # since a re-request of an existing name is the row being replaced.
    #
    placeholder_only: bool = False


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
        if job.operation == "cert_issue":
            requested = _issue_placeholder(job.payload)
            if requested is not None and requested[0] not in states:
                state = _issue_state_of(job, moment, requested[1])
                if state is not None:
                    states[requested[0]] = state
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
    only the running job and a fresh failure are overlays here - drawn on a
    placeholder row until the pending request is listed.
    """

    placeholder = _scep_placeholder(job.payload)
    if job.state in {"pending", "running"}:
        return DeletionState(
            "Enrolling", "The CA is being asked for the certificate", "info", True, placeholder
        )
    if job.finished_at is not None and now - job.finished_at > VERDICT_LIFETIME:
        return None
    if job.state == "failed":
        return DeletionState(
            "Enrollment failed",
            _failure(job, "The enrollment job failed"),
            "critical",
            False,
            placeholder,
        )
    return None


def _issue_state_of(job: Job, now: datetime, placeholder: Placeholder) -> DeletionState | None:
    """An ACME request in flight, just answered, or just refused.

    Certbot's own words on failure, in the cell: the reason a person used to
    be sent to the jobs page. A finished request stays a placeholder until
    the poller lists the certificate, and never overrides the row once it
    does.
    """

    if job.state in {"pending", "running"}:
        return DeletionState(
            "Requesting", "The CA is being asked for the certificate", "info", True, placeholder
        )
    if job.finished_at is not None and now - job.finished_at > VERDICT_LIFETIME:
        return None
    if job.state == "failed":
        return DeletionState(
            "Request failed",
            _failure(job, "The request job failed"),
            "critical",
            False,
            placeholder,
        )
    if job.state == "done":
        return DeletionState(
            "Issued",
            "Issued; the listing lists it at the next poll",
            "info",
            True,
            placeholder,
            placeholder_only=True,
        )
    return None


def _failure(job: Job, fallback: str) -> str:
    result = job.result if isinstance(job.result, Mapping) else {}
    error = result.get("error") if isinstance(result.get("error"), Mapping) else {}
    message = error.get("message") if isinstance(error, Mapping) else None
    return message if isinstance(message, str) and message else fallback


def _names(payload: Mapping[str, Any], key: str) -> tuple[str, ...]:
    value = payload.get(key)
    if not isinstance(value, list):
        return ()
    return tuple(item for item in value if isinstance(item, str))


def _issue_placeholder(payload: Mapping[str, Any]) -> tuple[str, Placeholder] | None:
    """The certificate a `cert_issue` payload asks for, named the engine's way."""

    domain = payload.get("domain")
    if not isinstance(domain, str):
        return None
    try:
        identifier, domains, wildcard = parse_domain(domain)
    except IssueError:
        return None
    return identifier, Placeholder(
        "Certbot",
        "acme",
        wildcard,
        domains,
        _names(payload, "clusters"),
        _names(payload, "receivers"),
    )


def _scep_placeholder(payload: Mapping[str, Any]) -> Placeholder:
    domains = _names(payload, "domains")
    return Placeholder(
        "NDES",
        "import",
        any(name.startswith("*.") for name in domains),
        domains,
        _names(payload, "clusters"),
        _names(payload, "receivers"),
    )


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
