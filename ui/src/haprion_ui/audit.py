"""The record as a person reads it: who did what, where, in one sentence (B275).

`audit_event` has been written since the first migration and read by nobody
in the interface. *Events → Audit* shows it to an admin; *Events → Jobs* takes
the name of whoever queued each job from it; the Servers card says who set a
drain. Each event is one sentence, built from its action and its detail by
`ACTIVITY_PHRASES`. An action the table does not know is shown by its own
name rather than hidden - a record that left rows out would be a record
nobody could trust - and a test holds the table to every action the code
writes.

A failed sign-in under a name no account has is shown as *unknown user*,
without the name: what somebody typed into the user field may be their
password.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from haprion_ui import labels, moments
from haprion_ui.db import AuditEvent

UNKNOWN_USER = "unknown user"

#
# What a queued job is, as the sentence names it: what the person asked for.
#
OPERATION_NAMES: Mapping[str, str] = {
    "backup_run": "a node backup",
    "backup_schedule": "a backup schedule change",
    "node_restore_prepare": "a restore preparation",
    "node_restore_preview": "a restore preview",
    "node_restore": "a node restore",
    "node_restore_discard": "discarding a restore",
    "node_restore_status": "a restore status check",
    "deploy": "a deploy",
    "cert_deploy": "a certificate deploy",
    "revert": "a revert",
    "changes_publish": "Publish & deploy",
    "cert_issue": "a certificate issue",
    "cert_import": "a certificate import",
    "cert_request": "a signing request",
    "dns_profile_apply": "a DNS profile change",
    "ndes_profile_apply": "an NDES profile change",
    "cert_scep": "an NDES enrollment",
    "cert_delete": "a certificate deletion",
    "cert_publish": "a certificate publish",
    "cert_target": "a certificate target change",
    "cert_receiver": "a receiver change",
    "cluster_node": "a node change",
    "cluster_define": "a cluster change",
    "server_state": "a server state change",
    "dynamic_unblock": "an unblock",
}

SERVER_STATES: Mapping[str, str] = {"drain": "drain", "maint": "maintenance", "ready": "ready"}


def _text(detail: Mapping[str, Any], key: str, fallback: str = "") -> str:
    value = detail.get(key)
    return value if isinstance(value, str) and value else fallback


def _list(detail: Mapping[str, Any], key: str) -> list[str]:
    value = detail.get(key)
    return [str(item) for item in value] if isinstance(value, list) else []


def _queued(detail: Mapping[str, Any]) -> str:
    operation = _text(detail, "operation")
    job = detail.get("job")
    numbered = f" (job {job})" if isinstance(job, int) else ""
    if operation == "server_state":
        servers = ", ".join(_list(detail, "servers")) or "servers"
        state = SERVER_STATES.get(_text(detail, "state"), _text(detail, "state", "a state"))
        return f"Set {servers} on {_text(detail, 'object', '?')} to {state}{numbered}"
    if operation == "dynamic_unblock":
        addresses = ", ".join(_list(detail, "addresses")) or "addresses"
        return f"Unblocked {addresses} on {_text(detail, 'object', '?')}{numbered}"
    name = OPERATION_NAMES.get(operation, operation or "a job")
    subject = _text(detail, "certificate") or _text(detail, "object")
    about = f" of {subject}" if subject else ""
    return f"Queued {name}{about}{numbered}"


def _saved(detail: Mapping[str, Any], verb: str) -> str:
    kind = _text(detail, "kind")
    if kind == "network":
        return f"{verb} the network description"
    if kind == "settings":
        return f"{verb} the logs & metrics settings"
    name = _text(detail, "object", "a proxy")
    if detail.get("removed") is True:
        return f"{verb} the removal of {name}"
    return f"{verb} {name}"


def _account(detail: Mapping[str, Any]) -> str:
    return _text(detail, "account", "an account")


def _signed_in(detail: Mapping[str, Any]) -> str:
    return "Signed in with the identity provider" if detail.get("via") == "oidc" else "Signed in"


def _sign_in_failed(detail: Mapping[str, Any]) -> str:
    reason = _text(detail, "reason")
    if reason == "throttled":
        return "Sign-in refused: too many attempts"
    if detail.get("via") == "oidc":
        return "Sign-in with the identity provider refused"
    return "Sign-in failed"


def _feature(detail: Mapping[str, Any]) -> str:
    state = "on" if detail.get("enabled") is True else "off"
    return f"Turned {_text(detail, 'feature', 'a feature')} {state}"


def _break_glass(detail: Mapping[str, Any]) -> str:
    if detail.get("break_glass") is True:
        return f"Made {_account(detail)} a break-glass account"
    return f"Made {_account(detail)} an ordinary account"


ACTIVITY_PHRASES: Mapping[str, Callable[[Mapping[str, Any]], str]] = {
    "login": _signed_in,
    "login_failed": _sign_in_failed,
    "logout": lambda _detail: "Signed out",
    "queue_job": _queued,
    "save_change": lambda detail: _saved(detail, "Saved"),
    "discard_change": lambda detail: _saved(detail, "Discarded the saved"),
    "save_draft": lambda detail: f"Saved a draft of {_text(detail, 'object', 'a proxy')}",
    "discard_draft": lambda detail: f"Discarded the draft of {_text(detail, 'object', 'a proxy')}",
    "account_created": lambda detail: f"Created the account {_account(detail)}",
    "account_deleted": lambda detail: f"Deleted the account {_account(detail)}",
    "account_disabled": lambda detail: f"Disabled the account {_account(detail)}",
    "account_enabled": lambda detail: f"Enabled the account {_account(detail)}",
    "role_changed": lambda detail: (
        f"Changed the role of {_account(detail)} to {_text(detail, 'role', '?')}"
    ),
    "password_changed": lambda _detail: "Changed their own password",
    "password_change_failed": lambda _detail: "Password change failed",
    "password_reset": lambda detail: f"Set a new password for {_account(detail)}",
    "break_glass_changed": _break_glass,
    "sessions_revoked": lambda detail: f"Signed {_account(detail)} out everywhere",
    "all_sessions_revoked": lambda detail: (
        f"Signed every account out ({labels.counted(detail.get('sessions', 0), 'session')})"
    ),
    "throttle_cleared": lambda detail: f"Cleared the sign-in throttle for {_account(detail)}",
    "oidc_configured": lambda _detail: "Changed the identity provider settings",
    "oidc_verified": lambda detail: (
        "Verified the identity provider"
        if detail.get("ok") is True
        else "Verified the identity provider, without success"
    ),
    "oidc_tested": lambda _detail: "Tried signing in with the identity provider",
    "oidc_enabled": lambda _detail: "Turned on sign-in with the identity provider",
    "feature_switched": _feature,
    "attention_acknowledged": lambda detail: (
        f"Acknowledged {_text(detail, 'subject', 'a row')}: {_text(detail, 'message', '')}"
    ),
    "getting_started_hidden": lambda _detail: "Hid the getting started list",
    "getting_started_shown": lambda _detail: "Showed the getting started list again",
    "status_access_changed": lambda detail: (
        "Changed the external monitoring addresses"
        if detail.get("networks")
        else "Switched external monitoring off"
    ),
    "certificate_export": lambda detail: (
        f"Exported the key of {_text(detail, 'certificate', 'a certificate')}"
    ),
    "certificate_download": lambda detail: (
        f"Downloaded {_text(detail, 'certificate', 'a certificate')} without its key"
    ),
    "job_finished": lambda detail: f"Job {detail.get('job', '?')} ended",
    "job_requeued": lambda detail: f"Job {detail.get('job', '?')} was queued again",
    "job_abandoned": lambda detail: f"Job {detail.get('job', '?')} was given up",
    "job_adopted": lambda detail: f"Job {detail.get('job', '?')} was ended on its kept answer",
    "jobs_held": lambda detail: (
        f"Held {labels.counted(len(detail.get('jobs') or []), 'job')} for an admin: {detail.get('reason', '')}"
    ),
    "held_job_decided": lambda detail: (
        f"Let held job {detail.get('job', '?')} run"
        if detail.get("decision") == "run"
        else f"Discarded held job {detail.get('job', '?')}"
    ),
}


#
# What a detail key is called on the row's opened line. A key not here is
# shown by its own name with the underscores spaced, so nothing recorded is
# hidden.
#
FACT_LABELS: Mapping[str, str] = {
    "client_ip": "Address",
    "via": "Through",
    "operation": "Job",
    "networks": "Allowed",
}


def _fact_value(value: Any) -> str:
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, list):
        return ", ".join(_fact_value(item) for item in value) or "—"
    if isinstance(value, dict):
        return ", ".join(f"{key} {_fact_value(item)}" for key, item in value.items()) or "—"
    return str(value)


def facts(detail: Mapping[str, Any]) -> tuple[tuple[str, str], ...]:
    """The detail as label and value, for the line under an opened row."""

    return tuple(
        (FACT_LABELS.get(key, key.replace("_", " ").capitalize()), _fact_value(value))
        for key, value in detail.items()
        if value not in (None, "", [], {})
    )


@dataclass(frozen=True, slots=True)
class AuditRow:
    id: int
    at: datetime
    shown_at: str
    who: str
    what: str
    where: str
    job: int | None
    request_id: UUID | None
    facts: tuple[tuple[str, str], ...]


def who(event: AuditEvent, accounts: frozenset[str]) -> str:
    """The actor, except a failed sign-in under a name no account has."""

    if event.actor is None:
        return "—"
    if event.action == "login_failed" and event.actor.lower() not in accounts:
        return UNKNOWN_USER
    return event.actor


def what(event: AuditEvent) -> str:
    phrase = ACTIVITY_PHRASES.get(event.action)
    if phrase is None:
        return event.action
    try:
        return phrase(event.detail if isinstance(event.detail, dict) else {})
    except (KeyError, TypeError, ValueError):
        return event.action


def rows(events: Iterable[AuditEvent], accounts: frozenset[str]) -> tuple[AuditRow, ...]:
    built: list[AuditRow] = []
    for event in events:
        detail = event.detail if isinstance(event.detail, dict) else {}
        shown = who(event, accounts)
        #
        # The detail of a failed sign-in under an unknown name carries no name
        # either way; what is drawn is only ever what the row says.
        #
        job = detail.get("job") if event.action == "queue_job" else None
        built.append(
            AuditRow(
                id=event.id,
                at=event.at,
                shown_at=moments.moment(event.at),
                who=shown,
                what=what(event),
                where=event.cluster or "—",
                job=job if isinstance(job, int) else None,
                request_id=event.request_id,
                facts=facts(detail),
            )
        )
    return tuple(built)


@dataclass(frozen=True, slots=True)
class SetBy:
    actor: str
    at: datetime
    shown_at: str


def set_by(events: Sequence[AuditEvent]) -> dict[tuple[str, str], SetBy]:
    """For each (server, state) the newest queue that asked for it, from newest-first events."""

    found: dict[tuple[str, str], SetBy] = {}
    for event in events:
        detail = event.detail if isinstance(event.detail, dict) else {}
        state = _text(detail, "state")
        for server in _list(detail, "servers"):
            key = (server, state)
            if key not in found and event.actor:
                found[key] = SetBy(event.actor, event.at, moments.moment(event.at))
    return found
