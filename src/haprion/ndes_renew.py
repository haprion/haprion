"""Scheduled renewal of the certificates the manager enrolled over NDES/SCEP.

Certbot renews its own lineages; a certificate the manager asked a Microsoft
CA for over SCEP (C6) has nobody to renew it, and until 2026-09-15 the plan
said so and left it to the expiry badge. The maintainer's decision that
evening: these certificates renew on schedule too, and the way is the one
that already exists - a new SCEP request under the same ID, with the same
profile, the names the current certificate carries and the targets the
registry holds. `cert_scep.enroll` does the rest: a fresh key, the request,
validation, and the import that replaces the published material only once
the new certificate has been checked. Nothing here has a second code path.

What decides
------------
The certificate's own `not_after`, read at its source, against a threshold
in days from the runtime policy (`ndes.renew_days`, default 30). A run may
also name one certificate to renew now, threshold or not - the test of this
path, since a CA template's validity cannot be shortened per request, and
the operator's way to rotate a key.

What is left behind
-------------------
One record per certificate under the NDES state root saying what the last
attempt did - renewed, pending at the CA, or failed and why - so the
listing helper can put it on the certificate's row. The record is the run's
word about itself; the material and the registry are still measured
directly. It names the certificate it tried to renew, and an enrollment
that imports a certificate or leaves a request with the CA - from any
entrance - ends it (`ndes_state.end_renewal`).
"""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from haprion import atomic_file
from haprion.cert_inventory import IMPORT_STORE, LETSENCRYPT_LIVE, measure_registered
from haprion.config import PathPolicy, RuntimeConfig
from haprion.ndes_state import record_path, records_directory

RENEW_DAYS_DEFAULT = 30


@dataclass(frozen=True, slots=True)
class Candidate:
    """One NDES certificate and what a renewal of it would ask for."""

    certificate_id: str
    profile_id: str
    domains: tuple[str, ...]
    clusters: tuple[str, ...]
    receivers: tuple[str, ...]
    not_after: datetime
    days_left: int
    interface: bool = False
    fingerprint: str = ""
    """The SHA-256 of the certificate this renewal replaces, for its record."""


@dataclass(frozen=True, slots=True)
class Outcome:
    certificate_id: str
    outcome: str
    """`renewed`, `pending` (the CA is holding the request), `failed` or `skipped`."""

    message: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "certificate": self.certificate_id,
            "outcome": self.outcome,
            "message": self.message,
        }


def candidates(
    runtime: RuntimeConfig,
    policy: PathPolicy,
    *,
    now: datetime,
    threshold_days: int,
    only: Sequence[str] = (),
    live: Path = LETSENCRYPT_LIVE,
    store: Path = IMPORT_STORE,
) -> tuple[list[Candidate], list[Outcome]]:
    """The NDES certificates due, and the ones that could not be considered.

    Due is `days_left < threshold`, or being named in `only`. A certificate
    whose material cannot be read is reported rather than guessed at: its
    names would have to come from that material.
    """

    registry = runtime.registry
    if registry is None or policy.certificate_root is None:
        return [], []
    wanted = set(only)
    due: list[Candidate] = []
    problems: list[Outcome] = []
    for entry in registry.certificates.values():
        profile_id = entry.source.ndes_profile
        if profile_id is None:
            if entry.certificate_id in wanted:
                problems.append(Outcome(entry.certificate_id, "skipped", "not an NDES certificate"))
            continue
        measured = measure_registered(
            entry, certificate_root=policy.certificate_root, live=live, store=store
        )
        if isinstance(measured, str):
            problems.append(Outcome(entry.certificate_id, "skipped", measured))
            continue
        fingerprint, facts, _ = measured
        days_left = (facts.not_after - now).days
        if entry.certificate_id not in wanted and days_left >= threshold_days:
            continue
        common = facts.common_name
        domains = tuple(
            dict.fromkeys(
                ([common] if common else []) + [name for name in facts.sans if name != common]
            )
        )
        if not domains:
            problems.append(
                Outcome(entry.certificate_id, "skipped", "the certificate carries no DNS name")
            )
            continue
        due.append(
            Candidate(
                entry.certificate_id,
                profile_id,
                domains,
                entry.clusters,
                entry.receivers,
                facts.not_after,
                days_left,
                entry.interface,
                fingerprint,
            )
        )
    return due, problems


Enroller = Callable[[Candidate], tuple[dict[str, Any], int]]


def outcome_of(candidate: Candidate, document: dict[str, Any], exit_code: int) -> Outcome:
    """What `cert_scep`'s envelope says, as one word and the CA's sentence."""

    result = document.get("result") if isinstance(document.get("result"), dict) else {}
    if document.get("outcome") == "done" and exit_code == 0:
        return Outcome(candidate.certificate_id, "renewed")
    if isinstance(result, dict) and result.get("state") == "pending":
        return Outcome(
            candidate.certificate_id, "pending", "CA approval is pending; resume the request"
        )
    error = document.get("error") if isinstance(document.get("error"), dict) else {}
    message = error.get("message") if isinstance(error, dict) else None
    if isinstance(error, dict) and error.get("code") == "busy":
        #
        # Another enrollment holds the certificate's lock - *Resume
        # enrollment*, *Renew…* or the terminal - and its outcome is the one
        # that counts. Written down as this pass's failure it stood on the
        # row after that enrollment had finished (review 2026-10-29, round 2,
        # BBB02); the next pass asks again.
        #
        return Outcome(
            candidate.certificate_id,
            "skipped",
            message if isinstance(message, str) and message else "another enrollment is running",
        )
    return Outcome(
        candidate.certificate_id,
        "failed",
        message if isinstance(message, str) and message else "the renewal did not complete",
    )


def write_record(
    state_root: Path, outcome: Outcome, *, now: datetime, fingerprint: str = ""
) -> None:
    """The attempt's record, naming the certificate it tried to renew (`ndes_state.renewal_of`)."""

    directory = records_directory(state_root)
    directory.mkdir(mode=0o700, exist_ok=True)
    path = record_path(state_root, outcome.certificate_id)
    body = {
        "certificate": outcome.certificate_id,
        "attempted_at": now.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "outcome": outcome.outcome,
        "message": outcome.message,
        **({"fingerprint_sha256": fingerprint} if fingerprint else {}),
    }
    atomic_file.write(path, json.dumps(body).encode("utf-8"), mode=0o600)


def renew(
    due: Sequence[Candidate],
    *,
    state_root: Path,
    enroll: Enroller,
    now: datetime,
) -> list[Outcome]:
    """Renew each candidate in turn and record what happened, per certificate.

    One at a time, because the SCEP path holds the publisher's lock for its
    import and Certmonger runs as one instance per request; a failure on one
    certificate is recorded and the next is tried.
    """

    outcomes: list[Outcome] = []
    for candidate in due:
        try:
            document, exit_code = enroll(candidate)
        except Exception as exc:  # noqa: BLE001 - one certificate's failure is recorded, not raised
            outcome = Outcome(candidate.certificate_id, "failed", str(exc) or type(exc).__name__)
        else:
            outcome = outcome_of(candidate, document, exit_code)
        if outcome.outcome != "skipped":
            write_record(state_root, outcome, now=now, fingerprint=candidate.fingerprint)
        outcomes.append(outcome)
    return outcomes
