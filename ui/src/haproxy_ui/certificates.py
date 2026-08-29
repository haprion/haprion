"""Read model for the certificate distribution catalogue.

Like every other page, this layer knows only the envelope the poller cached. It
cannot read a PEM, reach `/srv/certdist/` or ask openssl anything: the helper
already did that, with the leaf block alone, and a second parser here would be a
second place for key material to end up.

The question the page answers is renewal, not inventory. Issuing happens a few
times a year and lives in a later phase; what is read every week is whether the
certificates a cluster references are still going to be valid next month, and
whether the ones certbot is supposed to renew are actually being renewed.

That is why expiry is judged against `lifecycle` rather than against one
deadline. The two say different things at the same number of days left: a
`static` certificate with four weeks to go is simply due, while an `acme` one
that far down has missed renewals certbot should already have made. One
threshold would either shout about the first or stay quiet about the second.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from haproxy_ui.cluster_identity import accent_index
from haproxy_ui.dashboard import relative_age
from haproxy_ui.db import ClusterCertificates

type Tone = Literal["healthy", "warning", "critical", "unknown"]

#
# A static certificate is renewed by a person, so it is flagged a month out -
# long enough to get an internal CA request through and onto both nodes.
#
STATIC_WARNING = timedelta(days=30)

#
# Certbot renews at thirty days remaining and tries twice a day. A little slack
# below that is the renewal timer's own lag; five days below it is ten failed
# attempts, and that is a fact about the automation rather than about the
# calendar. It is the case this page exists to catch, because nothing else
# reports it.
#
ACME_WARNING = timedelta(days=25)

#
# Under a week is not a warning in either lifecycle. Reissuing an internal
# certificate and getting it onto both nodes is an afternoon's work, and an
# expired certificate is an outage on every hostname it serves.
#
CRITICAL_WINDOW = timedelta(days=7)


@dataclass(frozen=True, slots=True)
class CertificateView:
    identifier: str
    common_name: str
    sans: tuple[str, ...]
    issuer: str
    lifecycle: str
    lifecycle_label: str
    fingerprint: str
    referenced: bool
    usable: bool
    problem: str | None
    expires: str
    expiry_label: str
    tone: Tone


@dataclass(frozen=True, slots=True)
class CertificateClusterView:
    cluster: str
    accent: int
    configured: bool
    label: str
    tone: Tone
    detail: str
    observed_at: datetime | None
    observed_iso: str | None
    age_label: str
    stale: bool
    referenced_count: int
    available_count: int
    certificates: tuple[CertificateView, ...]


@dataclass(frozen=True, slots=True)
class CertificateOverview:
    clusters: tuple[CertificateClusterView, ...]
    cluster_count: int
    certificate_count: int
    acme_count: int
    attention_count: int


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _text(value: Any, fallback: str = "—") -> str:
    return value if isinstance(value, str) and value else fallback


def _sans(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(name for name in value if isinstance(name, str) and name)


def _expiry(value: Any) -> datetime | None:
    text = _text(value, "")
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _remaining(expires_at: datetime, now: datetime) -> str:
    """How long this certificate has left, in whole days.

    Deliberately not in hours: a page read once a week gains nothing from
    "expires in 43 hours" that "in 1 day" does not already say, and the shorter
    phrase is the one that gets read.
    """

    left = expires_at - now
    if left <= timedelta(0):
        return "Expired"
    days = left.days
    if days == 0:
        return "Expires today"
    return f"in {days} day{'' if days == 1 else 's'}"


def _expiry_state(
    expires_at: datetime | None, *, lifecycle: str, now: datetime
) -> tuple[str, str, Tone]:
    """The expiry column: the date, the phrase beside it, and the tone."""

    if expires_at is None:
        return "—", "No expiry date", "unknown"
    date = expires_at.astimezone(UTC).strftime("%Y-%m-%d")
    left = expires_at - now
    if left <= timedelta(0):
        return date, "Expired", "critical"
    if left <= CRITICAL_WINDOW:
        return date, _remaining(expires_at, now), "critical"
    warn_after = ACME_WARNING if lifecycle == "acme" else STATIC_WARNING
    if left <= warn_after:
        return date, _remaining(expires_at, now), "warning"
    return date, _remaining(expires_at, now), "healthy"


def _certificate_view(value: Any, *, now: datetime) -> CertificateView | None:
    entry = _mapping(value)
    identifier = _text(entry.get("id"), "")
    if not identifier:
        return None

    lifecycle = _text(entry.get("lifecycle"), "unknown")
    #
    # `deployable` is the helper's own verdict on whether it could read the
    # certificate at all. Schema v1 requires all nine measured fields, so an
    # unreadable certificate carries inert placeholders in them - which means
    # nothing here may look at an expiry or a subject before checking this.
    #
    usable = entry.get("deployable") is True and entry.get("valid") is True
    problem = entry.get("validation_error")
    if not usable:
        return CertificateView(
            identifier=identifier,
            common_name=identifier,
            sans=(),
            issuer="—",
            lifecycle=lifecycle,
            lifecycle_label=_lifecycle_label(lifecycle),
            fingerprint="",
            referenced=entry.get("referenced_by_cluster") is True,
            usable=False,
            problem=_text(problem, "The certificate could not be read"),
            expires="—",
            expiry_label="Unusable",
            tone="critical",
        )

    expires, expiry_label, tone = _expiry_state(
        _expiry(entry.get("not_after")), lifecycle=lifecycle, now=now
    )
    return CertificateView(
        identifier=identifier,
        common_name=_text(entry.get("common_name"), identifier),
        sans=_sans(entry.get("sans")),
        issuer=_text(entry.get("issuer")),
        lifecycle=lifecycle,
        lifecycle_label=_lifecycle_label(lifecycle),
        fingerprint=_text(entry.get("fingerprint_sha256"), "")[:12],
        referenced=entry.get("referenced_by_cluster") is True,
        usable=True,
        problem=None,
        expires=expires,
        expiry_label=expiry_label,
        tone=tone,
    )


def _lifecycle_label(lifecycle: str) -> str:
    """What renews this certificate, said as the operator would say it.

    `lifecycle` is measured against certbot's archive rather than declared, so
    the label states a fact about the installation and not an intention.
    """

    if lifecycle == "acme":
        return "Certbot"
    if lifecycle == "static":
        return "Manual"
    return "Unknown"


def _order(certificate: CertificateView) -> tuple[int, int, str]:
    """Referenced certificates first, then the soonest problem in each group.

    The helper already lists referenced ones first; this keeps that order while
    sorting within each group by how much attention the certificate wants,
    because the page is read to find the one that needs doing something about.
    """

    severity = {"critical": 0, "warning": 1, "unknown": 2, "healthy": 3}
    return (0 if certificate.referenced else 1, severity[certificate.tone], certificate.identifier)


def _empty(cluster: str, *, configured: bool) -> CertificateClusterView:
    return CertificateClusterView(
        cluster=cluster,
        accent=accent_index(cluster),
        configured=configured,
        label="No certificate data yet",
        tone="unknown",
        detail="Waiting for the first certificate listing",
        observed_at=None,
        observed_iso=None,
        age_label="Never",
        stale=False,
        referenced_count=0,
        available_count=0,
        certificates=(),
    )


def _state(
    reading: ClusterCertificates,
    *,
    stale: bool,
    certificates: tuple[CertificateView, ...],
) -> tuple[str, Tone, str]:
    """What this cluster's certificate listing means, as a badge and a sentence.

    Only referenced certificates decide the badge. An expired certificate that
    no cluster serves is a housekeeping matter; it is listed, with its own tone
    on its own row, but it must not colour a card that is otherwise fine - a
    warning nobody can act on is how a badge stops being read.
    """

    if reading.poll_error:
        return (
            "Collection unavailable",
            "critical",
            "The poller could not read the certificate catalogue",
        )
    if reading.outcome != "done":
        return "Certificates unavailable", "critical", "The certificate catalogue could not be read"
    if stale:
        return "Stale data", "warning", "Certificate data needs a fresh poll"

    referenced = tuple(entry for entry in certificates if entry.referenced)
    if not referenced:
        return (
            "None referenced",
            "unknown",
            "This cluster's configuration references no certificate",
        )
    unusable = sum(not entry.usable for entry in referenced)
    if unusable:
        return (
            f"{unusable} unusable",
            "critical",
            "A referenced certificate cannot be read",
        )
    critical = sum(entry.tone == "critical" for entry in referenced)
    if critical:
        return (
            f"{critical} expiring",
            "critical",
            "A referenced certificate expires within a week",
        )
    warning = sum(entry.tone == "warning" for entry in referenced)
    if warning:
        return (
            f"{warning} to renew",
            "warning",
            "A referenced certificate is inside its renewal window",
        )
    return "Current", "healthy", f"{len(referenced)} referenced, all valid"


def _cluster_view(
    reading: ClusterCertificates,
    *,
    configured: bool,
    now: datetime,
    stale_after: timedelta,
) -> CertificateClusterView:
    result = _mapping(reading.result)
    entries = result.get("certificates")
    parsed: list[CertificateView] = []
    if isinstance(entries, list):
        for entry in entries:
            certificate = _certificate_view(entry, now=now)
            if certificate is not None:
                parsed.append(certificate)
    certificates = tuple(sorted(parsed, key=_order))
    stale = now - reading.observed_at > stale_after
    label, tone, detail = _state(reading, stale=stale, certificates=certificates)

    return CertificateClusterView(
        cluster=reading.cluster,
        accent=accent_index(reading.cluster),
        configured=configured,
        label=label,
        tone=tone,
        detail=detail,
        observed_at=reading.observed_at,
        observed_iso=reading.observed_at.astimezone(UTC).isoformat(),
        age_label=relative_age(reading.observed_at, now),
        stale=stale,
        referenced_count=sum(entry.referenced for entry in certificates),
        available_count=sum(not entry.referenced for entry in certificates),
        certificates=certificates,
    )


def build_certificate_overview(
    configured_clusters: Iterable[str],
    readings: Iterable[ClusterCertificates],
    *,
    now: datetime | None = None,
    stale_after: timedelta,
) -> CertificateOverview:
    """Combine configured clusters and their newest cached certificate listing.

    The counters across the top are deduplicated by fingerprint. Every cluster
    reads the same distribution directory and differs only in what it
    references, so counting per listing would report one wildcard twice and turn
    a single expiry into two - the number would grow with the cluster count
    rather than with the material an operator has to look after.
    """

    now = now or datetime.now(UTC)
    rows = {reading.cluster: reading for reading in readings}
    clusters: list[CertificateClusterView] = []
    for cluster in tuple(configured_clusters):
        reading = rows.pop(cluster, None)
        clusters.append(
            _empty(cluster, configured=True)
            if reading is None
            else _cluster_view(reading, configured=True, now=now, stale_after=stale_after)
        )
    for cluster in sorted(rows):
        clusters.append(
            _cluster_view(rows[cluster], configured=False, now=now, stale_after=stale_after)
        )

    distinct: dict[str, CertificateView] = {}
    for cluster_view in clusters:
        for certificate in cluster_view.certificates:
            #
            # The fingerprint identifies the material; the id is a filename and
            # two clusters can reach the same file. A certificate the helper
            # could not read has no fingerprint, so it is counted by id.
            #
            key = certificate.fingerprint or f"id:{certificate.identifier}"
            distinct.setdefault(key, certificate)

    return CertificateOverview(
        clusters=tuple(clusters),
        cluster_count=len(clusters),
        certificate_count=len(distinct),
        acme_count=sum(entry.lifecycle == "acme" for entry in distinct.values()),
        attention_count=sum(entry.tone in {"critical", "warning"} for entry in distinct.values()),
    )
