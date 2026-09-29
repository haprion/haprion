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

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from haproxy_ui import certificate_receivers, metrics, sorting
from haproxy_ui.cluster_identity import accent_index
from haproxy_ui.dashboard import observation_label
from haproxy_ui.db import ClusterCertificates

type Tone = Literal["healthy", "warning", "critical", "unknown", "info"]

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
class CertificateClusterView:
    cluster: str
    accent: int | None
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
class TargetView:
    """One place a certificate goes, and what is known about the copy there.

    A cluster and a receiver are not the same kind of destination and the page
    must not let them read as one list: this manager rolls a cluster out and can
    then see, node by node, whether the certificate arrived. A receiver fetches
    on its own schedule with its own key and reports nothing back, so the most
    that can be said about one is when the file was written for it.
    """

    name: str
    kind: str
    published_at: datetime | None
    published_label: str
    current: bool | None


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
    #
    # The registry's columns, so the two views read the same way (asked for
    # on 2026-09-12: "same names on both"). Where the certificate goes comes
    # from the registry block; what the nodes carry from this cluster's own
    # status, so the state here is this cluster's and not every cluster's.
    #
    valid_from: str = "—"
    targets: tuple[TargetView, ...] = ()
    state_label: str = "Unknown"
    state_detail: str = ""
    state_tone: Tone = "unknown"
    wildcard: bool = False
    #
    # Always None here: the cluster listing reads the published copy, which
    # is the file it is about. Present so one row template serves both views.
    #
    material_note: str | None = None


@dataclass(frozen=True, slots=True)
class RegistryCertificateView:
    identifier: str
    source_label: str
    lifecycle: str
    wildcard: bool
    common_name: str
    sans: tuple[str, ...]
    issuer: str
    fingerprint: str
    readable: bool
    problem: str | None
    targets: tuple[TargetView, ...]
    expires: str
    expiry_label: str
    tone: Tone
    state_label: str
    state_detail: str
    state_tone: Tone
    #
    # The cluster operation is one job per cluster. Keep the measured subset
    # on the row so the UI never offers a deploy for a receiver, a current
    # cluster, or every cluster merely because one of them is behind.
    #
    older_copy_clusters: tuple[str, ...] = ()
    #
    # Whether Publish now has anything to do: some target lacks a current
    # copy. Measured from the targets, not read off the State label.
    #
    needs_publish: bool = False
    #
    # True while the State cell shows a job that is still running - the row's
    # badge then carries a spinner, on every action a button can start.
    #
    state_active: bool = False
    #
    # Where the facts were read from, when that was not the certificate's own
    # source. An import registered before the import helper exists has nothing
    # at its source, and its facts come from the published cluster copy - the
    # material the nodes are serving. Said in the detail row, because a reader
    # who sees an expiry has a right to know which file it was read off.
    # None on an older engine that does not report it, and for a source read.
    #
    material_note: str | None = None
    valid_from: str = "—"
    #
    # A row for a request the registry has not answered yet: drawn from the
    # job's payload, not from any file, so it has no material to read, no
    # box to tick and nothing to delete.
    #
    placeholder: bool = False
    #
    # The registry's own word for where the material comes from (`acme`,
    # `import`), beside `lifecycle`, which is measured against certbot's
    # archive. The row's upload (B165) is offered on an import and nothing
    # else, and that is the source's kind, not the lifecycle's.
    #
    source_kind: str = ""
    #
    # A signing request made on the manager (C9b), waiting for its
    # signature: the row hands the CSR out and takes the certificate back
    # on its upload. The text is here so the download route can serve it
    # from the same cached reading the page is drawn from.
    #
    csr_pem: str | None = None
    #
    # The NDES profile the registry binds this certificate to, for the
    # renewal that enrolls it again (C9c); empty for every other source.
    #
    ndes_profile: str = ""
    #
    # The manager's own interface certificate (B188). Drawn on the settings
    # page, not in this list: it has no targets and is published to nginx.
    #
    interface: bool = False

    @property
    def csr_pending(self) -> bool:
        return self.csr_pem is not None

    @property
    def lifecycle_label(self) -> str:
        """The badge's word, under the name the cluster row uses for it."""

        return self.source_label


@dataclass(frozen=True, slots=True)
class ServedView:
    """What nginx serves the interface with now, as the helper read it (B188)."""

    server_name: str
    common_name: str
    sans: tuple[str, ...]
    issuer: str
    expires: str
    expiry_label: str
    tone: Tone
    self_signed: bool
    fingerprint: str


@dataclass(frozen=True, slots=True)
class RegistryView:
    #
    # Where each certificate goes, by ID, for the cluster rows to share.
    #
    targets: Mapping[str, tuple[TargetView, ...]]
    certificates: tuple[RegistryCertificateView, ...]
    receivers: tuple[str, ...]
    certificate_count: int
    acme_count: int
    attention_count: int
    #
    # The receivers page's rows and the name a receiver reaches this manager
    # by (B142). Empty and None from a helper older than the page.
    #
    receiver_rows: tuple[certificate_receivers.ReceiverRow, ...] = ()
    manager: str | None = None
    #
    # The registry's entry for the interface's own certificate, kept out of
    # `certificates` - the list, its counts and its checkboxes - and what
    # nginx actually serves (B188). Both None from an older helper.
    #
    interface: RegistryCertificateView | None = None
    served: ServedView | None = None
    #
    # A signing request made for the interface, waiting for its signature:
    # the settings page hands its CSR out and takes the certificate back.
    #
    interface_request: RegistryCertificateView | None = None


@dataclass(frozen=True, slots=True)
class CertificateOverview:
    clusters: tuple[CertificateClusterView, ...]
    cluster_count: int
    #
    # Distinct certificates some cluster references - what the "on clusters"
    # view lists, counted once however many clusters share one. The switch
    # said the number of clusters until 2026-09-12, under a label that says
    # certificates.
    #
    on_clusters_count: int
    certificate_count: int
    acme_count: int
    attention_count: int
    #
    # None where the installation declares no certificate registry. The page
    # then shows the cluster cards alone, exactly as it did before C5, rather
    # than an empty view that looks like a fault.
    #
    registry: RegistryView | None = None


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _text(value: Any, fallback: str = "—") -> str:
    return value if isinstance(value, str) and value else fallback


def _sans(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(name for name in value if isinstance(name, str) and name)


def short_issuer(issuer: str) -> str:
    """The issuer as a person says it: its CN and O, nothing else.

    openssl prints the name in RFC 2253 form - `CN=R3,O=Let's Encrypt,C=US`,
    or `CN=ca,DC=example,DC=com` for a directory-issued one - and the country
    and directory components say nothing a reader is looking for. Kept in the
    order written; an escaped comma inside a value is not a separator. A name
    with neither component is left as it is rather than emptied.
    """

    parts = re.split(r"(?<!\\),", issuer)
    kept = [part for part in parts if re.match(r"\s*(CN|O)=", part)]
    return ",".join(kept) if kept else issuer


def _date(value: Any) -> str:
    """A measured timestamp as a date, or the dash the other unknown cells use."""

    moment = _expiry(value)
    return "—" if moment is None else metrics.shown(moment).date().isoformat()


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
    date = metrics.shown(expires_at).strftime("%Y-%m-%d")
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
        issuer=short_issuer(_text(entry.get("issuer"))),
        lifecycle=lifecycle,
        lifecycle_label=_lifecycle_label(lifecycle),
        fingerprint=_text(entry.get("fingerprint_sha256"), ""),
        referenced=entry.get("referenced_by_cluster") is True,
        usable=True,
        problem=None,
        expires=expires,
        expiry_label=expiry_label,
        tone=tone,
        valid_from=_date(entry.get("not_before")),
        wildcard=any(name.startswith("*.") for name in _sans(entry.get("sans"))),
    )


def with_deletion_states(
    overview: CertificateOverview, states: Mapping[str, Any]
) -> CertificateOverview:
    """The registry rows with the queue's word in the State cell where it has one.

    The states come from `certificate_activity`; they carry a label, detail
    and tone in the shape the cell already draws. A tone the badge CSS does
    not know would draw as plain text, so only the registry rows are touched
    and only for identifiers the queue actually names.
    """

    if overview.registry is None or not states:
        return overview
    listed = {entry.identifier for entry in overview.registry.certificates}

    def caught_up(entry: RegistryCertificateView, state: Any) -> bool:
        #
        # A publish has caught up when the measured row no longer needs one.
        # A reading taken before the job ran still says it does, so the
        # overlay stays exactly until the poller has been round.
        #
        if state.target_action == "publish":
            return not entry.needs_publish
        if state.target_action not in {"add", "remove"} or not state.target_names:
            return False
        current = {target.name for target in entry.targets}
        changed = set(state.target_names)
        return changed <= current if state.target_action == "add" else current.isdisjoint(changed)

    rows = tuple(
        replace(
            entry,
            state_label=states[entry.identifier].label,
            state_detail=states[entry.identifier].detail,
            state_tone=states[entry.identifier].tone,
            state_active=states[entry.identifier].active,
        )
        if entry.identifier in states
        and not states[entry.identifier].placeholder_only
        and not caught_up(entry, states[entry.identifier])
        else entry
        for entry in overview.registry.certificates
    )
    #
    # A request the registry cannot list yet is a row above the rest: the
    # newest thing on the page, and the one the person just came here for.
    #
    requested = tuple(
        _placeholder_row(identifier, state)
        for identifier, state in states.items()
        if identifier not in listed and state.placeholder is not None
    )
    return replace(overview, registry=replace(overview.registry, certificates=requested + rows))


def _placeholder_row(identifier: str, state: Any) -> RegistryCertificateView:
    asked = state.placeholder
    targets = tuple(TargetView(name, "cluster", None, "", None) for name in asked.clusters) + tuple(
        TargetView(name, "receiver", None, "not yet published", None) for name in asked.receivers
    )
    return RegistryCertificateView(
        identifier=identifier,
        source_label=asked.source_label,
        lifecycle=asked.lifecycle,
        wildcard=asked.wildcard,
        common_name=identifier,
        sans=asked.sans,
        issuer="—",
        fingerprint="",
        readable=False,
        problem=None,
        targets=targets,
        expires="—",
        expiry_label="",
        tone="unknown",
        state_label=state.label,
        state_detail=state.detail,
        state_tone=state.tone,
        state_active=state.active,
        placeholder=True,
    )


def _source_label(kind: str, source: Mapping[str, Any]) -> str:
    """Where the material came from, as the registry records it.

    An import the manager enrolled itself over NDES is still `import` to the
    registry - static material, no certbot lineage - but the operator asked
    a CA for it and should see that CA's name, not "Imported".
    """

    if kind == "acme":
        return "Certbot"
    if isinstance(source.get("ndes_profile"), str):
        return "NDES"
    return "Imported"


def _lifecycle_label(lifecycle: str) -> str:
    """What renews this certificate, said as the operator would say it.

    `lifecycle` is measured against certbot's archive rather than declared, so
    the label states a fact about the installation and not an intention.
    """

    if lifecycle == "acme":
        return "Certbot"
    if lifecycle == "static":
        #
        # The registry's word for the same thing. The two views share their
        # columns, so a badge that said Manual on one and Imported on the
        # other would read as two kinds of certificate where there is one.
        #
        return "Imported"
    return "Unknown"


def _order(certificate: CertificateView) -> tuple[int, str]:
    """Referenced certificates first, alphabetical by ID within each group.

    Alphabetical rather than by urgency since 2026-09-12: a row that moves
    when its expiry crosses a threshold is a row the reader has to find again,
    and the expiry column already carries the colour that says which ones
    want attention. The registry view sorts the same way for the same reason.
    """

    return (0 if certificate.referenced else 1, certificate.identifier)


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
    #
    # True only in snapshot mode, where the readings describe a moment that has
    # passed and `now` is that moment rather than the wall clock. It changes
    # what the freshness line says, not how staleness is judged. See
    # `dashboard.observation_label`.
    #
    captured: bool = False,
    targets: Mapping[str, tuple[TargetView, ...]] | None = None,
    carriage: NodeCarriage | None = None,
) -> CertificateClusterView:
    result = _mapping(reading.result)
    entries = result.get("certificates")
    parsed: list[CertificateView] = []
    if isinstance(entries, list):
        for entry in entries:
            certificate = _certificate_view(entry, now=now)
            if certificate is not None:
                parsed.append(_placed(certificate, reading.cluster, targets, carriage))
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
        age_label=observation_label(reading.observed_at, now, captured=captured),
        stale=stale,
        referenced_count=sum(entry.referenced for entry in certificates),
        available_count=sum(not entry.referenced for entry in certificates),
        certificates=certificates,
    )


def _placed(
    certificate: CertificateView,
    cluster: str,
    targets: Mapping[str, tuple[TargetView, ...]] | None,
    carriage: NodeCarriage | None,
) -> CertificateView:
    """One cluster's row with the registry's columns filled in.

    Used by comes from the registry; without one the cluster itself is the
    only known target, which is true rather than a guess. State is measured
    against this cluster's nodes only, with the same reading the registry
    uses - `_node_state` - so the two views cannot disagree about a node.
    """

    if targets is not None and certificate.identifier in targets:
        placed = targets[certificate.identifier]
    else:
        placed = (
            TargetView(
                name=cluster, kind="cluster", published_at=None, published_label="", current=None
            ),
        )
    label: str
    detail: str
    tone: Tone
    if not certificate.usable:
        label, detail, tone = "Unreadable", certificate.problem or "Could not be read", "critical"
    else:
        label, detail, tone = _node_state(
            certificate.identifier, certificate.fingerprint, [carriage] if carriage else []
        )
    return replace(
        certificate, targets=placed, state_label=label, state_detail=detail, state_tone=tone
    )


def _node_state(
    identifier: str, fingerprint: str, carriages: Iterable[NodeCarriage | None]
) -> tuple[str, str, Tone]:
    """What the given clusters' nodes report carrying, said without overreaching.

    Shared by the registry row, which asks about every cluster a certificate
    goes to, and the cluster row, which asks about one. `None` in the list is
    a cluster nobody has read yet and counts towards nothing.
    """

    on, total = 0, 0
    wrong = False
    for nodes in carriages:
        if nodes is None:
            continue
        held = nodes.fingerprints.get(identifier, frozenset())
        if fingerprint and any(value != fingerprint for value in held):
            wrong = True
        on += nodes.holders.get(identifier, 0)
        total += nodes.reporting
    if total == 0:
        return "Published", "No node has reported yet, so deployment is unknown", "unknown"
    if wrong:
        return (
            "Nodes hold an older copy",
            "Different certificate bytes reported",
            "warning",
        )
    if on == 0:
        return "Not on the nodes", "Published, but no node carries it yet", "warning"
    if on < total:
        return f"On {on} of {total} nodes", "A node is behind on this certificate", "warning"
    label = f"On all {total} nodes" if total > 1 else "On the node"
    return label, "Every reporting node carries this certificate", "healthy"


@dataclass(frozen=True, slots=True)
class NodeCarriage:
    """What one cluster's nodes report carrying, by certificate ID.

    Read from the node status rather than from anything the manager published,
    because the question the state column answers is whether the certificate is
    where it has to be to serve traffic. A node reports a fingerprint for every
    certificate it holds (`carried_certificate`), so this is a measurement and
    not an assumption about what a rollout did.

    `reporting` counts only nodes that answered with a certificate list at all.
    A node that could not be reached is left out of the denominator rather than
    counted as missing the certificate: "one of two nodes" would otherwise mean
    both "one node is behind" and "one node is down", which are different
    problems with different answers.
    """

    reporting: int
    holders: Mapping[str, int]
    fingerprints: Mapping[str, frozenset[str]]


def _carriage(readings: Iterable[Any]) -> dict[str, NodeCarriage]:
    carriage: dict[str, NodeCarriage] = {}
    for reading in readings:
        nodes = _mapping(reading.result).get("nodes")
        if not isinstance(nodes, list):
            continue
        reporting = 0
        holders: dict[str, int] = {}
        fingerprints: dict[str, set[str]] = {}
        for value in nodes:
            #
            # Under the node's own status document, where the status contract
            # puts it (`node_status.certificates`), and not beside `name` and
            # `reachable`. Read at the wrong level until 2026-09-12, so no node
            # ever "reported" and every cluster certificate stood as merely
            # Published - the maintainer saw it on the page. The rig's status
            # fixture had the same wrong shape, which is why the rig agreed.
            #
            entries = _mapping(_mapping(value).get("status")).get("certificates")
            if not isinstance(entries, list):
                continue
            reporting += 1
            for item in entries:
                entry = _mapping(item)
                identifier = _text(entry.get("id"), "")
                fingerprint = _text(entry.get("fingerprint_sha256"), "")
                if not identifier or not fingerprint:
                    continue
                holders[identifier] = holders.get(identifier, 0) + 1
                fingerprints.setdefault(identifier, set()).add(fingerprint)
        carriage[reading.cluster] = NodeCarriage(
            reporting=reporting,
            holders=holders,
            fingerprints={key: frozenset(value) for key, value in fingerprints.items()},
        )
    return carriage


def _published_label(published_at: datetime | None) -> str:
    """When the manager wrote this copy, and deliberately nothing more.

    Not "delivered", not "installed". The word has to survive a reader who
    skims: publication is a fact about this host, and everything past it
    belongs to whoever fetches.
    """

    if published_at is None:
        return "Not published"
    return f"Published {metrics.shown(published_at).strftime('%Y-%m-%d')}"


def _target_views(entry: Mapping[str, Any]) -> tuple[TargetView, ...]:
    targets = _mapping(entry.get("targets"))
    views: list[TargetView] = []
    for name in targets.get("clusters", []) if isinstance(targets.get("clusters"), list) else []:
        if isinstance(name, str) and name:
            views.append(
                TargetView(
                    name=name,
                    kind="cluster",
                    published_at=None,
                    published_label="",
                    current=None,
                )
            )
    receivers = targets.get("receivers")
    for value in receivers if isinstance(receivers, list) else []:
        receiver = _mapping(value)
        name = _text(receiver.get("id"), "")
        if not name:
            continue
        published_at = _expiry(receiver.get("published_at"))
        current = receiver.get("current")
        #
        # The helper says `current: false` for a copy it could not stat as
        # well as for one it read and found behind, and the page drew both as
        # "(older version)". A copy that is not there is not an older one.
        #
        if published_at is None:
            current = None
        views.append(
            TargetView(
                name=name,
                kind="receiver",
                published_at=published_at,
                published_label=_published_label(published_at),
                current=current if isinstance(current, bool) else None,
            )
        )
    return tuple(views)


def _registry_state(
    entry: Mapping[str, Any],
    targets: tuple[TargetView, ...],
    *,
    identifier: str,
    fingerprint: str,
    carriage: Mapping[str, NodeCarriage],
) -> tuple[str, str, Tone]:
    """What is true about this certificate's copies, said without overreaching.

    Two kinds of target, two kinds of certainty, and the column says whichever
    it actually has. For clusters the nodes report what they carry, so this can
    state deployment. For receivers it can state publication and stops there.
    """

    if entry.get("readable") is not True:
        #
        # No material yet because the CA is still holding the request is
        # waiting, not breakage; the listing helper says which (C6).
        #
        if entry.get("request_state") == "pending":
            if _mapping(entry.get("request")).get("kind") == "csr":
                return (
                    "Awaiting signature",
                    "Download the request, have a CA sign it, and upload the certificate here",
                    "info",
                )
            return (
                "Request pending",
                "The CA is holding the enrollment; resume it from the certificate form",
                "info",
            )
        return "Unreadable", _text(entry.get("validation_error"), "Could not be read"), "critical"

    #
    # The scheduled NDES renewal's last word about this certificate, when it
    # is not "renewed": a failure with the CA's sentence, or a request the
    # CA is holding. The material is still readable - it is the old one -
    # so this comes before the copies are judged, which would say "on all
    # nodes" about a certificate that is quietly running out.
    #
    renewal = _mapping(entry.get("renewal"))
    if renewal.get("outcome") == "failed":
        attempted = _expiry(renewal.get("attempted_at"))
        when = (
            f" (tried {metrics.shown(attempted).strftime(metrics.TIMESTAMP)})"
            if attempted is not None
            else ""
        )
        return (
            "Renewal failed",
            _text(renewal.get("message"), "The scheduled renewal failed") + when,
            "critical",
        )
    if renewal.get("outcome") == "pending":
        return (
            "Renewal pending",
            "The CA is holding the renewal request; resume it from the row",
            "info",
        )

    clusters = tuple(target.name for target in targets if target.kind == "cluster")
    receivers = tuple(target for target in targets if target.kind == "receiver")
    if not clusters and not receivers:
        return "No targets", "Registered, but published nowhere", "warning"

    if clusters:
        distribution = _mapping(entry.get("distribution"))
        if distribution.get("published_at") is None:
            return (
                "Not published",
                "No copy in the distribution directory the nodes read",
                "warning",
            )
        if distribution.get("current") is False:
            return (
                "Older version published",
                "The distribution directory holds an earlier certificate than the source",
                "warning",
            )
        label, detail, tone = _node_state(
            identifier, fingerprint, (carriage.get(cluster) for cluster in clusters)
        )
        #
        # The receivers are judged even when the certificate goes to a
        # cluster. Until 2026-09-20 this branch said "Published to N
        # receivers too" from the count alone, so a receiver whose copy had
        # been removed stood behind "On all 2 nodes" with no button to put
        # it back - seen on the maintainer's screen with a throwaway import.
        #
        missing = _receivers_without_copy(receivers)
        if missing and tone in {"healthy", "warning", "unknown"}:
            return "Not published", f"{label}; {missing}", "warning"
        stale = _receivers_with_older_copy(receivers)
        if stale and tone in {"healthy", "warning", "unknown"}:
            return "Older version published", f"{label}; {stale}", "warning"
        if receivers and tone == "healthy":
            #
            # Both halves in the label (maintainer, 2026-09-20): a row that
            # goes to nodes and to receivers said only the nodes' half, and
            # the receivers' half was a detail nobody opened. Short, because
            # the State column is the last one and the longest label already
            # reaches its edge at 1400 px.
            #
            noun = "receiver" if len(receivers) == 1 else "receivers"
            return "On nodes & published", f"{label}; published to {len(receivers)} {noun}", tone
        return label, detail, tone

    missing = _receivers_without_copy(receivers)
    if missing:
        return "Not published", missing, "warning"
    stale = _receivers_with_older_copy(receivers)
    if stale:
        return "Older version published", stale, "warning"
    newest = max(target.published_at for target in receivers if target.published_at is not None)
    return (
        _published_label(newest),
        "Whether it was fetched is not reported",
        "healthy",
    )


def _receivers_without_copy(receivers: Sequence[TargetView]) -> str:
    """How many receivers have no copy at all, as the State detail says it; empty if none."""

    unpublished = [target for target in receivers if target.published_at is None]
    return _receiver_count(unpublished, len(receivers), "has no copy", "have no copy")


def _receivers_with_older_copy(receivers: Sequence[TargetView]) -> str:
    """How many receivers hold a copy the source has moved past; empty if none."""

    stale = [target for target in receivers if target.current is False]
    return _receiver_count(stale, len(receivers), "holds an older copy", "hold an older copy")


def _receiver_count(affected: Sequence[TargetView], total: int, one: str, many: str) -> str:
    """`1 receiver has no copy`, `2 of 3 receivers have no copy`; short, because the State
    cell is the detail grid's last column and the action button stands under the sentence."""

    if not affected:
        return ""
    if total == 1:
        return f"1 receiver {one}"
    return f"{len(affected)} of {total} receivers {many}"


def needs_publishing(entry: Mapping[str, Any], targets: Sequence[TargetView]) -> bool:
    """Whether a publish run would write something for this certificate.

    True when any target lacks a current copy: the distribution directory the
    clusters read has none or an older one, or a receiver has none or an
    older one. The interface offers Publish now on this and nothing else -
    not on the State label, which since 2026-09-20 may say the same words
    for a receiver's missing copy behind a healthy cluster, and before that
    could not say them at all.
    """

    clusters = [target for target in targets if target.kind == "cluster"]
    if clusters:
        distribution = _mapping(entry.get("distribution"))
        if distribution.get("published_at") is None or distribution.get("current") is False:
            return True
    return any(
        target.published_at is None or target.current is False
        for target in targets
        if target.kind == "receiver"
    )


def _registry_certificate(
    value: Any,
    *,
    now: datetime,
    carriage: Mapping[str, NodeCarriage],
) -> RegistryCertificateView | None:
    entry = _mapping(value)
    identifier = _text(entry.get("id"), "")
    if not identifier:
        return None

    source = _mapping(entry.get("source"))
    kind = _text(source.get("kind"), "unknown")
    lifecycle = _text(entry.get("lifecycle"), "unknown")
    readable = entry.get("readable") is True
    sans = _sans(entry.get("sans"))
    #
    # A waiting signing request has no measured names, but it has the ones
    # it asked for, and the Names column is where a reader looks for them.
    #
    csr_pem: str | None = None
    pending_request = _mapping(entry.get("request"))
    if not readable and pending_request.get("kind") == "csr":
        sans = _sans(pending_request.get("domains"))
        text = pending_request.get("csr_pem")
        csr_pem = text if isinstance(text, str) and text else None
    fingerprint = _text(entry.get("fingerprint_sha256"), "")
    targets = _target_views(entry)

    if readable:
        expires, expiry_label, tone = _expiry_state(
            _expiry(entry.get("not_after")), lifecycle=lifecycle, now=now
        )
    else:
        #
        # Schema v1 fills the measured fields of an unreadable entry with inert
        # values, so they must never be rendered as measurements.
        #
        expires, expiry_label, tone = "—", "Unknown", "unknown"

    state_label, state_detail, state_tone = _registry_state(
        entry,
        targets,
        identifier=identifier,
        fingerprint=fingerprint,
        carriage=carriage,
    )
    cluster_targets = tuple(target.name for target in targets if target.kind == "cluster")
    older_copy_clusters = tuple(
        cluster
        for cluster in cluster_targets
        if (nodes := carriage.get(cluster)) is not None
        and fingerprint
        and (held := nodes.fingerprints.get(identifier, frozenset()))
        and any(value != fingerprint for value in held)
    )
    return RegistryCertificateView(
        identifier=identifier,
        source_label=_source_label(kind, source),
        source_kind=kind,
        lifecycle=lifecycle if readable else "unknown",
        wildcard=any(name.startswith("*.") for name in sans),
        common_name=_text(entry.get("common_name"), identifier),
        sans=sans,
        issuer=short_issuer(_text(entry.get("issuer"))) if readable else "—",
        fingerprint=fingerprint,
        readable=readable,
        problem=None if readable else _text(entry.get("validation_error"), "Could not be read"),
        targets=targets,
        expires=expires,
        expiry_label=expiry_label,
        tone=tone,
        state_label=state_label,
        state_detail=state_detail,
        state_tone=state_tone,
        older_copy_clusters=older_copy_clusters,
        needs_publish=readable and needs_publishing(entry, targets),
        material_note=(
            "Read from the published cluster copy; nothing is at its import source yet"
            if readable and entry.get("measured_at") == "distribution"
            else None
        ),
        valid_from=_date(entry.get("not_before")) if readable else "—",
        csr_pem=csr_pem,
        ndes_profile=_text(source.get("ndes_profile"), ""),
        interface=entry.get("interface") is True,
    )


def _served_view(value: Any, *, now: datetime) -> ServedView | None:
    entry = _mapping(value)
    fingerprint = _text(entry.get("fingerprint_sha256"), "")
    server_name = _text(entry.get("server_name"), "")
    if not fingerprint or not server_name:
        return None
    self_signed = entry.get("self_signed") is True
    expires, expiry_label, tone = _expiry_state(
        _expiry(entry.get("not_after")), lifecycle="static", now=now
    )
    return ServedView(
        server_name=server_name,
        common_name=_text(entry.get("common_name"), server_name),
        sans=_sans(entry.get("sans")),
        issuer="Self-signed" if self_signed else short_issuer(_text(entry.get("issuer"))),
        expires=expires,
        expiry_label=expiry_label,
        tone=tone,
        self_signed=self_signed,
        fingerprint=fingerprint,
    )


def profile_references(
    readings: Iterable[ClusterCertificates], *, field: str
) -> dict[str, tuple[str, ...]] | None:
    """Which registered certificates name each provider profile, by profile.

    `field` is `dns_profile` or `ndes_profile`, the registry's own binding.
    None where no reading carries a registry at all - then nothing can be
    said either way, and a caller must not treat silence as "unreferenced".
    The profile pages use this to drop a "removal refused" notice once the
    certificates it named are gone, without waiting for another attempt.
    """

    newest: ClusterCertificates | None = None
    for reading in readings:
        if not isinstance(_mapping(reading.result).get("registry"), Mapping):
            continue
        if newest is None or reading.observed_at > newest.observed_at:
            newest = reading
    if newest is None:
        return None
    entries = _mapping(_mapping(newest.result).get("registry")).get("certificates")
    references: dict[str, list[str]] = {}
    if isinstance(entries, list):
        for value in entries:
            entry = _mapping(value)
            profile = _mapping(entry.get("source")).get(field)
            identifier = entry.get("id")
            if isinstance(profile, str) and isinstance(identifier, str):
                references.setdefault(profile, []).append(identifier)
    return {profile: tuple(sorted(ids)) for profile, ids in references.items()}


def _registry_view(
    readings: Iterable[ClusterCertificates],
    status_readings: Iterable[Any],
    *,
    now: datetime,
) -> RegistryView | None:
    """The registry as one list, read from the freshest cluster that carried it.

    Every cluster's listing carries the same block, because it is the same file
    read the same way inside the same helper. Taking the newest rather than
    merging them means a registry rewritten between two clusters' polls is
    shown whole rather than half from each.
    """

    newest: ClusterCertificates | None = None
    for reading in readings:
        if not isinstance(_mapping(reading.result).get("registry"), Mapping):
            continue
        if newest is None or reading.observed_at > newest.observed_at:
            newest = reading
    if newest is None:
        return None

    block = _mapping(_mapping(newest.result).get("registry"))
    carriage = _carriage(status_readings)

    entries = block.get("certificates")
    parsed: list[RegistryCertificateView] = []
    if isinstance(entries, list):
        for value in entries:
            certificate = _registry_certificate(value, now=now, carriage=carriage)
            if certificate is not None:
                parsed.append(certificate)

    certificates = tuple(
        sorted((entry for entry in parsed if not entry.interface), key=lambda e: e.identifier)
    )
    marked = sorted(
        (entry for entry in parsed if entry.interface and not entry.csr_pending),
        key=lambda e: e.identifier,
    )
    waiting = sorted(
        (entry for entry in parsed if entry.interface and entry.csr_pending),
        key=lambda e: e.identifier,
    )
    receivers = block.get("receivers")
    manager, receiver_rows = certificate_receivers.parse_receiver_rows(block)
    return RegistryView(
        targets={entry.identifier: entry.targets for entry in certificates},
        certificates=certificates,
        receivers=tuple(name for name in receivers if isinstance(name, str))
        if isinstance(receivers, list)
        else (),
        certificate_count=len(certificates),
        acme_count=sum(entry.source_label == "Certbot" for entry in certificates),
        attention_count=sum(
            entry.tone in {"critical", "warning"} or entry.state_tone in {"critical", "warning"}
            for entry in certificates
        ),
        receiver_rows=receiver_rows,
        manager=manager,
        interface=marked[0] if marked else None,
        served=_served_view(block.get("interface_served"), now=now),
        interface_request=waiting[0] if waiting else None,
    )


def build_certificate_overview(
    configured_clusters: Iterable[str],
    readings: Iterable[ClusterCertificates],
    *,
    now: datetime | None = None,
    stale_after: timedelta,
    #
    # The node status, for the one thing the certificate listing cannot answer:
    # whether the nodes are actually carrying what the manager published. Empty
    # by default so a caller that has no status - the snapshot fixtures, and
    # every existing test - gets the page it had before, with deployment
    # reported as unknown rather than as a failure.
    #
    status_readings: Iterable[Any] = (),
    #
    # True only in snapshot mode, where the readings describe a moment that has
    # passed and `now` is that moment rather than the wall clock. It changes
    # what the freshness line says, not how staleness is judged. See
    # `dashboard.observation_label`.
    #
    captured: bool = False,
) -> CertificateOverview:
    """Combine configured clusters and their newest cached certificate listing.

    The counters across the top are deduplicated by fingerprint. Every cluster
    reads the same distribution directory and differs only in what it
    references, so counting per listing would report one wildcard twice and turn
    a single expiry into two - the number would grow with the cluster count
    rather than with the material an operator has to look after.
    """

    now = now or datetime.now(UTC)
    readings = tuple(readings)
    status_readings = tuple(status_readings)
    #
    # The registry and the node status first: the cluster rows carry the
    # registry's columns, and their state is read from the same carriage.
    #
    registry = _registry_view(readings, status_readings, now=now)
    carriage = _carriage(status_readings)
    targets = registry.targets if registry is not None else None
    rows = {reading.cluster: reading for reading in readings}
    clusters: list[CertificateClusterView] = []
    for cluster in tuple(configured_clusters):
        reading = rows.pop(cluster, None)
        clusters.append(
            _empty(cluster, configured=True)
            if reading is None
            else _cluster_view(
                reading,
                configured=True,
                now=now,
                stale_after=stale_after,
                captured=captured,
                targets=targets,
                carriage=carriage.get(cluster),
            )
        )
    for cluster in sorted(rows):
        clusters.append(
            _cluster_view(
                rows[cluster],
                configured=False,
                now=now,
                stale_after=stale_after,
                captured=captured,
                targets=targets,
                carriage=carriage.get(cluster),
            )
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
        #
        # Referenced by any cluster, not by the cluster whose listing happened
        # to come first: every listing names every file in the shared
        # directory, so a certificate one cluster serves is in the other's
        # listing as unreferenced, and `distinct` keeps whichever was first.
        # Counted that way the switch said 2 for three certificates.
        #
        on_clusters_count=len(
            {
                certificate.fingerprint or f"id:{certificate.identifier}"
                for cluster_view in clusters
                for certificate in cluster_view.certificates
                if certificate.referenced
            }
        ),
        #
        # The registry counts the material the manager looks after; the
        # per-cluster tally counts what the clusters can be given. Where a
        # registry exists it is the one that answers "how many certificates do
        # I have" - a receiver-only certificate is in no cluster's listing and
        # was counted by nothing before C5.
        #
        certificate_count=registry.certificate_count if registry else len(distinct),
        acme_count=registry.acme_count
        if registry
        else sum(entry.lifecycle == "acme" for entry in distinct.values()),
        attention_count=registry.attention_count
        if registry
        else sum(entry.tone in {"critical", "warning"} for entry in distinct.values()),
        registry=registry,
    )


#
# Both certificate views are sortable (THEME.md), with one choice for both:
# they are the same rows seen two ways. Dates are ISO strings and sort as
# text; "—" is a missing value and comes last.
#
def _known(value: str) -> str | None:
    return None if value in ("", "—") else value


TABLE = sorting.Table(
    columns=(
        sorting.Column("certificate", lambda row, _: sorting.text(row.identifier)),
        sorting.Column("names", lambda row, _: sorting.text(", ".join(row.sans))),
        sorting.Column("source", lambda row, _: sorting.text(row.lifecycle_label)),
        sorting.Column(
            "usedby",
            lambda row, _: sorting.text(", ".join(target.name for target in row.targets)),
        ),
        sorting.Column("validfrom", lambda row, _: _known(row.valid_from), descending_first=True),
        sorting.Column("expires", lambda row, _: _known(row.expires)),
        sorting.Column(
            "state", lambda row, _: (sorting.tone_rank(row.state_tone), row.state_label.casefold())
        ),
    ),
    cookie="haproxy_ui_certificates_sort",
    path="/certificates",
)
