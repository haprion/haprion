"""What needs doing, on one list: the dashboard's box and the monitoring endpoint (B274).

Everything here is already worked out somewhere - the certificate listing's
tones, the dashboard's node verdicts, the jobs, the backups, the WAF page's
*Not working*. This module counts nothing of its own: it reads those
builders' answers and keeps the ones that are wrong and want somebody, one
line each, the worst first.

What is left out on purpose: a state somebody chose. A drained server, a
maintenance page, a blocked address are on the cluster's *Operations* line,
and a list that raised them would be a list people learn to ignore.

Two forms of one answer. The dashboard draws it as rows that link to where
the fix is; `/status/attention.json` and `/status/metrics` hand the same rows
to a monitor - Uptime Kuma, Prometheus - so it can raise an alarm without
this application growing one.
"""

from __future__ import annotations

import ipaddress
import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

from haprion_ui import jobs as jobs_module
from haprion_ui.db import Job

type Severity = Literal["critical", "warning"]
SEVERITIES: tuple[Severity, ...] = ("critical", "warning")

#
# A job whose last run did not work, until a later run of the same operation
# on the same cluster does (B274): a certificate job that went through says
# nothing about a broken deploy.
#
UNSETTLED = frozenset({"failed", "partial", "blocked", "unknown"})


@dataclass(frozen=True, slots=True)
class Item:
    kind: str
    severity: Severity
    cluster: str | None
    subject: str
    message: str
    since: datetime | None
    link: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "severity": self.severity,
            "cluster": self.cluster,
            "subject": self.subject,
            "message": self.message,
            "since": _stamp(self.since),
            "link": self.link,
        }


@dataclass(frozen=True, slots=True)
class Attention:
    generated_at: datetime
    items: tuple[Item, ...]
    #
    # How old each cluster's status reading is, in seconds; None for a cluster
    # never read. What lets a monitor see that the manager itself has stopped.
    #
    status_age: Mapping[str, int | None]
    fresh: bool

    def counts(self) -> dict[str, int]:
        return {
            severity: sum(item.severity == severity for item in self.items)
            for severity in SEVERITIES
        }

    def as_json(self) -> str:
        return json.dumps(
            {
                "generated_at": _stamp(self.generated_at),
                "fresh": self.fresh,
                "counts": self.counts(),
                "items": [item.as_dict() for item in self.items],
            },
            separators=(",", ":"),
        )

    def as_metrics(self) -> str:
        """The Prometheus text format: one gauge per kind and severity, one age per cluster."""

        kinds = sorted({item.kind for item in self.items} | set(KINDS))
        lines = [
            "# HELP haprion_attention_items Things that need doing, by kind and severity.",
            "# TYPE haprion_attention_items gauge",
        ]
        for kind in kinds:
            for severity in SEVERITIES:
                count = sum(item.kind == kind and item.severity == severity for item in self.items)
                lines.append(
                    f'haprion_attention_items{{kind="{kind}",severity="{severity}"}} {count}'
                )
        lines += [
            "# HELP haprion_status_age_seconds How old each cluster's status reading is.",
            "# TYPE haprion_status_age_seconds gauge",
        ]
        for cluster, age in sorted(self.status_age.items()):
            if age is not None:
                lines.append(f'haprion_status_age_seconds{{cluster="{cluster}"}} {age}')
        return "\n".join(lines) + "\n"


KINDS = ("certificate", "job", "node", "reading", "waf", "backup")

#
# Enough for a monitor or two and their networks; a list longer than this is
# something other than a list of monitors.
#
MAX_ACCESS_ENTRIES = 32


def access_list(text: str) -> tuple[str, ...]:
    """Settings' address list for `/status/`: one address or network per line, or none.

    Strict, as the receivers' list is: `192.0.2.1/24` is a typo for the host
    or the network, and taking the network would let 255 more addresses in
    than whoever wrote it meant.
    """

    entries = [line.strip() for line in text.replace(",", "\n").splitlines() if line.strip()]
    if len(entries) > MAX_ACCESS_ENTRIES:
        raise ValueError(f"At most {MAX_ACCESS_ENTRIES} addresses or networks.")
    checked: list[str] = []
    for index, entry in enumerate(entries, start=1):
        try:
            network = ipaddress.ip_network(entry, strict=True)
        except ValueError:
            raise ValueError(
                f"Line {index} is not an address or a network (such as 192.0.2.10 or "
                "192.0.2.0/24); a network's host bits must be zero."
            ) from None
        if str(network) not in checked:
            checked.append(str(network))
    return tuple(checked)


def _stamp(moment: datetime | None) -> str | None:
    if moment is None:
        return None
    return moment.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _severity(tone: str | None) -> Severity | None:
    return tone if tone in ("critical", "warning") else None  # type: ignore[return-value]


def _expires(label: str) -> str:
    """`in 16 days` as `expires in 16 days`; `Expired` and the rest as they are."""

    return f"expires {label}" if label.startswith("in ") else label


def from_jobs(rows: Sequence[Job]) -> list[Item]:
    """The newest finished job per cluster and operation, when it did not work."""

    newest: dict[tuple[str | None, str], Job] = {}
    for job in sorted(rows, key=lambda row: (row.created_at, row.id), reverse=True):
        if job.state in ("pending", "running"):
            continue
        newest.setdefault((job.cluster, job.operation), job)
    items = []
    for (cluster, operation), job in newest.items():
        if job.state not in UNSETTLED:
            continue
        label = jobs_module.FAILURE_LABELS.get(operation, f"{operation} did not work")
        when = job.finished_at or job.created_at
        items.append(
            Item(
                kind="job",
                severity="critical",
                cluster=cluster,
                subject=f"job {job.id}",
                message=label,
                since=when,
                link=f"/jobs#job-{job.id}",
            )
        )
    return items


def from_dashboard(clusters: Iterable[Any], *, drift_label: str) -> list[Item]:
    """Nodes that are down, and clusters whose status reading has stopped.

    A node merely behind the published version is not listed (26-10-11): a
    publish waiting for its deploy is a choice, as a drain is, and the cluster
    card and Versions already say it. A deploy that failed is listed as its
    job; a node down while it ran, as the node.
    """

    items: list[Item] = []
    for cluster in clusters:
        if not getattr(cluster, "configured", True):
            continue
        if cluster.stale:
            items.append(
                Item(
                    kind="reading",
                    severity="warning",
                    cluster=cluster.cluster,
                    subject=cluster.cluster,
                    message=f"status last read {cluster.age_label}",
                    since=cluster.observed_at,
                    link="/",
                )
            )
            continue
        #
        # One line per node that is wrong: the node's own verdict names which
        # node. A node's time is the reading's, which says nothing about when
        # it went wrong, so there is none.
        #
        for node in cluster.nodes:
            severity = _severity(node.tone)
            if severity is None or node.label == drift_label:
                continue
            items.append(
                Item(
                    kind="node",
                    severity=severity,
                    cluster=cluster.cluster,
                    subject=node.name,
                    message=f"{node.label}" + (f" · {node.detail}" if node.detail else ""),
                    since=None,
                    link="/",
                )
            )
    return items


def from_certificates(registry: Any, clusters: Iterable[Any]) -> list[Item]:
    """Certificates that run out, cannot be read, or whose copies are not where they belong."""

    items: list[Item] = []
    if registry is not None:
        for row in (*registry.certificates, registry.interface):
            if row is None or getattr(row, "placeholder", False):
                continue
            #
            # The interface's own certificate is served by the manager, not
            # published to a target, so its row's state ("No targets") says
            # nothing; only its expiry counts.
            #
            state_tone = None if row.interface else row.state_tone
            tones = [tone for tone in (row.tone, state_tone) if _severity(tone)]
            if not tones:
                continue
            severity: Severity = "critical" if "critical" in tones else "warning"
            parts = []
            if _severity(row.tone):
                parts.append(_expires(row.expiry_label))
            if _severity(state_tone):
                parts.append(row.state_label)
            items.append(
                Item(
                    kind="certificate",
                    severity=severity,
                    cluster=None,
                    subject=row.identifier,
                    message=" · ".join(part for part in parts if part),
                    since=None,
                    link="/settings" if row.interface else "/certificates?view=registry",
                )
            )
        served = registry.served
        if served is not None and _severity(served.tone):
            items.append(
                Item(
                    kind="certificate",
                    severity=_severity(served.tone) or "warning",
                    cluster=None,
                    subject=served.server_name,
                    message=f"the interface's certificate · {_expires(served.expiry_label)}",
                    since=None,
                    link="/settings",
                )
            )
        return items
    #
    # Without a registry, the cluster listings are the only word.
    #
    for cluster in clusters:
        for row in cluster.certificates:
            found = _severity(row.tone)
            if found is None or not row.referenced:
                continue
            items.append(
                Item(
                    kind="certificate",
                    severity=found,
                    cluster=cluster.cluster,
                    subject=row.identifier,
                    message=_expires(row.expiry_label),
                    since=None,
                    link="/certificates",
                )
            )
    return items


def from_backups(clusters: Iterable[Any]) -> list[Item]:
    items: list[Item] = []
    for cluster in clusters:
        severity = _severity(cluster.tone)
        if severity is None or not getattr(cluster, "configured", True):
            continue
        items.append(
            Item(
                kind="backup",
                severity=severity,
                cluster=cluster.cluster,
                subject=cluster.cluster,
                message=f"node backup · {cluster.label}",
                since=None,
                link="/backups",
            )
        )
    return items


def from_waf(ineffective: Iterable[tuple[str, str, Any]], *, describe: Any) -> list[Item]:
    """Published exceptions the findings show are not taking effect."""

    return [
        Item(
            kind="waf",
            severity="warning",
            cluster=cluster,
            subject=name,
            message=f"WAF exception {describe(exception, name)} is not working",
            since=None,
            link="/waf?view=exceptions",
        )
        for cluster, name, exception in sorted(
            ineffective, key=lambda found: (found[0], found[1], str(found[2]))
        )
    ]


def build_attention(
    items: Iterable[Item],
    *,
    status_age: Mapping[str, int | None],
    stale_after_seconds: int,
    now: datetime | None = None,
) -> Attention:
    """The list, worst first and then newest first, and whether the readings are fresh."""

    ordered = sorted(
        items,
        key=lambda item: (
            SEVERITIES.index(item.severity),
            -(item.since.timestamp() if item.since else 0),
            item.cluster or "",
            item.subject,
        ),
    )
    fresh = bool(status_age) and all(
        age is not None and age <= stale_after_seconds for age in status_age.values()
    )
    return Attention(
        generated_at=now or datetime.now(UTC),
        items=tuple(ordered),
        status_age=dict(status_age),
        fresh=fresh,
    )
