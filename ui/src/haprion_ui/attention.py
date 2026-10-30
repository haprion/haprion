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
from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from typing import Any, Literal

from haprion import address_ranges, log_forwarding
from haprion.cluster_status import traffic_stream_problem
from haprion.node_package import short_version

from haprion_ui import jobs as jobs_module
from haprion_ui import labels
from haprion_ui.db import ClaimPause, Job, PackageWaiting

type Severity = Literal["critical", "warning"]
SEVERITIES: tuple[Severity, ...] = ("critical", "warning")

#
# A job whose last run did not work, until a later run of the same operation
# on the same cluster does (B274): a certificate job that went through says
# nothing about a broken deploy.
#
UNSETTLED = frozenset({"failed", "partial", "blocked", "unknown"})
#
# What the log page counts as old: the collector runs every minute.
#
LOG_STALE_SECONDS = 300
#
# A receiver that keeps up empties its queue within seconds; rsyslog writes
# the queue figures once a minute, so three minutes is a few readings in a row.
#
FORWARD_WAITING = timedelta(minutes=3)
#
# A job the worker would have taken in seconds. Ten minutes leaves room for a
# restart and for a long job ahead of it holding the cluster.
#
WORKER_WAITING = jobs_module.WORKER_WAITING
#
# How many days ahead `haprion-retention` creates each table's daily
# partitions (its TRAFFIC_AHEAD_DAYS and METRIC_AHEAD_DAYS; a test holds the
# two in step). The nightly run adds a day; a horizon more than a day short
# means it has not run.
#
MAINTENANCE_AHEAD = {"traffic_log": 31, "metric_frontend": 60}
#
# Two nights: one failed run is a warning the next night can clear by itself.
#
MAINTENANCE_UNFINISHED = timedelta(days=2)


def card_link(cluster: str) -> str:
    """The cluster's own card on the dashboard (`index.html`), not the top of it (04-03).

    A cluster ID is a valid fragment as it is (`CLUSTER_ID`: letters, digits, hyphens).
    """

    return f"/#cluster-{cluster}"


@dataclass(frozen=True, slots=True)
class Item:
    kind: str
    severity: Severity
    cluster: str | None
    subject: str
    message: str
    since: datetime | None
    link: str
    #
    # What else tells this row from the same row worse (B406): the label a node
    # carries. Part of what an acknowledgement names, with the severity.
    #
    variant: str = ""

    @property
    def page(self) -> str:
        #
        # A job's row goes to Events, whatever its kind: the kind keys the
        # acknowledgement and stays (rig 26-10-29).
        #
        if self.link.startswith("/jobs"):
            return "Events"
        return PAGES[self.kind]

    @property
    def needs_writes(self) -> bool:
        """Whether the row's page is one only management writes open.

        Every page under /settings is behind the write gate and answers 404
        without it, so in read-only mode such a row is text, not a link
        (review 26-10-24, 04-02).
        """

        return self.link == "/settings" or self.link.startswith(
            ("/settings/", "/settings#", "/settings?")
        )

    @property
    def key(self) -> tuple[str, str, str, str, str]:
        """What an acknowledgement names (B299, B406): the row as the list shows it.

        The severity is in it: a row that becomes worse is a new row, and its
        acknowledgement - of what it had been - does not hide it.
        """

        return (self.kind, self.cluster or "", self.subject, self.severity, self.variant)

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


#
# Every kind, and the page its row goes to - one list, so a kind cannot be
# raised that the dashboard has no word for (26-10-12: the template held its
# own copy, and a new kind would have failed the page).
#
PAGES = {
    "certificate": "Certificates",
    "job": "Events",
    "node": "Dashboard",
    "cluster": "Dashboard",
    "reading": "Dashboard",
    "service": "Proxies",
    "waf": "WAF logs",
    "backup": "Node backups",
    "logs": "Traffic logs",
    "forwarding": "Logs & metrics",
    "manager": "Dashboard",
    "preparation": "Dashboard",
    "node_package": "Dashboard",
    "traffic_stream": "Dashboard",
}
KINDS = tuple(PAGES)

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
        if address_ranges.has_host_bits(entry):
            raise ValueError(f"Line {index}: {address_ranges.HOST_BITS}.")
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
    """The newest finished run per cluster and operation, when it did not work.

    By step, not by job (review 2026-10-22, 1B-2): a Publish & deploy whose
    deploy failed is a failed deploy, which the next Deploy that works ends,
    and its publish counts as one that worked.
    """

    newest: dict[tuple[str | None, str, str], tuple[Job, str]] = {}
    for job in sorted(rows, key=lambda row: (row.created_at, row.id), reverse=True):
        if not jobs_module.ran(job):
            continue
        for operation, subject, state in jobs_module.keyed_states(job):
            newest.setdefault((job.cluster, operation, subject), (job, state))
    #
    # One row per job and step, however many of its certificates are still
    # unsettled: the job is the thing to open.
    #
    unsettled: dict[tuple[int, str], tuple[str | None, Job]] = {}
    for (cluster, operation, _subject), (job, state) in newest.items():
        if state in UNSETTLED:
            unsettled.setdefault((job.id, operation), (cluster, job))
    items = []
    for (_id, operation), (cluster, job) in unsettled.items():
        if operation == job.operation and _distributed_since(job, newest):
            continue
        state = dict(jobs_module.step_states(job))[operation]
        waiting = (
            jobs_module.waiting_for(job)
            if operation == job.operation and state == "partial"
            else None
        )
        label = waiting or (
            jobs_module.failure_label(job, operation, state)
            if jobs_module.action_names(job) or operation in jobs_module.FAILURE_LABELS
            else f"{operation} did not work"
        )
        when = job.finished_at or job.created_at
        items.append(
            Item(
                kind="job",
                #
                # A refusal changed nothing (26-10-29, O04).
                #
                severity="warning" if waiting or state == "blocked" else "critical",
                cluster=cluster,
                subject=f"job {job.id}",
                message=label,
                since=when,
                link=f"/jobs#job-{job.id}",
            )
        )
    return items


def _distributed_since(
    job: Job, newest: Mapping[tuple[str | None, str, str], tuple[Job, str]]
) -> bool:
    """Whether a later run took up an issued or imported certificate's distribution (O02).

    Keyed on the issue as before, so a second issue of the name still ends it;
    and also ended by what distributes it: a later publish of the certificate,
    or, when only a rollout failed, a later certificate deploy of each cluster
    it failed on. One of those that failed is listed itself (26-10-29).
    """

    left = jobs_module.undistributed(job)
    if left is None:
        return False

    def later(key: tuple[str | None, str, str]) -> Job | None:
        found = newest.get(key)
        if found is None or (found[0].created_at, found[0].id) <= (job.created_at, job.id):
            return None
        return found[0]

    published = later((None, "cert_publish", left.certificate))
    if published is not None:
        payload = published.payload if isinstance(published.payload, dict) else {}
        if payload.get("deploy") is not False or not left.clusters:
            return True
    return (
        not left.unwritten
        and bool(left.clusters)
        and all(later((name, "cert_deploy", "")) is not None for name in left.clusters)
    )


def from_dashboard(
    clusters: Iterable[Any], *, drift_label: str, cluster_faults: frozenset[str] = frozenset()
) -> list[Item]:
    """Nodes that are down, clusters whose status reading has stopped, and a cluster's own faults.

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
                    #
                    # The time is the row's own, written after the message;
                    # the card's "Observed 12m ago" beside it read "status
                    # last read Observed 12m ago" (review 2026-10-22, 2-6).
                    #
                    message="status last read",
                    since=cluster.observed_at,
                    link=card_link(cluster.cluster),
                )
            )
            continue
        #
        # One line per node that is wrong: the node's own verdict names which
        # node. A node's time is the reading's, which says nothing about when
        # it went wrong, so there is none.
        #
        #
        # What the cluster itself is, before its nodes: a VIP in split brain
        # or with no owner while every node reports Online, and a reading that
        # failed or had no node in it. The worst states a cluster has, and the
        # list - with every monitor reading /status/attention.json - said
        # nothing of them (review 2026-10-22, 2-1).
        #
        fault = _severity(cluster.tone) if cluster.label in cluster_faults else None
        if fault is not None:
            items.append(
                Item(
                    kind="cluster",
                    severity=fault,
                    cluster=cluster.cluster,
                    subject=cluster.cluster,
                    message=f"{cluster.label} · {cluster.detail}",
                    since=None,
                    link=card_link(cluster.cluster),
                    # What kind of fault, so that acknowledging "no owner" does
                    # not hide "split brain" (review 2026-10-30, R7).
                    variant=f"{cluster.label} · {cluster.detail}",
                )
            )
        for node in cluster.nodes:
            #
            # Its own row and kind, so that acknowledging a node that is down
            # does not also hide that it needs preparing (B363).
            #
            if node.prepare_pending:
                items.append(
                    Item(
                        kind="preparation",
                        severity="warning",
                        cluster=cluster.cluster,
                        subject=node.name,
                        message="the node package changed what its preparation sets up:"
                        " run  sudo haprion-node-prepare  on the node",
                        since=None,
                        link=card_link(cluster.cluster),
                    )
                )
            #
            # Its own kind too: a node left on an older haprion-node than the
            # manager's release carries (26-10-29). Updating it is `apt upgrade`
            # on the node, which nothing here can do for it.
            #
            if node.package_message:
                items.append(
                    Item(
                        kind="node_package",
                        severity="warning",
                        cluster=cluster.cluster,
                        subject=node.name,
                        message=node.package_message,
                        since=None,
                        link=card_link(cluster.cluster),
                    )
                )
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
                    link=card_link(cluster.cluster),
                    variant=node.label,
                )
            )
    return items


def from_services(lamps: Mapping[str, Mapping[str, Any]], *, held_label: str) -> list[Item]:
    """Objects whose servers are not up, as the *Proxies* lamp says it (26-10-12).

    The lamp's own verdict and nothing else: red where no node reaches any of
    the object's servers, amber where some are down or down on one node. What
    the lamp leaves grey - no health check, nothing reported - is not a fault
    anybody can act on here; a node that is down is its own row. A lamp held
    amber only by servers drained or in maintenance is a choice and is left to
    the *Operations* line, as B274 left every other one.
    """

    items: list[Item] = []
    for cluster, objects in lamps.items():
        for name, lamp in sorted(objects.items()):
            severity = _severity(lamp.tone)
            if severity is None or lamp.label == held_label:
                continue
            items.append(
                Item(
                    kind="service",
                    severity=severity,
                    cluster=cluster,
                    subject=name,
                    message=f"{lamp.label} · {lamp.detail}" if lamp.label else lamp.detail,
                    since=None,
                    link=f"/proxies/{cluster}/{name}#servers",
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


DATABASE_JOBS = (
    ("dump", "Database dump", "sudo systemctl start haprion-backup.service"),
    ("restore_check", "Restore check", "sudo systemctl start haprion-restore-check.service"),
)


def from_database_jobs(jobs: Mapping[str, Any] | None) -> list[Item]:
    """A database dump or restore check whose last run failed (B400); nothing for one that is
    not installed or has not failed. The row's text is the command to run: starting the
    unit, because the row reads the unit's last result, which only a run of the unit changes."""

    items: list[Item] = []
    for name, subject, command in DATABASE_JOBS:
        job = (jobs or {}).get(name)
        if not isinstance(job, Mapping) or job.get("last_result") in (None, "", "success"):
            continue
        items.append(
            Item(
                kind="manager",
                severity="critical",
                cluster=None,
                subject=subject,
                message=f"failed; run {command}",
                since=None,
                link="/",
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


def from_traffic_logs(nodes: Iterable[Any], *, now: datetime) -> list[Item]:
    """The log page's warning per node, less the minutes a burst takes to catch up (26-10-12).

    A collection that failed, has not succeeded for five minutes or never
    reached the node wants somebody. Catching up after a burst heals itself in
    a run or two and is left to the log page; a node still behind after that is
    listed, as one with older days waiting is.
    """

    items: list[Item] = []
    for node in nodes:
        #
        # A node still being joined has no keys in place yet; the collector
        # does not count it either (26-10-27, F25).
        #
        if node.being_joined(now=now):
            continue
        stale = node.stale_seconds(now=now)
        if node.latest_attempt_failed() and node.outcome == "budget":
            message = "log collection paused: the manager's copy is over its space budget"
        elif node.latest_attempt_failed():
            message = f"log collection failed ({node.outcome})"
        elif stale is None:
            message = "log collection has never reached the node"
        elif stale > LOG_STALE_SECONDS:
            message = f"log collection last succeeded {int(stale // 60)} min ago"
        elif node.lasting_backlog():
            message = "log collection behind" + (
                f" · {labels.counted(node.pending_days, 'older day')} waiting"
                if node.pending_days
                else f" for {node.behind_runs} runs"
            )
        else:
            continue
        items.append(
            Item(
                kind="logs",
                severity="warning",
                cluster=node.cluster,
                subject=node.node,
                message=message,
                since=node.last_success,
                link="/logs",
            )
        )
    return items


def from_traffic_stream(status_rows: Iterable[Any], *, unread: Collection[str] = ()) -> list[Item]:
    """Each node that drops every traffic record its release logs (review 2026-10-30-igen, R3).

    The reading is the engine's (`cluster_status.traffic_stream_problem`), the
    same `haprion-status` prints. Critical: nothing reaches the node's own log
    or any receiver until it is put right, and nothing else says so. A cluster
    whose reading is old (`unread`) is not judged by it: its own row says it
    was not read (review 2026-10-30, E5).
    """

    items: list[Item] = []
    for row in status_rows:
        if row.cluster in unread:
            continue
        result = row.result if isinstance(getattr(row, "result", None), Mapping) else {}
        for entry in result.get("nodes") or ():
            if not isinstance(entry, Mapping) or not entry.get("status_ok"):
                continue
            status = entry.get("status")
            if not isinstance(status, Mapping):
                continue
            reason = traffic_stream_problem(status)
            if reason is None:
                continue
            items.append(
                Item(
                    kind="traffic_stream",
                    severity="critical",
                    cluster=row.cluster,
                    subject=str(entry.get("name", "")),
                    message=f"drops its traffic log: {reason}",
                    since=None,
                    link=card_link(row.cluster),
                )
            )
    return items


RECEIVER_ARROW = " → "


def _receiver_subject(node: str, receiver: str | None) -> str:
    """The node, and the receiver when the row is about one: what an acknowledgement names (B406).

    Acknowledging one receiver's row must not hide another receiver's on the
    same node.
    """

    return f"{node}{RECEIVER_ARROW}{receiver}" if receiver else node


def _traffic_log(message: str, receiver: str | None) -> str:
    """The engine's line without the receiver, which the row's subject already names."""

    return (
        message.replace(f"traffic log to {receiver}: ", "traffic log: ", 1) if receiver else message
    )


def from_log_forwarding(
    status_rows: Iterable[Any], *, now: datetime, unread: Collection[str] = ()
) -> list[Item]:
    """Each node's receivers whose queue is long, not emptied, or dropped lines (B289).

    The reading of the figures is the engine's (`haprion.log_forwarding`), the
    same the terminal's status command prints. A queue that has not been empty
    for FORWARD_WAITING is the poller's to say (`forward_waiting_since`): on a
    quiet cluster a receiver out of reach shows as a few lines that never leave,
    long before the queue is long (26-10-12, external behind a closed firewall).
    A cluster whose reading is old (`unread`) says nothing here: the time that
    has passed since is not time the lines waited (review 2026-10-30, E5).
    """

    items: list[Item] = []
    for row in status_rows:
        if row.cluster in unread:
            continue
        result = row.result if isinstance(getattr(row, "result", None), Mapping) else {}
        for entry in result.get("nodes") or ():
            if not isinstance(entry, Mapping) or not entry.get("status_ok"):
                continue
            status = entry.get("status")
            if not isinstance(status, Mapping):
                continue
            forwarding = status.get("log_forwarding")
            found = log_forwarding.problems(forwarding)
            for problem in found:
                items.append(
                    Item(
                        kind="forwarding",
                        severity=problem.severity,
                        cluster=row.cluster,
                        subject=_receiver_subject(str(entry.get("name", "")), problem.receiver),
                        message=_traffic_log(problem.message, problem.receiver),
                        since=None,
                        link=f"/settings/clusters/{row.cluster}#delivery",
                    )
                )
            said = {problem.receiver for problem in found if problem.receiver}
            waiting = entry.get("forward_waiting_since")
            reasons = {
                str(receiver.get("name")): log_forwarding.unreached(receiver)
                for receiver in (
                    forwarding.get("receivers") if isinstance(forwarding, Mapping) else None
                )
                or ()
                if isinstance(receiver, Mapping)
            }
            queued = {
                str(receiver.get("name")): receiver.get("queued")
                for receiver in (
                    forwarding.get("receivers") if isinstance(forwarding, Mapping) else None
                )
                or ()
                if isinstance(receiver, Mapping)
            }
            for name, stamp in sorted(waiting.items() if isinstance(waiting, Mapping) else ()):
                try:
                    since = datetime.fromisoformat(str(stamp))
                except ValueError:
                    continue
                if name in said or now - since < FORWARD_WAITING:
                    continue
                lines = queued.get(name)
                items.append(
                    Item(
                        kind="forwarding",
                        severity="warning",
                        cluster=row.cluster,
                        subject=_receiver_subject(str(entry.get("name", "")), name),
                        message="traffic log: "
                        + (
                            f"{labels.counted(lines, 'line')} "
                            if isinstance(lines, int) and not isinstance(lines, bool)
                            else ""
                        )
                        + "not delivered"
                        + (f" ({reasons[name]})" if reasons.get(name) else ""),
                        since=since,
                        link=f"/settings/clusters/{row.cluster}#delivery",
                    )
                )
    return items


def from_packages(rows: Sequence[PackageWaiting]) -> list[Item]:
    """The manager's packages with a newer version waiting in the repository (0088, B357).

    A fix that is published and not installed. The version waiting is in the
    row's subject, so an acknowledged row comes back when a newer one arrives.
    """

    return [
        Item(
            kind="manager",
            severity="warning",
            cluster=None,
            subject=f"{row.name} {short_version(row.available)}",
            message=f"waits in the repository; {short_version(row.installed)} is installed",
            since=row.read_at,
            link="/",
        )
        for row in rows
    ]


def from_manager(
    *,
    cluster_list_at: datetime | None,
    poller_silent_after: timedelta,
    rows: Sequence[Job],
    writes: bool,
    horizons: Mapping[str, date | None],
    now: datetime,
    maintained_at: datetime | None = None,
    claim_pause: ClaimPause | None = None,
) -> list[Item]:
    """The manager's own services, read from what they leave in the database.

    The interface cannot ask systemd (it runs without that right), so each
    service is judged by its trace (review 2026-10-18 S1/A8, B333): the poller
    writes the cluster list on every pass; the worker takes a queued job within
    seconds while writes are on, and keeps the lease of the one it runs;
    `haprion-retention` creates daily partitions ahead of time every night.
    """

    items: list[Item] = []
    if cluster_list_at is None or now - cluster_list_at > poller_silent_after:
        items.append(
            Item(
                kind="manager",
                severity="critical",
                cluster=None,
                subject="poller",
                message="the poller (haprion-poller) has not read the clusters since"
                if cluster_list_at
                else "the poller (haprion-poller) has never read the clusters",
                since=cluster_list_at,
                link="/",
            )
        )
    #
    # A held job waits for an admin, not for the worker (0082): it is its own
    # row, and never the worker's silence. Held at the worker's start or by
    # `haprion-backup after-restore`, which starts nothing (review 26-10-29, R04).
    #
    held = [job for job in rows if job.waits_for_decision]
    if held:
        items.append(
            Item(
                kind="manager",
                severity="warning",
                cluster=None,
                subject="held jobs",
                message=f"{labels.counted(len(held), 'job')} held after a restart or a restore {'waits' if len(held) == 1 else 'wait'} for Run or Discard",
                since=min(job.held_since for job in held if job.held_since is not None),
                link="/jobs",
            )
        )
    #
    # A running job whose lease ran out long ago: its worker is stopped, hung
    # or crashing, or waits for what will not come by itself (review 26-10-29,
    # Q01/R01). By job, so an acknowledgement names that job alone. Not with
    # writes off, when no job moves on purpose, as the worker's row (A2).
    #
    for job in rows:
        if jobs_module.no_worker(job, now, writes=writes):
            items.append(
                Item(
                    kind="manager",
                    severity="critical",
                    cluster=job.cluster,
                    subject=f"job {job.id}",
                    message="running, but no worker has held it since",
                    since=job.lease_lapsed_since,
                    link=f"/jobs#job-{job.id}",
                )
            )
    #
    # Only a job under a living lease holds the worker's row back: a job its
    # worker left is what a worker that died leaves. Nor is it raised while a
    # release pauses the claims (Q06): the worker then does as it should.
    #
    waiting = [job for job in rows if job.state == "pending" and not job.waits_for_decision]
    running = any(
        job.state == "running" and not job.waits_for_decision and job.lease_lapsed_since is None
        for job in rows
    )
    untaken = [
        job for job in waiting if jobs_module.not_taken(job, now, writes=writes, pause=claim_pause)
    ]
    if untaken and not running:
        oldest = min(job.created_at for job in waiting)
        items.append(
            Item(
                kind="manager",
                severity="critical",
                cluster=None,
                subject="worker",
                message=f"{labels.counted(len(waiting), 'job')} waiting and the worker takes none",
                since=oldest,
                link="/jobs",
            )
        )
    today = now.date()
    for table, ahead in MAINTENANCE_AHEAD.items():
        horizon = horizons.get(table)
        if horizon is None:
            #
            # No partition at all: the maintenance has never run here, and
            # every sample the poller takes is refused for want of one. The
            # check said nothing, since it compared a date it did not have
            # (review 2026-10-22, 3-2).
            #
            items.append(
                Item(
                    kind="manager",
                    severity="critical",
                    cluster=None,
                    subject="retention",
                    message=f"the nightly maintenance (haprion-retention) has never run: {table} has no partitions",
                    since=None,
                    link="/",
                )
            )
            break
        if horizon < today + timedelta(days=ahead - 1):
            last_run = horizon - timedelta(days=ahead)
            items.append(
                Item(
                    kind="manager",
                    severity="warning",
                    cluster=None,
                    subject="retention",
                    message=f"the nightly maintenance (haprion-retention) has not run since {last_run}",
                    since=datetime.combine(last_run, datetime.min.time(), UTC),
                    link="/",
                )
            )
            break
    #
    # A run that extended the partitions and then failed left the horizon
    # fresh (review 26-10-24, 05-09): when the last whole run finished says it.
    # One row about the maintenance, the horizon's first.
    #
    if (
        maintained_at is not None
        and now - maintained_at > MAINTENANCE_UNFINISHED
        and not any(item.subject == "retention" for item in items)
    ):
        items.append(
            Item(
                kind="manager",
                severity="warning",
                cluster=None,
                subject="retention",
                message="the nightly maintenance (haprion-retention) has not finished since",
                since=maintained_at,
                link="/",
            )
        )
    return items


def unacknowledged(
    items: Iterable[Item], acknowledged: set[tuple[str, str, str, str, str]]
) -> tuple[list[Item], set[tuple[str, str, str, str, str]]]:
    """The rows nobody has acknowledged, and the acknowledgements whose row has gone (B299).

    An acknowledgement lasts as long as its row: when what the row says is put
    right, or a later run of a job's operation works, the row goes, and so
    does the acknowledgement - the same trouble coming back is a row again.
    """

    listed = list(items)
    present = {item.key for item in listed}
    return [item for item in listed if item.key not in acknowledged], acknowledged - present


#
# The kinds of row a cluster's status reading makes, and so the acknowledgements
# that only a whole, fresh reading can say are done with (review 2026-10-30, E2).
#
READ_PER_CLUSTER = frozenset({"cluster", "service"})
READ_PER_NODE = frozenset({"node", "preparation", "node_package", "forwarding", "traffic_stream"})


def held_through_gaps(
    gone: set[tuple[str, str, str, str, str]],
    status_rows: Iterable[Any],
    *,
    now: datetime,
    stale_after: timedelta,
) -> set[tuple[str, str, str, str, str]]:
    """Of the acknowledgements whose row is not listed, those it is right to forget.

    A row made from a cluster's status reading is not listed while the reading
    is old, failed or missing the node, and then it has not gone - it could not
    be told. Its acknowledgement stays until a whole, fresh reading leaves the
    row out.
    """

    rows = {row.cluster: row for row in status_rows}
    forget: set[tuple[str, str, str, str, str]] = set()
    for key in gone:
        kind, cluster, named = key[:3]
        row = rows.get(cluster)
        if kind not in READ_PER_CLUSTER | READ_PER_NODE or row is None:
            forget.add(key)
            continue
        result = row.result if isinstance(getattr(row, "result", None), Mapping) else {}
        unread = bool(row.poll_error) or now - row.observed_at > stale_after
        if kind in READ_PER_CLUSTER:
            if unread or row.outcome != "done":
                continue
        else:
            nodes = {
                str(entry.get("name")): entry
                for entry in result.get("nodes") or ()
                if isinstance(entry, Mapping)
            }
            entry = nodes.get(named.partition(RECEIVER_ARROW)[0])
            if unread or (
                entry is not None and not (entry.get("reachable") and entry.get("status_ok"))
            ):
                continue
            if entry is None and row.outcome != "done":
                continue
        forget.add(key)
    return forget


def build_attention(
    items: Iterable[Item],
    *,
    status_age: Mapping[str, int | None],
    stale_after_seconds: int,
    list_age: int | None = None,
    now: datetime | None = None,
) -> Attention:
    """The list, worst first and then newest first, and whether the readings are fresh.

    With no cluster there is no status to be old, so the readings are fresh
    while the poller keeps reading the cluster list (`list_age`, seconds) - a
    new installation is not down until its first cluster (26-10-24).
    """

    ordered = sorted(
        items,
        key=lambda item: (
            SEVERITIES.index(item.severity),
            -(item.since.timestamp() if item.since else 0),
            item.cluster or "",
            item.subject,
        ),
    )
    if status_age:
        fresh = all(age is not None and age <= stale_after_seconds for age in status_age.values())
    else:
        fresh = list_age is not None and list_age <= stale_after_seconds
    return Attention(
        generated_at=now or datetime.now(UTC),
        items=tuple(ordered),
        status_age=dict(status_age),
        fresh=fresh,
    )
