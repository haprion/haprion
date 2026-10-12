"""Settings -> Logs & metrics: each cluster's log targets, exporter and shared counters.

Fas 15 (B209) for the first two, B270 for the third.

The card reads the poller's cached `cluster_settings` rows and says, one line
per cluster, where its traffic log goes and whether metrics are on. A cluster's
own page is a form that becomes one `managed/cluster.yaml`, built here from
named fields and parsed by the engine's one parser before it is queued, so the
browser never hands a document of its own to the helper.

There are no switches for this under Features: no target means nothing is sent,
and the exporter off means nothing listens (2026-09-29).
"""

from __future__ import annotations

import contextlib
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from urllib.parse import quote

from haprion import cluster_settings, log_forwarding
from haprion.config import ConfigError

from haprion_ui.attention import FORWARD_WAITING
from haprion_ui.cluster_identity import accent_index

MAX_TARGETS = cluster_settings.MAX_TARGETS


class FormProblem(ValueError):
    """What is wrong with the form, as a sentence for the page."""


@dataclass(frozen=True, slots=True)
class ClusterSettingsView:
    cluster: str
    accent: int | None
    href: str
    readable: bool
    logs: str
    metrics: str
    counters: str = ""
    #
    # Whether something is set, for the check mark; and the whole of it for the
    # hover. The cell names the receivers only - four of them with addresses
    # did not fit at 1280 px (measured 2026-09-29) - and counts the sources.
    #
    logs_set: bool = False
    metrics_set: bool = False
    counters_set: bool = False
    logs_title: str = ""
    metrics_title: str = ""
    #
    # A publish done since the last deploy - "Reconfigured · deploy to
    # activate", the proxy listing's words. *Active* only when there is none,
    # so a published change is never shown as live.
    #
    waiting: bool = False
    #
    # The cluster's job in flight, by its label. Publishing sends the reader
    # back here the moment the job is queued, before it is done - so without
    # this the row said nothing, and the deploy badge only appeared on a reload
    # nobody made (2026-10-05). Drawn with `data-busy`, so the page reloads
    # itself when the job ends.
    #
    running: str = ""


@dataclass(frozen=True, slots=True)
class TargetRow:
    name: str = ""
    address: str = ""
    port: str = ""
    disk_mib: str = ""
    tls: bool = False


@dataclass(frozen=True, slots=True)
class SettingsForm:
    targets: tuple[TargetRow, ...]
    not_logged_from: str = ""
    metrics_on: bool = False
    metrics_port: str = ""
    metrics_sources: str = ""
    peers_on: bool = False
    peers_port: str = ""


def href(cluster: str) -> str:
    return f"/settings/clusters/{quote(cluster, safe='')}"


def _endpoint(target: Mapping[str, Any]) -> str:
    address = str(target.get("address", ""))
    shown = f"[{address}]" if ":" in address else address
    return f"{shown}:{target.get('port', '')}"


def _targets(result: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    targets = result.get("log_targets")
    return [target for target in targets or [] if isinstance(target, Mapping)]


def _tls(target: Mapping[str, Any]) -> str:
    return " (TLS)" if target.get("tls") else ""


def _logs(result: Mapping[str, Any]) -> str:
    targets = _targets(result)
    if not targets:
        return "Not sent"
    return ", ".join(f"{target.get('name')}{_tls(target)}" for target in targets)


def _logs_title(result: Mapping[str, Any]) -> str:
    return ", ".join(
        f"{target.get('name')} {_endpoint(target)}{_tls(target)}" for target in _targets(result)
    )


def _sources(result: Mapping[str, Any]) -> list[str]:
    metrics = result.get("metrics")
    sources = metrics.get("sources") if isinstance(metrics, Mapping) else None
    return [str(source) for source in sources] if isinstance(sources, list) else []


def _metrics(result: Mapping[str, Any]) -> str:
    metrics = result.get("metrics")
    if not isinstance(metrics, Mapping):
        return "Off"
    count = len(_sources(result))
    return f"Port {metrics.get('port')} · {count} source{'' if count == 1 else 's'}"


def _peers_port(result: Mapping[str, Any]) -> int | None:
    peers = result.get("peers")
    port = peers.get("port") if isinstance(peers, Mapping) else None
    return port if isinstance(port, int) else None


def _counters(result: Mapping[str, Any]) -> str:
    port = _peers_port(result)
    return "Off" if port is None else f"Port {port}"


#
# What makes a row's settings not yet what its nodes run: publishing them, on
# their own or with other changes, and deploying. Another job on the cluster -
# a backup schedule switched off with its feature, a drain - holds the queue's
# slot for a second but says nothing about logs and metrics (26-10-10).
#
SETTINGS_OPERATIONS = frozenset({"cluster_settings_publish", "changes_publish", "deploy"})


def card_views(
    clusters: Sequence[str],
    rows: Iterable[Any],
    *,
    waiting: Iterable[str] = (),
    running: Mapping[str, str] | None = None,
) -> list[ClusterSettingsView]:
    """One row per listed cluster, in the order the installation lists them."""

    waiting = frozenset(waiting)

    readings = {row.cluster: row for row in rows}
    views: list[ClusterSettingsView] = []
    for cluster in clusters:
        row = readings.get(cluster)
        result = row.result if row is not None and row.outcome == "done" else None
        readable = isinstance(result, Mapping)
        views.append(
            ClusterSettingsView(
                cluster=cluster,
                accent=accent_index(cluster),
                href=href(cluster),
                readable=readable,
                logs=_logs(result) if isinstance(result, Mapping) else "Not read yet",
                metrics=_metrics(result) if isinstance(result, Mapping) else "",
                counters=_counters(result) if isinstance(result, Mapping) else "",
                counters_set=isinstance(result, Mapping) and _peers_port(result) is not None,
                waiting=cluster in waiting,
                running=(running or {}).get(cluster, ""),
                logs_set=isinstance(result, Mapping) and bool(_targets(result)),
                metrics_set=isinstance(result, Mapping)
                and isinstance(result.get("metrics"), Mapping),
                logs_title=_logs_title(result) if isinstance(result, Mapping) else "",
                metrics_title=", ".join(_sources(result)) if isinstance(result, Mapping) else "",
            )
        )
    return views


def form_from_result(result: Mapping[str, Any]) -> SettingsForm:
    """The page's fields filled from a reading, with empty rows up to the limit."""

    rows = [
        TargetRow(
            name=str(target.get("name", "")),
            address=str(target.get("address", "")),
            port=str(target.get("port", "")),
            disk_mib=str(target.get("disk_mib", "")),
            tls=target.get("tls") is True,
        )
        for target in result.get("log_targets") or []
        if isinstance(target, Mapping)
    ]
    rows += [TargetRow()] * (MAX_TARGETS - len(rows))
    metrics = result.get("metrics")
    sources = metrics.get("sources") if isinstance(metrics, Mapping) else None
    peers_port = _peers_port(result)
    quiet = result.get("not_logged_from")
    return SettingsForm(
        targets=tuple(rows[:MAX_TARGETS]),
        not_logged_from="\n".join(str(source) for source in quiet or []),
        metrics_on=isinstance(metrics, Mapping),
        metrics_port=str(metrics.get("port", "")) if isinstance(metrics, Mapping) else "",
        metrics_sources="\n".join(str(source) for source in sources or []),
        peers_on=peers_port is not None,
        peers_port="" if peers_port is None else str(peers_port),
    )


def _number(value: str, what: str) -> int:
    text = value.strip()
    if not text.isdigit():
        raise FormProblem(f"{what} must be a number.")
    return int(text)


def settings_from_form(form: SettingsForm) -> cluster_settings.ClusterSettings:
    """The settings the form describes, checked by the engine's own parser.

    A row with nothing in it is not a target; a row with anything in it is,
    and must be complete.
    """

    targets: dict[str, dict[str, Any]] = {}
    for number, row in enumerate(form.targets, start=1):
        if not (row.name.strip() or row.address.strip() or row.port.strip()):
            continue
        name = row.name.strip()
        if not name:
            raise FormProblem(f"Log target {number} needs a name.")
        if name in targets:
            raise FormProblem(f"Two log targets are called {name}.")
        entry: dict[str, Any] = {
            "address": row.address.strip(),
            "port": _number(row.port, f"The port of {name}"),
            "tls": row.tls,
        }
        if row.disk_mib.strip():
            entry["disk_mib"] = _number(row.disk_mib, f"The disk queue of {name}")
        targets[name] = entry
    document: dict[str, Any] = {}
    if targets:
        document["log_targets"] = targets
    quiet = [line.strip() for line in form.not_logged_from.splitlines() if line.strip()]
    if quiet:
        document["not_logged_from"] = quiet
    if form.metrics_on:
        document["metrics"] = {
            "port": _number(form.metrics_port, "The metrics port"),
            "sources": [line.strip() for line in form.metrics_sources.splitlines() if line.strip()],
        }
    if form.peers_on:
        document["peers"] = {"port": _number(form.peers_port, "The port for shared counters")}
    try:
        return cluster_settings.load_mapping(document)
    except ConfigError as exc:
        raise FormProblem(_sentence(str(exc))) from exc


#
# The parser names a field as the file spells it; the page says it in the
# form's own words, so `not_logged_from` never reaches a person.
#
_FIELDS = (
    (re.compile(r"^log_targets\.([a-z0-9-]+)\.address\b"), r"The IP address of \1"),
    (re.compile(r"^log_targets\.([a-z0-9-]+)\.port\b"), r"The port of \1"),
    (re.compile(r"^log_targets\.([a-z0-9-]+)\.disk_mib\b"), r"The disk queue of \1"),
    (re.compile(r"^log_targets\.([a-z0-9-]+)\.tls\b"), r"TLS for \1"),
    (re.compile(r"^metrics\.sources\b"), "Allowed sources"),
    (re.compile(r"^metrics\.port\b"), "The metrics port"),
    (re.compile(r"^peers\.port\b"), "The port for shared counters"),
    (re.compile(r"^not_logged_from\b"), "Not logged from"),
)
_NOT_AN_ADDRESS = re.compile(r"^(.+?) is not an address or a network: (.+)$")


def _sentence(message: str) -> str:
    text = message.removeprefix(f"{cluster_settings.LOCATION} ")
    for field, words in _FIELDS:
        text = field.sub(words, text, count=1)
    wrong = _NOT_AN_ADDRESS.match(text)
    if wrong:
        text = f"{wrong.group(1)}: {wrong.group(2)} is not an address or a network"
    return text[:1].upper() + text[1:] + ("" if text.endswith(".") else ".")


def comment_for(settings: cluster_settings.ClusterSettings) -> str:
    """The version's comment, said from what the settings now are."""

    logs = (
        "logs to " + ", ".join(target.name for target in settings.log_targets)
        if settings.log_targets
        else "no external logs"
    )
    if settings.not_logged_from:
        logs += ", not from " + ", ".join(settings.not_logged_from)
    metrics = (
        f"metrics on {settings.metrics.port}" if settings.metrics is not None else "metrics off"
    )
    counters = (
        f"counters shared on {settings.peers.port}"
        if settings.peers is not None
        else "counters not shared"
    )
    return f"Logs & metrics: {logs}; {metrics}; {counters}"


@dataclass(frozen=True, slots=True)
class DeliveryRow:
    """One receiver as one node sends to it, on the cluster's page (26-10-12)."""

    node: str
    receiver: str
    queued: str
    state: str
    tone: str
    since: datetime | None = None
    reason: str = ""


def delivery(result: Mapping[str, Any] | None, *, now: datetime) -> list[DeliveryRow]:
    """Each node's receivers, read as the attention list reads them.

    Dropped lines are critical; a queue that has not emptied for
    attention.FORWARD_WAITING, or one that is long, is behind. The reason is the
    node's own (`last_error`, from rsyslog's journal), shown whatever the state.
    A node not read is a row only beside a node that forwards: a cluster that
    sends its log nowhere has no deliveries to show (review 26-10-12 F4).
    """

    rows: list[DeliveryRow] = []
    unread: list[DeliveryRow] = []
    nodes = result.get("nodes") if isinstance(result, Mapping) else None
    for entry in nodes if isinstance(nodes, list) else ():
        if not isinstance(entry, Mapping):
            continue
        name = str(entry.get("name", ""))
        status = entry.get("status")
        if not entry.get("status_ok") or not isinstance(status, Mapping):
            unread.append(DeliveryRow(name, "", "", "Not read", "unknown"))
            continue
        forwarding = status.get("log_forwarding")
        receivers = forwarding.get("receivers") if isinstance(forwarding, Mapping) else None
        waiting = entry.get("forward_waiting_since")
        for receiver in receivers if isinstance(receivers, list) else ():
            if not isinstance(receiver, Mapping):
                continue
            target = str(receiver.get("name", ""))
            queued = receiver.get("queued")
            dropped = receiver.get("dropped_last_hour")
            reason = log_forwarding.unreached(receiver) or ""
            since = None
            if isinstance(waiting, Mapping) and target in waiting:
                with contextlib.suppress(TypeError, ValueError):
                    since = datetime.fromisoformat(str(waiting[target]))
            if isinstance(dropped, int) and dropped > 0:
                state, tone = (
                    f"{log_forwarding.count(dropped)} dropped in the last hour",
                    "critical",
                )
            elif since is not None and now - since >= FORWARD_WAITING:
                state, tone = "Not delivered", "warning"
            elif isinstance(queued, int) and queued >= log_forwarding.QUEUE_WARNING:
                state, tone = "Behind", "warning"
            elif not isinstance(queued, int):
                state, tone = "Unknown", "unknown"
            else:
                state, tone = "Delivering", "healthy"
            if reason and tone == "healthy":
                tone = "warning"
            rows.append(
                DeliveryRow(
                    node=name,
                    receiver=target,
                    queued=log_forwarding.count(queued) if isinstance(queued, int) else "—",
                    state=state,
                    tone=tone,
                    since=since if tone != "healthy" else None,
                    reason=reason,
                )
            )
    if not rows:
        return []
    return sorted(rows + unread, key=lambda row: (row.receiver, row.node))
