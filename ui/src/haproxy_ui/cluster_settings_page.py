"""Settings -> Logs & metrics: each cluster's log targets and exporter (Fas 15, B209).

The card reads the poller's cached `cluster_settings` rows and says, one line
per cluster, where its traffic log goes and whether metrics are on. A cluster's
own page is a form that becomes one `managed/cluster.yaml`, built here from
named fields and parsed by the engine's one parser before it is queued, so the
browser never hands a document of its own to the helper.

There are no switches for this under Features: no target means nothing is sent,
and the exporter off means nothing listens (2026-09-29).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

from haproxy_mgmt import cluster_settings
from haproxy_mgmt.config import ConfigError

from haproxy_ui.cluster_identity import accent_index

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
    #
    # Whether something is set, for the check mark; and the whole of it for the
    # hover. The cell names the receivers only - four of them with addresses
    # did not fit at 1280 px (measured 2026-09-29) - and counts the sources.
    #
    logs_set: bool = False
    metrics_set: bool = False
    logs_title: str = ""
    metrics_title: str = ""
    #
    # Where the settings have got to, as the network page answers it for its
    # one document per cluster: a publish still running, or one done since
    # the last deploy - "Reconfigured · deploy to activate", the proxy listing's words. *Active* only
    # when neither, so a published change is never shown as live.
    #
    running: str = ""
    waiting: bool = False


@dataclass(frozen=True, slots=True)
class TargetRow:
    name: str = ""
    address: str = ""
    port: str = ""
    buffer_kib: str = ""
    tls: bool = False


@dataclass(frozen=True, slots=True)
class SettingsForm:
    targets: tuple[TargetRow, ...]
    metrics_on: bool = False
    metrics_port: str = ""
    metrics_sources: str = ""


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


def card_views(
    clusters: Sequence[str],
    rows: Iterable[Any],
    *,
    running: Mapping[str, str] | None = None,
    waiting: Iterable[str] = (),
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
                running=(running or {}).get(cluster, ""),
                waiting=cluster in waiting,
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
            buffer_kib=str(target.get("buffer_kib", "")),
            tls=target.get("tls") is True,
        )
        for target in result.get("log_targets") or []
        if isinstance(target, Mapping)
    ]
    rows += [TargetRow()] * (MAX_TARGETS - len(rows))
    metrics = result.get("metrics")
    if isinstance(metrics, Mapping):
        sources = metrics.get("sources")
        return SettingsForm(
            targets=tuple(rows[:MAX_TARGETS]),
            metrics_on=True,
            metrics_port=str(metrics.get("port", "")),
            metrics_sources="\n".join(str(source) for source in sources or []),
        )
    return SettingsForm(targets=tuple(rows[:MAX_TARGETS]))


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
        if row.buffer_kib.strip():
            entry["buffer_kib"] = _number(row.buffer_kib, f"The buffer of {name}")
        targets[name] = entry
    document: dict[str, Any] = {}
    if targets:
        document["log_targets"] = targets
    if form.metrics_on:
        document["metrics"] = {
            "port": _number(form.metrics_port, "The metrics port"),
            "sources": [line.strip() for line in form.metrics_sources.splitlines() if line.strip()],
        }
    try:
        return cluster_settings.load_mapping(document)
    except ConfigError as exc:
        raise FormProblem(_sentence(str(exc))) from exc


def _sentence(message: str) -> str:
    text = message.removeprefix(f"{cluster_settings.LOCATION} ")
    return text[:1].upper() + text[1:] + ("" if text.endswith(".") else ".")


def comment_for(settings: cluster_settings.ClusterSettings) -> str:
    """The version's comment, said from what the settings now are."""

    logs = (
        "logs to " + ", ".join(target.name for target in settings.log_targets)
        if settings.log_targets
        else "no external logs"
    )
    metrics = (
        f"metrics on {settings.metrics.port}" if settings.metrics is not None else "metrics off"
    )
    return f"Logs & metrics: {logs}; {metrics}"
