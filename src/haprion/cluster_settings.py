"""The cluster's own HAProxy settings: where its traffic log goes, and metrics.

`managed/cluster.yaml` holds what applies to a whole cluster rather than to an
object or an address (Fas 15, B209): the external targets the traffic log is
sent to, and the Prometheus exporter. Application-owned, published through its
own helper like `managed/network.yaml`, and this module is its one parser and
serializer - the form, the helper and the generator all read it through here.

A missing file is a cluster with neither: nothing is sent anywhere and nothing
new listens.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any

import yaml

from haprion import safe_yaml
from haprion.config import ConfigError

LOCATION = "managed/cluster.yaml"
MAX_BYTES = 16 * 1024

#
# A target's name becomes part of a ring's and a server's name in the
# configuration, so it is held to what both accept.
#
TARGET_NAME = re.compile(r"^[a-z][a-z0-9-]{0,23}$")
MAX_TARGETS = 4
#
# The ring is what a receiver's outage is survived with: HAProxy keeps sending
# what fits in it and drops the rest, and the traffic itself is not affected
# (measured 2026-09-29). 4 MiB holds a few thousand records.
#
DEFAULT_BUFFER_KIB = 4096
MIN_BUFFER_KIB = 64
MAX_BUFFER_KIB = 65536
MAX_SOURCES = 32


@dataclass(frozen=True, slots=True)
class LogTarget:
    """One receiver of the traffic log, as syslog over TCP (RFC 5424)."""

    name: str
    #
    # An address and never a name. A ring's server is resolved when the
    # configuration is read, `init-addr` or not, so a name that does not
    # resolve at a reload fails the whole configuration (measured 2026-09-29).
    #
    address: str
    port: int
    buffer_kib: int = DEFAULT_BUFFER_KIB
    tls: bool = False


@dataclass(frozen=True, slots=True)
class Metrics:
    """HAProxy's Prometheus exporter, on every address of both nodes."""

    port: int
    sources: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ClusterSettings:
    log_targets: tuple[LogTarget, ...] = ()
    metrics: Metrics | None = None


NOTHING = ClusterSettings()


def _mapping(raw: Any, where: str) -> dict[str, Any]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ConfigError(f"{where} must be a mapping")
    return raw


def _only(raw: dict[str, Any], allowed: set[str], where: str) -> None:
    unknown = sorted(str(key) for key in raw if key not in allowed)
    if unknown:
        raise ConfigError(f"{where} has unknown field(s): {', '.join(unknown)}")


def _port(raw: Any, where: str) -> int:
    if type(raw) is not int or not 1 <= raw <= 65535:
        raise ConfigError(f"{where} must be a port from 1 to 65535")
    return raw


def _address(raw: Any, where: str) -> str:
    if not isinstance(raw, str):
        raise ConfigError(f"{where} must be an IP address")
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError as exc:
        raise ConfigError(f"{where} must be an IP address, not a name: {raw!r}") from exc


def _source(raw: Any, where: str) -> str:
    if not isinstance(raw, str):
        raise ConfigError(f"{where} must be an address or a network")
    try:
        return str(ipaddress.ip_network(raw, strict=True))
    except ValueError as exc:
        raise ConfigError(f"{where} is not an address or a network: {raw!r}") from exc


def _target(name: Any, raw: Any) -> LogTarget:
    where = f"{LOCATION} log_targets.{name}"
    if not isinstance(name, str) or not TARGET_NAME.fullmatch(name):
        raise ConfigError(
            f"{LOCATION} log target {name!r} must be a lowercase letter followed by up to 23 "
            "lowercase letters, digits or hyphens"
        )
    entry = _mapping(raw, where)
    _only(entry, {"address", "port", "buffer_kib", "tls"}, where)
    buffer_kib = entry.get("buffer_kib", DEFAULT_BUFFER_KIB)
    if type(buffer_kib) is not int or not MIN_BUFFER_KIB <= buffer_kib <= MAX_BUFFER_KIB:
        raise ConfigError(
            f"{where}.buffer_kib must be a whole number from {MIN_BUFFER_KIB} to {MAX_BUFFER_KIB}"
        )
    tls = entry.get("tls", False)
    if type(tls) is not bool:
        raise ConfigError(f"{where}.tls must be true or false")
    return LogTarget(
        name=name,
        address=_address(entry.get("address"), f"{where}.address"),
        port=_port(entry.get("port"), f"{where}.port"),
        buffer_kib=buffer_kib,
        tls=tls,
    )


def _metrics(raw: Any) -> Metrics | None:
    if raw is None:
        return None
    where = f"{LOCATION} metrics"
    entry = _mapping(raw, where)
    _only(entry, {"port", "sources"}, where)
    sources = entry.get("sources")
    #
    # Required and never empty. An exporter nobody may reach is not a setting
    # anyone meant, and one everybody may reach is a choice somebody has to
    # write down as 0.0.0.0/0.
    #
    if not isinstance(sources, list) or not sources:
        raise ConfigError(f"{where}.sources must list at least one address or network")
    if len(sources) > MAX_SOURCES:
        raise ConfigError(f"{where}.sources lists more than {MAX_SOURCES}")
    parsed = tuple(_source(value, f"{where}.sources") for value in sources)
    if len(set(parsed)) != len(parsed):
        raise ConfigError(f"{where}.sources lists the same network twice")
    return Metrics(port=_port(entry.get("port"), f"{where}.port"), sources=parsed)


def load_mapping(raw: Any) -> ClusterSettings:
    """Apply the schema to already-decoded, untrusted YAML."""

    document = _mapping(raw, LOCATION)
    _only(document, {"log_targets", "metrics"}, LOCATION)
    targets_raw = _mapping(document.get("log_targets"), f"{LOCATION} log_targets")
    if len(targets_raw) > MAX_TARGETS:
        raise ConfigError(f"{LOCATION} names more than {MAX_TARGETS} log targets")
    targets = tuple(_target(name, targets_raw[name]) for name in sorted(targets_raw, key=str))
    endpoints = [(target.address, target.port) for target in targets]
    if len(set(endpoints)) != len(endpoints):
        #
        # Two rings to one receiver would send every record twice.
        #
        raise ConfigError(f"{LOCATION} names the same address and port for two log targets")
    return ClusterSettings(log_targets=targets, metrics=_metrics(document.get("metrics")))


def load_document(document: bytes | None) -> ClusterSettings:
    """Parse one untrusted document exactly as a published tree does; None is nothing."""

    if document is None:
        return NOTHING
    if len(document) > MAX_BYTES:
        raise ConfigError(f"{LOCATION} exceeds the {MAX_BYTES} byte size limit")
    try:
        parsed: Any = safe_yaml.load(document.decode("utf-8"))
    except (UnicodeError, yaml.YAMLError) as exc:
        raise ConfigError(f"{LOCATION} is not valid YAML") from exc
    return load_mapping(parsed)


def dump_document(settings: ClusterSettings) -> bytes:
    """The canonical YAML, so a version diff shows what changed and nothing else."""

    document: dict[str, object] = {}
    if settings.log_targets:
        document["log_targets"] = {
            target.name: {
                "address": target.address,
                "port": target.port,
                "buffer_kib": target.buffer_kib,
                "tls": target.tls,
            }
            for target in sorted(settings.log_targets, key=lambda target: target.name)
        }
    if settings.metrics is not None:
        document["metrics"] = {
            "port": settings.metrics.port,
            "sources": list(settings.metrics.sources),
        }
    return yaml.safe_dump(document, sort_keys=False, default_flow_style=False).encode("utf-8")


def document_result(settings: ClusterSettings) -> dict[str, object]:
    """The settings as a helper reports them: the same fields as the file."""

    return {
        "log_targets": [
            {
                "name": target.name,
                "address": target.address,
                "port": target.port,
                "buffer_kib": target.buffer_kib,
                "tls": target.tls,
            }
            for target in settings.log_targets
        ],
        "metrics": (
            None
            if settings.metrics is None
            else {"port": settings.metrics.port, "sources": list(settings.metrics.sources)}
        ),
    }
