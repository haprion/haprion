"""The cluster's own HAProxy settings: its traffic log, metrics and shared counters.

`managed/cluster.yaml` holds what applies to a whole cluster rather than to an
object or an address (Fas 15, B209): the external targets the traffic log is
sent to, the sources whose answered requests it leaves out, the Prometheus exporter, and the port the nodes share their stick
tables over (B270). Application-owned, published through its
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
# A target's name becomes part of rsyslog's action and queue file names on the
# nodes, so it is held to what both accept.
#
TARGET_NAME = re.compile(r"^[a-z][a-z0-9-]{0,23}$")
MAX_TARGETS = 4
#
# rsyslog on the node sends to the receivers (B286), and a receiver that is
# away or slower than the traffic is survived with a queue on the node's disk:
# what fits is sent when the receiver reads again, what does not is counted and
# dropped, and the node's own traffic log is not held up (measured 26-10-12).
# About 800 bytes a record on disk, so 1 GiB holds some 1.3 million (B288).
#
DEFAULT_DISK_MIB = 1024
MIN_DISK_MIB = 64
MAX_DISK_MIB = 65536
#
# The memory ring's size before B286. Still read, so a cluster.yaml written
# then is not refused, and range-checked as it was; it no longer sizes
# anything, and the next save writes `disk_mib` instead.
#
LEGACY_MIN_BUFFER_KIB = 64
LEGACY_MAX_BUFFER_KIB = 65536
MAX_SOURCES = 32


@dataclass(frozen=True, slots=True)
class LogTarget:
    """One receiver of the traffic log, as syslog over TCP (RFC 5424)."""

    name: str
    #
    # An address and never a name: what the nodes send to must not depend on
    # their resolver at the moment rsyslog starts.
    #
    address: str
    port: int
    disk_mib: int = DEFAULT_DISK_MIB
    tls: bool = False


@dataclass(frozen=True, slots=True)
class Metrics:
    """HAProxy's Prometheus exporter, on every address of both nodes."""

    port: int
    sources: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Peers:
    """The nodes share their stick tables over this port (B270).

    What is shared is the counters the generated tables keep - the abuse
    brake's and the rate limits' - so they survive a failover, and a reload
    while another node is up: the reloaded node takes them back from it within
    seconds (measured on 3.4.6; alone, it starts from zero).
    The port has to be open between the nodes, both ways, and nowhere else
    needs it; that firewall is the operator's, which is why this is off until
    somebody turns it on.
    """

    port: int


@dataclass(frozen=True, slots=True)
class ClusterSettings:
    log_targets: tuple[LogTarget, ...] = ()
    metrics: Metrics | None = None
    peers: Peers | None = None
    #
    # Sources whose answered requests are not logged (B291): a monitor asking
    # every service once a minute. By the connection's address, never by
    # anything the request says, so nobody can quiet themselves with a header;
    # and an answer of 400 or more is logged whoever asked.
    #
    not_logged_from: tuple[str, ...] = ()


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
    _only(entry, {"address", "port", "disk_mib", "buffer_kib", "tls"}, where)
    disk_mib = entry.get("disk_mib", DEFAULT_DISK_MIB)
    if type(disk_mib) is not int or not MIN_DISK_MIB <= disk_mib <= MAX_DISK_MIB:
        raise ConfigError(
            f"{where}.disk_mib must be a whole number from {MIN_DISK_MIB} to {MAX_DISK_MIB}"
        )
    if "buffer_kib" in entry:
        legacy = entry["buffer_kib"]
        if type(legacy) is not int or not LEGACY_MIN_BUFFER_KIB <= legacy <= LEGACY_MAX_BUFFER_KIB:
            raise ConfigError(
                f"{where}.buffer_kib must be a whole number from {LEGACY_MIN_BUFFER_KIB} to "
                f"{LEGACY_MAX_BUFFER_KIB}; it no longer sizes anything, use disk_mib"
            )
    tls = entry.get("tls", False)
    if type(tls) is not bool:
        raise ConfigError(f"{where}.tls must be true or false")
    return LogTarget(
        name=name,
        address=_address(entry.get("address"), f"{where}.address"),
        port=_port(entry.get("port"), f"{where}.port"),
        disk_mib=disk_mib,
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


def _peers(raw: Any) -> Peers | None:
    if raw is None:
        return None
    where = f"{LOCATION} peers"
    entry = _mapping(raw, where)
    _only(entry, {"port"}, where)
    return Peers(port=_port(entry.get("port"), f"{where}.port"))


def _not_logged_from(raw: Any) -> tuple[str, ...]:
    if raw is None:
        return ()
    where = f"{LOCATION} not_logged_from"
    if not isinstance(raw, list):
        raise ConfigError(f"{where} must list addresses or networks")
    if len(raw) > MAX_SOURCES:
        raise ConfigError(f"{where} lists more than {MAX_SOURCES}")
    parsed = tuple(_source(value, where) for value in raw)
    if len(set(parsed)) != len(parsed):
        raise ConfigError(f"{where} lists the same network twice")
    return parsed


def load_mapping(raw: Any) -> ClusterSettings:
    """Apply the schema to already-decoded, untrusted YAML."""

    document = _mapping(raw, LOCATION)
    _only(document, {"log_targets", "not_logged_from", "metrics", "peers"}, LOCATION)
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
    metrics = _metrics(document.get("metrics"))
    peers = _peers(document.get("peers"))
    if metrics is not None and peers is not None and metrics.port == peers.port:
        raise ConfigError(f"{LOCATION} names the same port for metrics and peers")
    return ClusterSettings(
        log_targets=targets,
        metrics=metrics,
        peers=peers,
        not_logged_from=_not_logged_from(document.get("not_logged_from")),
    )


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
                "disk_mib": target.disk_mib,
                "tls": target.tls,
            }
            for target in sorted(settings.log_targets, key=lambda target: target.name)
        }
    if settings.not_logged_from:
        document["not_logged_from"] = list(settings.not_logged_from)
    if settings.metrics is not None:
        document["metrics"] = {
            "port": settings.metrics.port,
            "sources": list(settings.metrics.sources),
        }
    if settings.peers is not None:
        document["peers"] = {"port": settings.peers.port}
    return yaml.safe_dump(document, sort_keys=False, default_flow_style=False).encode("utf-8")


def document_result(settings: ClusterSettings) -> dict[str, object]:
    """The settings as a helper reports them: the same fields as the file."""

    return {
        "log_targets": [
            {
                "name": target.name,
                "address": target.address,
                "port": target.port,
                "disk_mib": target.disk_mib,
                "tls": target.tls,
            }
            for target in settings.log_targets
        ],
        "not_logged_from": list(settings.not_logged_from),
        "metrics": (
            None
            if settings.metrics is None
            else {"port": settings.metrics.port, "sources": list(settings.metrics.sources)}
        ),
        "peers": None if settings.peers is None else {"port": settings.peers.port},
    }
