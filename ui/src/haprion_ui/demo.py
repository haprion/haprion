"""Explicit synthetic data for visually reviewing the development interface.

This is not a fallback for a failed poll and it never touches the database,
network, Git or runtime configuration.  The deployment must opt in through
``demo_fixture = true`` while declaring no real clusters and keeping management
writes disabled.  Its only job is to make a development browser review useful
before a safe non-production cluster fixture exists.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Any

from haprion.config import Network, Vip
from haprion.objects import objects_result

from haprion_ui.db import (
    ClusterBackups,
    ClusterCertificates,
    ClusterHistory,
    ClusterInventory,
    ClusterNetwork,
    ClusterObjects,
    ClusterSettingsRow,
    ClusterStatus,
    ManagerCertificates,
)

CLUSTERS = ("edge-demo", "service-demo")


#
# `public-web`'s pool as both edge nodes report it: two servers up and the
# third drained (B263), with the sessions each node holds.
#
def _public_web(sessions: tuple[int, int, int]) -> list[dict[str, Any]]:
    return [
        {
            "backend": "web",
            "server": f"s{index + 1}",
            "status": status,
            "check_status": "L4OK",
            "admin": admin,
            "counters": {"scur": count},
        }
        for index, (status, admin, count) in enumerate(
            zip(("UP", "UP", "DRAIN"), ("ready", "ready", "drain"), sessions, strict=True)
        )
    ]


PACKAGES = {
    "haproxy": "3.4.6-1ppa1~resolute",
    "keepalived": "2.3.4-1",
    "dnsdist": "2.1.10-1pdns.ubuntu26.04",
    "waf_engine": "0.9.0-4",
    "openssl": "3.5.5-1ubuntu3.10",
}


def _node(
    name: str,
    *,
    owner: bool,
    version: int,
    current: bool,
    cpu: int,
    memory: int,
    servers: list[dict[str, Any]] | None = None,
    packages: dict[str, str] | None = None,
    blocked: dict[str, Any] | None = None,
    forwarding: dict[str, Any] | None = None,
    waiting: dict[str, str] | None = None,
) -> dict[str, Any]:
    # A node with 1 GiB; `memory` is the share in use (B239).
    total = 1_048_576
    extra: dict[str, Any] = {"servers": servers} if servers is not None else {}
    #
    # The packages beside HAProxy; service-b is a day behind its partner on two
    # of them, as a node patched second is (26-10-09).
    #
    extra["packages"] = packages or PACKAGES
    if blocked is not None:
        extra["blocked"] = blocked
    if forwarding is not None:
        extra["log_forwarding"] = forwarding
    outer: dict[str, Any] = {"forward_waiting_since": waiting} if waiting else {}
    return {
        **outer,
        "name": name,
        "mgmt_host": f"{name}.demo.example",
        "reachable": True,
        "status_ok": True,
        "current": current,
        "cpu_percent": cpu,
        "status": {
            "haproxy": {"active": True},
            "keepalived": {"active": True, "state": "MASTER" if owner else "BACKUP"},
            "vip": {"owner": owner},
            "release": {"version": version},
            "config_validation": {"valid": True},
            "stats_ok": True,
            "runtime": {"version": "3.2", "uptime_sec": 272_400},
            "resources": {
                "cpu": {"total": 34_000_000, "idle": 33_000_000},
                "memory": {"total_kb": total, "available_kb": total * (100 - memory) // 100},
                "load": cpu / 100,
                "cpus": 1,
            },
            **extra,
        },
    }


#
# Two scanners caught by public-web's dynamic blocking (B271), shared by both
# nodes as a cluster with shared counters holds them.
#
BLOCKED = {
    "public-web": {
        "count": 2,
        "addresses": [
            {"address": "198.51.100.23", "expires_in_ms": 1_640_000},
            {"address": "2001:db8:44::17", "expires_in_ms": 734_000},
        ],
    }
}


def _forwarding(loki_queued: int, reason: str = "") -> dict[str, Any]:
    """edge-demo's two receivers, as Settings names them (26-10-12)."""

    loki: dict[str, Any] = {"name": "loki", "queued": loki_queued, "dropped_last_hour": 0}
    if reason:
        loki["last_error"] = {"reason": reason, "age_sec": 40}
    return {
        "stats_age_sec": 20,
        "receivers": [{"name": "graylog", "queued": 0, "dropped_last_hour": 0}, loki],
    }


def status_rows(now: datetime | None = None) -> tuple[ClusterStatus, ...]:
    """Two representative healthy/degraded pairs for the dashboard."""

    observed = (now or datetime.now(UTC)) - timedelta(seconds=18)
    #
    # edge-a cannot reach loki: three lines waiting for eight minutes, and the
    # reason rsyslog gave - the forwarding row on the dashboard and the
    # cluster's Delivery table (26-10-12).
    #
    loki_waiting = {"loki": (observed - timedelta(minutes=8)).isoformat()}
    return (
        ClusterStatus(
            cluster="edge-demo",
            observed_at=observed,
            outcome="done",
            result={
                "nodes": [
                    _node(
                        "edge-a",
                        owner=True,
                        version=24,
                        current=True,
                        cpu=3,
                        memory=38,
                        servers=_public_web((14, 12, 3)),
                        blocked=BLOCKED,
                        forwarding=_forwarding(3, "Connection timed out"),
                        waiting=loki_waiting,
                    ),
                    _node(
                        "edge-b",
                        owner=False,
                        version=24,
                        current=True,
                        cpu=1,
                        memory=36,
                        servers=_public_web((0, 0, 0)),
                        blocked=BLOCKED,
                        forwarding=_forwarding(0),
                    ),
                ],
                "summary": {
                    "configured_nodes": 2,
                    "reachable_nodes": 2,
                    "vip_state": "single_owner",
                    "vip_owners": ["edge-a"],
                    "target": {"version": 24},
                    "release_state": "converged",
                },
            },
            warnings=[],
            error=None,
            poll_error=None,
        ),
        ClusterStatus(
            cluster="service-demo",
            observed_at=observed - timedelta(seconds=9),
            outcome="done",
            result={
                "nodes": [
                    _node("service-a", owner=True, version=24, current=True, cpu=12, memory=41),
                    _node(
                        "service-b",
                        owner=False,
                        version=23,
                        current=False,
                        cpu=2,
                        memory=88,
                        packages={
                            **PACKAGES,
                            "dnsdist": "2.1.2-1pdns.ubuntu26.04",
                            "openssl": "3.5.5-1ubuntu3.7",
                        },
                    ),
                ],
                "summary": {
                    "configured_nodes": 2,
                    "reachable_nodes": 2,
                    "vip_state": "single_owner",
                    "vip_owners": ["service-a"],
                    "target": {"version": 24},
                    "release_state": "behind",
                },
            },
            warnings=[],
            error=None,
            poll_error=None,
        ),
    )


def inventory_rows(now: datetime | None = None) -> tuple[ClusterInventory, ...]:
    """Published-looking proxy inventory, including an unmanaged legacy entry."""

    observed = (now or datetime.now(UTC)) - timedelta(seconds=18)
    return (
        ClusterInventory(
            cluster="edge-demo",
            observed_at=observed,
            outcome="done",
            result={
                "version": 24,
                "proxies": [
                    {
                        "name": "public-web",
                        "protocol": "https",
                        "managed": True,
                        "enabled": True,
                        "hostnames": ["app.demo.example", "www.demo.example"],
                        "bind_ports": [443],
                        "backend_count": 3,
                    },
                    {
                        "name": "metrics",
                        "protocol": "http",
                        "managed": False,
                        "enabled": True,
                        "hostnames": ["metrics.demo.example"],
                        "bind_ports": [80],
                        "backend_count": 1,
                    },
                ],
            },
            warnings=[],
            error=None,
            poll_error=None,
        ),
        ClusterInventory(
            cluster="service-demo",
            observed_at=observed - timedelta(seconds=9),
            outcome="done",
            result={
                "version": 24,
                "proxies": [
                    {
                        "name": "api",
                        "protocol": "https",
                        "managed": True,
                        "enabled": True,
                        "hostnames": ["api.demo.example"],
                        "bind_ports": [443],
                        "backend_count": 2,
                    },
                    {
                        "name": "legacy-tcp",
                        "protocol": "tcp",
                        "managed": False,
                        "enabled": True,
                        "hostnames": [],
                        "bind_ports": [8443],
                        "backend_count": 2,
                    },
                ],
            },
            warnings=[],
            error=None,
            poll_error=None,
        ),
    )


def _versions(top: int) -> list[dict[str, Any]]:
    """Five saved versions in the frozen `list` shape, newest first."""

    comments = {
        26: "Raise the API backend to four members",
        25: "Add a maintenance page backend",
        24: "Shorten the health check interval",
        23: "Move the metrics frontend off the shared port",
        22: "Split the internal and public frontends",
        21: "Add the staging backend",
        20: "Initial managed configuration",
    }
    return [
        {
            "version": number,
            "hash": f"{number:040d}",
            "created_at": f"2026-08-{number - 5:02d}T09:1{number % 10}:00+00:00",
            "comment": comments.get(number, f"Change {number}"),
            "current": number == top,
        }
        for number in range(top, top - 5, -1)
    ]


def history_rows(now: datetime | None = None) -> tuple[ClusterHistory, ...]:
    """One cluster fully published, one holding a saved but unpublished change."""

    observed = (now or datetime.now(UTC)) - timedelta(seconds=18)
    return (
        ClusterHistory(
            cluster="edge-demo",
            observed_at=observed,
            outcome="done",
            result={
                "current_version": 24,
                "total_versions": 24,
                "versions": _versions(24),
                "published_version": 24,
                "published_hash": f"{24:040d}",
                "unpublished": 0,
                "truncated": False,
            },
            warnings=[],
            error=None,
            poll_error=None,
        ),
        ClusterHistory(
            cluster="service-demo",
            observed_at=observed - timedelta(seconds=9),
            outcome="done",
            result={
                "current_version": 26,
                "total_versions": 26,
                "versions": _versions(26),
                "published_version": 24,
                "published_hash": f"{24:040d}",
                "unpublished": 2,
                "truncated": False,
            },
            warnings=[],
            error=None,
            poll_error=None,
        ),
    )


def _certificate(
    identifier: str,
    *,
    common_name: str,
    sans: list[str],
    days_left: int,
    lifecycle: str,
    referenced: bool,
    now: datetime,
) -> dict[str, Any]:
    """One catalogue entry in the frozen `cert_list` shape."""

    not_after = now + timedelta(days=days_left)
    return {
        "id": identifier,
        "fingerprint_sha256": sha256(identifier.encode("utf-8")).hexdigest(),
        "common_name": common_name,
        "sans": sans,
        "not_before": (not_after - timedelta(days=90)).isoformat().replace("+00:00", "Z"),
        "not_after": not_after.isoformat().replace("+00:00", "Z"),
        "issuer": "Demo Let's Encrypt" if lifecycle == "acme" else "Demo Internal CA",
        "lifecycle": lifecycle,
        "valid": True,
        "referenced_by_cluster": referenced,
        "deployable": True,
        "validation_error": None,
    }


def certificate_rows(now: datetime | None = None) -> tuple[ClusterCertificates, ...]:
    """Each cluster's listing; the registry is the manager's (B304)."""

    return _catalogue(now)[0]


def manager_certificates(now: datetime | None = None) -> ManagerCertificates:
    """The registry both clusters' certificates come from, read for the manager."""

    _, registry, observed = _catalogue(now)
    return ManagerCertificates(
        observed_at=observed,
        outcome="done",
        result={"interface_served": None, "registry": registry},
        warnings=[],
        error=None,
        poll_error=None,
    )


def _catalogue(
    now: datetime | None,
) -> tuple[tuple[ClusterCertificates, ...], dict[str, Any], datetime]:
    """One healthy catalogue, and one holding a certificate worth renewing.

    Both clusters read the same distribution directory and differ only in what
    they reference, which is what the page has to make readable - and it is also
    what the deduplicated counters across the top exist to keep honest.
    """

    moment = now or datetime.now(UTC)
    observed = moment - timedelta(seconds=18)
    wildcard = _certificate(
        "demo.example.pem",
        common_name="*.demo.example",
        sans=["*.demo.example", "demo.example"],
        days_left=63,
        lifecycle="acme",
        referenced=True,
        now=moment,
    )
    internal = _certificate(
        "internal.demo.example.pem",
        common_name="internal.demo.example",
        sans=["internal.demo.example"],
        days_left=17,
        lifecycle="static",
        referenced=True,
        now=moment,
    )
    retired = _certificate(
        "legacy.demo.example.pem",
        common_name="legacy.demo.example",
        sans=["legacy.demo.example"],
        days_left=-9,
        lifecycle="static",
        referenced=False,
        now=moment,
    )
    #
    # The registry block, as the helper carries it beside the catalogue: the
    # same certificates with a source and targets, and the receivers the
    # receivers page lists (B142). Enough rows to see the list's shape, not
    # a survey of every transport's every state.
    #
    stamp = (moment - timedelta(hours=5)).isoformat().replace("+00:00", "Z")

    def _registered(entry: dict[str, Any], **fields: Any) -> dict[str, Any]:
        return {
            **{
                key: entry[key]
                for key in entry
                if key not in {"referenced_by_cluster", "deployable"}
            },
            "readable": True,
            "measured_at": "distribution",
            "source": {"kind": "acme", "lineage": entry["id"]},
            "targets": {"clusters": [], "receivers": []},
            "distribution": {"published_at": stamp, "current": True},
            **fields,
        }

    receivers = [
        {
            "id": "backup-demo.example",
            "transport": "sftp",
            "layout": "per-certificate",
            "owner": "crx-backup-demo-example",
            "path": "/srv/certdist/receivers/backup-demo.example",
            "allow": [],
            "certificates": ["internal.demo.example.pem"],
        },
        {
            "id": "kiosk-demo.example",
            "transport": "rsync",
            "layout": "per-certificate",
            "owner": "crx-kiosk-demo-example",
            "path": "/srv/certdist/receivers/kiosk-demo.example",
            "allow": [],
            "certificates": [],
        },
        {
            "id": "192.0.2.40",
            "transport": "https",
            "layout": "per-certificate",
            "owner": "www-data",
            "path": "/srv/certdist/receivers/192.0.2.40",
            "allow": ["192.0.2.40/32"],
            "certificates": ["demo.example.pem"],
        },
    ]
    registry = {
        "certificates": [
            _registered(
                wildcard,
                targets={
                    "clusters": ["edge-demo", "service-demo"],
                    "receivers": [
                        {
                            "id": "192.0.2.40",
                            "format": "pem",
                            "published_at": stamp,
                            "current": True,
                        }
                    ],
                },
            ),
            _registered(
                internal,
                source={"kind": "import", "lineage": None},
                targets={
                    "clusters": ["edge-demo", "service-demo"],
                    "receivers": [
                        {
                            "id": "backup-demo.example",
                            "format": "pkcs12",
                            "published_at": stamp,
                            "current": True,
                        }
                    ],
                },
            ),
            _registered(
                retired,
                source={"kind": "import", "lineage": None},
                distribution=None,
            ),
        ],
        "receivers": [row["id"] for row in receivers],
        "manager": "manager.demo.example",
        "receiver_records": receivers,
    }
    rows = (
        ClusterCertificates(
            cluster="edge-demo",
            observed_at=observed,
            outcome="done",
            result={
                "certificates": [wildcard, {**internal, "referenced_by_cluster": False}, retired],
            },
            warnings=[],
            error=None,
            poll_error=None,
        ),
        ClusterCertificates(
            cluster="service-demo",
            observed_at=observed - timedelta(seconds=9),
            outcome="done",
            result={
                "certificates": [
                    internal,
                    {**wildcard, "referenced_by_cluster": False},
                    retired,
                ],
            },
            warnings=[],
            error=None,
            poll_error=None,
        ),
    )
    return rows, registry, observed


def _archives(node_hour: datetime, count: int) -> list[dict[str, Any]]:
    """`count` daily archives, newest first, in the frozen `list_backups` shape."""

    return [
        {
            "version": (node_hour - timedelta(days=day)).strftime("%Y-%m-%d_%H-%M-%S"),
            "created_at": (node_hour - timedelta(days=day) + timedelta(seconds=41))
            .isoformat()
            .replace("+00:00", "Z"),
            "size_bytes": 28672 + day * 96,
            "latest": day == 0,
        }
        for day in range(count)
    ]


def backup_rows(now: datetime | None = None) -> tuple[ClusterBackups, ...]:
    """One cluster backed up on both nodes, and one where a node has fallen behind.

    The second cluster is the state the page exists for: nothing has failed, no
    error is reported, and one node has quietly not taken a backup in five days -
    past the longest gap its Monday, Wednesday and Friday schedule leaves.
    """

    moment = now or datetime.now(UTC)
    observed = moment - timedelta(seconds=18)
    last_run = (moment - timedelta(hours=6)).replace(minute=0, second=0, microsecond=0)
    schedule = {
        "unit": "haprion-state-backup.timer",
        "known": True,
        "enabled": True,
        "active": True,
        "calendar": "Mon,Wed,Fri *-*-* 05:00:00",
        "next_run": (last_run + timedelta(days=1)).isoformat().replace("+00:00", "Z"),
        "last_run": last_run.isoformat().replace("+00:00", "Z"),
        "last_result": "success",
        "scheduled": True,
        "retention": 21,
    }
    return (
        ClusterBackups(
            cluster="edge-demo",
            observed_at=observed,
            outcome="done",
            result={
                "limit": None,
                "schedule": schedule,
                "nodes": [
                    {
                        "name": "edge-a",
                        "available": True,
                        "latest_version": _archives(last_run, 1)[0]["version"],
                        "retained_count": 21,
                        "retained_size_bytes": sum(
                            item["size_bytes"] for item in _archives(last_run, 21)
                        ),
                        "backups": _archives(last_run, 21),
                        "error": None,
                    },
                    {
                        "name": "edge-b",
                        "available": True,
                        "latest_version": _archives(last_run, 1)[0]["version"],
                        "retained_count": 21,
                        "retained_size_bytes": sum(
                            item["size_bytes"] for item in _archives(last_run, 21)
                        ),
                        "backups": _archives(last_run, 21),
                        "error": None,
                    },
                ],
            },
            warnings=[],
            error=None,
            poll_error=None,
        ),
        ClusterBackups(
            cluster="service-demo",
            observed_at=observed - timedelta(seconds=9),
            outcome="done",
            result={
                "limit": 14,
                "schedule": schedule,
                "nodes": [
                    {
                        "name": "service-a",
                        "available": True,
                        "latest_version": _archives(last_run, 1)[0]["version"],
                        "retained_count": 14,
                        "retained_size_bytes": sum(
                            item["size_bytes"] for item in _archives(last_run, 14)
                        ),
                        "backups": _archives(last_run, 14),
                        "error": None,
                    },
                    {
                        "name": "service-b",
                        "available": True,
                        "latest_version": _archives(last_run - timedelta(days=5), 1)[0]["version"],
                        "retained_count": 2,
                        "retained_size_bytes": sum(
                            item["size_bytes"]
                            for item in _archives(last_run - timedelta(days=5), 2)
                        ),
                        "backups": _archives(last_run - timedelta(days=5), 2),
                        "error": None,
                    },
                ],
            },
            warnings=[],
            error=None,
            poll_error=None,
        ),
    )


def settings_rows(now: datetime | None = None) -> tuple[ClusterSettingsRow, ...]:
    """One cluster that sends its log, exposes metrics and shares counters, and one that does none."""

    observed = (now or datetime.now(UTC)) - timedelta(seconds=18)
    return (
        ClusterSettingsRow(
            cluster="edge-demo",
            observed_at=observed,
            outcome="done",
            result={
                "cluster": "edge-demo",
                "head": "a" * 40,
                "stored": True,
                "log_targets": [
                    {
                        "name": "graylog",
                        "address": "192.0.2.60",
                        "port": 6514,
                        "disk_mib": 1024,
                        "tls": False,
                    },
                    {
                        "name": "loki",
                        "address": "2001:db8::60",
                        "port": 6514,
                        "disk_mib": 1024,
                        "tls": True,
                    },
                ],
                "metrics": {"port": 8405, "sources": ["192.0.2.0/24", "198.51.100.7/32"]},
                "peers": {"port": 10000},
            },
            warnings=[],
            error=None,
            poll_error=None,
        ),
        ClusterSettingsRow(
            cluster="service-demo",
            observed_at=observed,
            outcome="done",
            result={
                "cluster": "service-demo",
                "head": "b" * 40,
                "stored": False,
                "log_targets": [],
                "metrics": None,
                "peers": None,
            },
            warnings=[],
            error=None,
            poll_error=None,
        ),
    )


def network_rows(now: datetime | None = None) -> tuple[ClusterNetwork, ...]:
    """One cluster that has moved its description, and one that has not.

    The difference is the whole point of the fixture. `edge-demo` keeps its
    tables in the cluster repository and can therefore be edited from the
    interface; `service-demo` still keeps them in the engine's configuration
    and can only be read. Both states exist in real installations - the second
    is every cluster that predates the move - and the page has to be legible in
    each.
    """

    moment = now or datetime.now(UTC)
    observed = moment - timedelta(seconds=22)
    return (
        ClusterNetwork(
            cluster="edge-demo",
            observed_at=observed,
            outcome="done",
            result={
                "cluster": "edge-demo",
                "head": "a" * 40,
                "origin": "repository",
                "ownership_vip": "192.0.2.20",
                "default_vip": "public",
                "default_vip_object_count": 3,
                "vips": [
                    #
                    # One VIP with a policy and one without, because the page
                    # has to be legible in both states: a description written
                    # before the column existed names none, and the editor has
                    # to show that as missing rather than as an answer.
                    #
                    {"name": "partner", "address": "192.0.2.21", "source": "192.0.2.26"},
                    {
                        "name": "public",
                        "address": "192.0.2.20",
                        "source": "192.0.2.25",
                        "tls": "intermediate",
                    },
                ],
                "sources": [{"name": "outbound", "address": "192.0.2.35"}],
                "groups": [
                    {"name": "office", "members": ["198.51.100.0/24"]},
                    {"name": "vpn", "members": ["203.0.113.0/24", "203.0.113.64/26"]},
                ],
            },
            warnings=[],
            error=None,
            poll_error=None,
        ),
        ClusterNetwork(
            cluster="service-demo",
            observed_at=observed - timedelta(seconds=7),
            outcome="done",
            result={
                "cluster": "service-demo",
                "head": "b" * 40,
                "origin": "cluster_file",
                "ownership_vip": "198.51.100.20",
                "default_vip": "main",
                "default_vip_object_count": 0,
                "vips": [{"name": "main", "address": "198.51.100.20", "source": None}],
                "sources": [],
                "groups": [],
            },
            warnings=[],
            error=None,
            poll_error=None,
        ),
    )


PUBLIC_WEB = """schema: 1
name: public-web
hostnames:
  - app.demo.example
  - www.demo.example
listen:
  protocol: https
  certificate: wildcard-demo-example
  redirect_http: true
routes:
  - path: /
    backend: web
backends:
  web:
    balance: roundrobin
    health:
      type: tcp
    servers:
      - host: 192.0.2.10
        port: 8080
      - host: 192.0.2.11
        port: 8080
      - host: 192.0.2.12
        port: 8080
"""

API = """schema: 1
name: api
hostnames:
  - api.demo.example
listen:
  protocol: https
  certificate: api-demo-example
routes:
  - path: /
    backend: service
backends:
  service:
    balance: leastconn
    health:
      type: tcp
    servers:
      - host: 198.51.100.10
        port: 8443
      - host: 198.51.100.11
        port: 8443
"""

SHOP = """schema: 1
name: shop
hostnames:
  - shop.demo.example
listen:
  protocol: https
  certificate: wildcard-demo-example
routes:
  - path: /
    backend: storefront
backends:
  storefront:
    balance: roundrobin
    health:
      type: tcp
    servers:
      - host: 192.0.2.20
        port: 8080
"""

#
# Deliberately broken, and the most useful entry in the fixture. An object the
# engine cannot read is the one somebody has to open, so the page has to stay
# legible for it - it is listed with the refusal instead of its shape, and the
# document is still there to be read. A fixture without this case would let a
# page ship that renders only objects that parse.
#
HALF_WRITTEN = """schema: 1
name: staging
listen:
  protocol: https
"""


def _engine_fields(cluster: str, entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Each entry with what the objects helper works out from it (B222).

    By the engine's own function against the fixture's network, so the demo
    shows the VIP and source a real helper would report rather than a second
    guess written here.
    """

    reading = next(row for row in network_rows() if row.cluster == cluster)
    result = reading.result
    network = Network(
        vips={
            vip["name"]: Vip(name=vip["name"], address=vip["address"], source=vip.get("source"))
            for vip in result["vips"]
        },
        default_vip=result["default_vip"],
        sources={source["name"]: source["address"] for source in result.get("sources", [])},
        networks={},
    )
    files = {
        f"managed/proxies/{entry['name']}.yaml": entry["document"].encode() for entry in entries
    }
    listed: Any = objects_result(files, "0" * 40, network=network)["objects"]
    computed = {entry["name"]: entry for entry in listed}
    #
    # `runtime_backends` too: the nodes report `public-web`'s pool as `web`
    # (B263's servers), and only the objects say whose pool that is.
    #
    fields = (
        "vip",
        "source",
        "servers",
        "health_checked",
        "runtime_backends",
        "description",
        "groups",
    )
    return [{**entry, **{key: computed[entry["name"]][key] for key in fields}} for entry in entries]


def object_rows(now: datetime | None = None) -> tuple[ClusterObjects, ...]:
    """The objects as written, beside the inventory that shows them published.

    `public-web` and `api` are the managed rows the inventory carries, so the
    two readings describe the same sites; `metrics` and `legacy-tcp` have no
    object, because they are unmanaged and their configuration was not written
    here. That asymmetry is the point - it is what a real cluster looks like
    part-way through the move.
    """

    moment = now or datetime.now(UTC)
    observed = moment - timedelta(seconds=15)
    return (
        ClusterObjects(
            cluster="edge-demo",
            observed_at=observed,
            outcome="done",
            result={
                #
                # The published version's own hash, so the fixture shows an
                # object that has actually reached the nodes.
                #
                "commit": f"{24:040d}",
                "generated_at": observed.isoformat().replace("+00:00", "Z"),
                "objects": _engine_fields(
                    "edge-demo",
                    [
                        {
                            "name": "public-web",
                            "document": PUBLIC_WEB,
                            "readable": True,
                            "problem": None,
                            "protocol": "https",
                            "hostnames": ["app.demo.example", "www.demo.example"],
                        },
                        {
                            #
                            # Written and committed, serving nothing: no published
                            # frontend carries its hostname yet. The common state
                            # of an edit, and the one the overview must not hide.
                            #
                            "name": "shop",
                            "document": SHOP,
                            "readable": True,
                            "problem": None,
                            "protocol": "https",
                            "hostnames": ["shop.demo.example"],
                        },
                        {
                            "name": "staging",
                            "document": HALF_WRITTEN,
                            "readable": False,
                            "problem": "staging.routes is required for an http object",
                            "protocol": None,
                            "hostnames": [],
                        },
                    ],
                ),
            },
            warnings=[],
            error=None,
            poll_error=None,
        ),
        ClusterObjects(
            cluster="service-demo",
            observed_at=observed - timedelta(seconds=6),
            outcome="done",
            result={
                #
                # Committed past the release, which is the other real state: an
                # edit that is saved and versioned but not published yet.
                #
                "commit": f"{26:040d}",
                "generated_at": (observed - timedelta(seconds=6))
                .isoformat()
                .replace("+00:00", "Z"),
                "objects": _engine_fields(
                    "service-demo",
                    [
                        {
                            "name": "api",
                            "document": API,
                            "readable": True,
                            "problem": None,
                            "protocol": "https",
                            "hostnames": ["api.demo.example"],
                        }
                    ],
                ),
            },
            warnings=[],
            error=None,
            poll_error=None,
        ),
    )
