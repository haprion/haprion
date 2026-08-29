"""Explicit synthetic data for visually reviewing the development interface.

This is not a fallback for a failed poll and it never touches the database,
network, Git or runtime configuration.  The deployment must opt in through
``demo_fixture = true`` while declaring no real clusters and keeping management
writes disabled.  Its only job is to make a development browser review useful
before a safe non-production cluster fixture exists.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from haproxy_ui.db import ClusterHistory, ClusterInventory, ClusterStatus

CLUSTERS = ("edge-demo", "service-demo")


def _node(name: str, *, owner: bool, version: int, current: bool) -> dict[str, Any]:
    return {
        "name": name,
        "mgmt_host": f"{name}.demo.example",
        "reachable": True,
        "status_ok": True,
        "current": current,
        "status": {
            "haproxy": {"active": True},
            "keepalived": {"active": True, "state": "MASTER" if owner else "BACKUP"},
            "vip": {"owner": owner},
            "release": {"version": version},
            "config_validation": {"valid": True},
            "stats_ok": True,
            "runtime": {"version": "3.2", "uptime_sec": 272_400},
        },
    }


def status_rows(now: datetime | None = None) -> tuple[ClusterStatus, ...]:
    """Two representative healthy/degraded pairs for the dashboard."""

    observed = (now or datetime.now(UTC)) - timedelta(seconds=18)
    return (
        ClusterStatus(
            cluster="edge-demo",
            observed_at=observed,
            outcome="done",
            result={
                "nodes": [
                    _node("edge-a", owner=True, version=24, current=True),
                    _node("edge-b", owner=False, version=24, current=True),
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
                    _node("service-a", owner=True, version=24, current=True),
                    _node("service-b", owner=False, version=23, current=False),
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
        26: "Raise the API pool to four members",
        25: "Add a maintenance page backend",
        24: "Shorten the health check interval",
        23: "Move the metrics listener off the shared port",
        22: "Split the internal and public frontends",
        21: "Add the staging backend pool",
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
