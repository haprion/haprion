from __future__ import annotations

import unittest
from datetime import UTC, datetime, timedelta

from haproxy_ui.db import ClusterInventory
from haproxy_ui.proxies import build_proxy_overview

NOW = datetime(2026, 8, 29, 10, 0, tzinfo=UTC)


def reading(*, age_seconds: int = 15, poll_error: str | None = None) -> ClusterInventory:
    return ClusterInventory(
        cluster="alpha",
        observed_at=NOW - timedelta(seconds=age_seconds),
        outcome="done",
        result={
            "version": 12,
            "proxies": [
                {
                    "name": "app",
                    "protocol": "https",
                    "managed": True,
                    "enabled": True,
                    "hostnames": ["app.example.test"],
                    "bind_ports": [443],
                    "backend_count": 2,
                },
                {
                    "name": "legacy",
                    "protocol": "tcp",
                    "managed": False,
                    "enabled": True,
                    "hostnames": [],
                    "bind_ports": [8443],
                    "backend_count": 1,
                },
            ],
        },
        warnings=[],
        error=None,
        poll_error=poll_error,
    )


class ProxyOverviewTests(unittest.TestCase):
    def test_managed_and_unmanaged_proxies_are_kept_distinct(self) -> None:
        overview = build_proxy_overview(
            ("alpha",), (reading(),), now=NOW, stale_after=timedelta(minutes=2)
        )
        #
        # The overview counts nothing any more: a frontend is not a proxy
        # anybody wrote, and `objects.counted` does the counting from the rows
        # the table draws. What is asserted here is the distinction itself.
        #
        self.assertTrue(overview.clusters[0].proxies[0].managed)
        self.assertFalse(overview.clusters[0].proxies[1].managed)
        self.assertEqual(overview.clusters[0].proxies[0].hostnames, ("app.example.test",))

    def test_an_unavailable_or_stale_cache_is_not_presented_as_current(self) -> None:
        unavailable = build_proxy_overview(
            ("alpha",),
            (reading(poll_error="sudo refused"),),
            now=NOW,
            stale_after=timedelta(minutes=2),
        )
        self.assertEqual(unavailable.clusters[0].label, "Collection unavailable")
        stale = build_proxy_overview(
            ("alpha",), (reading(age_seconds=121),), now=NOW, stale_after=timedelta(minutes=2)
        )
        self.assertEqual(stale.clusters[0].label, "Stale data")

    def test_configured_cluster_without_a_reading_stays_visible(self) -> None:
        overview = build_proxy_overview(("alpha",), (), now=NOW, stale_after=timedelta(minutes=2))
        self.assertEqual(overview.clusters[0].label, "No inventory yet")


if __name__ == "__main__":
    unittest.main()
