from __future__ import annotations

import unittest
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from haproxy_ui import health, proxies
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


class WhatThePoolsAreCalled(unittest.TestCase):
    """The runtime's own names, which is the only name some proxies have.

    Read from the inventory rather than from a stored object, because a proxy
    nobody wrote here has no stored object - and anything that needed one
    silently skipped every unmanaged proxy.
    """

    def view(self, **extra: object) -> proxies.ProxyView:
        view = proxies._proxy_view(
            {
                "name": "public",
                "protocol": "http",
                "managed": False,
                "enabled": True,
                "hostnames": [],
                "bind_ports": [80],
                "backend_count": 2,
                **extra,
            }
        )
        if view is None:
            raise AssertionError("the row was not read as a proxy")
        return view

    def test_the_names_are_carried_as_reported(self) -> None:
        self.assertEqual(
            self.view(backends=["a_backend", "b_backend"]).backends, ("a_backend", "b_backend")
        )

    def test_a_manager_too_old_to_report_them_is_not_a_proxy_without_backends(self) -> None:
        """Empty is "not told"; the count beside it says how many there are."""

        older = self.view()
        self.assertEqual(older.backends, ())
        self.assertEqual(older.backend_count, 2)

    def test_anything_that_is_not_a_name_is_left_out(self) -> None:
        self.assertEqual(self.view(backends=["a_backend", "", 7, None]).backends, ("a_backend",))


if __name__ == "__main__":
    unittest.main()


class TheListingSaysWhenTheNodesAreBehind(unittest.TestCase):
    """Publishing does not deploy, and the listing was the page that never said so.

    A row already says "deploy to add" or "deploy to remove" for an object on
    its way in or out. A *changed* object is neither, so an edit could be
    published and leave the page showing nothing while the nodes went on
    serving the previous version.
    """

    def rows(self, *nodes: object) -> list[object]:
        return [SimpleNamespace(cluster="alpha", result={"nodes": list(nodes)})]

    def test_a_node_that_is_not_current_puts_its_cluster_behind(self) -> None:
        behind = health.clusters_behind(self.rows({"reachable": True, "current": False}))

        self.assertEqual(behind, frozenset({"alpha"}))

    def test_a_current_node_does_not(self) -> None:
        behind = health.clusters_behind(self.rows({"reachable": True, "current": True}))

        self.assertEqual(behind, frozenset())

    def test_a_node_nobody_could_read_is_not_a_claim_that_it_is_up_to_date(self) -> None:
        """Silence is not agreement, so only an explicit false counts."""

        behind = health.clusters_behind(self.rows({"reachable": False, "current": False}))

        self.assertEqual(behind, frozenset())

    def test_a_reading_without_nodes_says_nothing(self) -> None:
        self.assertEqual(
            health.clusters_behind([SimpleNamespace(cluster="alpha", result={})]), frozenset()
        )
