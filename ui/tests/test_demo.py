from __future__ import annotations

import unittest
from datetime import UTC, datetime, timedelta

from haproxy_ui import demo
from haproxy_ui.dashboard import build_dashboard
from haproxy_ui.history import build_history_overview
from haproxy_ui.proxies import build_proxy_overview

NOW = datetime(2026, 8, 29, 12, 0, tzinfo=UTC)


class DemoFixtureTests(unittest.TestCase):
    def test_it_is_realistic_enough_to_exercise_both_read_only_views(self) -> None:
        dashboard = build_dashboard(
            demo.CLUSTERS, demo.status_rows(NOW), now=NOW, stale_after=timedelta(minutes=2)
        )
        proxies = build_proxy_overview(
            demo.CLUSTERS, demo.inventory_rows(NOW), now=NOW, stale_after=timedelta(minutes=2)
        )
        self.assertEqual(len(dashboard.clusters), 2)
        self.assertEqual(dashboard.attention_clusters, 1)
        self.assertEqual(
            (proxies.proxy_count, proxies.managed_count, proxies.unmanaged_count), (4, 2, 2)
        )

    def test_the_version_fixture_shows_both_a_published_and_a_waiting_cluster(self) -> None:
        #
        # A fixture where every cluster looks the same cannot show that the two
        # states render differently, which is what the browser review is for.
        #
        history = build_history_overview(
            demo.CLUSTERS, demo.history_rows(NOW), now=NOW, stale_after=timedelta(minutes=2)
        )
        tones = [cluster.tone for cluster in history.clusters]

        self.assertEqual(history.cluster_count, 2)
        self.assertEqual(tones, ["healthy", "warning"])
        self.assertEqual(history.waiting_count, 2)
        self.assertTrue(any(version.published for version in history.clusters[0].versions))
