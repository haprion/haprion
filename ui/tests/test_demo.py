from __future__ import annotations

import unittest
from datetime import UTC, datetime, timedelta

from haproxy_ui import demo
from haproxy_ui.backups import build_backup_overview
from haproxy_ui.certificates import build_certificate_overview
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

    def test_the_certificate_fixture_shows_a_renewal_and_a_certificate_nobody_serves(self) -> None:
        #
        # The page has two jobs a browser review has to be able to see: it must
        # single out the certificate that needs renewing, and it must list the
        # ones sitting in the distribution directory without colouring a card
        # for them.
        #
        certificates = build_certificate_overview(
            demo.CLUSTERS, demo.certificate_rows(NOW), now=NOW, stale_after=timedelta(minutes=2)
        )
        tones = [cluster.tone for cluster in certificates.clusters]

        # One wildcard, one internal certificate and one retired one, each read
        # by both clusters and therefore counted once.
        self.assertEqual(certificates.certificate_count, 3)
        self.assertEqual(certificates.acme_count, 1)
        self.assertEqual(tones, ["healthy", "warning"])
        self.assertTrue(
            any(
                not entry.referenced
                for cluster in certificates.clusters
                for entry in cluster.certificates
            )
        )

    def test_the_backup_fixture_shows_a_node_that_has_quietly_fallen_behind(self) -> None:
        #
        # Nothing has failed in the second cluster: no error, no unreachable
        # node, and one node has not taken a backup in three days. A fixture
        # where every node looks the same cannot show that this renders
        # differently, which is what the browser review is for.
        #
        backups = build_backup_overview(
            demo.CLUSTERS, demo.backup_rows(NOW), now=NOW, stale_after=timedelta(minutes=2)
        )
        tones = [cluster.tone for cluster in backups.clusters]

        self.assertEqual(tones, ["healthy", "warning"])
        self.assertEqual((backups.node_count, backups.protected_count), (4, 3))
        self.assertTrue(backups.clusters[0].archives)
