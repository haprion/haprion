from __future__ import annotations

import unittest
from datetime import timedelta

from haproxy_ui import activity, dashboard, demo


class ActivityTests(unittest.TestCase):
    def test_latest_cluster_and_node_observations_are_flattened_in_order(self) -> None:
        current = dashboard.build_dashboard(
            demo.CLUSTERS,
            demo.status_rows(),
            stale_after=timedelta(minutes=5),
        )
        entries = activity.build_activity(current)
        self.assertEqual(
            [(entry.cluster, entry.subject) for entry in entries],
            [
                ("edge-demo", "Healthy"),
                ("edge-demo", "edge-a"),
                ("edge-demo", "edge-b"),
                ("service-demo", "Not on the latest version"),
                ("service-demo", "service-a"),
                ("service-demo", "service-b"),
            ],
        )

    def test_the_counters_are_the_feed_counted(self) -> None:
        current = dashboard.build_dashboard(
            demo.CLUSTERS,
            demo.status_rows(),
            stale_after=timedelta(minutes=5),
        )
        entries = activity.build_activity(current)
        summary = activity.summarise_activity(entries)
        self.assertEqual(summary.observation_count, len(entries))
        self.assertEqual(summary.cluster_count, len(current.clusters))
        self.assertEqual(
            summary.attention_count,
            sum(entry.tone != "healthy" for entry in entries),
        )
        # The demo fixture carries a degraded cluster on purpose, so a zero here
        # would mean the counter is not looking at the tones at all.
        self.assertGreater(summary.attention_count, 0)


if __name__ == "__main__":
    unittest.main()
