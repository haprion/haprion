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
                ("service-demo", "Degraded"),
                ("service-demo", "service-a"),
                ("service-demo", "service-b"),
            ],
        )


if __name__ == "__main__":
    unittest.main()
