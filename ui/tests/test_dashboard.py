"""Dashboard semantics: health comes from nodes, never the envelope outcome."""

from __future__ import annotations

import json
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from haproxy_ui import dashboard
from haproxy_ui.dashboard import build_dashboard, relative_age
from haproxy_ui.db import ClusterNetwork, ClusterStatus

FIXTURES = Path(__file__).parents[2] / "fixtures" / "haproxy-status" / "valid"
NOW = datetime(2026, 8, 28, 12, 0, tzinfo=UTC)


def reading(name: str, *, age_seconds: int = 15, poll_error: str | None = None) -> ClusterStatus:
    envelope: dict[str, Any] = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    return ClusterStatus(
        cluster=str(envelope.get("cluster") or "alpha"),
        observed_at=NOW - timedelta(seconds=age_seconds),
        outcome=str(envelope["outcome"]),
        result=envelope.get("result") or {},
        warnings=envelope.get("warnings") or [],
        error=envelope.get("error"),
        poll_error=poll_error,
    )


class HealthDerivation(unittest.TestCase):
    def dashboard(self, status: ClusterStatus):
        return build_dashboard(("alpha",), (status,), now=NOW, stale_after=timedelta(seconds=120))

    def test_done_and_converged_is_only_green_when_node_services_are_healthy(self) -> None:
        status = reading("done-single-owner.json")
        result = dict(status.result)
        nodes = [dict(node) for node in result["nodes"]]
        nodes[0]["status"] = dict(nodes[0]["status"])
        nodes[0]["status"]["haproxy"] = {"active": False}
        result["nodes"] = nodes
        dashboard = self.dashboard(
            ClusterStatus(
                cluster=status.cluster,
                observed_at=status.observed_at,
                outcome="done",
                result=result,
                warnings=[],
                error=None,
                poll_error=None,
            )
        )

        cluster = dashboard.clusters[0]
        self.assertEqual(cluster.tone, "critical")
        self.assertEqual(cluster.nodes[0].label, "HAProxy stopped")
        self.assertNotEqual(cluster.label, "Healthy")

    def test_a_stopped_keepalived_reads_stopped_not_its_last_state(self) -> None:
        """The state file outlives keepalived: a stopped owner still read MASTER."""

        status = reading("done-single-owner.json")
        result = dict(status.result)
        nodes = [dict(node) for node in result["nodes"]]
        nodes[0]["status"] = dict(nodes[0]["status"])
        nodes[0]["status"]["keepalived"] = {
            **nodes[0]["status"]["keepalived"],
            "active": False,
            "state": "MASTER",
        }
        result["nodes"] = nodes
        cluster = self.dashboard(
            ClusterStatus(
                cluster=status.cluster,
                observed_at=status.observed_at,
                outcome=status.outcome,
                result=result,
                warnings=status.warnings,
                error=status.error,
                poll_error=None,
            )
        ).clusters[0]
        self.assertEqual(cluster.nodes[0].keepalived, "STOPPED")
        self.assertEqual(cluster.nodes[0].label, "Keepalived fault")

    def test_stats_failure_is_distinct_from_an_unreachable_node(self) -> None:
        status = reading("done-single-owner.json")
        result = dict(status.result)
        nodes = [dict(node) for node in result["nodes"]]
        nodes[0]["status"] = dict(nodes[0]["status"])
        nodes[0]["status"]["stats_ok"] = False
        result["nodes"] = nodes
        cluster = self.dashboard(
            ClusterStatus(
                cluster=status.cluster,
                observed_at=status.observed_at,
                outcome=status.outcome,
                result=result,
                warnings=status.warnings,
                error=status.error,
                poll_error=None,
            )
        ).clusters[0]

        self.assertEqual(cluster.label, "Degraded")
        self.assertEqual(cluster.nodes[0].label, "Stats unavailable")
        self.assertEqual(cluster.nodes[0].tone, "warning")

        unreachable = self.dashboard(reading("partial-unreachable.json")).clusters[0]
        self.assertEqual(unreachable.nodes[1].label, "Unreachable")
        self.assertEqual(unreachable.nodes[1].tone, "critical")

    def test_version_drift_is_visible_without_calling_the_cluster_unhealthy(self) -> None:
        """Named for what it is, rather than as a fault.

        A node that has not been deployed to yet is behind, not degraded: the
        first says a deploy is outstanding and the second says the cluster is
        serving worse than it should. They lead an operator to different places.
        """

        cluster = self.dashboard(reading("done-node-behind.json")).clusters[0]
        self.assertEqual(cluster.label, "Not on the latest version")
        self.assertEqual(cluster.nodes[1].label, "Version drift")
        self.assertEqual(cluster.version, "v7")

    def test_old_data_cannot_remain_green(self) -> None:
        cluster = self.dashboard(reading("done-single-owner.json", age_seconds=121)).clusters[0]
        self.assertTrue(cluster.stale)
        self.assertEqual(cluster.label, "Stale data")
        self.assertEqual(cluster.tone, "warning")

    def test_a_poller_failure_is_not_reported_as_a_cluster_answer(self) -> None:
        cluster = self.dashboard(
            reading("done-single-owner.json", poll_error="sudo refused")
        ).clusters[0]
        self.assertEqual(cluster.label, "Collection unavailable")
        self.assertEqual(cluster.tone, "critical")


class DashboardShape(unittest.TestCase):
    def test_configured_cluster_without_a_row_is_kept_visible(self) -> None:
        dashboard = build_dashboard(("alpha",), (), now=NOW, stale_after=timedelta(seconds=120))
        self.assertEqual(len(dashboard.clusters), 1)
        self.assertEqual(dashboard.clusters[0].label, "No data")

    def test_a_removed_cluster_row_stays_visible_but_not_counted(self) -> None:
        orphan = reading("done-single-owner.json")
        orphan = ClusterStatus(
            cluster="beta",
            observed_at=orphan.observed_at,
            outcome=orphan.outcome,
            result=orphan.result,
            warnings=orphan.warnings,
            error=orphan.error,
            poll_error=orphan.poll_error,
        )
        dashboard = build_dashboard(
            ("alpha",), (orphan,), now=NOW, stale_after=timedelta(seconds=120)
        )
        self.assertEqual([cluster.cluster for cluster in dashboard.clusters], ["alpha", "beta"])
        self.assertFalse(dashboard.clusters[1].configured)
        self.assertEqual(dashboard.clusters[1].label, "Not configured")
        self.assertEqual(dashboard.healthy_clusters, 0)

    def test_active_vips_counts_addresses_not_clusters(self) -> None:
        #
        # Seen on the maintainer's dashboard 2026-09-20: two clusters, three
        # VIPs, a card saying 2. A cluster's VRRP instance carries every VIP
        # in its network description as one address list, so the status
        # helper's single owner answers for all of them and the count is
        # the description's.
        #
        alpha = reading("done-single-owner.json")
        beta = reading("partial-unreachable.json")
        beta = ClusterStatus(
            cluster="beta",
            observed_at=beta.observed_at,
            outcome=beta.outcome,
            result=beta.result,
            warnings=beta.warnings,
            error=beta.error,
            poll_error=beta.poll_error,
        )

        def network(cluster: str, *names: str) -> ClusterNetwork:
            return ClusterNetwork(
                cluster=cluster,
                observed_at=NOW,
                outcome="done",
                result={"vips": [{"name": name, "address": "192.0.2.1"} for name in names]},
                warnings=[],
                error=None,
                poll_error=None,
            )

        view = build_dashboard(
            ("alpha", "beta"),
            (alpha, beta),
            now=NOW,
            stale_after=timedelta(seconds=120),
            network_readings=(network("alpha", "vip-a", "vip-a2"), network("beta", "vip-b")),
        )
        # alpha's two addresses have a single owner; beta's one is `incomplete`.
        self.assertEqual((view.active_vips, view.total_vips), (2, 3))

        # Without a network description a cluster counts its status VIP, and
        # nothing more, so an older cache never makes the card say 0.
        bare = build_dashboard(
            ("alpha", "beta"), (alpha, beta), now=NOW, stale_after=timedelta(seconds=120)
        )
        self.assertEqual((bare.active_vips, bare.total_vips), (1, 2))

    def test_relative_age_is_compact_and_never_negative(self) -> None:
        self.assertEqual(relative_age(NOW - timedelta(seconds=4), NOW), "Just now")
        self.assertEqual(relative_age(NOW - timedelta(minutes=4), NOW), "4m ago")
        self.assertEqual(relative_age(NOW + timedelta(minutes=1), NOW), "Just now")


if __name__ == "__main__":
    unittest.main()


class TheFreshnessLineDoesNotClaimTheWallClock(unittest.TestCase):
    """A snapshot's readings are judged against its capture, and say so.

    Judging them against the capture is right and argued for in
    `views.read_source`: measured against the wall clock every cluster in a
    snapshot is stale forever, and a warning that is always lit stops being
    read. But the label followed the clock into saying "Observed just now" about
    data that was two days old, one line above a badge stating its true age.
    Found by the code review on 2026-08-31 as F6.
    """

    def test_a_live_reading_says_when_it_was_observed(self) -> None:
        now = datetime.now(UTC)

        label = dashboard.observation_label(now - timedelta(minutes=3), now, captured=False)

        self.assertEqual(label, "Observed 3m ago")

    def test_a_captured_reading_says_it_was_current_when_taken(self) -> None:
        captured_at = datetime.now(UTC) - timedelta(hours=42)

        label = dashboard.observation_label(captured_at, captured_at, captured=True)

        self.assertEqual(label, "Current at capture")
        #
        # The relative age is the snapshot's, not the cluster's, and the badge
        # states it once. Repeating it per cluster is what made the page
        # contradict itself.
        #
        self.assertNotIn("ago", label)
