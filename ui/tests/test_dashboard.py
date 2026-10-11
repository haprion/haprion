"""Dashboard semantics: health comes from nodes, never the envelope outcome."""

from __future__ import annotations

import json
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from haprion_ui import dashboard
from haprion_ui.dashboard import DashboardView, build_dashboard, relative_age
from haprion_ui.db import ClusterNetwork, ClusterStatus

FIXTURES = Path(__file__).parents[2] / "fixtures" / "haprion-status" / "valid"
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


class HaproxyVersions(unittest.TestCase):
    """Fas 16 punkt 3b: a node on an older HAProxy is named on its Runtime cell."""

    def view(
        self,
        versions: tuple[str, str],
        validator: str | None,
        packages: tuple[dict[str, str], dict[str, str]] | None = None,
    ) -> Any:
        status = reading("done-single-owner.json")
        result = dict(status.result)
        nodes = [dict(node) for node in result["nodes"]]
        for index, (node, version) in enumerate(zip(nodes, versions, strict=True)):
            node["status"] = dict(node["status"])
            node["status"]["runtime"] = {"version": version, "uptime_sec": 60}
            if packages is not None:
                node["status"]["packages"] = packages[index]
        result["nodes"] = nodes
        result["summary"] = {**result["summary"], "validator_version": validator}
        changed = ClusterStatus(
            cluster=status.cluster,
            observed_at=status.observed_at,
            outcome="done",
            result=result,
            warnings=[],
            error=None,
            poll_error=None,
        )
        cluster = build_dashboard(
            ("alpha",), (changed,), now=NOW, stale_after=timedelta(seconds=120)
        ).clusters[0]
        return [node.runtime_note for node in cluster.nodes], cluster

    def test_one_version_says_nothing_and_leaves_the_cluster_as_it_was(self) -> None:
        notes, cluster = self.view(("3.4.6-1", "3.4.6-1"), "3.4.4-1")
        self.assertEqual(notes, [None, None])
        self.assertEqual(cluster.label, "Healthy")

    def test_the_older_node_is_named(self) -> None:
        notes, _ = self.view(("3.4.6-1", "3.4.4-1"), "3.4.4-1")
        self.assertEqual(notes, [None, "Behind 3.4.6"])

    def test_a_newer_validator_is_named_on_every_node(self) -> None:
        notes, _ = self.view(("3.4.4-1", "3.4.4-1"), "3.4.6-1")
        self.assertEqual(notes, ["Manager validates with 3.4.6"] * 2)

    def test_a_node_patched_a_day_after_its_partner_is_named_per_package(self) -> None:
        """26-10-09: the packages beside HAProxy, in dpkg's order."""

        notes, cluster = self.view(
            ("3.4.6-1", "3.4.6-1"),
            None,
            (
                {"keepalived": "2.3.4-1", "openssl": "3.5.5-1ubuntu3.10"},
                {"keepalived": "2.3.3-1", "openssl": "3.5.5-1ubuntu3.10"},
            ),
        )
        self.assertEqual(notes, [None, "Behind: keepalived"])
        self.assertEqual(cluster.nodes[1].runtime_title, "keepalived behind 2.3.4-1")
        self.assertEqual(cluster.label, "Healthy")


class HealthDerivation(unittest.TestCase):
    def dashboard(self, status: ClusterStatus) -> DashboardView:
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

    def test_the_target_version_is_kept_as_a_number_for_the_deploy_button(self) -> None:
        cluster = self.dashboard(reading("done-single-owner.json")).clusters[0]
        self.assertEqual((cluster.version, cluster.target_version), ("v7", 7))

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

    def engine(self, *, published: bool | None, active: bool) -> Any:
        status = reading("done-single-owner.json")
        result = dict(status.result)
        nodes = [dict(node) for node in result["nodes"]]
        for node in nodes:
            node["status"] = {
                **node["status"],
                "waf_engine": {"version": "0.9.0-4", "active": True},
            }
        nodes[1]["status"]["waf_engine"] = {"version": "0.9.0-4", "active": active}
        result["nodes"] = nodes
        if published is not None:
            result["summary"] = {**result["summary"], "waf_published": published}
        return self.dashboard(
            ClusterStatus(
                cluster=status.cluster,
                observed_at=status.observed_at,
                outcome="done",
                result=result,
                warnings=[],
                error=None,
                poll_error=None,
            )
        ).clusters[0]

    def sharing(self, *peers: Any, uptime: int | None = None) -> Any:
        """The single-owner reading with each node's `peers` replaced (B270)."""

        status = reading("done-single-owner.json")
        result = dict(status.result)
        nodes = [dict(node) for node in result["nodes"]]
        for node, reported in zip(nodes, peers, strict=True):
            node["status"] = {**node["status"], "peers": reported}
            if uptime is not None:
                node["status"]["runtime"] = {
                    **node["status"].get("runtime", {}),
                    "uptime_sec": uptime,
                }
        result["nodes"] = nodes
        return self.dashboard(
            ClusterStatus(
                cluster=status.cluster,
                observed_at=status.observed_at,
                outcome="done",
                result=result,
                warnings=[],
                error=None,
                poll_error=None,
            )
        ).clusters[0]

    def peer(self, name: str, connected: bool) -> dict[str, Any]:
        return {"name": name, "address": "192.0.2.9:10000", "connected": connected}

    def test_counters_shared_both_ways_say_nothing(self) -> None:
        cluster = self.sharing([self.peer("b", True)], [self.peer("a", True)])
        self.assertEqual([node.label for node in cluster.nodes], ["Online", "Online"])

    def test_a_peer_not_connected_is_named_on_the_node_that_misses_it(self) -> None:
        cluster = self.sharing([self.peer("b", False)], [self.peer("a", True)])
        self.assertEqual(
            (cluster.nodes[0].label, cluster.nodes[0].tone), ("Counters not shared", "warning")
        )
        self.assertIn("not reaching b", cluster.nodes[0].detail)
        self.assertEqual(cluster.nodes[1].label, "Online")

    def test_right_after_a_reload_the_peers_are_given_time_to_connect(self) -> None:
        settling = self.sharing([self.peer("b", False)], [self.peer("a", False)], uptime=30)
        settled = self.sharing([self.peer("b", False)], [self.peer("a", False)], uptime=600)

        self.assertEqual([node.label for node in settling.nodes], ["Online", "Online"])
        self.assertEqual(settled.nodes[0].label, "Counters not shared")

    def test_a_node_in_no_peer_line_is_named_where_the_others_share(self) -> None:
        cluster = self.sharing([], [self.peer("a", False)])
        self.assertEqual(cluster.nodes[0].label, "Counters not shared")
        self.assertEqual(cluster.nodes[0].detail, "Shares no counters with the other nodes")

    def test_a_cluster_that_shares_nothing_or_an_older_node_says_nothing(self) -> None:
        cases: tuple[tuple[list[Any] | None, ...], ...] = (([], []), (None, None))
        for peers in cases:
            with self.subTest(peers=peers):
                cluster = self.sharing(*peers)
                self.assertEqual([node.label for node in cluster.nodes], ["Online", "Online"])

    def test_a_stopped_waf_engine_is_named_where_the_release_has_rules(self) -> None:
        # Review 2026-10-04 F3: the node reported it, and nothing showed it.
        cluster = self.engine(published=True, active=False)
        self.assertEqual(
            (cluster.nodes[1].label, cluster.nodes[1].tone), ("WAF engine stopped", "warning")
        )
        self.assertEqual(cluster.nodes[0].label, "Online")
        self.assertEqual(cluster.label, "Degraded")

    def test_a_stopped_waf_engine_is_normal_without_rules_or_without_knowing(self) -> None:
        for published in (False, None):
            with self.subTest(published=published):
                cluster = self.engine(published=published, active=False)
                self.assertEqual(cluster.nodes[1].label, "Online")
                self.assertEqual(cluster.label, "Healthy")

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


class TheFreshnessLine(unittest.TestCase):
    """A card says how long ago its reading was observed."""

    def test_a_live_reading_says_when_it_was_observed(self) -> None:
        now = datetime.now(UTC)

        label = dashboard.observation_label(now - timedelta(minutes=3), now)

        self.assertEqual(label, "Observed 3m ago")


def with_resources(
    status: ClusterStatus, figures: dict[str, tuple[int | None, int]]
) -> ClusterStatus:
    """`figures`: per node name, its CPU share and the memory share in use."""

    result = dict(status.result)
    nodes = []
    for node in result["nodes"]:
        node = dict(node)
        if node["name"] in figures:
            cpu, memory = figures[node["name"]]
            node["cpu_percent"] = cpu
            node["status"] = {
                **node["status"],
                "resources": {
                    "cpu": {"total": 1000, "idle": 500},
                    "memory": {"total_kb": 1000, "available_kb": 1000 - memory * 10},
                    "load": 0.1,
                    "cpus": 1,
                },
            }
        nodes.append(node)
    result["nodes"] = nodes
    return ClusterStatus(
        cluster=status.cluster,
        observed_at=status.observed_at,
        outcome=status.outcome,
        result=result,
        warnings=[],
        error=None,
        poll_error=None,
    )


class NodeResources(unittest.TestCase):
    """The card's CPU and Memory columns (B239)."""

    def cluster(self, status: ClusterStatus) -> Any:
        return build_dashboard(
            ("alpha",), (status,), now=NOW, stale_after=timedelta(seconds=120)
        ).clusters[0]

    def test_the_vip_owners_figure_is_shown_and_every_node_is_in_the_hover(self) -> None:
        cluster = self.cluster(
            with_resources(
                reading("done-single-owner.json"), {"node-b": (12, 41), "node-a": (2, 30)}
            )
        )

        self.assertEqual(cluster.cpu.shown, "12 %")
        self.assertEqual(cluster.memory.shown, "41 %")
        self.assertEqual(cluster.memory.title, "node-a 30 % · node-b 41 %")
        self.assertFalse(cluster.memory.high)

    def test_a_standby_running_high_marks_the_column(self) -> None:
        cluster = self.cluster(
            with_resources(
                reading("done-single-owner.json"), {"node-b": (12, 41), "node-a": (2, 88)}
            )
        )

        self.assertEqual(cluster.memory.shown, "41 %")
        self.assertTrue(cluster.memory.high)
        self.assertFalse(cluster.cpu.high)

    def test_the_first_reading_after_a_gap_shows_a_dash_for_cpu(self) -> None:
        cluster = self.cluster(
            with_resources(
                reading("done-single-owner.json"), {"node-b": (None, 41), "node-a": (None, 30)}
            )
        )

        self.assertEqual(cluster.cpu.shown, "–")
        self.assertEqual(cluster.memory.shown, "41 %")

    def test_nodes_from_before_leave_the_columns_out(self) -> None:
        cluster = self.cluster(reading("done-single-owner.json"))

        self.assertIsNone(cluster.cpu)
        self.assertIsNone(cluster.memory)
