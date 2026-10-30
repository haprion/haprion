"""Dashboard semantics: health comes from nodes, never the envelope outcome."""

from __future__ import annotations

import json
import unittest
from dataclasses import replace
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
        self.assertEqual(notes, [None, "Older than 3.4.6"])

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
        self.assertEqual(notes, [None, "Older package: keepalived"])
        self.assertEqual(cluster.nodes[1].runtime_title, "keepalived older than 2.3.4-1")
        self.assertEqual(cluster.label, "Healthy")


class NodePackage(unittest.TestCase):
    """26-10-29: a node's haprion-node, read against the one the manager's release carries."""

    CARRIED = "0.99.6+git20261029120000.0123abcd4567"
    OLDER = "0.99.5+git20261028210223.49d2aeb20207"

    def nodes(self, installations: tuple[object, object], carried: object = CARRIED) -> Any:
        status = reading("done-single-owner.json")
        result = dict(status.result)
        nodes = [dict(node) for node in result["nodes"]]
        for node, installation in zip(nodes, installations, strict=True):
            node["status"] = {
                key: value for key, value in node["status"].items() if key != "installation"
            }
            if installation is not None:
                node["status"]["installation"] = installation
        result["nodes"] = nodes
        result["summary"] = {**result["summary"], "node_package_version": carried}
        return build_dashboard(
            ("alpha",), (replace(status, result=result),), now=NOW, stale_after=timedelta(120)
        ).clusters[0]

    @staticmethod
    def installed(version: str | None) -> dict[str, object]:
        return {"node_api": 1, "scripts_current": True, "scripts": {}, "version": version}

    def test_the_same_package_says_nothing_and_an_older_one_is_named(self) -> None:
        cluster = self.nodes((self.installed(self.CARRIED), self.installed(self.OLDER)))
        current, older = cluster.nodes
        self.assertIsNone(current.package_note)
        self.assertIsNone(current.package_message)
        self.assertEqual(older.package_note, "Older node package")
        self.assertEqual(
            older.package_message,
            "haprion-node 0.99.5 (49d2aeb2) is installed; the manager's is 0.99.6 (0123abcd)"
            " - run sudo apt upgrade on the node",
        )
        self.assertEqual(cluster.label, "Healthy")

    def test_a_node_reporting_no_version_runs_an_older_package(self) -> None:
        cluster = self.nodes(({"node_api": 1, "scripts_current": True, "scripts": {}}, None))
        for node in cluster.nodes:
            self.assertEqual(node.package_note, "Older node package")
            self.assertEqual(
                node.package_message,
                "haprion-node is older than the manager's 0.99.6 (0123abcd) - run sudo apt upgrade on the node",
            )

    def test_a_package_the_node_did_not_configure_is_named_before_its_version(self) -> None:
        """Review 26-10-29, A06: the same version, a postinst that failed, and nothing said."""

        unconfigured = {**self.installed(self.CARRIED), "configured": False}
        node = self.nodes((unconfigured, self.installed(self.CARRIED))).nodes[0]
        self.assertEqual(node.package_note, "Node package not configured")
        self.assertEqual(
            node.package_message,
            "haprion-node 0.99.6 (0123abcd) is installed but not configured - run sudo dpkg "
            "--configure -a on the node, or, if dpkg leaves it unconfigured, sudo apt install "
            "--reinstall haprion-node",
        )

    def test_an_older_package_says_what_to_run_on_the_node(self) -> None:
        """Review 2026-10-30, E8: the status command names the action; so does the row."""

        older = "0.99.5+git20261028210223.49d2aeb20207"
        node = self.nodes((self.installed(older), self.installed(self.CARRIED))).nodes[0]
        self.assertIn("run sudo apt upgrade on the node", node.package_message or "")

    def test_a_newer_package_is_named_as_newer(self) -> None:
        newer = "0.99.7+git20261101090000.89abcdef0123"
        node = self.nodes((self.installed(newer), self.installed(self.CARRIED))).nodes[0]
        self.assertEqual(node.package_note, "Newer node package")
        self.assertEqual(
            node.package_message,
            "haprion-node 0.99.7 (89abcdef) is installed, newer than the manager's 0.99.6 (0123abcd)",
        )

    def test_nothing_is_said_without_a_carried_package_or_an_installed_one(self) -> None:
        for installations, carried in (
            ((self.installed(self.OLDER), None), None),
            ((self.installed(None), self.installed(None)), self.CARRIED),
        ):
            with self.subTest(carried=carried):
                cluster = self.nodes(installations, carried)
                self.assertEqual([node.package_note for node in cluster.nodes], [None, None])


class HealthDerivation(unittest.TestCase):
    def dashboard(self, status: ClusterStatus) -> DashboardView:
        return build_dashboard(("alpha",), (status,), now=NOW, stale_after=timedelta(seconds=120))

    def test_a_node_reports_whether_its_step_four_is_the_package_s(self) -> None:
        """B363: `preparation` from the node's status; an older node says nothing."""

        status = reading("done-single-owner.json")
        for reported, pending in (
            ({"current": False}, True),
            ({"current": True}, False),
            (None, False),
        ):
            with self.subTest(reported=reported):
                result = dict(status.result)
                nodes = [dict(node) for node in result["nodes"]]
                nodes[0]["status"] = dict(nodes[0]["status"])
                if reported is not None:
                    nodes[0]["status"]["preparation"] = reported
                result["nodes"] = nodes
                view = self.dashboard(replace(status, result=result))
                self.assertEqual(view.clusters[0].nodes[0].prepare_pending, pending)
                self.assertFalse(view.clusters[0].nodes[1].prepare_pending)

    def test_a_joining_node_whose_command_fails_is_joining_not_invalid(self) -> None:
        """Review 26-10-30, R2: step 4 has no sudo in place yet, so the command exits 1."""

        status = reading("done-single-owner.json")
        nodes = [dict(node) for node in status.result["nodes"]]
        nodes[0] = {
            **nodes[0],
            "reachable": True,
            "status_ok": False,
            "status": None,
            "joining": True,
            "error": {
                "code": "node_status_invalid",
                "message": "the status command failed on the node (exit 1): sudo: a password",
                "node": nodes[0]["name"],
                "details": None,
            },
        }
        view = self.dashboard(replace(status, result={**status.result, "nodes": nodes}))
        shown = view.clusters[0].nodes[0]
        self.assertEqual((shown.label, shown.tone), ("Joining", "unknown"))

    def test_a_node_whose_status_command_failed_shows_what_failed(self) -> None:
        """Review 2026-10-30, E3."""

        status = reading("done-single-owner.json")
        nodes = [dict(node) for node in status.result["nodes"]]
        nodes[0] = {
            **nodes[0],
            "reachable": True,
            "status_ok": False,
            "status": None,
            "error": {
                "code": "node_status_invalid",
                "message": "the status command failed on the node (exit 1): ERROR: no cluster",
                "node": nodes[0]["name"],
                "details": None,
            },
        }
        view = self.dashboard(replace(status, result={**status.result, "nodes": nodes}))
        shown = view.clusters[0].nodes[0]
        self.assertEqual(shown.label, "Invalid status")
        self.assertEqual(shown.detail, "The status command failed on the node")
        self.assertIn("exit 1", shown.reason or "")

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

    def test_a_node_without_keepalived_conf_is_not_configured_rather_than_faulty(self) -> None:
        # B313: before the product's first deploy there is nothing to have failed.
        status = reading("done-single-owner.json")
        result = dict(status.result)
        nodes = [dict(node) for node in result["nodes"]]
        nodes[0]["status"] = dict(nodes[0]["status"])
        nodes[0]["status"]["keepalived"] = {"active": False, "state": None, "configured": "missing"}
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
        self.assertEqual(cluster.nodes[0].label, "Keepalived not configured")
        self.assertEqual(cluster.nodes[0].tone, "warning")

    def test_a_cluster_never_deployed_is_not_deployed_and_raises_nothing(self) -> None:
        """Finding 52: before the first deploy nothing has failed; there is nothing yet."""

        from haprion_ui import attention

        status = reading("done-single-owner.json")
        result = dict(status.result)
        nodes = []
        for node in result["nodes"]:
            node = dict(node)
            node["status"] = {
                **node["status"],
                "keepalived": {"active": False, "state": None, "configured": "missing"},
                "release": {"version": None, "hash": None, "timestamp": None, "cluster": None},
                "stats_ok": False,
                "runtime": {"version": None, "uptime_sec": None},
            }
            nodes.append(node)
        result["nodes"] = nodes
        result["summary"] = {**result["summary"], "vip_state": "no_owner", "vip_owners": []}
        undeployed = ClusterStatus(
            cluster=status.cluster,
            observed_at=status.observed_at,
            outcome=status.outcome,
            result=result,
            warnings=status.warnings,
            error=status.error,
            poll_error=None,
        )
        view = self.dashboard(undeployed)
        cluster = view.clusters[0]
        self.assertEqual([node.label for node in cluster.nodes], ["Not deployed"] * len(nodes))
        # The nodes page reads the same rule (Fas 18, finding 69).
        self.assertTrue(dashboard.not_deployed(undeployed))
        self.assertFalse(dashboard.not_deployed(status))
        self.assertFalse(dashboard.not_deployed(None))
        self.assertEqual((cluster.label, cluster.tone), ("Not deployed", "unknown"))
        self.assertEqual(cluster.vip, "None")
        #
        # Said once: no failover state, address, runtime or statistics to
        # report before a first release (Fas 18, finding 61).
        #
        for node in cluster.nodes:
            self.assertEqual(
                (node.detail, node.keepalived, node.vip, node.version, node.runtime, node.stats),
                ("", "", "", "—", "", ""),
            )
        self.assertEqual(view.online_nodes, len(nodes))
        self.assertEqual(attention.from_dashboard(view.clusters, drift_label="Behind"), [])

    def test_a_new_node_in_a_deployed_cluster_is_not_deployed_not_a_fault(self) -> None:
        status = reading("done-single-owner.json")
        result = dict(status.result)
        nodes = [dict(node) for node in result["nodes"]]
        nodes[1]["status"] = {
            **nodes[1]["status"],
            "keepalived": {"active": False, "state": None, "configured": "missing"},
            "release": {"version": None, "hash": None, "timestamp": None, "cluster": None},
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
        self.assertEqual(
            (cluster.nodes[1].label, cluster.nodes[1].tone), ("Not deployed", "unknown")
        )
        self.assertNotEqual(cluster.label, "Not deployed")
        self.assertFalse(dashboard.not_deployed(replace(status, result=result)))

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

    def test_a_node_that_has_not_answered_yet_is_joining_not_an_error(self) -> None:
        """B329: the poller marks it; no red, no failed connection."""

        status = reading("partial-unreachable.json")
        nodes = [dict(entry) for entry in status.result["nodes"]]
        nodes[1]["joining"] = True
        joining = self.dashboard(replace(status, result={**status.result, "nodes": nodes}))
        node = joining.clusters[0].nodes[1]
        self.assertEqual((node.label, node.tone), ("Joining", "unknown"))
        self.assertNotIn("connection failed", node.detail)
        # Review 26-10-22, 1B-7: out of the nodes card's figures until it answers.
        self.assertEqual((joining.online_nodes, joining.total_nodes), (1, 1))
        self.assertEqual(joining.node_tone, "healthy")

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
        self.assertEqual(cluster.label, "Behind")
        self.assertEqual(cluster.nodes[1].label, "Behind")
        self.assertEqual(cluster.version, "v7")

    def test_a_node_on_the_target_with_a_file_behind_says_which(self) -> None:
        """Review 26-10-13 r16k, F1: not "not on the target release" about a node that is."""

        target = "c3" * 20
        node = {
            "name": "node-b",
            "mgmt_host": "node-b.example.com",
            "reachable": True,
            "status_ok": True,
            "current": False,
            "status": {
                "haproxy": {"active": True},
                "keepalived": {"active": True, "state": "BACKUP"},
                "vip": {"owner": False},
                "release": {"version": "8", "hash": target},
                "runtime": {"version": "3.4.6", "uptime_sec": 10},
                "config_validation": {"valid": True},
                "stats_ok": True,
                "forward_file": {
                    "published": True,
                    "published_sha256": "a1" * 32,
                    "installed": True,
                    "installed_sha256": "b2" * 32,
                },
            },
        }

        on_target = dashboard._node_view(node, target)
        self.assertEqual(on_target.label, "Behind")
        self.assertEqual(on_target.detail, "The log forwarding is older than the published version")
        self.assertFalse(on_target.release_behind)

        behind = dashboard._node_view(node, "d4" * 20)
        self.assertEqual(behind.detail, "Node is not on the published version")
        self.assertTrue(behind.release_behind)

    def test_a_node_whose_steps_after_the_reload_failed_says_so(self) -> None:
        """Review 26-10-30, D1: keepalived.conf has no field of its own."""

        target = "c3" * 20
        node = {
            "name": "node-b",
            "mgmt_host": "node-b.example.com",
            "reachable": True,
            "status_ok": True,
            "current": False,
            "status": {
                "haproxy": {"active": True},
                "keepalived": {"active": True, "state": "BACKUP"},
                "vip": {"owner": False},
                "release": {"version": "8", "hash": target, "complete": False},
                "runtime": {"version": "3.4.6", "uptime_sec": 10},
                "config_validation": {"valid": True},
                "stats_ok": True,
            },
        }
        view = dashboard._node_view(node, target)
        self.assertEqual(view.label, "Behind")
        self.assertEqual(view.detail, "A step after the reload did not finish")
        self.assertFalse(view.release_behind)

    def test_a_node_past_the_published_version_needs_attention(self) -> None:
        """R2 26-10-27 (F18): *Behind* for nodes on a version the manager had no record of."""

        node = {
            "name": "node-b",
            "mgmt_host": "node-b.example.com",
            "reachable": True,
            "status_ok": True,
            "current": False,
            "status": {
                "haproxy": {"active": True},
                "keepalived": {"active": True, "state": "BACKUP"},
                "vip": {"owner": False},
                "release": {"version": 13, "hash": "d4" * 20},
                "runtime": {"version": "3.4.6", "uptime_sec": 10},
                "config_validation": {"valid": True},
                "stats_ok": True,
            },
        }
        ahead = dashboard._node_view(node, "c3" * 20, 12)
        self.assertEqual((ahead.label, ahead.tone), ("Unknown version", "critical"))
        self.assertEqual(
            ahead.detail,
            "Runs version 13, which this manager has no record of, as after a restore of the"
            " manager from older state. A deploy puts version 12 on it",
        )
        behind = dashboard._node_view(node, "c3" * 20, 14)
        self.assertEqual(behind.label, "Behind")

    def test_old_data_cannot_remain_green(self) -> None:
        cluster = self.dashboard(reading("done-single-owner.json", age_seconds=121)).clusters[0]
        self.assertTrue(cluster.stale)
        self.assertEqual(cluster.label, "Stale data")
        self.assertEqual(cluster.tone, "warning")

    def test_old_data_does_not_say_all_is_reporting(self) -> None:
        """Review 26-10-24, 04-06: the card said "All reporting" in green and the
        nodes "Serving and reporting normally" beside the cluster's "Stale data"."""

        view = self.dashboard(reading("done-single-owner.json", age_seconds=121))
        fresh = self.dashboard(reading("done-single-owner.json"))
        self.assertEqual((view.stale_clusters, view.node_tone), (1, "warning"))
        self.assertEqual((fresh.stale_clusters, fresh.node_tone), (0, "healthy"))
        online = [node for node in view.clusters[0].nodes if node.label == "Online"]
        self.assertTrue(online)
        self.assertEqual({node.detail for node in online}, {"Last read 2m ago"})
        self.assertIn(
            "Serving and reporting normally", {node.detail for node in fresh.clusters[0].nodes}
        )

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

    def test_each_summary_card_s_icon_says_its_state(self) -> None:
        """B343: the icons were decoration - a red release card on an installation in order."""

        def tones(*names: str) -> tuple[str, str, str, str]:
            readings = tuple(
                replace(reading(name), cluster=cluster)
                for name, cluster in zip(names, ("alpha", "beta"), strict=False)
            )
            view = build_dashboard(
                tuple(r.cluster for r in readings),
                readings,
                now=NOW,
                stale_after=timedelta(seconds=120),
            )
            return (view.cluster_tone, view.node_tone, view.vip_tone, view.release_tone)

        self.assertEqual(tones(), ("unknown",) * 4)
        self.assertEqual(tones("done-single-owner.json"), ("healthy",) * 4)
        self.assertEqual(
            tones("done-single-owner.json", "partial-unreachable.json"),
            ("critical", "critical", "warning", "warning"),
        )
        behind = tones("done-node-behind.json")
        self.assertEqual((behind[0], behind[3]), ("warning", "warning"))

    def test_the_vip_owner_is_a_node_or_words_never_a_status_code(self) -> None:
        """B335: `no_owner` and `split_brain` were shown as they are spelt in the contract."""

        self.assertEqual(dashboard._vip_words("no_owner", 0), "None")
        self.assertEqual(dashboard._vip_words("split_brain", 2), "Split brain (2 nodes)")
        self.assertEqual(dashboard._vip_words("incomplete", 1), "Not every node read")
        self.assertEqual(dashboard._vip_words("something_new", 0), "Unknown")

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


class ThePageLooksForTheNextReading(unittest.TestCase):
    """Fas 18, 26-10-16: a redraw every interval came ~17 s after the reading it showed."""

    def rows(self, *ages: int) -> list[ClusterStatus]:
        status = reading("done-single-owner.json")
        return [replace(status, observed_at=NOW - timedelta(seconds=age)) for age in ages]

    def test_the_redraw_comes_just_after_the_next_reading_is_due(self) -> None:
        self.assertEqual(dashboard.next_reading(self.rows(17), 20, NOW), 5.0)
        self.assertEqual(dashboard.next_reading(self.rows(0), 20, NOW), 22.0)
        # The newest reading decides: one pass writes every cluster.
        self.assertEqual(dashboard.next_reading(self.rows(30, 5), 20, NOW), 17.0)

    def test_a_late_reading_is_asked_after_soon_and_a_stopped_poller_is_not(self) -> None:
        self.assertEqual(dashboard.next_reading(self.rows(25), 20, NOW), dashboard.READING_RETRY)
        self.assertIsNone(dashboard.next_reading(self.rows(41), 20, NOW))
        self.assertIsNone(dashboard.next_reading([], 20, NOW))
