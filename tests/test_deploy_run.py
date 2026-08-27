"""The whole deploy path driven against the harness, end to end.

Not the matrix again - that is tested directly in test_deploy_plan. What is
tested here is that the three pieces agree: the status envelope is parsed the
way the helper writes it, the decision is taken on what came back, and the loop
re-reads after every mutation instead of trusting what it decided earlier.

Every case below is a state the production pair cannot be put into.
"""

from __future__ import annotations

import io
import unittest

from haproxy_mgmt import deploy_run
from haproxy_mgmt.cluster_status import NodeStatus, parse_status
from haproxy_mgmt.deploy_plan import ReleaseTarget
from haproxy_mgmt.deploy_run import DeployReport
from tests.node_harness import OLD_HASH, TARGET_HASH, FakeCluster, FakeNode, pair

TARGET = ReleaseTarget(version=8, hash=TARGET_HASH)

LAST_REPORT: list[DeployReport] = []


def deploy(
    cluster: FakeCluster,
    *,
    expected_hash: str | None = None,
    allow_vip_unknown: bool = False,
) -> tuple[int, str]:
    """Run one deploy. The report is kept aside for the cases that inspect it."""

    out = io.StringIO()

    def read_status():  # type: ignore[no-untyped-def]
        return parse_status(cluster.read_status())

    def trigger(node: NodeStatus) -> int:
        return cluster.trigger(node.name)

    outcome = deploy_run.run(
        read_status,
        trigger,
        out,
        target=ReleaseTarget(version=8, hash=expected_hash) if expected_hash else None,
        allow_vip_unknown=allow_vip_unknown,
    )
    LAST_REPORT[:] = [outcome.report]
    return outcome.exit_code, out.getvalue()


class OrderingTests(unittest.TestCase):
    def test_the_owner_is_deployed_last(self) -> None:
        cluster = pair()

        code, shown = deploy(cluster)

        self.assertEqual(cluster.triggered, ["node-b", "node-a"])
        self.assertEqual(code, 0)
        self.assertIn("RESULT: OK", shown)

    def test_the_status_is_read_again_after_every_deploy(self) -> None:
        #
        # Once at the start, once after each of the two deploys. Trusting the
        # first reading for the second decision is the bug this whole shape
        # exists to prevent.
        #
        cluster = pair()

        deploy(cluster)

        self.assertEqual(cluster.reads, 3)

    def test_a_vip_that_moves_mid_run_changes_the_remaining_order(self) -> None:
        cluster = FakeCluster(
            nodes=[
                FakeNode(name="node-a", mgmt_host="node-a.example.com", owns_vip=True),
                FakeNode(name="node-b", mgmt_host="node-b.example.com", owns_vip=False),
                FakeNode(name="node-c", mgmt_host="node-c.example.com", owns_vip=False),
            ],
            on_deploy=lambda cluster, node: (
                cluster.move_vip("node-c") if node.name == "node-b" else None
            ),
        )

        code, _ = deploy(cluster)

        #
        # node-a was the owner when the run started, so it was held back. Once
        # the address moved to node-c it stopped being the one to protect, and
        # node-c took its place at the end.
        #
        self.assertEqual(cluster.triggered, ["node-b", "node-a", "node-c"])
        self.assertEqual(code, 0)


class BlockedStateTests(unittest.TestCase):
    def test_split_brain_blocks_before_anything_is_touched(self) -> None:
        cluster = pair()
        cluster.split_brain()

        code, shown = deploy(cluster)

        self.assertEqual(cluster.triggered, [])
        self.assertEqual(code, 65)
        self.assertIn("split brain", shown)

    def test_split_brain_appearing_mid_run_stops_the_rest(self) -> None:
        cluster = pair()
        cluster.on_deploy = lambda cluster, node: cluster.split_brain()

        code, shown = deploy(cluster)

        self.assertEqual(cluster.triggered, ["node-b"])
        self.assertEqual(code, 65)
        self.assertIn("split brain", shown)

    def test_an_indeterminate_answer_blocks_and_the_override_releases_it(self) -> None:
        cluster = pair()
        cluster.node("node-a").owns_vip = None

        blocked, shown = deploy(cluster)
        self.assertEqual(cluster.triggered, [])
        self.assertEqual(blocked, 65)
        self.assertIn("--allow-vip-unknown", shown)

        allowed, shown = deploy(cluster, allow_vip_unknown=True)
        self.assertEqual(cluster.triggered, ["node-a", "node-b"])
        self.assertEqual(allowed, 0)
        self.assertIn("explicit CLI override accepted", shown)

    def test_no_node_readable_at_all_stops(self) -> None:
        cluster = pair()
        for node in cluster.nodes:
            node.reachable = False

        code, shown = deploy(cluster)

        self.assertEqual(cluster.triggered, [])
        self.assertEqual(code, 68)
        self.assertIn("no node returned usable status", shown)


class DegradedTests(unittest.TestCase):
    def test_an_unreachable_peer_is_reconciled_around_and_reported_partial(self) -> None:
        cluster = pair()
        cluster.node("node-a").reachable = False

        code, shown = deploy(cluster)

        self.assertEqual(cluster.triggered, ["node-b"])
        self.assertEqual(code, 69)
        self.assertIn("RESULT: PARTIAL", shown)
        self.assertIn("unavailable: node-a", shown)

    def test_a_node_answering_null_is_treated_as_unusable_not_as_a_crash(self) -> None:
        #
        # The collecting helper marks status_ok as soon as the JSON parsed, so
        # this node arrives claiming a status it does not have. Everything
        # downstream has to survive that.
        #
        cluster = pair()
        cluster.node("node-a").answers = "null"

        code, shown = deploy(cluster)

        self.assertEqual(cluster.triggered, ["node-b"])
        self.assertEqual(code, 69)
        self.assertIn("RESULT: PARTIAL", shown)

    def test_a_node_answering_something_that_is_not_a_status_is_survived_too(self) -> None:
        cluster = pair()
        cluster.node("node-a").answers = "garbage"

        code, _ = deploy(cluster)

        self.assertEqual(cluster.triggered, ["node-b"])
        self.assertEqual(code, 69)

    def test_a_node_that_disappears_mid_run_is_skipped_not_blocked(self) -> None:
        cluster = pair()
        cluster.on_deploy = lambda cluster, node: setattr(
            cluster.node("node-a"), "reachable", False
        )

        code, shown = deploy(cluster)

        self.assertEqual(cluster.triggered, ["node-b"])
        self.assertEqual(code, 69)
        self.assertIn("RESULT: PARTIAL", shown)


class ReloadFailureTests(unittest.TestCase):
    def test_a_failing_reload_stops_before_the_next_node(self) -> None:
        cluster = pair()
        cluster.node("node-b").reload_fails = True

        code, shown = deploy(cluster)

        self.assertEqual(cluster.triggered, ["node-b"])
        self.assertEqual(code, 69)
        self.assertIn("RESULT: FAILED", shown)
        self.assertIn("the deploy trigger failed on node-b", shown)

    def test_a_failing_reload_leaves_the_node_on_what_it_had(self) -> None:
        cluster = pair()
        cluster.node("node-b").reload_fails = True

        deploy(cluster)

        self.assertEqual(cluster.node("node-b").release_hash, OLD_HASH)
        self.assertEqual(cluster.node("node-a").release_hash, OLD_HASH)

    def test_the_status_is_read_again_even_after_a_failure(self) -> None:
        #
        # The failure already changed the cluster. Reporting the state from
        # before it would describe something that is no longer true.
        #
        cluster = pair()
        cluster.node("node-b").reload_fails = True

        deploy(cluster)

        self.assertEqual(cluster.reads, 2)


class CurrentSkipTests(unittest.TestCase):
    def test_a_node_already_on_the_target_is_not_redeployed(self) -> None:
        cluster = pair()
        cluster.node("node-a").release_hash = TARGET_HASH

        code, shown = deploy(cluster, expected_hash=TARGET_HASH)

        self.assertEqual(cluster.triggered, ["node-b"])
        self.assertEqual(code, 0)
        self.assertIn("node-a already runs this version", shown)

    def test_a_rerun_after_a_partial_costs_one_deploy_not_two(self) -> None:
        cluster = pair()
        cluster.node("node-a").reachable = False

        first, _ = deploy(cluster, expected_hash=TARGET_HASH)
        self.assertEqual(first, 69)
        self.assertEqual(cluster.triggered, ["node-b"])

        cluster.node("node-a").reachable = True
        second, _ = deploy(cluster, expected_hash=TARGET_HASH)

        #
        # node-b was brought to the target by the first run, so the second one
        # only has node-a left to do.
        #
        self.assertEqual(cluster.triggered, ["node-b", "node-a"])
        self.assertEqual(second, 0)

    def test_a_cluster_already_everywhere_on_target_does_nothing_and_succeeds(self) -> None:
        cluster = pair()
        for node in cluster.nodes:
            node.release_hash = TARGET_HASH

        code, shown = deploy(cluster, expected_hash=TARGET_HASH)

        self.assertEqual(cluster.triggered, [])
        self.assertEqual(code, 0)
        self.assertIn("RESULT: OK", shown)


class ZeroOwnerTests(unittest.TestCase):
    def test_with_the_vip_down_both_nodes_are_deployed_in_configured_order(self) -> None:
        cluster = pair()
        cluster.move_vip(None)

        code, shown = deploy(cluster)

        self.assertEqual(cluster.triggered, ["node-a", "node-b"])
        self.assertEqual(code, 0)
        self.assertIn("no node currently owns the VIP; it is down", shown)

    def test_with_the_vip_down_a_failure_still_stops_before_the_second_node(self) -> None:
        cluster = pair()
        cluster.move_vip(None)
        cluster.node("node-a").reload_fails = True

        code, _ = deploy(cluster)

        self.assertEqual(cluster.triggered, ["node-a"])
        self.assertEqual(code, 69)


if __name__ == "__main__":
    unittest.main()
