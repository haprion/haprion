"""The whole deploy path driven against the harness, end to end.

Not the matrix again - that is tested directly in test_deploy_plan. What is
tested here is that the three pieces agree: the status envelope is parsed the
way the helper writes it, the decision is taken on what came back, and the loop
re-reads after every mutation instead of trusting what it decided earlier.

Every case below is a state the production pair cannot be put into.
"""

from __future__ import annotations

import importlib.util
import io
import unittest
from pathlib import Path
from typing import Any

from haprion import deploy_run, exit_codes
from haprion.cluster_status import ClusterStatus, NodeStatus, StatusError, parse_status
from haprion.deploy_plan import CertificateRef, CertificateTarget, ReleaseTarget
from haprion.deploy_run import CertificatePreflight, DeployReport
from tests.node_harness import OLD_HASH, TARGET_HASH, FakeCluster, FakeNode, pair

TARGET = ReleaseTarget(version=8, hash=TARGET_HASH)

LAST_REPORT: list[DeployReport] = []


def deploy(
    cluster: FakeCluster,
    *,
    expected_hash: str | None = None,
    allow_vip_unknown: bool = False,
    preflight: CertificatePreflight | None = None,
    pause: Any = None,
) -> tuple[int, str]:
    """Run one deploy. The report is kept aside for the cases that inspect it."""

    out = io.StringIO()

    def read_status() -> ClusterStatus:
        return parse_status(cluster.read_status())

    def trigger(node: NodeStatus) -> int:
        return cluster.trigger(node.name)

    outcome = deploy_run.run(
        read_status,
        trigger,
        out,
        target=ReleaseTarget(version=8, hash=expected_hash) if expected_hash else None,
        allow_vip_unknown=allow_vip_unknown,
        preflight=preflight,
        pause=pause or (lambda _seconds: None),
    )
    LAST_REPORT[:] = [outcome.report]
    # Every run must also make a valid answer: a partial that kept its error
    # passed every assertion here and failed only when the envelope was built
    # (review 2026-10-24).
    # And the exit must be the one that outcome is, or writing it fails (06-04).
    exit_codes.check(outcome.report.as_envelope("alpha")["outcome"], outcome.exit_code)
    return outcome.exit_code, out.getvalue()


def reconcile_semantics() -> Any:
    """The contract's own semantic check, `contract-tests/validate_contracts.py`."""

    path = Path(__file__).resolve().parents[1] / "contract-tests" / "validate_contracts.py"
    spec = importlib.util.spec_from_file_location("validate_contracts", path)
    assert spec is not None and spec.loader is not None  # a fixed file
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.check_reconcile_semantics


class TheEndIsJudgedOnTheLastReading(unittest.TestCase):
    """CR-08: converged means every node runs the target in the run's last reading."""

    def finish(self, cluster: FakeCluster) -> tuple[int, dict[str, Any]]:
        code, _ = deploy(cluster, expected_hash=TARGET_HASH)
        document = LAST_REPORT[0].as_envelope("alpha")
        reconcile_semantics()(document, Path("deploy"))
        return code, document

    def test_a_node_that_falls_back_while_the_owner_is_deployed_is_not_converged(self) -> None:
        """Scenario A: node-b deployed and verified, then back on the old release."""

        def fall_back(cluster: FakeCluster, node: FakeNode) -> None:
            if node.name == "node-a":
                cluster.node("node-b").release_hash = OLD_HASH

        code, document = self.finish(pair(on_deploy=fall_back))

        self.assertEqual(code, 69)
        self.assertEqual(document["outcome"], "partial")
        self.assertFalse(document["result"]["converged"])
        rows = {row["name"]: row for row in document["result"]["nodes"]}
        self.assertEqual(rows["node-b"]["outcome"], "failed")
        self.assertFalse(rows["node-b"]["verified"])
        self.assertEqual(rows["node-b"]["error"]["code"], "target_not_reached")

    def test_a_node_unreadable_after_its_deploy_that_returns_behind_is_not_converged(self) -> None:
        """Scenario B: unreadable right after its trigger, back on the old release later."""

        def flicker(cluster: FakeCluster, node: FakeNode) -> None:
            other = cluster.node("node-b")
            if node.name == "node-b":
                other.reachable = False
            else:
                other.reachable, other.release_hash = True, OLD_HASH

        code, document = self.finish(pair(on_deploy=flicker))

        self.assertEqual(code, 69)
        self.assertFalse(document["result"]["converged"])
        rows = {row["name"]: row for row in document["result"]["nodes"]}
        self.assertEqual(rows["node-b"]["outcome"], "failed")

    def test_a_node_unreadable_after_its_deploy_that_returns_right_is_verified(self) -> None:
        def flicker(cluster: FakeCluster, node: FakeNode) -> None:
            cluster.node("node-b").reachable = node.name != "node-b"

        code, document = self.finish(pair(on_deploy=flicker))

        self.assertEqual(code, 0)
        self.assertTrue(document["result"]["converged"])
        rows = {row["name"]: row for row in document["result"]["nodes"]}
        self.assertEqual((rows["node-b"]["outcome"], rows["node-b"]["verified"]), ("updated", True))

    def test_a_node_unreadable_at_the_end_is_not_converged_and_not_called_updated(self) -> None:
        def gone(cluster: FakeCluster, node: FakeNode) -> None:
            cluster.node("node-b").reachable = False

        code, document = self.finish(pair(on_deploy=gone))

        self.assertEqual(code, 69)
        self.assertFalse(document["result"]["converged"])
        rows = {row["name"]: row for row in document["result"]["nodes"]}
        self.assertEqual(rows["node-b"]["outcome"], "failed")
        self.assertEqual(rows["node-b"]["error"]["code"], "node_unverified")

    def test_a_node_that_was_current_and_drifts_is_named(self) -> None:
        cluster = pair()
        cluster.node("node-b").release_hash = TARGET_HASH

        def drift(cluster: FakeCluster, node: FakeNode) -> None:
            cluster.node("node-b").release_hash = OLD_HASH

        cluster.on_deploy = drift
        code, document = self.finish(cluster)

        self.assertEqual(code, 69)
        self.assertIn(
            "node-b was current when it was passed over and is not any more",
            [warning["message"] for warning in document["warnings"]],
        )


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


class SharedCountersTests(unittest.TestCase):
    """A reloaded node is given time to reach its peers before the next (B270)."""

    def sharing(self) -> FakeCluster:
        cluster = pair()
        for node in cluster.nodes:
            other = "node-b" if node.name == "node-a" else "node-a"
            node.peers = [{"name": other, "address": "192.0.2.9:10000", "connected": True}]
        return cluster

    def test_the_next_node_waits_until_the_deployed_one_is_connected(self) -> None:
        cluster = self.sharing()
        paused: list[float] = []

        def disconnect(_: FakeCluster, node: FakeNode) -> None:
            assert node.peers is not None  # set above
            node.peers[0]["connected"] = False

        def pause(seconds: float) -> None:
            paused.append(seconds)
            for node in cluster.nodes:
                assert node.peers is not None  # set above
                node.peers[0]["connected"] = True

        cluster.on_deploy = disconnect
        code, shown = deploy(cluster, pause=pause)

        self.assertEqual(code, 0, shown)
        self.assertEqual(paused, [1.0, 1.0])
        self.assertNotIn("share counters", shown)

    def test_a_node_that_never_connects_is_named_and_the_deploy_goes_on(self) -> None:
        cluster = self.sharing()

        def disconnect(_: FakeCluster, node: FakeNode) -> None:
            assert node.peers is not None  # set above
            node.peers[0]["connected"] = False

        cluster.on_deploy = disconnect
        code, shown = deploy(cluster)

        self.assertEqual(code, 0, shown)
        self.assertEqual(cluster.triggered, ["node-b", "node-a"])
        self.assertIn("node-b has not reached node-a to share counters", shown)
        codes = [warning.code for warning in LAST_REPORT[0].warnings]
        self.assertIn("counters_not_shared", codes)

    def test_a_reading_that_fails_while_waiting_stops_before_the_next_node(self) -> None:
        # Review 26-10-13, L1: the wait broke off and the next node was chosen
        # from the reading before the failure.
        cluster = self.sharing()

        def disconnect(_: FakeCluster, node: FakeNode) -> None:
            assert node.peers is not None  # set above
            node.peers[0]["connected"] = False

        cluster.on_deploy = disconnect
        healthy = cluster.read_status

        def failing() -> dict[str, Any]:
            if cluster.reads >= 2:
                cluster.reads += 1
                return {"operation": "status"}
            return healthy()

        cluster.read_status = failing  # type: ignore[method-assign]
        code, shown = deploy(cluster)

        self.assertEqual(code, 68, shown)
        self.assertEqual(cluster.triggered, ["node-b"])
        self.assertIn("The remaining nodes were not touched", shown)
        report = LAST_REPORT[0]
        self.assertEqual(report.nodes["node-b"].outcome, "updated")
        assert report.error is not None  # asserted by the exit code
        self.assertEqual(report.error.code, "status_unavailable")

    def test_turning_sharing_on_does_not_wait_for_a_node_still_without_it(self) -> None:
        # Review 26-10-10, F2: the node deployed first reports the other, which
        # still runs the release without `peers` and has nothing to connect to.
        cluster = pair()
        paused: list[float] = []

        def turn_on(_: FakeCluster, node: FakeNode) -> None:
            other = "node-a" if node.name == "node-b" else "node-b"
            node.peers = [{"name": other, "address": "192.0.2.9:10000", "connected": False}]
            for peer in cluster.nodes:
                if peer.name == other and peer.peers is None:
                    peer.peers = []
                elif peer.name == other and peer.peers:
                    peer.peers[0]["connected"] = True
                    node.peers[0]["connected"] = True

        cluster.on_deploy = turn_on
        code, shown = deploy(cluster, pause=paused.append)

        self.assertEqual(code, 0, shown)
        self.assertEqual(paused, [])
        self.assertNotIn("share counters", shown)

    def test_a_cluster_that_shares_nothing_is_not_waited_for(self) -> None:
        cluster = pair()
        paused: list[float] = []

        deploy(cluster, pause=paused.append)

        self.assertEqual(paused, [])


class BlockedStateTests(unittest.TestCase):
    def test_split_brain_blocks_before_anything_is_touched(self) -> None:
        cluster = pair()
        cluster.split_brain()

        code, shown = deploy(cluster)

        self.assertEqual(cluster.triggered, [])
        self.assertEqual(code, exit_codes.BLOCKED)
        self.assertIn("split brain", shown)

    def test_split_brain_appearing_mid_run_stops_the_rest(self) -> None:
        cluster = pair()
        cluster.on_deploy = lambda cluster, node: cluster.split_brain()

        code, shown = deploy(cluster)

        # node-b was deployed before the block: partial, and said so (review
        # 2026-09-28 F4). The block before anything is touched stays 65, above.
        self.assertEqual(cluster.triggered, ["node-b"])
        self.assertEqual(code, 69)
        self.assertIn("split brain", shown)
        self.assertIn("node-b already carries the target", shown)
        self.assertIn("Some nodes carry the target and some do not.", shown)
        # The block is named in the answer too: as a warning, since a partial
        # envelope carries no top-level error (review 2026-10-24).
        document = LAST_REPORT[0].as_envelope("alpha")
        self.assertEqual(document["outcome"], "partial")
        self.assertIsNone(document["error"])
        self.assertIn("deploy_blocked", [warning["code"] for warning in document["warnings"]])

    def test_an_indeterminate_answer_blocks_and_the_override_releases_it(self) -> None:
        cluster = pair()
        cluster.node("node-a").owns_vip = None

        blocked, shown = deploy(cluster)
        self.assertEqual(cluster.triggered, [])
        self.assertEqual(blocked, exit_codes.BLOCKED)
        self.assertIn("--allow-vip-unknown", shown)

        allowed, shown = deploy(cluster, allow_vip_unknown=True)
        # The known standby first, the node of unknown ownership after (review 2026-10-03, F1).
        self.assertEqual(cluster.triggered, ["node-b", "node-a"])
        self.assertEqual(allowed, 0)
        self.assertIn("explicit CLI override accepted", shown)

    def test_no_node_readable_at_all_stops(self) -> None:
        cluster = pair()
        for node in cluster.nodes:
            node.reachable = False

        code, shown = deploy(cluster)

        self.assertEqual(cluster.triggered, [])
        self.assertEqual(code, exit_codes.BLOCKED)
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
        self.assertEqual(code, exit_codes.FAILED)
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


class AStatusThatCannotBeRead(unittest.TestCase):
    """Review 26-10-24, 06-04/13-04: both branches built answers the contract refused."""

    def run_deploy(self, cluster: FakeCluster, *, readable: int) -> deploy_run.DeployRun:
        reads = 0

        def read_status() -> ClusterStatus:
            nonlocal reads
            reads += 1
            if reads > readable:
                raise StatusError("the status helper did not answer")
            return parse_status(cluster.read_status())

        run = deploy_run.run(
            read_status,
            lambda node: cluster.trigger(node.name),
            io.StringIO(),
            target=None,
            allow_vip_unknown=False,
            preflight=None,
            pause=lambda _seconds: None,
        )
        exit_codes.check(run.report.as_envelope("alpha")["outcome"], run.exit_code)
        return run

    def test_no_reading_at_all_is_blocked_with_its_own_exit(self) -> None:
        run = self.run_deploy(pair(), readable=0)

        self.assertEqual(run.exit_code, exit_codes.BLOCKED)

    def test_a_node_deployed_and_not_read_afterwards_is_failed(self) -> None:
        cluster = pair()

        run = self.run_deploy(cluster, readable=1)

        self.assertEqual(cluster.triggered, ["node-b"])
        self.assertEqual(run.report.as_envelope("alpha")["outcome"], "failed")
        self.assertEqual(run.report.nodes["node-b"].outcome, "failed")


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


class HalfWayNodeTests(unittest.TestCase):
    """The failure the release hash cannot see, and the run that repairs it.

    A node activates the configuration and then the keepalived address list.
    When the second step fails the address file is put back and the new
    configuration stays live, so the node reports the target hash with the old
    addresses - and the deploy that reports the failure is the same deploy the
    operator re-runs after fixing the cause.
    """

    def test_a_node_left_half_way_is_not_skipped_as_current(self) -> None:
        cluster = pair()
        for node in cluster.nodes:
            node.release_hash = TARGET_HASH
        cluster.node("node-a").addresses = "stale"

        code, shown = deploy(cluster, expected_hash=TARGET_HASH)

        self.assertEqual(cluster.triggered, ["node-a"])
        self.assertEqual(code, 0)
        self.assertIn("node-b already runs this version", shown)

    def test_the_rerun_finishes_the_half_that_was_left(self) -> None:
        cluster = pair()
        for node in cluster.nodes:
            node.release_hash = TARGET_HASH
        cluster.node("node-a").addresses = "stale"

        deploy(cluster, expected_hash=TARGET_HASH)
        self.assertEqual(cluster.node("node-a").addresses, "in_use")

        code, _ = deploy(cluster, expected_hash=TARGET_HASH)

        #
        # Nothing left to do on the second run: the repair happened on the
        # first, and the node is now current in both of its components.
        #
        self.assertEqual(cluster.triggered, ["node-a"])
        self.assertEqual(code, 0)


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
        self.assertEqual(code, exit_codes.FAILED)


if __name__ == "__main__":
    unittest.main()


class StoppingBecauseTheCallerLetGo(unittest.TestCase):
    """The checkpoint, and the three answers it can give.

    The lifeline exists because the caller cannot stop this process: the helper
    runs as root and the worker does not. So the loop stops itself, and the
    whole value of stopping at the top of an iteration is that the result is a
    state the contract already names.

    A fake lifeline rather than a real pipe here: what is under test is where
    the loop asks and what it reports, not how EOF reaches a thread. That is
    tested against real file descriptors in test_helper_protocol.
    """

    class Held:
        released = False

    class Released:
        released = True
        reason = "the caller closed the lifeline"

    class ReleasedAfter:
        """Held for the first n questions, released from then on."""

        reason = "the caller closed the lifeline"

        def __init__(self, hold_for: int) -> None:
            self._left = hold_for

        @property
        def released(self) -> bool:
            if self._left > 0:
                self._left -= 1
                return False
            return True

    def run_with(self, cluster: FakeCluster, lifeline: object) -> tuple[int, str]:
        out = io.StringIO()
        outcome = deploy_run.run(
            lambda: parse_status(cluster.read_status()),
            lambda node: cluster.trigger(node.name),
            out,
            target=TARGET,
            lifeline=lifeline,  # type: ignore[arg-type]
        )
        LAST_REPORT[:] = [outcome.report]
        outcome.report.as_envelope("alpha")
        return outcome.exit_code, out.getvalue()

    def test_released_before_anything_ran_is_blocked_and_touches_nothing(self) -> None:
        cluster = pair()
        code, text = self.run_with(cluster, self.Released())

        self.assertEqual(code, exit_codes.BLOCKED)
        self.assertEqual(LAST_REPORT[0].outcome.value, "blocked")
        self.assertIn("No node was touched", text)
        self.assertEqual(cluster.triggered, [])

    def test_released_after_one_node_is_partial(self) -> None:
        cluster = pair()
        code, text = self.run_with(cluster, self.ReleasedAfter(1))

        self.assertEqual(code, 69)
        self.assertEqual(LAST_REPORT[0].outcome.value, "partial")
        self.assertEqual(len(cluster.triggered), 1)
        self.assertIn("Run the same command again", text)
        document = LAST_REPORT[0].as_envelope("alpha")
        self.assertEqual(document["outcome"], "partial")
        self.assertIsNone(document["error"])
        self.assertIn("caller_released", [warning["code"] for warning in document["warnings"]])

    def test_the_reason_is_carried_into_the_report(self) -> None:
        cluster = pair()
        self.run_with(cluster, self.Released())

        error = LAST_REPORT[0].error
        assert error is not None
        self.assertEqual(error.code, "caller_released")
        self.assertEqual(error.message, "the caller closed the lifeline")

    def test_a_held_lifeline_changes_nothing(self) -> None:
        cluster = pair()
        code, _ = self.run_with(cluster, self.Held())

        self.assertEqual(code, 0)
        self.assertEqual(LAST_REPORT[0].outcome.value, "done")
        self.assertEqual(len(cluster.triggered), 2)


class TheTerminalNamesTheSameCodeAsThePage(unittest.TestCase):
    """One failure, one string, wherever a person happens to be reading.

    The stable code is what the jobs page shows and what the audit trail keeps.
    Printing only prose here left an operator comparing "the deploy trigger
    failed on node-b" against `deploy_failed` and guessing they were the same
    event. Added 2026-08-31 as F1b, out of the code review's F1.
    """

    def test_a_failed_deploy_prints_its_code_beside_the_reason(self) -> None:
        cluster = pair()
        cluster.node("node-b").reload_fails = True

        _, shown = deploy(cluster)

        self.assertIn("RESULT: FAILED  [deploy_failed]", shown)
        self.assertIn("the deploy trigger failed on node-b", shown)

    def test_a_partial_deploy_lists_the_warning_codes_it_recorded(self) -> None:
        cluster = pair()
        cluster.node("node-a").reachable = False

        _, shown = deploy(cluster)

        #
        # Every distinct warning code, sorted, rather than the first one. A
        # partial deploy usually has more than one thing to say, and picking one
        # would make the line depend on the order they happened to be recorded
        # in.
        #
        self.assertIn("RESULT: PARTIAL  [cluster_state, node_unverified]", shown)
        #
        # The codes come from the warnings the report actually holds, so the
        # line cannot name one the envelope does not carry.
        #
        self.assertEqual(
            sorted({warning.code for warning in LAST_REPORT[0].warnings}),
            ["cluster_state", "node_unverified"],
        )

    def test_a_successful_deploy_carries_no_brackets_at_all(self) -> None:
        _, shown = deploy(pair())

        self.assertIn("RESULT: OK", shown)
        self.assertNotIn("[", shown.split("RESULT:")[1])


#
# The certificates a release references, as the manager published them, and
# the fingerprints a node has to answer with to be current on them.
#
PUBLISHED = (("example-com", "a" * 64), ("example-net", "b" * 64))


def preflight(
    *published: tuple[str, str],
    authorities: tuple[tuple[str, str], ...] = (),
    root: bool = True,
) -> CertificatePreflight:
    return CertificatePreflight(
        target=CertificateTarget(
            certificates=tuple(CertificateRef(id=i, fingerprint=f) for i, f in published),
            authorities=tuple(CertificateRef(id=i, fingerprint=f) for i, f in authorities),
        )
        if root
        else None,
        referenced=tuple(identifier for identifier, _ in (*published, *authorities)),
        next_command="haprion-cert-deploy -c alpha",
    )


#
# A CA file the cluster's pools verify against (B276), as the manager published it.
#
AUTHORITY = (("corp-root", "e" * 64),)


def carrying(*published: tuple[str, str]) -> FakeCluster:
    cluster = pair()
    for node in cluster.nodes:
        node.certificates = published
    return cluster


class CertificatePreflightTests(unittest.TestCase):
    """§6.4: a configuration deploy blocks when a readable node lacks a certificate.

    Blocks, names the node and the certificate, names `cert-deploy`, and touches
    nothing - and does not run `cert-deploy` itself. The plan forbids the
    implicit chain, so that a certificate rollout is always asked for by name.
    """

    def test_a_node_missing_a_referenced_certificate_blocks_before_anything_is_touched(
        self,
    ) -> None:
        cluster = carrying(PUBLISHED[0])

        code, shown = deploy(cluster, preflight=preflight(*PUBLISHED))

        self.assertEqual(cluster.triggered, [])
        self.assertEqual(code, exit_codes.BLOCKED)
        self.assertIn("ERROR: [certificates_not_deployed]", shown)
        self.assertIn("node-a (missing example-net)", shown)
        self.assertIn("node-b (missing example-net)", shown)
        self.assertIn("Run haprion-cert-deploy -c alpha first, then deploy again", shown)

        report = LAST_REPORT[0]
        self.assertEqual(report.outcome.value, "blocked")
        assert report.error is not None
        self.assertEqual(report.error.code, "certificates_not_deployed")
        self.assertEqual(
            report.error.details,
            {
                "nodes": [
                    {"node": "node-a", "missing": ["example-net"], "stale": []},
                    {"node": "node-b", "missing": ["example-net"], "stale": []},
                ],
                "next_command": "haprion-cert-deploy -c alpha",
            },
        )

    def test_a_node_carrying_other_bytes_is_stale_and_blocks_too(self) -> None:
        #
        # A renewal that did not reach one node. The other node is current and
        # is not named: the message is about who has to be fixed, not a roll
        # call.
        #
        cluster = carrying(*PUBLISHED)
        cluster.node("node-b").certificates = (PUBLISHED[0], ("example-net", "c" * 64))

        code, shown = deploy(cluster, preflight=preflight(*PUBLISHED))

        self.assertEqual(cluster.triggered, [])
        self.assertEqual(code, exit_codes.BLOCKED)
        self.assertIn("node-b (stale example-net)", shown)
        self.assertNotIn("node-a (", shown)

    def test_nodes_carrying_the_published_bytes_are_deployed_as_usual(self) -> None:
        cluster = carrying(*PUBLISHED)

        code, shown = deploy(cluster, preflight=preflight(*PUBLISHED))

        self.assertEqual(cluster.triggered, ["node-b", "node-a"])
        self.assertEqual(code, 0)
        self.assertNotIn("certificate", shown)
        self.assertEqual(LAST_REPORT[0].warnings, [])

    def test_a_certificate_the_node_carries_but_the_cluster_does_not_reference_is_ignored(
        self,
    ) -> None:
        cluster = carrying(*PUBLISHED, ("something-else", "d" * 64))

        code, _ = deploy(cluster, preflight=preflight(*PUBLISHED))

        self.assertEqual(code, 0)

    def test_a_node_that_says_nothing_about_certificates_is_warned_about_not_blocked(
        self,
    ) -> None:
        #
        # Silence is not absence. A status script from before the field
        # existed would otherwise refuse every deploy, with nothing anybody
        # could do about it short of upgrading the node first.
        #
        cluster = carrying(*PUBLISHED)
        cluster.node("node-b").certificates = None

        code, shown = deploy(cluster, preflight=preflight(*PUBLISHED))

        self.assertEqual(cluster.triggered, ["node-b", "node-a"])
        self.assertEqual(code, 0)
        self.assertIn("WARNING: node-b did not report its certificates", shown)
        warning = LAST_REPORT[0].warnings[0]
        self.assertEqual((warning.code, warning.node), ("certificates_unverified", "node-b"))

    def test_an_unreachable_peer_is_not_judged(self) -> None:
        #
        # The reachable node is checked and deployed; the peer is what partial
        # already means. Blocking on a node nobody could read would turn every
        # degraded deploy into a refusal.
        #
        cluster = carrying(*PUBLISHED)
        cluster.node("node-a").reachable = False

        code, shown = deploy(cluster, preflight=preflight(*PUBLISHED))

        self.assertEqual(cluster.triggered, ["node-b"])
        self.assertEqual(code, 69)
        self.assertIn("RESULT: PARTIAL", shown)

    def test_a_reachable_node_behind_still_blocks_a_degraded_deploy(self) -> None:
        cluster = carrying(PUBLISHED[0])
        cluster.node("node-a").reachable = False

        code, shown = deploy(cluster, preflight=preflight(*PUBLISHED))

        self.assertEqual(cluster.triggered, [])
        self.assertEqual(code, exit_codes.BLOCKED)
        self.assertIn("node-b (missing example-net)", shown)

    def test_the_check_comes_after_the_cluster_wide_blocks(self) -> None:
        #
        # Split brain is the worse fault and the one with no override; it is
        # what the operator has to hear about first.
        #
        cluster = carrying(PUBLISHED[0])
        cluster.split_brain()

        code, shown = deploy(cluster, preflight=preflight(*PUBLISHED))

        self.assertEqual(code, exit_codes.BLOCKED)
        self.assertIn("split brain", shown)
        self.assertNotIn("certificates_not_deployed", shown)

    def test_without_a_certificate_root_the_run_says_the_check_was_skipped(self) -> None:
        cluster = carrying()

        code, shown = deploy(cluster, preflight=preflight(*PUBLISHED, root=False))

        self.assertEqual(code, 0)
        self.assertIn(
            "WARNING: no certificate root is configured; example-com, example-net "
            "not checked on the nodes",
            shown,
        )
        self.assertEqual(LAST_REPORT[0].warnings[0].code, "certificates_unchecked")

    def test_a_cluster_referencing_nothing_is_not_checked_and_not_warned_about(self) -> None:
        cluster = carrying()
        cluster.node("node-b").certificates = None

        code, shown = deploy(cluster, preflight=preflight())

        self.assertEqual(code, 0)
        self.assertNotIn("certificate", shown)
        self.assertEqual(LAST_REPORT[0].warnings, [])

    def test_a_cluster_with_only_a_ca_file_is_still_checked(self) -> None:
        #
        # Review 2026-10-18, L1: an HTTP frontend in front of an HTTPS pool
        # references no certificate, only the CA - and the check used to stop
        # at the empty certificate list.
        #
        cluster = carrying()
        for node in cluster.nodes:
            node.authorities = ()

        code, shown = deploy(cluster, preflight=preflight(authorities=AUTHORITY))

        self.assertEqual(cluster.triggered, [])
        self.assertEqual(code, exit_codes.BLOCKED)
        self.assertIn("node-a (missing CA corp-root)", shown)
        report = LAST_REPORT[0]
        assert report.error is not None and report.error.details is not None
        self.assertEqual(
            report.error.details["nodes"][0],
            {
                "node": "node-a",
                "missing": [],
                "stale": [],
                "missing_authorities": ["corp-root"],
                "stale_authorities": [],
            },
        )

    def test_a_node_carrying_an_older_ca_file_blocks_beside_a_current_certificate(
        self,
    ) -> None:
        #
        # The worse half of L1: HAProxy accepts the old file, so nothing on the
        # node would have stopped the release.
        #
        cluster = carrying(*PUBLISHED)
        for node in cluster.nodes:
            node.authorities = AUTHORITY
        cluster.node("node-b").authorities = (("corp-root", "f" * 64),)

        code, shown = deploy(cluster, preflight=preflight(*PUBLISHED, authorities=AUTHORITY))

        self.assertEqual(cluster.triggered, [])
        self.assertEqual(code, exit_codes.BLOCKED)
        self.assertIn("node-b (stale CA corp-root)", shown)
        self.assertNotIn("node-a (", shown)

    def test_nodes_carrying_the_published_ca_file_are_deployed(self) -> None:
        cluster = carrying(*PUBLISHED)
        for node in cluster.nodes:
            node.authorities = AUTHORITY

        code, _ = deploy(cluster, preflight=preflight(*PUBLISHED, authorities=AUTHORITY))

        self.assertEqual(code, 0)
        self.assertEqual(cluster.triggered, ["node-b", "node-a"])
        self.assertEqual(LAST_REPORT[0].warnings, [])

    def test_a_node_that_says_nothing_about_ca_files_is_warned_about_not_blocked(
        self,
    ) -> None:
        cluster = carrying(*PUBLISHED)
        cluster.node("node-a").authorities = AUTHORITY

        code, shown = deploy(cluster, preflight=preflight(*PUBLISHED, authorities=AUTHORITY))

        self.assertEqual(code, 0)
        self.assertIn("WARNING: node-b did not report its CA files", shown)
        self.assertEqual(
            [(w.code, w.node) for w in LAST_REPORT[0].warnings],
            [("certificates_unverified", "node-b")],
        )

    def test_without_a_preflight_nothing_is_compared(self) -> None:
        #
        # `cert-deploy` runs this same loop and is the command that fixes what
        # the check finds; it must never be refused by it.
        #
        cluster = carrying()

        code, _ = deploy(cluster)

        self.assertEqual(code, 0)


class TheFirstDeployWaitsForTheVip(unittest.TestCase):
    """Fas 18, 26-10-16: the first deploy ended before keepalived had chosen a MASTER."""

    def nobody(self) -> FakeCluster:
        cluster = pair()
        cluster.move_vip(None)
        return cluster

    def test_a_deploy_that_ends_without_an_owner_waits_for_one(self) -> None:
        cluster = self.nobody()
        paused: list[float] = []

        def pause(seconds: float) -> None:
            paused.append(seconds)
            if len(paused) == 3:
                cluster.move_vip("node-a")

        code, shown = deploy(cluster, pause=pause)

        self.assertEqual(code, 0, shown)
        self.assertEqual(paused, [1.0, 1.0, 1.0])
        self.assertIn("Final status: VIP=single_owner, owner=node-a", shown)
        codes = [warning.code for warning in LAST_REPORT[0].warnings]
        self.assertNotIn("vip_not_owned", codes)

    def test_no_owner_by_the_end_of_the_wait_is_named(self) -> None:
        paused: list[float] = []
        code, shown = deploy(self.nobody(), pause=paused.append)

        self.assertEqual(code, 0, shown)
        self.assertEqual(len(paused), deploy_run.VIP_WAIT_SECONDS)
        self.assertIn("no node took the VIP within 15 s", shown)
        codes = [warning.code for warning in LAST_REPORT[0].warnings]
        self.assertIn("vip_not_owned", codes)

    def test_nothing_deployed_is_not_waited_for(self) -> None:
        cluster = self.nobody()
        for node in cluster.nodes:
            node.release_hash = TARGET_HASH
        paused: list[float] = []
        deploy(cluster, expected_hash=TARGET_HASH, pause=paused.append)

        self.assertEqual(cluster.triggered, [])
        self.assertEqual(paused, [])

    def test_an_owner_at_the_end_is_not_waited_for(self) -> None:
        paused: list[float] = []
        code, _ = deploy(pair(), pause=paused.append)

        self.assertEqual(code, 0)
        self.assertEqual(paused, [])

    def test_a_reading_that_fails_while_waiting_fails_the_deploy(self) -> None:
        cluster = self.nobody()
        readable = cluster.read_status

        def failing() -> dict[str, Any]:
            if len(cluster.triggered) == len(cluster.nodes):
                cluster.reads += 1
                if cluster.reads > 4:
                    return {"operation": "status"}
            return readable()

        cluster.read_status = failing  # type: ignore[method-assign]
        paused: list[float] = []
        code, shown = deploy(cluster, pause=paused.append)

        self.assertEqual(code, 68, shown)
        self.assertTrue(paused)
        self.assertIn("waiting for a node to take the VIP", shown)
        report = LAST_REPORT[0]
        assert report.error is not None  # asserted by the exit code
        self.assertEqual(report.error.code, "status_unavailable")


class TheRunKeepsToItsBudget(unittest.TestCase):
    """Review 2026-10-22, 6-9: each step had a limit and the run had none."""

    BUDGET = deploy_run.Budget(seconds=840.0, node_step=360.0, reading=60.0)

    def run_slowly(self, cluster: FakeCluster, *, per_node: float) -> tuple[int, dict[str, Any]]:
        now = [0.0]

        def read_status() -> ClusterStatus:
            return parse_status(cluster.read_status())

        def trigger(node: NodeStatus) -> int:
            now[0] += per_node
            return cluster.trigger(node.name)

        outcome = deploy_run.run(
            read_status,
            trigger,
            io.StringIO(),
            target=TARGET,
            pause=lambda _seconds: None,
            budget=self.BUDGET,
            clock=lambda: now[0],
        )
        document = outcome.report.as_envelope("alpha")
        reconcile_semantics()(document, Path("deploy"))
        return outcome.exit_code, document

    def test_a_node_there_is_no_time_left_for_is_named_and_not_started(self) -> None:
        cluster = pair()
        code, document = self.run_slowly(cluster, per_node=500.0)

        self.assertEqual(cluster.triggered, ["node-b"])
        self.assertEqual((code, document["outcome"]), (69, "partial"))
        rows = {row["name"]: row for row in document["result"]["nodes"]}
        self.assertEqual(rows["node-a"]["outcome"], "not_attempted")
        self.assertEqual(rows["node-a"]["error"]["code"], "deploy_budget_exhausted")
        self.assertEqual(rows["node-b"]["outcome"], "updated")

    def test_nodes_that_fit_are_all_deployed(self) -> None:
        cluster = pair()
        code, document = self.run_slowly(cluster, per_node=300.0)

        self.assertEqual(sorted(cluster.triggered), ["node-a", "node-b"])
        self.assertEqual((code, document["outcome"]), (0, "done"))

    def test_without_time_for_the_first_node_nothing_is_touched(self) -> None:
        self.BUDGET = deploy_run.Budget(seconds=300.0, node_step=360.0, reading=60.0)
        cluster = pair()
        code, document = self.run_slowly(cluster, per_node=1.0)

        self.assertEqual(cluster.triggered, [])
        self.assertEqual(document["outcome"], "blocked")
        self.assertEqual(document["error"]["code"], "deploy_budget_exhausted")
        self.assertEqual(code, exit_codes.BLOCKED)
