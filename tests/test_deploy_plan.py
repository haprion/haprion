"""The deploy matrix in §6.3, row by row.

The plan calls that matrix normative and complete: every state has a defined
behaviour and order, and none of it may be left to the implementation to
interpret. So it is tested as a matrix rather than as a handful of happy paths,
and the rows that cannot be provoked on a real pair - split brain, zero owners,
an indeterminate answer - are exactly the rows that matter most here.

The loop is modelled the way the real one will run: observe, ask, act, observe
again. Feeding a stale observation back is the one way to misuse the module, so
the driver below always takes the next observation from a list.
"""

from __future__ import annotations

import unittest

from haproxy_mgmt.deploy_plan import (
    Action,
    Outcome,
    ReleaseTarget,
    VipState,
    next_step,
    warnings_for,
)
from tests.plan_harness import BEHIND, TARGET, drive, node, pair


class BothNodesReadableTests(unittest.TestCase):
    """Table one: both nodes return usable status."""

    def test_exactly_one_owner_deploys_the_non_owner_first(self) -> None:
        state = pair(
            VipState.SINGLE_OWNER,
            node("node-a", owner=True),
            node("node-b", owner=False),
        )

        trace, outcome, code = drive([state, state, state])

        self.assertEqual(trace, ["deploy:node-b", "deploy:node-a"])
        self.assertIs(outcome, Outcome.DONE)
        self.assertEqual(code, 0)

    def test_zero_owners_deploys_both_in_configured_order_and_warns(self) -> None:
        state = pair(
            VipState.NO_OWNER,
            node("node-a", owner=False),
            node("node-b", owner=False),
        )

        trace, outcome, _ = drive([state, state, state])

        self.assertEqual(trace, ["deploy:node-a", "deploy:node-b"])
        self.assertIs(outcome, Outcome.DONE)
        self.assertIn("no node currently owns the VIP; it is down", warnings_for(state))

    def test_two_owners_block_and_cannot_be_overridden(self) -> None:
        state = pair(
            VipState.SPLIT_BRAIN,
            node("node-a", owner=True),
            node("node-b", owner=True),
        )

        for override in (False, True):
            step = next_step(state, allow_vip_unknown=override)
            self.assertIs(step.action, Action.BLOCKED, override)
            self.assertIs(step.outcome, Outcome.BLOCKED)
            self.assertEqual(step.exit_code, 65)
            self.assertIn("split brain", step.reason)

    def test_an_indeterminate_answer_blocks_without_the_override(self) -> None:
        state = pair(
            VipState.UNKNOWN,
            node("node-a", owner=None),
            node("node-b", owner=False),
        )

        step = next_step(state)

        self.assertIs(step.action, Action.BLOCKED)
        self.assertEqual(step.exit_code, 65)
        self.assertIn("--allow-vip-unknown", step.reason)

    def test_the_override_turns_it_into_the_zero_owner_row(self) -> None:
        state = pair(
            VipState.UNKNOWN,
            node("node-a", owner=None),
            node("node-b", owner=False),
        )

        trace, outcome, _ = drive([state, state, state], allow_vip_unknown=True)

        self.assertEqual(trace, ["deploy:node-a", "deploy:node-b"])
        self.assertIs(outcome, Outcome.DONE)
        self.assertIn("explicit CLI override accepted", warnings_for(state, allow_vip_unknown=True))


class OneNodeReadableTests(unittest.TestCase):
    """Table two: the peer cannot be read. Always partial, never blocked."""

    def test_the_reachable_node_is_reconciled_whoever_owns_the_vip(self) -> None:
        for owner in (True, False, None):
            state = pair(
                VipState.INCOMPLETE,
                node("node-a", ok=False, owner=None, hash_=None),
                node("node-b", owner=owner),
            )

            trace, outcome, code = drive([state, state])

            self.assertEqual(trace, ["skip:node-a", "deploy:node-b"], owner)
            self.assertIs(outcome, Outcome.PARTIAL, owner)
            self.assertEqual(code, 69)

    def test_an_unreadable_peer_is_named_in_the_warnings(self) -> None:
        state = pair(
            VipState.INCOMPLETE,
            node("node-a", ok=False, owner=None, hash_=None),
            node("node-b"),
        )

        self.assertEqual(
            warnings_for(state),
            (
                "partial cluster status; only reachable nodes will be reconciled",
                "unavailable: node-a",
            ),
        )

    def test_no_node_readable_at_all_stops_before_anything_is_touched(self) -> None:
        state = pair(
            VipState.INCOMPLETE,
            node("node-a", ok=False, owner=None, hash_=None),
            node("node-b", ok=False, owner=None, hash_=None),
        )

        step = next_step(state)

        self.assertIs(step.action, Action.BLOCKED)
        self.assertEqual(step.exit_code, 68)
        self.assertIn("no node returned usable status", step.reason)


class ReplanningTests(unittest.TestCase):
    """The gap the shell command had: the order is re-decided, not remembered."""

    def test_a_vip_that_moves_mid_run_changes_the_remaining_order(self) -> None:
        #
        # Three nodes so the reordering is visible: node-a owns the VIP at the
        # start, so it should go last - but after the first deploy the VIP moves
        # to node-c, and node-a is no longer the one to hold back.
        #
        before = pair(
            VipState.SINGLE_OWNER,
            node("node-a", owner=True),
            node("node-b", owner=False),
            node("node-c", owner=False),
        )
        after = pair(
            VipState.SINGLE_OWNER,
            node("node-a", owner=False),
            node("node-b", owner=False),
            node("node-c", owner=True),
        )

        trace, outcome, _ = drive([before, after, after, after])

        self.assertEqual(trace, ["deploy:node-b", "deploy:node-a", "deploy:node-c"])
        self.assertIs(outcome, Outcome.DONE)

    def test_split_brain_appearing_mid_run_stops_the_rest(self) -> None:
        before = pair(
            VipState.SINGLE_OWNER,
            node("node-a", owner=True),
            node("node-b", owner=False),
        )
        after = pair(
            VipState.SPLIT_BRAIN,
            node("node-a", owner=True),
            node("node-b", owner=True),
        )

        trace, outcome, code = drive([before, after, after])

        self.assertEqual(trace, ["deploy:node-b"])
        self.assertIs(outcome, Outcome.BLOCKED)
        self.assertEqual(code, 65)

    def test_ownership_becoming_unknown_mid_run_stops_the_rest(self) -> None:
        before = pair(
            VipState.SINGLE_OWNER,
            node("node-a", owner=True),
            node("node-b", owner=False),
        )
        after = pair(
            VipState.UNKNOWN,
            node("node-a", owner=None),
            node("node-b", owner=False),
        )

        trace, outcome, code = drive([before, after, after])

        self.assertEqual(trace, ["deploy:node-b"])
        self.assertIs(outcome, Outcome.BLOCKED)
        self.assertEqual(code, 65)

    def test_a_node_that_stops_answering_mid_run_is_skipped_not_blocked(self) -> None:
        before = pair(
            VipState.SINGLE_OWNER,
            node("node-a", owner=True),
            node("node-b", owner=False),
        )
        after = pair(
            VipState.INCOMPLETE,
            node("node-a", ok=False, owner=None, hash_=None),
            node("node-b", owner=False),
        )

        trace, outcome, code = drive([before, after, after])

        self.assertEqual(trace, ["deploy:node-b", "skip:node-a"])
        self.assertIs(outcome, Outcome.PARTIAL)
        self.assertEqual(code, 69)


class CurrentSkipTests(unittest.TestCase):
    """Step 3 of §6.3: a node already on the target is not redeployed."""

    def test_a_node_already_on_the_target_is_skipped(self) -> None:
        state = pair(
            VipState.SINGLE_OWNER,
            node("node-a", owner=True, hash_=TARGET),
            node("node-b", owner=False, hash_=BEHIND),
        )

        trace, outcome, code = drive([state, state], target=ReleaseTarget(version=8, hash=TARGET))

        self.assertEqual(trace, ["deploy:node-b", "skip:node-a"])
        self.assertIs(outcome, Outcome.DONE)
        self.assertEqual(code, 0)

    def test_skipping_a_current_node_is_success_not_partial(self) -> None:
        #
        # The distinction that makes a re-run after a partial worth doing: a node
        # passed over because it was already right is not a node that could not
        # be verified.
        #
        state = pair(
            VipState.SINGLE_OWNER,
            node("node-a", owner=True, hash_=TARGET),
            node("node-b", owner=False, hash_=TARGET),
        )

        trace, outcome, code = drive([state], target=ReleaseTarget(version=8, hash=TARGET))

        self.assertEqual(trace, ["skip:node-b", "skip:node-a"])
        self.assertIs(outcome, Outcome.DONE)
        self.assertEqual(code, 0)

    def test_without_a_target_nothing_is_skipped_as_current(self) -> None:
        state = pair(
            VipState.SINGLE_OWNER,
            node("node-a", owner=True, hash_=TARGET),
            node("node-b", owner=False, hash_=TARGET),
        )

        trace, _, _ = drive([state, state, state])

        self.assertEqual(trace, ["deploy:node-b", "deploy:node-a"])


class StopRuleTests(unittest.TestCase):
    def test_a_failure_on_the_first_node_stops_before_the_second(self) -> None:
        state = pair(
            VipState.NO_OWNER,
            node("node-a", owner=False),
            node("node-b", owner=False),
        )

        trace, outcome, code = drive([state, state, state], fail_on="node-a")

        self.assertEqual(trace, ["deploy:node-a"])
        self.assertIs(outcome, Outcome.FAILED)
        self.assertEqual(code, 69)

    def test_a_target_that_moved_under_the_lock_blocks_everything(self) -> None:
        state = pair(
            VipState.SINGLE_OWNER,
            node("node-a", owner=True),
            node("node-b", owner=False),
        )

        step = next_step(state, target_moved=True)

        self.assertIs(step.action, Action.BLOCKED)
        self.assertIs(step.outcome, Outcome.BLOCKED)
        self.assertEqual(step.exit_code, 65)
        self.assertIn("nothing was deployed", step.reason)

    def test_the_target_check_runs_before_the_ownership_checks(self) -> None:
        #
        # Order matters for the message an operator gets: a moved target is a
        # reason not to deploy at all, and reporting split brain instead would
        # send them to investigate the wrong thing.
        #
        state = pair(
            VipState.SPLIT_BRAIN,
            node("node-a", owner=True),
            node("node-b", owner=True),
        )

        step = next_step(state, target_moved=True)

        self.assertIn("the published target changed", step.reason)


if __name__ == "__main__":
    unittest.main()
