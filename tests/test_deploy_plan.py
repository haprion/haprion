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

from haprion import exit_codes
from haprion.cluster_status import parse_status
from haprion.deploy_plan import (
    Action,
    Outcome,
    ReleaseTarget,
    VipState,
    next_step,
    warnings_for,
)
from tests.plan_harness import BEHIND, TARGET, drive, node, pair
from tests.test_status_addresses import envelope, node_status


class MoreThanTwoNodesTests(unittest.TestCase):
    """Every standby first in configured order, the owner last (B211)."""

    def test_the_owner_in_the_middle_is_still_deployed_last(self) -> None:
        state = pair(
            VipState.SINGLE_OWNER,
            node("node-a", owner=False),
            node("node-b", owner=True),
            node("node-c", owner=False),
        )

        trace, outcome, code = drive([state] * 4)

        self.assertEqual(trace, ["deploy:node-a", "deploy:node-c", "deploy:node-b"])
        self.assertIs(outcome, Outcome.DONE)
        self.assertEqual(code, 0)

    def test_one_unreadable_node_of_three_leaves_the_others_reconciled(self) -> None:
        state = pair(
            VipState.INCOMPLETE,
            node("node-a", owner=True),
            node("node-b", ok=False, owner=None, hash_=None),
            node("node-c"),
        )

        trace, outcome, code = drive([state] * 3)

        # The owner last although the summary is INCOMPLETE (review 2026-10-03, F1).
        self.assertEqual(trace, ["skip:node-b", "deploy:node-c", "deploy:node-a"])
        self.assertIs(outcome, Outcome.PARTIAL)
        self.assertEqual(code, 69)


class ANodeThatStartsKeepalivedGoesLast(unittest.TestCase):
    """B320, Fas 18 finding 75: the node whose deploy starts keepalived goes after the owner.

    Deployed first, an added node started keepalived before the owner had it as
    a peer, heard nobody, and would have taken the addresses three advertisement
    intervals later had the owner's deploy not come within one second.
    """

    def test_an_added_node_goes_after_the_owner(self) -> None:
        state = pair(
            VipState.SINGLE_OWNER,
            node("node-a", owner=True, keepalived=True),
            node("node-b", owner=False, keepalived=False),
        )

        trace, outcome, code = drive([state] * 3)

        self.assertEqual(trace, ["deploy:node-a", "deploy:node-b"])
        self.assertIs(outcome, Outcome.DONE)
        self.assertEqual(code, 0)

    def test_the_running_standbys_still_go_before_the_owner(self) -> None:
        state = pair(
            VipState.SINGLE_OWNER,
            node("node-a", owner=True, keepalived=True),
            node("node-b", owner=False, keepalived=False),
            node("node-c", owner=False, keepalived=True),
        )

        trace, _, _ = drive([state] * 4)

        self.assertEqual(trace, ["deploy:node-c", "deploy:node-a", "deploy:node-b"])

    def test_a_new_cluster_keeps_its_configured_order(self) -> None:
        state = pair(
            VipState.NO_OWNER,
            node("node-a", owner=False, keepalived=False),
            node("node-b", owner=False, keepalived=False),
        )

        trace, _, _ = drive([state] * 3)

        self.assertEqual(trace, ["deploy:node-a", "deploy:node-b"])

    def test_a_node_that_did_not_say_is_ordered_as_before(self) -> None:
        state = pair(
            VipState.SINGLE_OWNER,
            node("node-a", owner=True, keepalived=None),
            node("node-b", owner=False, keepalived=None),
        )

        trace, _, _ = drive([state] * 3)

        self.assertEqual(trace, ["deploy:node-b", "deploy:node-a"])

    def test_an_owner_whose_keepalived_reads_stopped_is_still_an_owner(self) -> None:
        state = pair(
            VipState.SINGLE_OWNER,
            node("node-a", owner=True, keepalived=False),
            node("node-b", owner=False, keepalived=True),
        )

        trace, _, _ = drive([state] * 3)

        self.assertEqual(trace, ["deploy:node-b", "deploy:node-a"])

    def test_the_deploy_reads_it_from_the_status_it_parsed(self) -> None:
        for active, expected in ((True, True), (False, False), ("yes", None)):
            with self.subTest(active=active):
                status = node_status({"active": active, "state": "BACKUP"})
                observed = parse_status(envelope(status)).observation().nodes[0]
                self.assertIs(observed.keepalived_active, expected)

        observed = parse_status(envelope(node_status(None))).observation().nodes[0]
        self.assertIsNone(observed.keepalived_active)


class AnObservedConflictIsNeverDeployedInto(unittest.TestCase):
    """Review 2026-10-03, F1: what is known about the nodes, not only the summary."""

    def test_two_owners_and_an_unreadable_node_stop_even_with_the_override(self) -> None:
        for summary in (VipState.INCOMPLETE, VipState.UNKNOWN):
            state = pair(
                summary,
                node("node-a", owner=True),
                node("node-b", owner=True),
                node("node-c", ok=False, owner=None, hash_=None),
            )
            for override in (False, True):
                with self.subTest(summary=summary, override=override):
                    trace, outcome, _ = drive([state], allow_vip_unknown=override)
                    self.assertEqual(trace, [])
                    self.assertIs(outcome, Outcome.BLOCKED)

    def test_a_conflict_that_appears_after_the_first_change_stops_the_rest(self) -> None:
        before = pair(
            VipState.INCOMPLETE,
            node("node-a", owner=False),
            node("node-b", owner=True),
            node("node-c", ok=False, owner=None, hash_=None),
        )
        after = pair(
            VipState.INCOMPLETE,
            node("node-a", owner=True, hash_=TARGET),
            node("node-b", owner=True),
            node("node-c", ok=False, owner=None, hash_=None),
        )

        trace, outcome, _ = drive([before, after], target=ReleaseTarget(version=8, hash=TARGET))

        self.assertEqual(trace, ["deploy:node-a"])
        # Something already changed: partial, as any stop after a change (review 2026-09-28 F4).
        self.assertIs(outcome, Outcome.PARTIAL)

    def test_with_one_node_unreadable_the_standby_goes_before_the_owner(self) -> None:
        state = pair(
            VipState.INCOMPLETE,
            node("node-a", owner=True),
            node("node-b", owner=False),
            node("node-c", ok=False, owner=None, hash_=None),
        )

        trace, outcome, _ = drive([state] * 3)

        self.assertEqual(trace, ["deploy:node-b", "skip:node-c", "deploy:node-a"])
        self.assertIs(outcome, Outcome.PARTIAL)

    def test_unknown_ownership_among_several_goes_between_standby_and_owner(self) -> None:
        state = pair(
            VipState.UNKNOWN,
            node("node-a", owner=True),
            node("node-b", owner=None),
            node("node-c", owner=False),
        )

        trace, _, _ = drive([state] * 4, allow_vip_unknown=True)

        self.assertEqual(trace, ["deploy:node-c", "deploy:node-b", "deploy:node-a"])


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

    def test_the_first_deploy_says_nothing_about_the_vip_it_brings_up(self) -> None:
        state = pair(
            VipState.NO_OWNER,
            node("node-a", owner=False, hash_=None),
            node("node-b", owner=False, hash_=None),
        )

        trace, outcome, _ = drive([state, state, state])

        self.assertEqual(trace, ["deploy:node-a", "deploy:node-b"])
        self.assertIs(outcome, Outcome.DONE)
        self.assertEqual(warnings_for(state), ())

    def test_a_node_with_a_release_and_no_owner_still_warns(self) -> None:
        state = pair(
            VipState.NO_OWNER,
            node("node-a", owner=False, hash_=None),
            node("node-b", owner=False),
        )

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
            self.assertEqual(step.exit_code, exit_codes.BLOCKED)
            self.assertIn("split brain", step.reason)

    def test_an_indeterminate_answer_blocks_without_the_override(self) -> None:
        state = pair(
            VipState.UNKNOWN,
            node("node-a", owner=None),
            node("node-b", owner=False),
        )

        step = next_step(state)

        self.assertIs(step.action, Action.BLOCKED)
        self.assertEqual(step.exit_code, exit_codes.BLOCKED)
        self.assertIn("--allow-vip-unknown", step.reason)

    def test_the_override_turns_it_into_the_zero_owner_row(self) -> None:
        state = pair(
            VipState.UNKNOWN,
            node("node-a", owner=None),
            node("node-b", owner=False),
        )

        trace, outcome, _ = drive([state, state, state], allow_vip_unknown=True)

        # The known standby before the node whose ownership is unknown (review 2026-10-03, F1).
        self.assertEqual(trace, ["deploy:node-b", "deploy:node-a"])
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
        self.assertEqual(step.exit_code, exit_codes.BLOCKED)
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

        # node-b already carries the target: partial, not "nothing was touched"
        # (review 2026-09-28 F4).
        self.assertEqual(trace, ["deploy:node-b"])
        self.assertIs(outcome, Outcome.PARTIAL)
        self.assertEqual(code, 69)

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

        # node-b already carries the target: partial, not "nothing was touched"
        # (review 2026-09-28 F4).
        self.assertEqual(trace, ["deploy:node-b"])
        self.assertIs(outcome, Outcome.PARTIAL)
        self.assertEqual(code, 69)

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
        #
        # The reading after node-b's deploy shows it on the target. Fed the
        # same state twice, the run ended converged with node-b still behind -
        # which is the gap CR-08 closed, not a property worth keeping.
        #
        landed = pair(
            VipState.SINGLE_OWNER,
            node("node-a", owner=True, hash_=TARGET),
            node("node-b", owner=False, hash_=TARGET),
        )

        trace, outcome, code = drive([state, landed], target=ReleaseTarget(version=8, hash=TARGET))

        self.assertEqual(trace, ["deploy:node-b", "skip:node-a"])
        self.assertIs(outcome, Outcome.DONE)
        self.assertEqual(code, 0)

    def test_a_node_that_fell_back_while_another_was_deployed_is_not_converged(self) -> None:
        """CR-08 scenario A: node-b deployed and verified, then back on the old release."""

        before = pair(
            VipState.SINGLE_OWNER,
            node("node-a", owner=True, hash_=BEHIND),
            node("node-b", owner=False, hash_=BEHIND),
        )
        b_landed = pair(
            VipState.SINGLE_OWNER,
            node("node-a", owner=True, hash_=BEHIND),
            node("node-b", owner=False, hash_=TARGET),
        )
        b_fell_back = pair(
            VipState.SINGLE_OWNER,
            node("node-a", owner=True, hash_=TARGET),
            node("node-b", owner=False, hash_=BEHIND),
        )

        trace, outcome, code = drive(
            [before, b_landed, b_fell_back], target=ReleaseTarget(version=8, hash=TARGET)
        )

        self.assertEqual(trace, ["deploy:node-b", "deploy:node-a"])
        self.assertIs(outcome, Outcome.PARTIAL)
        self.assertEqual(code, exit_codes.PARTIAL)

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

    def test_the_release_hash_alone_does_not_make_a_node_current(self) -> None:
        """The half-way node, and the reason current means every component.

        The node took the configuration and did not take the address list its
        release publishes. Its hash is the target hash, so the hash alone calls
        it done and passes over the one node that still needs the repair.
        """

        state = pair(
            VipState.SINGLE_OWNER,
            node("node-a", owner=True, hash_=TARGET, addresses=False),
            node("node-b", owner=False, hash_=TARGET, addresses=True),
        )
        repaired = pair(
            VipState.SINGLE_OWNER,
            node("node-a", owner=True, hash_=TARGET, addresses=True),
            node("node-b", owner=False, hash_=TARGET, addresses=True),
        )

        trace, outcome, code = drive(
            [state, repaired], target=ReleaseTarget(version=8, hash=TARGET)
        )

        self.assertEqual(trace, ["skip:node-b", "deploy:node-a"])
        self.assertIs(outcome, Outcome.DONE)
        self.assertEqual(code, 0)

    def test_a_node_whose_rsyslog_kept_the_old_forwarding_is_not_current(self) -> None:
        """Review 26-10-13, A1: rsyslog refused the new receivers after the reload.

        The node runs the target hash and put the previous forwarding back, so
        the hash alone passes it over and it forwards to the old receivers until
        an unrelated release comes along.
        """

        state = pair(
            VipState.SINGLE_OWNER,
            node("node-a", owner=True, hash_=TARGET, forwarding=False),
            node("node-b", owner=False, hash_=TARGET),
        )
        repaired = pair(
            VipState.SINGLE_OWNER,
            node("node-a", owner=True, hash_=TARGET),
            node("node-b", owner=False, hash_=TARGET),
        )

        trace, outcome, code = drive(
            [state, repaired], target=ReleaseTarget(version=8, hash=TARGET)
        )

        self.assertEqual(trace, ["skip:node-b", "deploy:node-a"])
        self.assertIs(outcome, Outcome.DONE)
        self.assertEqual(code, 0)

    def test_a_node_that_said_nothing_about_its_addresses_is_not_called_current(self) -> None:
        """Unknown is not the same as right, and it is not the same as wrong.

        A node still running an older status script cannot answer the question,
        so it is reconciled rather than skipped. Redeploying a node that was
        already right costs one pull; skipping one that was not costs the VIP.
        """

        state = pair(
            VipState.SINGLE_OWNER,
            node("node-a", owner=True, hash_=TARGET, addresses=None),
            node("node-b", owner=False, hash_=TARGET, addresses=None),
        )

        trace, _, _ = drive([state, state, state], target=ReleaseTarget(version=8, hash=TARGET))

        self.assertEqual(trace, ["deploy:node-b", "deploy:node-a"])

    def test_a_node_behind_on_the_release_is_behind_whatever_its_addresses_say(self) -> None:
        state = pair(
            VipState.SINGLE_OWNER,
            node("node-a", owner=True, hash_=TARGET),
            node("node-b", owner=False, hash_=BEHIND, addresses=None),
        )

        target = ReleaseTarget(version=8, hash=TARGET)

        self.assertIs(target.is_current(state.nodes[1]), False)

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
        self.assertEqual(code, exit_codes.FAILED)

    def test_a_target_that_moved_under_the_lock_blocks_everything(self) -> None:
        state = pair(
            VipState.SINGLE_OWNER,
            node("node-a", owner=True),
            node("node-b", owner=False),
        )

        step = next_step(state, target_moved=True)

        self.assertIs(step.action, Action.BLOCKED)
        self.assertIs(step.outcome, Outcome.BLOCKED)
        self.assertEqual(step.exit_code, exit_codes.BLOCKED)
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
