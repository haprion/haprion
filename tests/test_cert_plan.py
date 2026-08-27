"""The certificate matrix in §6.4, against the same decision module as §6.3.

The plan is explicit that cert-deploy "jämför fingerprints, skippar current, kör
non-owner före owner och använder samma partial, invalid-VIP och manuella
catch-up-semantik som config-deploy". This file is what holds that claim to
account: the ordering, blocking and partial rows are re-run against a
certificate target, so a change that made the two operations behave differently
would fail here rather than be discovered during a certificate rollout.

What is deliberately NOT tested here
------------------------------------
Whether a real node honours any of this. The node-side pull path was inventoried
2026-08-27 (Ö6) and provably cannot yet: it is hardcoded to a single certificate
in both its source path and its validation. These are the rules the rewritten
node script has to satisfy, written down before it is rewritten so that the
rewrite has something to be measured against.
"""

from __future__ import annotations

import unittest

from haproxy_mgmt.deploy_plan import (
    CertificateRef,
    CertificateTarget,
    NodeObservation,
    Outcome,
    VipState,
)
from tests.plan_harness import drive, pair

WILDCARD = "a" * 64
INTERNAL = "b" * 64
ROTATED = "c" * 64
UNRELATED = "d" * 64

BOTH = CertificateTarget(
    certificates=(
        CertificateRef(id="example-net", fingerprint=WILDCARD),
        CertificateRef(id="example-com", fingerprint=INTERNAL),
    )
)
ONE = CertificateTarget(certificates=(CertificateRef(id="example-net", fingerprint=WILDCARD),))


def node(
    name: str,
    *,
    ok: bool = True,
    owner: bool | None = False,
    certificates: tuple[tuple[str, str], ...] | None = (),
) -> NodeObservation:
    return NodeObservation(
        name=name,
        status_ok=ok,
        owns_vip=owner,
        release_hash=None,
        certificates=certificates,
    )


CURRENT = (("example-com", INTERNAL), ("example-net", WILDCARD))
STALE = (("example-com", INTERNAL), ("example-net", ROTATED))


class FingerprintComparisonTests(unittest.TestCase):
    """Same bytes means nothing to do; different bytes means act."""

    def test_matching_fingerprints_are_skipped_as_current(self) -> None:
        state = pair(
            VipState.SINGLE_OWNER,
            node("node-a", owner=True, certificates=CURRENT),
            node("node-b", owner=False, certificates=CURRENT),
        )

        trace, outcome, code = drive([state], target=BOTH)

        self.assertEqual(trace, ["skip:node-b", "skip:node-a"])
        self.assertIs(outcome, Outcome.DONE)
        self.assertEqual(code, 0)

    def test_a_rotated_certificate_is_deployed(self) -> None:
        #
        # The renewal case: same id, different bytes. Comparing ids alone would
        # make every renewal a no-op, which is the failure that would go
        # unnoticed until a certificate expired in production.
        #
        state = pair(
            VipState.SINGLE_OWNER,
            node("node-a", owner=True, certificates=STALE),
            node("node-b", owner=False, certificates=STALE),
        )
        after = pair(
            VipState.SINGLE_OWNER,
            node("node-a", owner=True, certificates=STALE),
            node("node-b", owner=False, certificates=CURRENT),
        )
        done = pair(
            VipState.SINGLE_OWNER,
            node("node-a", owner=True, certificates=CURRENT),
            node("node-b", owner=False, certificates=CURRENT),
        )

        trace, outcome, code = drive([state, after, done], target=BOTH)

        self.assertEqual(trace, ["deploy:node-b", "deploy:node-a"])
        self.assertIs(outcome, Outcome.DONE)
        self.assertEqual(code, 0)

    def test_a_missing_referenced_certificate_is_deployed(self) -> None:
        state = pair(
            VipState.SINGLE_OWNER,
            node("node-a", owner=True, certificates=(("example-net", WILDCARD),)),
            node("node-b", owner=False, certificates=(("example-net", WILDCARD),)),
        )

        trace, _, _ = drive([state, state, state], target=BOTH)

        self.assertEqual(trace, ["deploy:node-b", "deploy:node-a"])

    def test_a_node_carrying_no_certificates_is_deployed(self) -> None:
        state = pair(
            VipState.SINGLE_OWNER,
            node("node-a", owner=True, certificates=()),
            node("node-b", owner=False, certificates=()),
        )

        trace, _, _ = drive([state, state, state], target=BOTH)

        self.assertEqual(trace, ["deploy:node-b", "deploy:node-a"])


class ReferencedSetTests(unittest.TestCase):
    """Only what the cluster references is compared, and only that."""

    def test_an_unreferenced_certificate_on_the_node_is_ignored(self) -> None:
        #
        # §6.4: cert-deploy syncs the referenced list, it does not make the node
        # match the directory. A node carrying something extra is current, and
        # the extra file is left alone rather than removed - deleting key
        # material a node may still be serving is the worse failure, and nothing
        # here can tell whether it is in use.
        #
        state = pair(
            VipState.SINGLE_OWNER,
            node("node-a", owner=True, certificates=(*CURRENT, ("other-example", UNRELATED))),
            node("node-b", owner=False, certificates=(*CURRENT, ("other-example", UNRELATED))),
        )

        trace, outcome, _ = drive([state], target=BOTH)

        self.assertEqual(trace, ["skip:node-b", "skip:node-a"])
        self.assertIs(outcome, Outcome.DONE)

    def test_a_cluster_referencing_one_certificate_ignores_the_other(self) -> None:
        #
        # The invariant that matters for a shared distribution directory: a
        # certificate reaches exactly the clusters that reference it. Here the
        # node is missing the one it does not reference, and is still current.
        #
        state = pair(
            VipState.SINGLE_OWNER,
            node("node-a", owner=True, certificates=(("example-net", WILDCARD),)),
            node("node-b", owner=False, certificates=(("example-net", WILDCARD),)),
        )

        trace, outcome, _ = drive([state], target=ONE)

        self.assertEqual(trace, ["skip:node-b", "skip:node-a"])
        self.assertIs(outcome, Outcome.DONE)


class UnansweredTests(unittest.TestCase):
    """A node that says nothing about certificates is unknown, not empty."""

    def test_a_node_that_reports_nothing_cannot_be_told_apart_as_current(self) -> None:
        observation = node("node-a", certificates=None)

        self.assertIsNone(BOTH.is_current(observation))

    def test_a_node_that_reports_nothing_is_deployed_rather_than_skipped(self) -> None:
        state = pair(
            VipState.SINGLE_OWNER,
            node("node-a", owner=True, certificates=None),
            node("node-b", owner=False, certificates=None),
        )

        trace, _, _ = drive([state, state, state], target=BOTH)

        self.assertEqual(trace, ["deploy:node-b", "deploy:node-a"])

    def test_an_empty_list_is_missing_everything_not_unknown(self) -> None:
        self.assertIs(BOTH.is_current(node("node-a", certificates=())), False)


class OrderAndBlockingTests(unittest.TestCase):
    """The §6.3 rows, re-run against a certificate target."""

    def test_the_owner_is_taken_last(self) -> None:
        state = pair(
            VipState.SINGLE_OWNER,
            node("node-a", owner=True, certificates=STALE),
            node("node-b", owner=False, certificates=STALE),
        )

        trace, _, _ = drive([state, state, state], target=BOTH)

        self.assertEqual(trace, ["deploy:node-b", "deploy:node-a"])

    def test_split_brain_blocks_and_touches_nothing(self) -> None:
        state = pair(
            VipState.SPLIT_BRAIN,
            node("node-a", owner=True, certificates=STALE),
            node("node-b", owner=True, certificates=STALE),
        )

        trace, outcome, code = drive([state], target=BOTH)

        self.assertEqual(trace, [])
        self.assertIs(outcome, Outcome.BLOCKED)
        self.assertEqual(code, 65)

    def test_an_unknown_vip_blocks_unless_overridden(self) -> None:
        state = pair(
            VipState.UNKNOWN,
            node("node-a", owner=None, certificates=STALE),
            node("node-b", owner=False, certificates=STALE),
        )

        _, blocked, _ = drive([state], target=BOTH)
        trace, overridden, _ = drive([state, state, state], target=BOTH, allow_vip_unknown=True)

        self.assertIs(blocked, Outcome.BLOCKED)
        self.assertIs(overridden, Outcome.DONE)
        self.assertEqual(trace, ["deploy:node-a", "deploy:node-b"])

    def test_an_unreadable_peer_still_reconciles_the_reachable_node(self) -> None:
        state = pair(
            VipState.INCOMPLETE,
            node("node-a", ok=False, owner=None, certificates=None),
            node("node-b", owner=False, certificates=STALE),
        )

        trace, outcome, code = drive([state, state], target=BOTH)

        self.assertEqual(trace, ["skip:node-a", "deploy:node-b"])
        self.assertIs(outcome, Outcome.PARTIAL)
        self.assertEqual(code, 69)

    def test_a_later_run_catches_up_only_the_node_that_is_behind(self) -> None:
        #
        # Manual catch-up: the operator runs the same command again once the
        # missing node is back, and it costs one deploy, not two.
        #
        state = pair(
            VipState.SINGLE_OWNER,
            node("node-a", owner=True, certificates=STALE),
            node("node-b", owner=False, certificates=CURRENT),
        )
        after = pair(
            VipState.SINGLE_OWNER,
            node("node-a", owner=True, certificates=CURRENT),
            node("node-b", owner=False, certificates=CURRENT),
        )

        trace, outcome, code = drive([state, after], target=BOTH)

        self.assertEqual(trace, ["skip:node-b", "deploy:node-a"])
        self.assertIs(outcome, Outcome.DONE)
        self.assertEqual(code, 0)

    def test_the_order_is_recomputed_when_the_vip_moves_mid_run(self) -> None:
        #
        # Harness-only in the plan's own words, and still untested in the field:
        # if the address moves after the first node is done, the remaining order
        # is decided from where it is now, not from where it was at the start.
        #
        before = pair(
            VipState.SINGLE_OWNER,
            node("node-a", owner=True, certificates=STALE),
            node("node-b", owner=False, certificates=STALE),
        )
        moved = pair(
            VipState.SINGLE_OWNER,
            node("node-a", owner=False, certificates=STALE),
            node("node-b", owner=True, certificates=CURRENT),
        )

        trace, _, _ = drive([before, moved, moved], target=BOTH)

        self.assertEqual(trace, ["deploy:node-b", "deploy:node-a"])


class ResultFieldsTests(unittest.TestCase):
    """What the run reports it was aiming at, in the frozen contract's shape."""

    def test_the_target_is_reported_as_the_referenced_list(self) -> None:
        self.assertEqual(
            BOTH.result_fields(),
            {
                "target_certificates": [
                    {"id": "example-net", "fingerprint_sha256": WILDCARD},
                    {"id": "example-com", "fingerprint_sha256": INTERNAL},
                ]
            },
        )


if __name__ == "__main__":
    unittest.main()
