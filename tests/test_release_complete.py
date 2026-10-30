"""A node that failed after its HAProxy reload is not current (review 26-10-30, D1).

`haprion-pull-deploy` keeps a marker from the reload until every step after it
has succeeded; the node reports it as `release.complete: false`. The case that
motivated it: only keepalived.conf changed, the step failed, and no other field
measures that file - the node carried the target hash and an unchanged address
list, so the next deploy called it current.
"""

from __future__ import annotations

import io
import unittest

from haprion import deploy_run
from haprion.cluster_status import BEHIND_STEPS, behind_part, parse_status, release_complete
from haprion.deploy_plan import NodeObservation, ReleaseTarget
from tests.node_harness import TARGET_HASH, pair

TARGET = ReleaseTarget(version=8, hash=TARGET_HASH)


class WhatTheManagerMakesOfIt(unittest.TestCase):
    def test_only_an_explicit_false_is_incomplete(self) -> None:
        self.assertIs(release_complete({"release": {"complete": False}}), False)
        self.assertIs(release_complete({"release": {"complete": True}}), True)

    def test_a_node_from_before_the_field_is_not_held_to_it(self) -> None:
        self.assertIs(release_complete({"release": {"hash": "a"}}), True)
        self.assertIs(release_complete({}), True)

    def test_the_target_hash_with_an_incomplete_release_is_not_current(self) -> None:
        node = NodeObservation(
            name="node-a", status_ok=True, release_hash=TARGET_HASH, addresses_current=True
        )
        self.assertIs(TARGET.is_current(node), True)
        incomplete = NodeObservation(
            name="node-a",
            status_ok=True,
            release_hash=TARGET_HASH,
            addresses_current=True,
            release_complete=False,
        )
        self.assertIs(TARGET.is_current(incomplete), False)

    def test_the_part_is_named(self) -> None:
        status = {"release": {"hash": TARGET_HASH, "complete": False}}
        self.assertEqual(behind_part(status, TARGET_HASH), BEHIND_STEPS)
        self.assertIsNone(behind_part({"release": {"hash": TARGET_HASH}}, TARGET_HASH))


class TheNextDeployTriesAgain(unittest.TestCase):
    def test_a_node_on_the_target_hash_that_never_completed_is_triggered(self) -> None:
        cluster = pair()
        cluster.node("node-b").release_hash = TARGET_HASH
        cluster.node("node-b").complete = False
        out = io.StringIO()

        result = deploy_run.run(
            lambda: parse_status(cluster.read_status()),
            lambda node: cluster.trigger(node.name),
            out,
            target=TARGET,
            pause=lambda seconds: None,
        )

        self.assertIn("node-b", cluster.triggered)
        self.assertNotIn("node-b already runs", out.getvalue())
        self.assertEqual(result.exit_code, 0, out.getvalue())
        self.assertIs(cluster.node("node-b").complete, True)


if __name__ == "__main__":
    unittest.main()
