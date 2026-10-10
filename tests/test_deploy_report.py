"""The deploy result, validated against the frozen schema that describes it.

A result is not "some JSON the command happens to print". `haprion-deploy` has a
contract in `schemas/v1/haprion-deploy.schema.json`, frozen in phase 0, and the
interface and the poller will read it. So every outcome the loop can reach is
generated here and validated against that schema rather than against a
hand-written example of it.
"""

from __future__ import annotations

import io
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from haprion import deploy_run
from haprion.cluster_status import ClusterStatus, NodeStatus, parse_status
from haprion.deploy_plan import ReleaseTarget, Target
from haprion.deploy_run import DeployRun
from tests.node_harness import TARGET_HASH, FakeCluster, pair

SCHEMA_DIR = Path(__file__).resolve().parents[1] / "schemas" / "v1"
DEPLOY_SCHEMA = "https://example.com/haprion/schemas/v1/haprion-deploy.schema.json"

TARGET = ReleaseTarget(version=8, hash=TARGET_HASH)


def validator() -> Draft202012Validator:
    registry = Registry()
    schema = None
    for path in sorted(SCHEMA_DIR.glob("*.schema.json")):
        contents = json.loads(path.read_text(encoding="utf-8"))
        registry = registry.with_resource(contents["$id"], Resource.from_contents(contents))
        if contents["$id"] == DEPLOY_SCHEMA:
            schema = contents
    assert schema is not None
    return Draft202012Validator(schema, registry=registry)


def deploy(cluster: FakeCluster, *, target: Target | None = TARGET, **options: object) -> DeployRun:
    def read_status() -> ClusterStatus:
        return parse_status(cluster.read_status())

    def trigger(node: NodeStatus) -> int:
        return cluster.trigger(node.name)

    return deploy_run.run(read_status, trigger, io.StringIO(), target=target, **options)  # type: ignore[arg-type]


class ContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.validator = validator()

    def check(self, run: DeployRun) -> dict:  # type: ignore[type-arg]
        payload = run.report.as_envelope("alpha")
        errors = sorted(self.validator.iter_errors(payload), key=str)
        self.assertEqual(
            [error.message for error in errors], [], json.dumps(payload, indent=2, sort_keys=True)
        )
        return payload

    def test_a_clean_run_produces_a_valid_done_envelope(self) -> None:
        payload = self.check(deploy(pair()))

        self.assertEqual(payload["outcome"], "done")
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["result"]["converged"])
        self.assertIsNone(payload["error"])
        self.assertEqual(
            [node["outcome"] for node in payload["result"]["nodes"]], ["updated", "updated"]
        )

    def test_a_partial_run_carries_the_node_that_could_not_be_read(self) -> None:
        cluster = pair()
        cluster.node("node-a").reachable = False

        payload = self.check(deploy(cluster))

        self.assertEqual(payload["outcome"], "partial")
        self.assertFalse(payload["result"]["converged"])
        self.assertGreaterEqual(len(payload["warnings"]), 1)
        by_name = {node["name"]: node for node in payload["result"]["nodes"]}
        self.assertEqual(by_name["node-a"]["outcome"], "unavailable")
        self.assertFalse(by_name["node-a"]["reachable"])
        self.assertIsNone(by_name["node-a"]["current_before"])
        self.assertEqual(by_name["node-b"]["outcome"], "updated")

    def test_a_blocked_run_carries_an_error_and_no_result(self) -> None:
        cluster = pair()
        cluster.split_brain()

        payload = self.check(deploy(cluster))

        self.assertEqual(payload["outcome"], "blocked")
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"]["code"], "deploy_blocked")
        self.assertIn("split brain", payload["error"]["message"])

    def test_a_failed_run_names_the_node_that_failed(self) -> None:
        cluster = pair()
        cluster.node("node-b").reload_fails = True

        payload = self.check(deploy(cluster))

        self.assertEqual(payload["outcome"], "failed")
        by_name = {node["name"]: node for node in payload["result"]["nodes"]}
        self.assertEqual(by_name["node-b"]["outcome"], "failed")
        self.assertEqual(by_name["node-b"]["error"]["code"], "trigger_failed")
        self.assertEqual(by_name["node-a"]["outcome"], "not_attempted")

    def test_a_node_already_current_is_reported_as_current_not_updated(self) -> None:
        cluster = pair()
        cluster.node("node-a").release_hash = TARGET_HASH

        payload = self.check(deploy(cluster))

        by_name = {node["name"]: node for node in payload["result"]["nodes"]}
        self.assertTrue(by_name["node-a"]["current_before"])
        self.assertEqual(by_name["node-a"]["action"], "skip")
        self.assertEqual(by_name["node-a"]["outcome"], "current")
        self.assertTrue(by_name["node-a"]["verified"])
        self.assertEqual(payload["outcome"], "done")

    def test_both_summaries_are_the_status_commands_own(self) -> None:
        #
        # Passed through rather than rebuilt: the deploy result and the status
        # command must not be able to describe the same cluster differently.
        #
        cluster = pair()
        before = cluster.read_status()["result"]["summary"]

        payload = self.check(deploy(cluster))

        self.assertEqual(payload["result"]["initial_summary"], before)
        self.assertEqual(payload["result"]["final_summary"]["vip_state"], "single_owner")


class VerificationTests(unittest.TestCase):
    """A node that reports success is not taken at its word."""

    def test_a_node_that_reports_success_without_landing_on_the_target_fails(self) -> None:
        cluster = pair()
        #
        # The trigger returns 0 but the node stays where it was - a reload that
        # claimed to work, or a pull that quietly wrote nothing.
        #
        cluster.target_hash = "9" * 40

        run = deploy(cluster)

        self.assertEqual(run.report.outcome.value, "failed")
        entry = run.report.nodes["node-b"]
        self.assertEqual(entry.outcome, "failed")
        assert entry.error is not None
        self.assertEqual(entry.error.code, "target_not_reached")
        self.assertEqual(cluster.triggered, ["node-b"])

    def test_a_node_that_lands_on_the_target_is_marked_verified(self) -> None:
        run = deploy(pair())

        self.assertTrue(all(node.verified for node in run.report.nodes.values()))

    def test_without_a_target_nothing_is_claimed_as_verified(self) -> None:
        #
        # Honest rather than optimistic: with no target there is nothing to
        # compare the node against, so "verified" would be a claim about a
        # comparison that never happened.
        #
        run = deploy(pair(), target=None)

        self.assertFalse(any(node.verified for node in run.report.nodes.values()))
        self.assertIsNone(run.report.result())


if __name__ == "__main__":
    unittest.main()
