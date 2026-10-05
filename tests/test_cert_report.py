"""The cert-deploy result, against the frozen schema that describes it.

The loop and the matrix are shared with config deploy; the contract is not.
`haproxy-cert-deploy.schema.json` was frozen in phase 0 with its own required
`target_certificates`, and a run that produced a deploy-shaped result would
validate against the wrong schema and reach the interface as a valid-looking
lie. So every outcome is generated through the real loop and validated here.
"""

from __future__ import annotations

import io
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from haproxy_mgmt import deploy_run
from haproxy_mgmt.cluster_status import ClusterStatus, NodeStatus, parse_status
from haproxy_mgmt.deploy_plan import CertificateRef, CertificateTarget
from haproxy_mgmt.deploy_run import CERT_OPERATION, DeployRun
from tests.node_harness import FakeCluster, FakeNode

SCHEMA_DIR = Path(__file__).resolve().parents[1] / "schemas" / "v1"
CERT_SCHEMA = "https://example.com/haproxy-manager/schemas/v1/haproxy-cert-deploy.schema.json"

WILDCARD = "a" * 64
STALE = "c" * 64

CARRIED = (("example-net", WILDCARD),)
BEHIND = (("example-net", STALE),)
TARGET = CertificateTarget(certificates=(CertificateRef(id="example-net", fingerprint=WILDCARD),))


def validator() -> Draft202012Validator:
    registry = Registry()
    schema = None
    for path in sorted(SCHEMA_DIR.glob("*.schema.json")):
        contents = json.loads(path.read_text(encoding="utf-8"))
        registry = registry.with_resource(contents["$id"], Resource.from_contents(contents))
        if contents["$id"] == CERT_SCHEMA:
            schema = contents
    assert schema is not None
    return Draft202012Validator(schema, registry=registry)


def cluster(**overrides: object) -> FakeCluster:
    nodes = [
        FakeNode(name="node-a", mgmt_host="node-a.example.com", owns_vip=True, certificates=BEHIND),
        FakeNode(
            name="node-b", mgmt_host="node-b.example.com", owns_vip=False, certificates=BEHIND
        ),
    ]
    return FakeCluster(nodes=nodes, target_certificates=CARRIED, **overrides)  # type: ignore[arg-type]


def cert_deploy(fake: FakeCluster, **options: object) -> DeployRun:
    def read_status() -> ClusterStatus:
        return parse_status(fake.read_status())

    def trigger(node: NodeStatus) -> int:
        return fake.trigger(node.name)

    return deploy_run.run(
        read_status,
        trigger,
        io.StringIO(),
        target=TARGET,
        operation=CERT_OPERATION,
        **options,  # type: ignore[arg-type]
    )


class ContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.validator = validator()

    def check(self, run: DeployRun) -> dict:  # type: ignore[type-arg]
        payload = run.report.as_envelope("alpha")
        errors = sorted(self.validator.iter_errors(payload), key=str)
        self.assertEqual(errors, [], f"result does not match the frozen contract: {errors}")
        return payload

    def test_a_converged_run_announces_itself_as_cert_deploy(self) -> None:
        payload = self.check(cert_deploy(cluster()))

        self.assertEqual(payload["operation"], "cert_deploy")
        self.assertEqual(payload["outcome"], "done")
        self.assertTrue(payload["result"]["converged"])

    def test_the_referenced_list_is_reported_as_the_target(self) -> None:
        payload = self.check(cert_deploy(cluster()))

        self.assertEqual(
            payload["result"]["target_certificates"],
            [{"id": "example-net", "fingerprint_sha256": WILDCARD}],
        )

    def test_an_unreachable_node_is_partial_and_still_valid(self) -> None:
        fake = cluster()
        fake.node("node-b").reachable = False

        payload = self.check(cert_deploy(fake))

        self.assertEqual(payload["outcome"], "partial")
        self.assertFalse(payload["result"]["converged"])
        self.assertTrue(payload["warnings"])

    def test_a_node_that_reports_no_certificates_fails_verification(self) -> None:
        #
        # The state every real node is in today: the node-side status script
        # hardcodes an empty certificate list (Ö7). The trigger succeeds, the
        # re-read still shows the certificate missing, and the run reports
        # failure rather than claiming a rollout it cannot see.
        #
        fake = cluster()
        fake.target_certificates = ()

        payload = self.check(cert_deploy(fake))

        self.assertEqual(payload["outcome"], "failed")
        failed = [node for node in payload["result"]["nodes"] if node["outcome"] == "failed"]
        self.assertEqual(len(failed), 1)
        self.assertEqual(failed[0]["error"]["code"], "target_not_reached")


if __name__ == "__main__":
    unittest.main()
