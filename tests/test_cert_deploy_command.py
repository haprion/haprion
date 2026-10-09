"""The two halves of the certificate command, and the seam between them.

The matrix is tested in test_cert_plan and the result shape in test_cert_report.
What is tested here is the boundary: what the caller may say, what the
privileged half refuses to be told, and where each decision is taken.

The property worth stating plainly: the caller cannot name a certificate. It
sends a cluster name and two booleans. Which certificates go out is read from
the cluster configuration inside the boundary, so an unprivileged process cannot
put key material on a node the configuration never referenced.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

from haproxy_mgmt.cli import cert_deploy, cert_deploy_helper
from haproxy_mgmt.cluster_lock import hold
from haproxy_mgmt.cluster_status import ClusterStatus, NodeStatus, parse_status
from haproxy_mgmt.config import DeployIdentity
from tests.contract_schema import assert_contract
from tests.node_harness import FakeCluster, FakeNode

BASE = Path(__file__).resolve().parents[1]
REQUEST_ID = "55555555-5555-4555-8555-555555555555"

DELIMITER = "-" * 5
LEAF = b"the-leaf-certificate"
FINGERPRINT = hashlib.sha256(LEAF).hexdigest()


def pem() -> str:
    body = base64.b64encode(LEAF).decode("ascii")
    return (
        f"{DELIMITER}BEGIN CERTIFICATE{DELIMITER}\n{body}\n{DELIMITER}END CERTIFICATE{DELIMITER}\n"
    )


def request(cluster: str = "alpha", **parameters: bool) -> bytes:
    return json.dumps(
        {
            "schema_version": 1,
            "operation": "cert_deploy_cluster",
            "cluster": cluster,
            "request_id": REQUEST_ID,
            "parameters": parameters,
        }
    ).encode()


class HelperFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.requests: list[str] = []
        self.cluster = FakeCluster(
            nodes=[
                FakeNode(name="node-a", mgmt_host="node-a.example.com", owns_vip=True),
                FakeNode(name="node-b", mgmt_host="node-b.example.com", owns_vip=False),
            ],
            target_certificates=(("example-net", FINGERPRINT),),
        )

    def runtime(self, *, certificates: bool = True, identity: bool = True) -> Path:
        config_root = self.root / "config"
        publish_root = self.root / "published"
        cert_root = self.root / "validation"
        dist_root = self.root / "certdist"
        for directory in (config_root, publish_root, cert_root, dist_root):
            directory.mkdir(parents=True, exist_ok=True)
        (cert_root / "validation.pem").write_text("dummy PEM\n", encoding="utf-8")
        (config_root / "alpha").mkdir(exist_ok=True)
        if certificates:
            (dist_root / "example-net.pem").write_text(pem(), encoding="ascii")

        clusters = yaml.safe_load((BASE / "examples/clusters.yaml").read_text())
        entry = clusters["clusters"]["alpha"]
        entry["config_path"] = str(config_root / "alpha")
        entry["publish_path"] = str(publish_root / "alpha")
        entry["validation_certs"] = str(cert_root)
        entry["certificate_ids"] = ["example-net"]
        entry["default_certificate"] = "example-net"
        (self.root / "clusters.yaml").write_text(yaml.safe_dump(clusters), encoding="utf-8")

        policy = {
            "schema_version": 1,
            "cluster_file": str(self.root / "clusters.yaml"),
            "config_root": str(config_root),
            "publish_root": str(publish_root),
            "validation_certs_root": str(cert_root),
            "certificate_root": str(dist_root),
        }
        if identity:
            policy["cert_deploy_identity"] = {"user": "svc-app", "key": "/root/.ssh/id_ed25519"}

        policy_path = self.root / "runtime-policy.yaml"
        policy_path.write_text(yaml.safe_dump(policy), encoding="utf-8")
        return policy_path

    def run_helper(
        self, payload: bytes, *, policy_path: Path | None = None, real_trigger: bool = False
    ) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()

        def read_status() -> ClusterStatus:
            return parse_status(self.cluster.read_status())

        def trigger(node: NodeStatus) -> int:
            self.requests.append(node.name)
            return self.cluster.trigger(node.name)

        code = cert_deploy_helper.main(
            [],
            policy_path=policy_path or self.runtime(),
            input_stream=io.BytesIO(payload),
            output_stream=out,
            error_stream=err,
            require_secure=False,
            require_root=False,
            lock_root=self.root / "locks",
            status_reader=read_status,
            node_trigger=None if real_trigger else trigger,
        )
        return code, out.getvalue(), err.getvalue()


class BoundaryTests(HelperFixture):
    def test_the_helper_refuses_command_line_arguments(self) -> None:
        err = io.StringIO()

        code = cert_deploy_helper.main(
            ["-c", "alpha"],
            input_stream=io.BytesIO(b""),
            output_stream=io.StringIO(),
            error_stream=err,
            require_root=False,
        )

        self.assertEqual(code, 64)
        self.assertIn("accepts no command-line arguments", err.getvalue())

    def test_the_caller_cannot_name_a_certificate(self) -> None:
        #
        # The option does not exist, and adding one would be the whole security
        # property gone: the referenced list is configuration, not a parameter.
        #
        with self.assertRaises(SystemExit):
            cert_deploy._parse(["-c", "alpha", "--certificate", "example-net"])

    def test_a_deploy_request_is_not_accepted_here(self) -> None:
        code, _, err = self.run_helper(
            json.dumps(
                {
                    "schema_version": 1,
                    "operation": "deploy_cluster",
                    "cluster": "alpha",
                    "request_id": REQUEST_ID,
                    "parameters": {},
                }
            ).encode()
        )

        self.assertEqual(code, 64)
        self.assertIn("operation", err)


class ConfigurationTests(HelperFixture):
    def test_a_missing_certificate_root_is_named_not_guessed(self) -> None:
        policy = self.runtime()
        data = yaml.safe_load(policy.read_text())
        del data["certificate_root"]
        policy.write_text(yaml.safe_dump(data), encoding="utf-8")

        code, _, err = self.run_helper(request(), policy_path=policy)

        self.assertEqual(code, 78)
        self.assertIn("certificate_root", err)
        self.assertEqual(self.requests, [])

    def test_a_missing_identity_is_named_not_guessed(self) -> None:
        policy = self.runtime(identity=False)

        code, _, err = self.run_helper(request(), policy_path=policy, real_trigger=True)

        self.assertEqual(code, 78)
        self.assertIn("cert_deploy_identity", err)

    def test_a_referenced_certificate_that_is_absent_stops_the_run(self) -> None:
        #
        # Nothing is triggered: what is knowable before the first node is
        # touched is checked before the first node is touched.
        #
        policy = self.runtime(certificates=False)

        code, _, err = self.run_helper(request(), policy_path=policy)

        self.assertEqual(code, 68)
        self.assertIn("example-net", err)
        self.assertEqual(self.requests, [])


class RolloutTests(HelperFixture):
    def test_the_non_owner_is_taken_first_and_the_result_is_cert_deploy(self) -> None:
        code, out, _ = self.run_helper(request(json=True))

        payload = json.loads(out)
        self.assertEqual(code, 0)
        self.assertEqual(self.requests, ["node-b", "node-a"])
        self.assertEqual(payload["operation"], "cert_deploy")
        self.assertEqual(payload["request_id"], REQUEST_ID)
        self.assertEqual(
            payload["result"]["target_certificates"],
            [{"id": "example-net", "fingerprint_sha256": FINGERPRINT}],
        )

    def test_json_mode_keeps_a_refusing_nodes_own_words_as_diagnostics(self) -> None:
        # As for deploy (26-10-03): the node's sentence is the job's diagnostics.
        class Refused:
            returncode = 1
            stdout = "ERROR: the certificate could not be installed.\n"
            stderr = ""

        with mock.patch.object(subprocess, "run", lambda *_, **__: Refused()):
            code, out, err = self.run_helper(request(json=True), real_trigger=True)

        self.assertNotEqual(code, 0)
        self.assertEqual(json.loads(out)["operation"], "cert_deploy")
        self.assertIn("ERROR: the certificate could not be installed.", err)

    def test_the_target_is_read_from_the_distribution_directory(self) -> None:
        #
        # Not from the caller and not from the node: the fingerprint in the
        # result is the one computed from the file the manager holds.
        #
        code, out, _ = self.run_helper(request(json=True))

        self.assertEqual(code, 0)
        self.assertEqual(
            json.loads(out)["result"]["target_certificates"][0]["fingerprint_sha256"],
            hashlib.sha256(LEAF).hexdigest(),
        )

    def test_a_second_run_skips_nodes_that_already_carry_them(self) -> None:
        self.run_helper(request())
        self.requests.clear()

        code, out, _ = self.run_helper(request())

        self.assertEqual(code, 0)
        self.assertEqual(self.requests, [])
        self.assertIn("already has the referenced certificates", out)


class TriggerTests(unittest.TestCase):
    def test_the_node_is_asked_with_the_verb_and_the_ids(self) -> None:
        #
        # The exact string the node's wrapper parses out of
        # SSH_ORIGINAL_COMMAND. If this drifts, the wrapper rejects the request
        # rather than doing something unintended - but the rollout stops.
        #
        from haproxy_mgmt.deploy_plan import CertificateRef, CertificateTarget

        target = CertificateTarget(
            certificates=(
                CertificateRef(id="example-net", fingerprint="a" * 64),
                CertificateRef(id="example-com", fingerprint="b" * 64),
            )
        )
        sent: list[list[str]] = []

        class FakeCompleted:
            returncode = 0
            stdout = ""
            stderr = ""

        def fake_run(argv: list[str], **_: object) -> FakeCompleted:
            sent.append(argv)
            return FakeCompleted()

        with mock.patch.object(subprocess, "run", fake_run):
            cert_deploy_helper.trigger_node(
                NodeStatus(
                    name="node-a",
                    mgmt_host="node-a.example.com",
                    reachable=True,
                    status_ok=True,
                    owns_vip=True,
                    release_hash=None,
                    error_code=None,
                ),
                DeployIdentity(user="svc-app", key=Path("/root/.ssh/id_ed25519")),
                target,
                io.StringIO(),
            )

        self.assertEqual(sent[0][-1], "cert-pull example-net example-com")


class RefusalContractTests(HelperFixture):
    """A certificate run that stops early still owes its caller a result.

    Same reason as the configuration deploy: a worker that gets an exit code and
    no document can only record `unknown`, and `unknown` is the one outcome the
    plan forbids retrying automatically. A refusal that reached no node is a
    thing worth being definite about.
    """

    def test_a_missing_certificate_root_is_refused_in_the_frozen_envelope(self) -> None:
        policy = self.runtime()
        data = yaml.safe_load(policy.read_text())
        del data["certificate_root"]
        policy.write_text(yaml.safe_dump(data), encoding="utf-8")

        code, out, _ = self.run_helper(request(json=True), policy_path=policy)

        self.assertEqual(code, 78)
        document = assert_contract("haprion-cert-deploy", out)
        self.assertEqual(document["operation"], "cert_deploy")
        self.assertEqual(document["outcome"], "failed")
        self.assertEqual(document["request_id"], REQUEST_ID)
        self.assertEqual(document["error"]["code"], "dependency_unavailable")
        self.assertEqual(self.requests, [])

    def test_a_referenced_certificate_that_is_absent_names_its_stable_code(self) -> None:
        policy = self.runtime(certificates=False)

        code, out, _ = self.run_helper(request(json=True), policy_path=policy)

        document = assert_contract("haprion-cert-deploy", out)
        self.assertEqual(code, 68)
        self.assertEqual(document["error"]["code"], "certificate_missing")
        self.assertEqual(self.requests, [])

    def test_a_held_lock_is_blocked_rather_than_failed(self) -> None:
        with hold("alpha", operation="deploy", root=self.root / "locks"):
            code, out, _ = self.run_helper(request(json=True))

        self.assertEqual(code, 75)
        document = assert_contract("haprion-cert-deploy", out)
        self.assertEqual(document["outcome"], "blocked")
        self.assertEqual(document["error"]["code"], "operation_locked")
        self.assertEqual(self.requests, [])


if __name__ == "__main__":
    unittest.main()
