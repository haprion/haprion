"""The two halves of the deploy command, and the seam between them.

The loop itself is tested against the harness in test_deploy_run. What is tested
here is the boundary: what the caller is allowed to say, what the privileged
half refuses to be told, and where each decision is actually taken.

The one property worth stating plainly, because it is the whole point of the
split: the caller cannot influence which nodes are touched. It sends a cluster
name and two booleans. The target, the status and the order are all resolved
inside the boundary.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path

import yaml

from haproxy_mgmt.cli import deploy, deploy_helper
from haproxy_mgmt.cluster_lock import hold
from haproxy_mgmt.cluster_status import NodeStatus, parse_status
from tests.contract_schema import assert_contract
from tests.node_harness import TARGET_HASH, pair

BASE = Path(__file__).resolve().parents[1]
REQUEST_ID = "44444444-4444-4444-8444-444444444444"


def request(cluster: str = "alpha", **parameters: bool) -> bytes:
    return json.dumps(
        {
            "schema_version": 1,
            "operation": "deploy_cluster",
            "cluster": cluster,
            "request_id": REQUEST_ID,
            "parameters": parameters,
        }
    ).encode()


DELIMITER = "-" * 5


def fingerprint(identifier: str) -> str:
    """What a node has to answer with to be current on this test certificate."""

    return hashlib.sha256(identifier.encode("ascii")).hexdigest()


def pem(identifier: str) -> str:
    """A PEM whose leaf is the ID itself, so its fingerprint is `fingerprint(id)`."""

    body = base64.b64encode(identifier.encode("ascii")).decode("ascii")
    return (
        f"{DELIMITER}BEGIN CERTIFICATE{DELIMITER}\n{body}\n{DELIMITER}END CERTIFICATE{DELIMITER}\n"
    )


#
# What examples/clusters.yaml has alpha referencing.
#
REFERENCED = ("example.com", "example.net")


class HelperFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.cluster = pair()
        self.triggered: list[str] = []

    def runtime(
        self,
        *,
        published_hash: str | None = TARGET_HASH,
        distributed: tuple[str, ...] | None = None,
    ) -> Path:
        """The policy, and with `distributed` a certificate root holding those IDs.

        Without it the policy names no certificate root, which is the shape
        every case before the preflight existed ran against, and which the
        preflight has to let through with a warning rather than refuse.
        """

        config_root = self.root / "config"
        publish_root = self.root / "published"
        cert_root = self.root / "certs"
        dist_root = self.root / "certdist"
        for directory in (config_root, publish_root, cert_root, dist_root):
            directory.mkdir(parents=True, exist_ok=True)
        (cert_root / "validation.pem").write_text("dummy PEM\n", encoding="utf-8")
        (config_root / "alpha").mkdir(exist_ok=True)
        for identifier in distributed or ():
            (dist_root / f"{identifier}.pem").write_text(pem(identifier), encoding="ascii")

        clusters = yaml.safe_load((BASE / "examples/clusters.yaml").read_text())
        entry = clusters["clusters"]["alpha"]
        entry["config_path"] = str(config_root / "alpha")
        entry["publish_path"] = str(publish_root / "alpha")
        entry["validation_certs"] = str(cert_root)
        (self.root / "clusters.yaml").write_text(yaml.safe_dump(clusters), encoding="utf-8")

        if published_hash is not None:
            release = publish_root / "alpha" / "current" / entry["node_path"]
            release.mkdir(parents=True, exist_ok=True)
            (release / "RELEASE").write_text(
                f"schema=1\ncluster=alpha\nversion=8\nhash={published_hash}\n"
                "timestamp=2026-01-02T03:04:05+00:00\n",
                encoding="utf-8",
            )

        policy = {
            "schema_version": 1,
            "cluster_file": str(self.root / "clusters.yaml"),
            "config_root": str(config_root),
            "publish_root": str(publish_root),
            "validation_certs_root": str(cert_root),
        }
        if distributed is not None:
            policy["certificate_root"] = str(dist_root)
        policy_path = self.root / "runtime-policy.yaml"
        policy_path.write_text(yaml.safe_dump(policy), encoding="utf-8")
        return policy_path

    def run_helper(
        self, payload: bytes, *, policy_path: Path | None = None
    ) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()

        def read_status():  # type: ignore[no-untyped-def]
            return parse_status(self.cluster.read_status())

        def trigger(node: NodeStatus) -> int:
            self.triggered.append(node.name)
            return self.cluster.trigger(node.name)

        code = deploy_helper.main(
            [],
            policy_path=policy_path or self.runtime(),
            input_stream=io.BytesIO(payload),
            output_stream=out,
            error_stream=err,
            require_secure=False,
            require_root=False,
            lock_root=self.root / "locks",
            status_reader=read_status,
            node_trigger=trigger,
        )
        return code, out.getvalue(), err.getvalue()


class StatusIdentityTests(HelperFixture):
    """Reading a node and changing one are separate identities, or the run stops.

    The convenient default here would be to read status with the deploy
    identity, which is already configured and already reaches the node. That is
    exactly what must not happen: it would dissolve the separation at the one
    moment nobody is watching, and it would do it silently.
    """

    def test_deploy_refuses_to_run_without_a_status_identity(self) -> None:
        out, err = io.StringIO(), io.StringIO()
        code = deploy_helper.main(
            [],
            policy_path=self.runtime(),
            input_stream=io.BytesIO(request()),
            output_stream=out,
            error_stream=err,
            require_secure=False,
            require_root=False,
            lock_root=self.root / "locks",
            node_trigger=lambda node: 0,
        )
        self.assertEqual(code, deploy_helper.EXIT_NO_IDENTITY)
        self.assertIn("status_identity", err.getvalue())
        self.assertNotIn("deploy_identity", err.getvalue())


class HelperBoundaryTests(HelperFixture):
    def test_the_helper_refuses_command_line_arguments(self) -> None:
        err = io.StringIO()
        code = deploy_helper.main(
            ["-c", "alpha"],
            input_stream=io.BytesIO(b""),
            output_stream=io.StringIO(),
            error_stream=err,
            require_root=False,
        )

        self.assertEqual(code, 64)
        self.assertIn("accepts no command-line arguments", err.getvalue())

    def test_the_helper_refuses_a_request_for_another_operation(self) -> None:
        payload = json.dumps(
            {
                "schema_version": 1,
                "operation": "publish_version",
                "cluster": "alpha",
                "request_id": REQUEST_ID,
                "parameters": {},
            }
        ).encode()

        code, _, err = self.run_helper(payload)

        self.assertEqual(code, 64)
        self.assertIn("operation is not allowed", err)

    def test_the_helper_refuses_an_unknown_parameter(self) -> None:
        payload = json.dumps(
            {
                "schema_version": 1,
                "operation": "deploy_cluster",
                "cluster": "alpha",
                "request_id": REQUEST_ID,
                "parameters": {"nodes": ["node-a"]},
            }
        ).encode()

        code, _, err = self.run_helper(payload)

        #
        # The caller must not be able to name nodes. If it could, the boundary
        # would only be moving the decision, not protecting it.
        #
        self.assertEqual(code, 65)
        self.assertIn("unknown field(s): nodes", err)
        self.assertEqual(self.triggered, [])

    def test_the_helper_refuses_a_non_boolean_option(self) -> None:
        code, _, err = self.run_helper(request(allow_vip_unknown="yes"))  # type: ignore[arg-type]

        self.assertEqual(code, 65)
        self.assertIn("allow_vip_unknown must be a boolean", err)

    def test_an_unknown_cluster_is_refused_inside_the_boundary_too(self) -> None:
        code, _, err = self.run_helper(request(cluster="gamma"))

        self.assertEqual(code, 64)
        self.assertIn("gamma", err)
        self.assertEqual(self.triggered, [])


class HelperBehaviourTests(HelperFixture):
    def test_the_rollout_is_streamed_and_the_nodes_are_ordered(self) -> None:
        code, shown, _ = self.run_helper(request())

        self.assertEqual(code, 0)
        self.assertEqual(self.triggered, ["node-b", "node-a"])
        self.assertIn("=== Deploy: node-b ===", shown)
        self.assertIn("RESULT: OK", shown)

    def test_the_target_comes_from_the_published_tree_not_the_request(self) -> None:
        #
        # Both nodes already run the published hash, so a target resolved inside
        # the boundary means nothing is touched. A caller cannot ask for a
        # different one - there is no field for it.
        #
        for node in self.cluster.nodes:
            node.release_hash = TARGET_HASH

        code, shown, _ = self.run_helper(request())

        self.assertEqual(code, 0)
        self.assertEqual(self.triggered, [])
        self.assertIn("already runs this version", shown)

    def test_json_mode_prints_one_document_and_no_progress(self) -> None:
        code, shown, _ = self.run_helper(request(json=True))

        payload = json.loads(shown)
        self.assertEqual(code, 0)
        self.assertEqual(payload["operation"], "deploy")
        self.assertEqual(payload["outcome"], "done")
        self.assertEqual(payload["request_id"], REQUEST_ID)
        self.assertNotIn("=== Deploy", shown)

    def test_a_second_deploy_is_refused_while_one_is_running(self) -> None:
        from haproxy_mgmt.cluster_lock import hold

        with hold("alpha", root=self.root / "locks"):
            code, _, err = self.run_helper(request())

        self.assertEqual(code, 75)
        self.assertIn("another operation is already running", err)
        self.assertEqual(self.triggered, [])

    def test_the_override_reaches_the_decision(self) -> None:
        self.cluster.node("node-a").owns_vip = None

        blocked, _, _ = self.run_helper(request())
        self.assertEqual(blocked, 65)

        self.cluster = pair()
        self.cluster.node("node-a").owns_vip = None
        allowed, shown, _ = self.run_helper(request(allow_vip_unknown=True))

        self.assertEqual(allowed, 0)
        self.assertIn("explicit CLI override accepted", shown)


class CertificatePreflightTests(HelperFixture):
    """The preflight resolves inside the boundary, from the distribution root.

    The loop's own behaviour is covered in test_deploy_run. What is tested here
    is the seam: the referenced certificates come from the policy's certificate
    root and the cluster's registry, never from the request, and every way the
    check can end is a frozen envelope the worker can file.
    """

    def carry(self, *identifiers: str) -> None:
        for node in self.cluster.nodes:
            node.certificates = tuple((i, fingerprint(i)) for i in identifiers)

    def test_a_node_behind_on_a_certificate_blocks_in_the_frozen_envelope(self) -> None:
        self.carry("example.com")

        code, out, err = self.run_helper(
            request(json=True), policy_path=self.runtime(distributed=REFERENCED)
        )

        self.assertEqual(code, 65)
        self.assertEqual(self.triggered, [])
        document = assert_contract("haproxy-deploy", out)
        self.assertEqual(document["outcome"], "blocked")
        self.assertEqual(document["error"]["code"], "certificates_not_deployed")
        self.assertEqual(
            document["error"]["details"]["next_command"], "haproxy-cert-deploy -c alpha"
        )
        self.assertEqual(
            document["error"]["details"]["nodes"],
            [
                {"node": "node-a", "missing": ["example.net"], "stale": []},
                {"node": "node-b", "missing": ["example.net"], "stale": []},
            ],
        )
        #
        # Nothing was deployed, and the result says so node by node rather
        # than being dropped: a blocked deploy still has a target and a
        # cluster picture worth recording.
        #
        self.assertFalse(document["result"]["converged"])
        self.assertTrue(
            all(node["outcome"] == "not_attempted" for node in document["result"]["nodes"])
        )

    def test_nodes_carrying_the_published_bytes_are_deployed(self) -> None:
        self.carry(*REFERENCED)

        code, out, _ = self.run_helper(
            request(json=True), policy_path=self.runtime(distributed=REFERENCED)
        )

        self.assertEqual(code, 0)
        self.assertEqual(self.triggered, ["node-b", "node-a"])
        document = assert_contract("haproxy-deploy", out)
        self.assertEqual(document["outcome"], "done")
        self.assertEqual(document["warnings"], [])

    def test_a_certificate_the_manager_itself_lacks_is_refused_with_cert_deploys_code(
        self,
    ) -> None:
        #
        # `cert-deploy` would fail on the same missing file with the same
        # code; a refusal that sent somebody to it would be a loop.
        #
        self.carry(*REFERENCED)

        code, out, err = self.run_helper(
            request(json=True), policy_path=self.runtime(distributed=("example.com",))
        )

        self.assertEqual(code, deploy_helper.EXIT_CERTIFICATE_MISSING)
        self.assertEqual(self.triggered, [])
        self.assertIn("[certificate_missing]", err)
        self.assertIn("example.net", err)
        document = assert_contract("haproxy-deploy", out)
        self.assertEqual(document["error"]["code"], "certificate_missing")
        self.assertIsNone(document["result"])

    def test_without_a_certificate_root_the_deploy_runs_and_the_envelope_says_unchecked(
        self,
    ) -> None:
        code, out, _ = self.run_helper(request(json=True))

        self.assertEqual(code, 0)
        self.assertEqual(self.triggered, ["node-b", "node-a"])
        document = assert_contract("haproxy-deploy", out)
        self.assertEqual(document["outcome"], "done")
        self.assertEqual(
            [warning["code"] for warning in document["warnings"]], ["certificates_unchecked"]
        )
        self.assertIn("example.com, example.net", document["warnings"][0]["message"])

    def test_the_human_mode_names_the_command_to_run_next(self) -> None:
        self.carry("example.com")

        code, out, _ = self.run_helper(request(), policy_path=self.runtime(distributed=REFERENCED))

        self.assertEqual(code, 65)
        self.assertIn("ERROR: [certificates_not_deployed]", out)
        self.assertIn("Run haproxy-cert-deploy -c alpha first, then deploy again", out)


class CallerTests(unittest.TestCase):
    def test_the_caller_sends_only_a_cluster_and_two_booleans(self) -> None:
        sent: list[bytes] = []

        class Completed:
            returncode = 0

        def fake_run(command, input, check):  # type: ignore[no-untyped-def]
            sent.append(input)
            return Completed()

        original = deploy.subprocess.run
        deploy.subprocess.run = fake_run  # type: ignore[assignment]
        original_lookup = deploy._config_path
        deploy._config_path = lambda cluster: Path("/configs/haproxy/alpha")  # type: ignore[assignment]
        try:
            code = deploy.main(["-c", "alpha", "--allow-vip-unknown"])
        finally:
            deploy.subprocess.run = original  # type: ignore[assignment]
            deploy._config_path = original_lookup  # type: ignore[assignment]

        payload = json.loads(sent[0])
        self.assertEqual(code, 0)
        self.assertEqual(payload["operation"], "deploy_cluster")
        self.assertEqual(payload["cluster"], "alpha")
        self.assertEqual(payload["parameters"], {"allow_vip_unknown": True, "json": False})

    def test_the_argument_contract(self) -> None:
        from contextlib import redirect_stdout

        for argv in (
            [],
            ["alpha"],
            ["-c"],
            ["-c", "alpha", "--force"],
            ["-c", "alpha", "--json", "--json"],
        ):
            shown = io.StringIO()
            with self.assertRaises(SystemExit) as raised, redirect_stdout(shown):
                deploy.main(argv)
            self.assertEqual(raised.exception.code, 64, argv)
            self.assertEqual(shown.getvalue(), deploy.USAGE)


class RefusalContractTests(HelperFixture):
    """A refusal is a result too, and in JSON mode it has to look like one.

    These paths used to return an exit code and a line of stderr. A worker
    parsing that sees no document, and the only honest thing it can record is
    `unknown` - "the operation may have taken effect". For a run that stopped
    before it reached a node, that is the worst of the available answers: it is
    the one nothing may safely retry.
    """

    def test_an_unknown_cluster_is_refused_in_the_frozen_envelope(self) -> None:
        code, out, err = self.run_helper(request("beta", json=True))
        self.assertEqual(code, 64)
        self.assertIn("unknown cluster", err)

        document = assert_contract("haproxy-deploy", out)
        self.assertEqual(document["operation"], "deploy")
        self.assertEqual(document["outcome"], "failed")
        self.assertEqual(document["request_id"], REQUEST_ID)
        self.assertEqual(document["error"]["code"], "bad_input")
        self.assertIsNone(document["result"])

    def test_a_missing_status_identity_is_refused_in_the_frozen_envelope(self) -> None:
        out, err = io.StringIO(), io.StringIO()
        code = deploy_helper.main(
            [],
            policy_path=self.runtime(),
            input_stream=io.BytesIO(request(json=True)),
            output_stream=out,
            error_stream=err,
            require_secure=False,
            require_root=False,
            lock_root=self.root / "locks",
            node_trigger=lambda node: 0,
        )
        self.assertEqual(code, deploy_helper.EXIT_NO_IDENTITY)
        document = assert_contract("haproxy-deploy", out.getvalue())
        self.assertEqual(document["error"]["code"], "dependency_unavailable")
        self.assertEqual(document["outcome"], "failed")

    def test_a_held_lock_is_blocked_rather_than_failed(self) -> None:
        with hold("alpha", operation="revert", root=self.root / "locks"):
            code, out, _ = self.run_helper(request(json=True))

        self.assertEqual(code, 75)
        document = assert_contract("haproxy-deploy", out)
        self.assertEqual(document["outcome"], "blocked")
        self.assertEqual(document["error"]["code"], "operation_locked")
        self.assertEqual(self.triggered, [])

    def test_the_human_mode_still_prints_only_the_error(self) -> None:
        """No document without JSON mode. A person reading a terminal gets a
        sentence, and a stray envelope on stdout would be noise in the middle
        of a rollout."""

        code, out, err = self.run_helper(request("beta"))
        self.assertEqual(code, 64)
        self.assertEqual(out, "")
        self.assertIn("unknown cluster", err)


if __name__ == "__main__":
    unittest.main()
