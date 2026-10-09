"""Drain, maintenance and ready from the manager (Fas 20, B263).

The helper is where a request somebody typed stops being text, so most cases
are about what it will not send: a server the object does not have, a pool that
is not HAProxy's, a request with one bad server in it. The rest are about what
a half means - one node that did not take it is a `partial` job naming that
node, not a failure and not a success.

The last class runs the node's own forced command with the words this side
sends, so the two halves cannot come to disagree about the request's form.
"""

from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path
from unittest import mock

import yaml
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from haproxy_mgmt import server_state
from haproxy_mgmt.cli import server_state as command
from haproxy_mgmt.cli import server_state_helper
from haproxy_mgmt.config import DeployIdentity, Node
from haproxy_mgmt.guid import server_guid
from haproxy_mgmt.proxy_model import Server, load_proxy

BASE = Path(__file__).resolve().parents[1]
REQUEST_ID = "5a1c2b64-6f3f-4f3a-9c6e-1d2b3c4d5e6f"

SHOP = b"""schema: 1
name: shop
hostnames: [shop.example.com]
listen: {protocol: http}
routes:
  - {path: /, backend: web}
  - {path: /api, backend: api}
backends:
  web:
    balance: roundrobin
    servers:
      - {host: 198.51.100.10, port: 8080}
      - {host: 198.51.100.11, port: 8080}
  api:
    balance: roundrobin
    servers:
      - {host: 198.51.100.10, port: 8080}
      - {host: 198.51.100.20, port: 9000}
"""

RESOLVER = b"""schema: 1
name: resolver
listen: {protocol: dns, port: 53}
backend: dns
backends:
  dns: {balance: roundrobin, servers: [{host: 198.51.100.53, port: 53}]}
"""

WEB_10 = server_guid("shop", "web", Server(host="198.51.100.10", port=8080))
WEB_11 = server_guid("shop", "web", Server(host="198.51.100.11", port=8080))
API_20 = server_guid("shop", "api", Server(host="198.51.100.20", port=9000))

type Ask = Callable[[Node, DeployIdentity, str, str], subprocess.CompletedProcess[str]]


def node_said(
    guid: str, state: str, *, code: int = 0, outcome: str = "done", message: str | None = None
) -> subprocess.CompletedProcess[str]:
    """One line as `haprion-server-state set` prints it."""

    document: dict[str, object] = {"node": "node", "guid": guid, "outcome": outcome}
    if outcome == "done":
        document.update(backend="mgd-shop-web", server="s1", state=state)
    if message:
        document["message"] = message
    return subprocess.CompletedProcess(["ssh"], code, json.dumps(document) + "\n", "")


def everyone_takes_it(
    node: Node, identity: DeployIdentity, guid: str, state: str
) -> subprocess.CompletedProcess[str]:
    return node_said(guid, state)


def commit(repo: Path, files: dict[str, bytes]) -> None:
    def git(*args: str) -> None:
        subprocess.run(["/usr/bin/git", "-C", str(repo), *args], check=True, capture_output=True)

    git("init", "-q", "-b", "main")
    git("config", "user.name", "Example Maintainer")
    git("config", "user.email", "maintainer@example.com")
    for path, content in files.items():
        target = repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    git("add", "-A")
    git("commit", "-qm", "objects")


class HelperFixture(unittest.TestCase):
    """A real policy, the shipped cluster file and a repository with the objects committed."""

    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="srvstate-"))
        self.addCleanup(shutil.rmtree, self.root, True)
        config_root = self.root / "config"
        cert_root = self.root / "certs"
        for directory in (config_root / "alpha", self.root / "published", cert_root):
            directory.mkdir(parents=True, exist_ok=True)
        (cert_root / "validation.pem").write_text("dummy PEM\n", encoding="utf-8")

        clusters = yaml.safe_load((BASE / "examples/clusters.yaml").read_text())
        entry = clusters["clusters"]["alpha"]
        entry["config_path"] = str(config_root / "alpha")
        entry["publish_path"] = str(self.root / "published" / "alpha")
        entry["validation_certs"] = str(cert_root)
        self.clusters = self.root / "clusters.yaml"
        self.clusters.write_text(yaml.safe_dump(clusters), encoding="utf-8")
        self.nodes = [node["name"] for node in entry["nodes"]]
        self.repo = config_root / "alpha"
        commit(
            self.repo,
            {
                "managed/proxies/shop.yaml": SHOP,
                "managed/proxies/resolver.yaml": RESOLVER,
                #
                # A neighbour that no longer loads. A drain of shop must not
                # depend on it: only the named object's file is read.
                #
                "managed/proxies/broken.yaml": b"schema: 1\nname: broken\nlisten: nonsense\n",
            },
        )
        self.policy = self.root / "runtime-policy.yaml"
        self.write_policy(identity=True)

    def write_policy(self, *, identity: bool) -> None:
        document: dict[str, object] = {
            "schema_version": 1,
            "cluster_file": str(self.clusters),
            "config_root": str(self.root / "config"),
            "publish_root": str(self.root / "published"),
            "validation_certs_root": str(self.root / "certs"),
        }
        if identity:
            document["server_state_identity"] = {
                "key": str(self.root / "server-state.key"),
            }
        self.policy.write_text(yaml.safe_dump(document), encoding="utf-8")

    def run_helper(
        self, object_name: str, servers: list[str], state: str, *, ask: Ask = everyone_takes_it
    ) -> tuple[int, dict[str, object] | None, str]:
        request = server_state_helper.build_request(
            "alpha", REQUEST_ID, object_name=object_name, servers=servers, state=state
        )
        out, err = io.StringIO(), io.StringIO()
        code = server_state_helper.main(
            [],
            policy_path=self.policy,
            input_stream=io.BytesIO(request.encode()),
            output_stream=out,
            error_stream=err,
            require_secure=False,
            require_root=False,
            ask=ask,
        )
        document = json.loads(out.getvalue()) if out.getvalue() else None
        if document is not None:
            self.assert_contract(document)
        return code, document, err.getvalue()

    def assert_contract(self, document: dict[str, object]) -> None:
        schemas = BASE / "schemas" / "v1"
        registry: Registry = Registry()
        for path in schemas.glob("*.json"):
            contents = json.loads(path.read_text())
            registry = registry.with_resource(contents["$id"], Resource.from_contents(contents))
        schema = json.loads((schemas / "haprion-server-state.schema.json").read_text())
        errors = list(Draft202012Validator(schema, registry=registry).iter_errors(document))
        self.assertEqual(errors, [], document)


class EveryNodeIsAskedForEveryServer(HelperFixture):
    def test_a_drain_reaches_both_nodes_by_guid(self) -> None:
        asked: list[tuple[str, str, str]] = []

        def ask(
            node: Node, identity: DeployIdentity, guid: str, state: str
        ) -> subprocess.CompletedProcess[str]:
            asked.append((node.name, guid, state))
            return node_said(guid, state)

        code, document, _ = self.run_helper(
            "shop", ["web/198.51.100.10:8080", "198.51.100.11:8080"], "drain", ask=ask
        )

        self.assertEqual(code, 0)
        assert document is not None
        self.assertEqual(document["outcome"], "done")
        self.assertEqual(
            sorted(asked),
            sorted((node, guid, "drain") for node in self.nodes for guid in (WEB_10, WEB_11)),
        )

    def test_a_server_in_one_pool_needs_no_pool_named(self) -> None:
        code, document, _ = self.run_helper("shop", ["198.51.100.20:9000"], "maint")

        self.assertEqual(code, 0)
        assert document is not None
        result = document["result"]
        assert isinstance(result, dict)
        self.assertEqual(result["nodes"][0]["servers"][0]["guid"], API_20)
        self.assertEqual(result["nodes"][0]["servers"][0]["server"], "api/198.51.100.20:9000")

    def test_one_node_that_did_not_answer_is_a_partial_naming_it(self) -> None:
        silent = self.nodes[1]

        def ask(
            node: Node, identity: DeployIdentity, guid: str, state: str
        ) -> subprocess.CompletedProcess[str]:
            if node.name == silent:
                return subprocess.CompletedProcess(
                    ["ssh"], 255, "", "ssh: connect to host: timed out\n"
                )
            return node_said(guid, state)

        code, document, _ = self.run_helper("shop", ["web/198.51.100.10:8080"], "drain", ask=ask)

        self.assertEqual(code, server_state_helper.EXIT_INCOMPLETE)
        assert document is not None
        self.assertEqual(document["outcome"], "partial")
        warnings = document["warnings"]
        assert isinstance(warnings, list)
        self.assertEqual([warning["node"] for warning in warnings], [silent])
        self.assertIn("could not be reached", warnings[0]["message"])

    def test_a_node_that_does_not_run_the_server_yet_says_deploy(self) -> None:
        def ask(
            node: Node, identity: DeployIdentity, guid: str, state: str
        ) -> subprocess.CompletedProcess[str]:
            if node.name == self.nodes[0]:
                return node_said(guid, state, code=65, outcome="refused", message="no server")
            return node_said(guid, state)

        _, document, _ = self.run_helper("shop", ["web/198.51.100.10:8080"], "drain", ask=ask)

        assert document is not None
        warnings = document["warnings"]
        assert isinstance(warnings, list)
        self.assertEqual(warnings[0]["code"], "server_not_on_node")
        self.assertIn("deploy", warnings[0]["message"])

    def test_no_node_taking_it_is_a_failure(self) -> None:
        def ask(
            node: Node, identity: DeployIdentity, guid: str, state: str
        ) -> subprocess.CompletedProcess[str]:
            return node_said(
                guid, state, code=70, outcome="failed", message="HAProxy did not take it"
            )

        code, document, _ = self.run_helper("shop", ["web/198.51.100.10:8080"], "ready", ask=ask)

        self.assertEqual(code, server_state_helper.EXIT_INCOMPLETE)
        assert document is not None
        self.assertEqual(document["outcome"], "failed")
        error = document["error"]
        assert isinstance(error, dict)
        self.assertEqual(error["code"], "node_server_state_failed")

    def test_a_node_that_hangs_is_one_failed_answer(self) -> None:
        def ask(
            node: Node, identity: DeployIdentity, guid: str, state: str
        ) -> subprocess.CompletedProcess[str]:
            if node.name == self.nodes[0]:
                raise subprocess.TimeoutExpired(["ssh"], 30)
            return node_said(guid, state)

        _, document, _ = self.run_helper("shop", ["web/198.51.100.10:8080"], "drain", ask=ask)

        assert document is not None
        self.assertEqual(document["outcome"], "partial")

    def test_a_node_that_hangs_is_not_asked_again(self) -> None:
        """Review 26-10-09, F4: thirty seconds per server ran past the worker's limit."""

        asked: list[tuple[str, str]] = []

        def ask(
            node: Node, identity: DeployIdentity, guid: str, state: str
        ) -> subprocess.CompletedProcess[str]:
            asked.append((node.name, guid))
            if node.name == self.nodes[0]:
                raise subprocess.TimeoutExpired(["ssh"], 30)
            return node_said(guid, state)

        _, document, _ = self.run_helper(
            "shop", ["web/198.51.100.10:8080", "web/198.51.100.11:8080"], "drain", ask=ask
        )

        assert document is not None
        self.assertEqual(document["outcome"], "partial")
        self.assertEqual([guid for node, guid in asked if node == self.nodes[0]], [WEB_10])
        self.assertEqual([guid for node, guid in asked if node == self.nodes[1]], [WEB_10, WEB_11])
        result = document["result"]
        assert isinstance(result, dict)
        hung = next(entry for entry in result["nodes"] if entry["node"] == self.nodes[0])
        self.assertIn("not asked", hung["servers"][1]["message"])


class NothingIsSentForARequestThatIsWrong(HelperFixture):
    def refused(
        self, object_name: str, servers: list[str], state: str = "drain"
    ) -> dict[str, object]:
        def ask(
            node: Node, identity: DeployIdentity, guid: str, state: str
        ) -> subprocess.CompletedProcess[str]:
            raise AssertionError("a node was asked")

        code, document, _ = self.run_helper(object_name, servers, state, ask=ask)
        self.assertNotEqual(code, 0)
        assert document is not None
        self.assertEqual(document["outcome"], "failed")
        error = document["error"]
        assert isinstance(error, dict)
        return error

    def test_a_server_the_object_does_not_have(self) -> None:
        error = self.refused("shop", ["web/198.51.100.10:8080", "198.51.100.99:8080"])
        self.assertEqual(error["code"], "server_not_found")

    def test_one_address_in_two_pools_must_name_its_pool(self) -> None:
        error = self.refused("shop", ["198.51.100.10:8080"])
        self.assertEqual(error["code"], "bad_input")
        self.assertIn("api/198.51.100.10:8080", str(error["message"]))

    def test_an_object_the_cluster_does_not_have(self) -> None:
        self.assertEqual(
            self.refused("nothing", ["198.51.100.10:8080"])["code"], "server_not_found"
        )

    def test_a_dns_object_has_no_drain(self) -> None:
        error = self.refused("resolver", ["198.51.100.53:53"])
        self.assertIn("dnsdist", str(error["message"]))

    def test_words_that_are_not_a_server_or_an_object(self) -> None:
        for object_name, servers in (
            ("shop", ["198.51.100.10"]),
            ("shop", ["198.51.100.10:8080 drain"]),
            ("shop", []),
            ("Shop;id", ["198.51.100.10:8080"]),
            ("../shop", ["198.51.100.10:8080"]),
        ):
            with self.subTest(object_name=object_name, servers=servers):
                self.assertEqual(self.refused(object_name, servers)["code"], "bad_input")

    def test_a_state_that_is_not_one_of_three(self) -> None:
        self.assertEqual(
            self.refused("shop", ["web/198.51.100.10:8080"], "down")["code"], "bad_input"
        )

    def test_without_the_identity_it_says_what_to_add(self) -> None:
        self.write_policy(identity=False)
        code, document, _ = self.run_helper("shop", ["web/198.51.100.10:8080"], "drain")

        self.assertEqual(code, server_state_helper.EXIT_NO_IDENTITY)
        assert document is not None
        error = document["error"]
        assert isinstance(error, dict)
        self.assertEqual(error["code"], "server_state_unavailable")
        self.assertIn("server_state_identity", error["message"])


class TheNodeIsAskedWithItsOwnForcedCommand(unittest.TestCase):
    """The SSH call, and the node's trigger run with exactly the words it sends."""

    def test_the_call_names_the_identity_the_host_and_three_words(self) -> None:
        identity = DeployIdentity(user="svc-app", key=Path("/root/.ssh/example"))
        node = Node(name="node-a", mgmt_host="node-a.example.com")
        with mock.patch("haproxy_mgmt.server_state.subprocess.run") as run:
            server_state.ask_node(node, identity, WEB_10, "drain")

        argv = run.call_args.args[0]
        self.assertEqual(argv[0], "/usr/bin/ssh")
        self.assertIn("BatchMode=yes", argv)
        self.assertEqual(argv[-3:-1], ["/root/.ssh/example", "svc-app@node-a.example.com"])
        self.assertEqual(argv[-1], f"server-state {WEB_10} drain")
        self.assertEqual(run.call_args.kwargs["timeout"], server_state.CALL_TIMEOUT_SECONDS)

    def test_the_node_trigger_accepts_every_guid_and_state_this_side_sends(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="srvwords-"))
        self.addCleanup(shutil.rmtree, root, True)
        sudo = root / "sudo"
        sudo.write_text('#!/bin/sh\nprintf "%s\\n" "$*"\n')
        sudo.chmod(0o755)
        proxy = load_proxy("shop", SHOP)
        targets = server_state.resolve(
            proxy, ["web/198.51.100.10:8080", "198.51.100.11:8080", "198.51.100.20:9000"]
        )
        for target in targets:
            for state in server_state.STATES:
                with self.subTest(guid=target.guid, state=state):
                    done = subprocess.run(  # noqa: S603 - the file under test
                        ["/bin/bash", str(BASE / "install/node/haprion-server-state-trigger")],
                        env={
                            "PATH": f"{root}:{os.environ['PATH']}",
                            "SSH_ORIGINAL_COMMAND": f"{server_state.NODE_VERB} {target.guid} {state}",
                        },
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    self.assertEqual(done.returncode, 0, done.stderr)
                    self.assertTrue(done.stdout.strip().endswith(f"set {target.guid} {state}"))


class TheCommandSendsWhatTheWorkerSends(unittest.TestCase):
    def test_arguments_become_the_helpers_request(self) -> None:
        sent: list[str] = []

        def run(request: str) -> subprocess.CompletedProcess[str]:
            sent.append(request)
            answer = json.loads(
                (BASE / "fixtures/haprion-server-state/valid/done.json").read_text()
            )
            return subprocess.CompletedProcess(["sudo"], 0, json.dumps(answer), "")

        out = io.StringIO()
        with mock.patch.object(command, "run_helper", run):
            code = command.main(
                [
                    "-c",
                    "alpha",
                    "-o",
                    "shop",
                    "drain",
                    "198.51.100.10:8080",
                    "web/198.51.100.11:8080",
                ],
                writer=out,
            )

        self.assertEqual(code, 0)
        request = json.loads(sent[0])
        self.assertEqual(request["operation"], "server_state")
        self.assertEqual(request["cluster"], "alpha")
        self.assertEqual(
            request["parameters"],
            {
                "object": "shop",
                "servers": ["198.51.100.10:8080", "web/198.51.100.11:8080"],
                "state": "drain",
            },
        )
        self.assertIn("OK       web/198.51.100.10:8080", out.getvalue())
        self.assertIn("RESULT: DONE", out.getvalue())

    def test_a_missing_state_or_server_is_usage(self) -> None:
        for argv in (
            ["-c", "alpha", "-o", "shop", "drain"],
            ["-c", "alpha", "-o", "shop", "198.51.100.10:8080"],
            ["-c", "alpha", "drain", "198.51.100.10:8080"],
            ["-o", "shop", "drain", "198.51.100.10:8080"],
            ["-c", "alpha", "-o", "shop", "down", "198.51.100.10:8080"],
        ):
            with self.subTest(argv=argv), mock.patch("sys.stdout", io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    command.main(argv)
                self.assertNotEqual(raised.exception.code, 0)


if __name__ == "__main__":
    unittest.main()


class StepTwoNamesEveryIdentityStepThreeMakes(unittest.TestCase):
    """02-manager-config's policy block, run in bash and read by the policy reader.

    Until 2026-10-09 it wrote neither status_identity nor probe_identity, so a
    manager built from the scripts had a `haprion-status` that refused to run.
    """

    def rendered(self, answers: dict[str, str]) -> str:
        installer = (BASE / "install" / "02-manager-config").read_text(encoding="utf-8")
        start = installer.index('step "Runtime policy"')
        end = installer.index('ensure_dir "$(dirname "$POLICY_FILE")"')
        script = (
            "set -eu\nstep() { :; }\nensure_dir() { :; }\nvalid_abs_path() { :; }\n"
            'require_vars() { :; }\ndie() { echo "$*" >&2; exit 1; }\n'
            + installer[start:end]
            + '\nprintf "%s\\n" "$policy"\n'
        )
        done = subprocess.run(  # noqa: S603 - the installer's own block
            ["/bin/bash", "-c", script],
            env={"PATH": os.environ["PATH"], **answers},
            capture_output=True,
            text=True,
            check=True,
        )
        return done.stdout

    ANSWERS = {
        "CLUSTER_FILE": "/srv/haproxy-manager/clusters.yaml",
        "CONFIG_ROOT": "/srv/haproxy-manager/config",
        "PUBLISH_ROOT": "/srv/haproxy-manager/published",
        "VALIDATION_ROOT": "/srv/haproxy-manager/validation",
        "KEY_DIR": "/root/.ssh",
        "CONFIG_DEPLOY_KEY": "id_ed25519_config_deploy",
        "NODE_STATUS_KEY": "id_ed25519_node_status",
    }

    def load(self, answers: dict[str, str]) -> object:
        from haproxy_mgmt.config import load_policy

        path = Path(tempfile.mkdtemp(prefix="policy-")) / "runtime-policy.yaml"
        self.addCleanup(shutil.rmtree, path.parent, True)
        path.write_text(self.rendered(answers), encoding="utf-8")
        return load_policy(path, require_secure=False)

    def test_status_probe_and_server_state_are_named_when_their_keys_are(self) -> None:
        policy = self.load(
            {
                **self.ANSWERS,
                "NODE_PROBE_KEY": "id_ed25519_node_probe",
                "SERVER_STATE_KEY": "id_ed25519_server_state",
            }
        )

        self.assertEqual(
            policy.status_identity,  # type: ignore[attr-defined]
            DeployIdentity("_haprion-status", Path("/root/.ssh/id_ed25519_node_status")),
        )
        self.assertEqual(
            policy.probe_identity,  # type: ignore[attr-defined]
            DeployIdentity("_haprion-status", Path("/root/.ssh/id_ed25519_node_probe")),
        )
        self.assertEqual(
            policy.server_state_identity,  # type: ignore[attr-defined]
            DeployIdentity("_haprion-trigger", Path("/root/.ssh/id_ed25519_server_state")),
        )

    def test_an_optional_key_left_out_leaves_its_identity_out(self) -> None:
        policy = self.load(self.ANSWERS)

        self.assertIsNone(policy.probe_identity)  # type: ignore[attr-defined]
        self.assertIsNone(policy.server_state_identity)  # type: ignore[attr-defined]
