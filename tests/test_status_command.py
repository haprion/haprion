"""The two halves of the status command, and what each of them is allowed to decide.

The property worth stating plainly is the same one the deploy split exists for:
the caller sends a cluster name and nothing else. Which nodes are asked, and
which release they are compared against, are both resolved inside the boundary -
and the target in particular, because it is what decides whether an operator is
told the cluster is in sync.
"""

from __future__ import annotations

import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

from haproxy_mgmt import cluster_status
from haproxy_mgmt.cli import status, status_helper
from haproxy_mgmt.config import Node
from haproxy_mgmt.status_collect import NodeResponse
from tests.contract_schema import assert_contract

BASE = Path(__file__).resolve().parents[1]
REQUEST_ID = "55555555-5555-4555-8555-555555555555"
TARGET_HASH = "c" * 40


def request(cluster: str = "alpha", **overrides: object) -> bytes:
    document: dict[str, object] = {
        "schema_version": 1,
        "operation": "status",
        "cluster": cluster,
        "request_id": REQUEST_ID,
        "parameters": {},
    }
    document.update(overrides)
    return json.dumps(document).encode()


#
# The node carries the address list its release publishes. Digests made up: the
# comparison only asks whether two answers are equal.
#
ADDRESSES: dict[str, object] = {
    "published": True,
    "published_sha256": "a1" * 32,
    "installed": True,
    "installed_sha256": "a1" * 32,
    "included": True,
}


def node_status(
    name: str,
    *,
    owner: bool,
    release_hash: str,
    addresses: object = None,
    runtime: str = "3.2.9",
    waf_engine: dict[str, object] | None = None,
) -> str:
    return json.dumps(
        {
            **({} if waf_engine is None else {"waf_engine": waf_engine}),
            "schema_version": 1,
            "node": name,
            "cluster": "alpha",
            "haproxy": {"active": True},
            "keepalived": {
                "active": True,
                "state": "MASTER" if owner else "BACKUP",
                #
                # `False` models the node that reported no address list at all,
                # which is a status script from before it was measured.
                #
                **(
                    {}
                    if addresses is False
                    else {"addresses": ADDRESSES if addresses is None else addresses}
                ),
            },
            "vip": {"address": "192.0.2.10", "interface": "eth0", "owner": owner},
            "ip_nonlocal_bind": True,
            "release": {
                "cluster": "alpha",
                "version": "8",
                "hash": release_hash,
                "timestamp": "2026-01-02T03:04:05+00:00",
            },
            #
            # The shapes `haproxy-node-status` actually emits, not a stand-in.
            # These two carried `{"ok": true}` for months, which no node has ever
            # produced: the fixture was invented rather than copied, and the
            # tests built on it could not have caught a real node's document
            # drifting away from the frozen contract.
            #
            "config_validation": {"valid": True, "validated_at": "2026-01-02T03:00:00+00:00"},
            "stats_ok": True,
            "runtime": {"version": runtime, "uptime_sec": 3600},
            "certificates": [],
        }
    )


class HelperFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.asked: list[str] = []

    def runtime(
        self, *, published_hash: str | None = TARGET_HASH, identity: bool = True, waf: bool = False
    ) -> Path:
        config_root = self.root / "config"
        publish_root = self.root / "published"
        cert_root = self.root / "certs"
        for directory in (config_root, publish_root, cert_root):
            directory.mkdir(parents=True, exist_ok=True)
        (cert_root / "validation.pem").write_text("dummy PEM\n", encoding="utf-8")
        (config_root / "alpha").mkdir(exist_ok=True)

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
            if waf:
                (release / "waf").mkdir(exist_ok=True)
                (release / "waf" / "coraza.yaml").write_text("bind: 127.0.0.1:9520\n")

        document: dict[str, object] = {
            "schema_version": 1,
            "cluster_file": str(self.root / "clusters.yaml"),
            "config_root": str(config_root),
            "publish_root": str(publish_root),
            "validation_certs_root": str(cert_root),
        }
        if identity:
            document["status_identity"] = {
                "user": "svc-status",
                "key": str(self.root / "status.key"),
            }
        policy_path = self.root / "runtime-policy.yaml"
        policy_path.write_text(yaml.safe_dump(document), encoding="utf-8")
        return policy_path

    def reader(self, **stdout_by_name: str):
        def read(node: Node) -> NodeResponse:
            self.asked.append(node.name)
            return NodeResponse(exit_code=0, stdout=stdout_by_name[node.name])

        return read

    def engines(self, *, b_active: bool) -> object:
        return self.reader(
            **{
                "node-a": node_status(
                    "node-a",
                    owner=True,
                    release_hash=TARGET_HASH,
                    waf_engine={"version": "0.9.0-4", "active": True},
                ),
                "node-b": node_status(
                    "node-b",
                    owner=False,
                    release_hash=TARGET_HASH,
                    waf_engine={"version": "0.9.0-4", "active": b_active},
                ),
            }
        )

    def run_helper(
        self, payload: bytes, *, policy_path: Path | None = None, node_reader=None, **overrides
    ) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        version_reader = overrides.pop("version_reader", lambda: "3.2.9-1")
        code = status_helper.main(
            [],
            policy_path=policy_path or self.runtime(**overrides),
            input_stream=io.BytesIO(payload),
            output_stream=out,
            error_stream=err,
            require_secure=False,
            require_root=False,
            version_reader=version_reader,
            node_reader=node_reader
            or self.reader(
                **{
                    "node-a": node_status("node-a", owner=True, release_hash=TARGET_HASH),
                    "node-b": node_status("node-b", owner=False, release_hash=TARGET_HASH),
                }
            ),
        )
        return code, out.getvalue(), err.getvalue()


class HelperBoundaryTests(HelperFixture):
    def test_the_helper_refuses_command_line_arguments(self) -> None:
        err = io.StringIO()
        code = status_helper.main(
            ["-c", "alpha"],
            policy_path=self.runtime(),
            input_stream=io.BytesIO(request()),
            output_stream=io.StringIO(),
            error_stream=err,
            require_secure=False,
            require_root=False,
        )
        self.assertEqual(code, 64)
        self.assertIn("no command-line arguments", err.getvalue())

    def test_the_helper_refuses_a_caller_that_is_not_root(self) -> None:
        err = io.StringIO()
        code = status_helper.main(
            [],
            policy_path=self.runtime(),
            input_stream=io.BytesIO(request()),
            output_stream=io.StringIO(),
            error_stream=err,
            require_secure=False,
            require_root=True,
        )
        self.assertEqual(code, status_helper.EXIT_NOT_ROOT)

    def test_the_helper_refuses_an_unknown_cluster(self) -> None:
        code, _, err = self.run_helper(request(cluster="gamma"))
        self.assertEqual(code, 64)
        self.assertIn("unknown cluster", err)

    def test_the_helper_refuses_parameters_it_does_not_take(self) -> None:
        code, _, err = self.run_helper(request(parameters={"json": True}))
        self.assertEqual(code, 65)
        self.assertIn("json", err)

    def test_a_missing_status_identity_is_named_rather_than_guessed(self) -> None:
        out, err = io.StringIO(), io.StringIO()
        code = status_helper.main(
            [],
            policy_path=self.runtime(identity=False),
            input_stream=io.BytesIO(request()),
            output_stream=out,
            error_stream=err,
            require_secure=False,
            require_root=False,
        )
        self.assertEqual(code, status_helper.EXIT_NO_IDENTITY)
        self.assertIn("status_identity", err.getvalue())


class HelperReadingTests(HelperFixture):
    def test_it_asks_every_configured_node_and_reports_the_published_target(self) -> None:
        code, out, _ = self.run_helper(request())
        self.assertEqual(code, 0)
        self.assertEqual(self.asked, ["node-a", "node-b"])
        #
        # Held to the frozen schema, not only to the fields this test reads.
        # The poller parses this document on every tick; a field that quietly
        # changed shape here would surface as a dashboard that is wrong rather
        # than as a test that failed.
        #
        envelope = assert_contract("haproxy-status", out)
        self.assertEqual(envelope["outcome"], "done")
        self.assertEqual(envelope["request_id"], REQUEST_ID)
        self.assertEqual(
            envelope["result"]["summary"]["target"], {"version": 8, "hash": TARGET_HASH}
        )
        self.assertEqual(envelope["result"]["summary"]["release_state"], "converged")
        self.assertEqual(envelope["result"]["summary"]["validator_version"], "3.2.9-1")

    def test_a_validator_that_cannot_be_read_is_null_and_still_valid(self) -> None:
        code, out, _ = self.run_helper(request(), version_reader=lambda: None)
        self.assertEqual(code, 0)
        self.assertIsNone(
            assert_contract("haproxy-status", out)["result"]["summary"]["validator_version"]
        )

    def test_an_unknown_cluster_is_refused_in_the_frozen_envelope(self) -> None:
        """A refusal is a result. The contract promises one document on stdout
        on every path, and a caller that gets an exit code and nothing to parse
        has to guess what happened."""

        code, out, err = self.run_helper(request("beta"))

        self.assertEqual(code, 64)
        self.assertIn("unknown cluster", err)
        document = assert_contract("haproxy-status", out)
        self.assertEqual(document["operation"], "status")
        self.assertEqual(document["outcome"], "failed")
        self.assertEqual(document["request_id"], REQUEST_ID)
        self.assertEqual(document["error"]["code"], "bad_input")
        self.assertIsNone(document["result"])

    def test_a_node_on_another_release_is_reported_as_behind(self) -> None:
        code, out, _ = self.run_helper(
            request(),
            node_reader=self.reader(
                **{
                    "node-a": node_status("node-a", owner=True, release_hash=TARGET_HASH),
                    "node-b": node_status("node-b", owner=False, release_hash="d" * 40),
                }
            ),
        )
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["result"]["summary"]["release_state"], "behind")

    def test_a_node_with_the_release_but_not_its_addresses_is_behind(self) -> None:
        """The state the release hash alone reports as converged.

        Both nodes run the published version. One of them did not take the
        address list that version publishes, which is the half a deploy still
        has to finish - so the status has to say behind, or the operator is
        told to do nothing about a cluster that is not yet where it was sent.
        """

        stale = dict(ADDRESSES, installed_sha256="b2" * 32)
        code, out, _ = self.run_helper(
            request(),
            node_reader=self.reader(
                **{
                    "node-a": node_status("node-a", owner=True, release_hash=TARGET_HASH),
                    "node-b": node_status(
                        "node-b", owner=False, release_hash=TARGET_HASH, addresses=stale
                    ),
                }
            ),
        )

        self.assertEqual(code, 0)
        result = json.loads(out)["result"]
        self.assertEqual(result["summary"]["release_state"], "behind")
        self.assertIs(result["nodes"][1]["current"], False)

    def test_a_node_that_said_nothing_about_addresses_is_not_compared(self) -> None:
        """An older status script. Unknown, and never reported as converged."""

        code, out, _ = self.run_helper(
            request(),
            node_reader=self.reader(
                **{
                    "node-a": node_status("node-a", owner=True, release_hash=TARGET_HASH),
                    "node-b": node_status(
                        "node-b", owner=False, release_hash=TARGET_HASH, addresses=False
                    ),
                }
            ),
        )

        self.assertEqual(code, 0)
        result = json.loads(out)["result"]
        self.assertIsNone(result["nodes"][1]["current"])
        self.assertEqual(result["summary"]["release_state"], "incomplete")

    def test_a_stopped_engine_under_a_release_with_rules_is_a_warning(self) -> None:
        # Review 2026-10-04 F3: the node said so, and nothing passed it on.
        code, out, _ = self.run_helper(
            request(), waf=True, node_reader=self.engines(b_active=False)
        )
        self.assertEqual(code, 0)
        envelope = assert_contract("haproxy-status", out)
        self.assertEqual(envelope["outcome"], "done")
        self.assertIs(envelope["result"]["summary"]["waf_published"], True)
        self.assertEqual(
            [(w["code"], w["node"]) for w in envelope["warnings"]],
            [("waf_engine_stopped", "node-b")],
        )

    def test_a_stopped_engine_without_rules_is_how_it_should_be(self) -> None:
        code, out, _ = self.run_helper(request(), node_reader=self.engines(b_active=False))
        self.assertEqual(code, 0)
        envelope = assert_contract("haproxy-status", out)
        self.assertIs(envelope["result"]["summary"]["waf_published"], False)
        self.assertEqual(envelope["warnings"], [])

    def test_nothing_published_says_nothing_about_the_engine(self) -> None:
        code, out, _ = self.run_helper(
            request(), published_hash=None, node_reader=self.engines(b_active=False)
        )
        self.assertEqual(code, 0)
        self.assertNotIn("waf_published", json.loads(out)["result"]["summary"])

    def test_nothing_published_is_reported_as_unknown(self) -> None:
        code, out, _ = self.run_helper(request(), published_hash=None)
        self.assertEqual(code, 0)
        summary = json.loads(out)["result"]["summary"]
        self.assertIsNone(summary["target"])
        self.assertEqual(summary["release_state"], "unknown")


def completed(
    stdout: str, *, returncode: int = 0, stderr: str = ""
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        args=["helper"], returncode=returncode, stdout=stdout, stderr=stderr
    )


class CallerTests(HelperFixture):
    def envelope(self, **overrides) -> str:
        _, out, _ = self.run_helper(request(), **overrides)
        return out

    def run_caller(self, argv: list[str], payload: subprocess.CompletedProcess[str]):
        out, err = io.StringIO(), io.StringIO()
        self.sent: list[tuple[str, str]] = []

        def run_helper(cluster_id: str, request_id: str):
            self.sent.append((cluster_id, request_id))
            return payload

        code = status.main(argv, stream_out=out, stream_err=err, run_helper=run_helper)
        return code, out.getvalue(), err.getvalue()

    def test_the_caller_sends_only_the_cluster_name(self) -> None:
        code, out, _ = self.run_caller(["-c", "alpha"], completed(self.envelope()))
        self.assertEqual(code, 0)
        self.assertEqual(self.sent[0][0], "alpha")
        self.assertIn("Cluster: alpha", out)

    def test_the_human_output_names_the_version_and_that_it_is_published(self) -> None:
        _, out, _ = self.run_caller(["-c", "alpha"], completed(self.envelope()))
        self.assertIn("Version:      8   (published)", out)
        self.assertIn("Published:      8", out)
        self.assertIn("every node runs the published version", out)

    def test_the_address_list_is_named_when_it_is_the_half_that_is_behind(self) -> None:
        """Otherwise BEHIND on a matching version reads as a contradiction."""

        stale = dict(ADDRESSES, installed_sha256="b2" * 32)
        payload = self.envelope(
            node_reader=self.reader(
                **{
                    "node-a": node_status("node-a", owner=True, release_hash=TARGET_HASH),
                    "node-b": node_status(
                        "node-b", owner=False, release_hash=TARGET_HASH, addresses=stale
                    ),
                }
            )
        )

        _, out, _ = self.run_caller(["-c", "alpha"], completed(payload))

        self.assertIn("Addresses:    in use", out)
        self.assertIn("Addresses:    BEHIND the release - run haproxy-deploy", out)

    def test_a_node_behind_is_told_what_to_do_about_it(self) -> None:
        payload = self.envelope(
            node_reader=self.reader(
                **{
                    "node-a": node_status("node-a", owner=True, release_hash=TARGET_HASH),
                    "node-b": node_status("node-b", owner=False, release_hash="d" * 40),
                }
            )
        )
        _, out, _ = self.run_caller(["-c", "alpha"], completed(payload))
        self.assertIn("BEHIND - run haproxy-deploy", out)
        self.assertIn("at least one node is not running the published version", out)

    def test_a_node_on_an_older_haproxy_is_named_and_so_is_the_validator(self) -> None:
        """Fas 16 punkt 3b: the dashboard's rule, in the terminal's words."""

        payload = self.envelope(
            node_reader=self.reader(
                **{
                    "node-a": node_status(
                        "node-a", owner=True, release_hash=TARGET_HASH, runtime="3.4.6-1"
                    ),
                    "node-b": node_status(
                        "node-b", owner=False, release_hash=TARGET_HASH, runtime="3.4.4-1"
                    ),
                }
            ),
            version_reader=lambda: "3.4.4-1",
        )
        _, out, _ = self.run_caller(["-c", "alpha"], completed(payload))
        self.assertIn("HAProxy ver:  3.4.6-1\n", out)
        self.assertIn("HAProxy ver:  3.4.4-1  (Behind 3.4.6)", out)
        self.assertIn("Validator:      3.4.4-1 (this host)", out)

    def test_the_waf_engine_is_read_against_whether_the_release_has_rules(self) -> None:
        stopped = self.engines(b_active=False)
        # Without rules first: the fixture's published tree only ever gains them.
        _, out, _ = self.run_caller(["-c", "alpha"], completed(self.envelope(node_reader=stopped)))
        self.assertIn("WAF engine:   not in use (0.9.0-4)\n", out)
        self.assertNotIn("WARNING", out)
        _, out, _ = self.run_caller(
            ["-c", "alpha"], completed(self.envelope(waf=True, node_reader=stopped))
        )
        self.assertIn("WAF engine:   ACTIVE (0.9.0-4)\n", out)
        self.assertIn("WAF engine:   STOPPED (0.9.0-4)\n", out)
        self.assertIn("WARNING: the WAF engine is not running on node-b\n", out)

    def test_json_mode_prints_the_envelope_and_nothing_else(self) -> None:
        payload = self.envelope()
        code, out, _ = self.run_caller(["-c", "alpha", "--json"], completed(payload))
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["operation"], "status")
        self.assertEqual(out.count("\n"), 1)

    def test_a_helper_that_produced_no_document_reports_its_own_stderr(self) -> None:
        code, _, err = self.run_caller(
            ["-c", "alpha"],
            completed("", returncode=1, stderr="sudo: a password is required"),
        )
        self.assertEqual(code, 1)
        self.assertIn("password is required", err)

    def test_an_unusable_envelope_is_refused_rather_than_rendered(self) -> None:
        code, out, err = self.run_caller(["-c", "alpha"], completed('{"result": null}'))
        self.assertEqual(out, "")
        self.assertIn("ERROR", err)
        self.assertEqual(code, 68)

    def test_the_usage_is_refused_without_a_cluster(self) -> None:
        for argv in ([], ["alpha"], ["-c", "alpha", "--verbose"]):
            with self.subTest(argv=argv):
                with self.assertRaises(SystemExit) as raised:
                    self.run_caller(argv, completed(""))
                self.assertEqual(raised.exception.code, 64)


if __name__ == "__main__":
    unittest.main()


class KeepalivedStateTests(unittest.TestCase):
    """The state file outlives a stopped keepalived; what is shown must not."""

    def test_a_stopped_keepalived_reads_stopped_whatever_the_file_says(self) -> None:
        self.assertEqual(
            cluster_status.keepalived_state({"active": False, "state": "MASTER"}), "STOPPED"
        )

    def test_a_running_keepalived_reads_its_state(self) -> None:
        self.assertEqual(
            cluster_status.keepalived_state({"active": True, "state": "BACKUP"}), "BACKUP"
        )
        self.assertIsNone(cluster_status.keepalived_state({"active": True, "state": None}))
        self.assertIsNone(cluster_status.keepalived_state(None))
