from __future__ import annotations

import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

from haproxy_mgmt.cli import inventory, inventory_helper
from tests.contract_schema import assert_contract

BASE = Path(__file__).resolve().parents[1]
REQUEST_ID = "55555555-5555-4555-8555-555555555555"
TARGET_HASH = "c" * 40


def request(**overrides: object) -> bytes:
    document: dict[str, object] = {
        "schema_version": 1,
        "operation": "inventory",
        "cluster": "alpha",
        "request_id": REQUEST_ID,
        "parameters": {},
    }
    document.update(overrides)
    return json.dumps(document).encode()


class InventoryHelperTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def runtime(self, *, published: bool = True) -> Path:
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
        if published:
            release = publish_root / "alpha" / "current" / entry["node_path"]
            release.mkdir(parents=True)
            (release / "RELEASE").write_text(
                f"schema=1\ncluster=alpha\nversion=8\nhash={TARGET_HASH}\n",
                encoding="utf-8",
            )
        policy = {
            "schema_version": 1,
            "cluster_file": str(self.root / "clusters.yaml"),
            "config_root": str(config_root),
            "publish_root": str(publish_root),
            "validation_certs_root": str(cert_root),
        }
        policy_path = self.root / "runtime-policy.yaml"
        policy_path.write_text(yaml.safe_dump(policy), encoding="utf-8")
        return policy_path

    def run_helper(self, *, published: bool = True, tree_reader=None, cluster: str = "alpha"):
        out, err = io.StringIO(), io.StringIO()
        read = tree_reader or (lambda _repo, _commit: {"core/haproxy.cfg": b"global\n"})
        code = inventory_helper.main(
            [],
            policy_path=self.runtime(published=published),
            input_stream=io.BytesIO(request(cluster=cluster)),
            output_stream=out,
            error_stream=err,
            require_secure=False,
            require_root=False,
            tree_reader=read,
        )
        return code, out.getvalue(), err.getvalue()

    def test_it_reads_the_commit_named_by_the_published_release(self) -> None:
        called: list[tuple[Path, str]] = []

        def tree(repo: Path, commit: str) -> dict[str, bytes]:
            called.append((repo, commit))
            return {"managed/generated/1002-app.cfg": b"frontend app\n  bind :443 ssl\n"}

        code, out, _ = self.run_helper(tree_reader=tree)
        self.assertEqual(code, 0)
        self.assertEqual(called[0][1], TARGET_HASH)
        document = assert_contract("haproxy-inventory", out)
        self.assertEqual(document["outcome"], "done")
        self.assertEqual(document["request_id"], REQUEST_ID)
        self.assertTrue(document["result"]["proxies"][0]["managed"])

    def test_unpublished_cluster_is_empty_without_opening_a_work_tree(self) -> None:
        def must_not_read(_repo: Path, _commit: str) -> dict[str, bytes]:
            self.fail("an unpublished cluster must not read its work tree")

        code, out, _ = self.run_helper(published=False, tree_reader=must_not_read)
        self.assertEqual(code, 0)
        result = json.loads(out)["result"]
        self.assertIsNone(result["version"])
        self.assertEqual(result["proxies"], [])

    def test_bad_inventory_is_a_structured_failed_envelope(self) -> None:
        code, out, _ = self.run_helper(
            tree_reader=lambda _repo, _commit: {"core/haproxy.cfg": b"\xff"}
        )
        self.assertEqual(code, 65)
        document = assert_contract("haproxy-inventory", out)
        self.assertEqual(document["outcome"], "failed")
        self.assertEqual(document["error"]["code"], "inventory_invalid")

    def test_an_unknown_cluster_is_refused_in_the_frozen_envelope(self) -> None:
        code, out, err = self.run_helper(cluster="beta")

        self.assertEqual(code, 64)
        self.assertIn("unknown cluster", err)
        document = assert_contract("haproxy-inventory", out)
        self.assertEqual(document["outcome"], "failed")
        self.assertEqual(document["error"]["code"], "bad_input")

    def test_protocol_and_argument_errors_do_not_cross_the_boundary(self) -> None:
        err = io.StringIO()
        code = inventory_helper.main(
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


class InventoryCallerTests(unittest.TestCase):
    @staticmethod
    def document() -> str:
        return json.dumps(
            {
                "schema_version": 1,
                "ok": True,
                "outcome": "done",
                "operation": "inventory",
                "cluster": "alpha",
                "request_id": REQUEST_ID,
                "result": {
                    "version": 8,
                    "hash": TARGET_HASH,
                    "generated_at": "2026-08-29T12:30:00Z",
                    "proxies": [
                        {
                            "id": "proxy:app",
                            "name": "app",
                            "managed": True,
                            "source": "managed",
                            "protocol": "https",
                            "enabled": True,
                            "hostnames": ["app.example.test"],
                            "bind_ports": [443],
                            "backend_count": 2,
                        }
                    ],
                    "reservations": {"hostnames": [], "tcp_ports": []},
                },
                "warnings": [],
                "error": None,
            }
        )

    def run_caller(self, argv: list[str], payload: subprocess.CompletedProcess[str]):
        sent: list[tuple[str, str]] = []

        def helper(cluster: str, request_id: str) -> subprocess.CompletedProcess[str]:
            sent.append((cluster, request_id))
            return payload

        out, err = io.StringIO(), io.StringIO()
        code = inventory.main(argv, stream_out=out, stream_err=err, run_helper=helper)
        return code, out.getvalue(), err.getvalue(), sent

    def test_json_mode_forwards_the_helper_document(self) -> None:
        payload = subprocess.CompletedProcess(["helper"], 0, self.document(), "")
        code, shown, _, sent = self.run_caller(["-c", "alpha", "--json"], payload)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(shown)["operation"], "inventory")
        self.assertEqual(sent[0][0], "alpha")

    def test_human_mode_renders_a_small_inventory_table(self) -> None:
        payload = subprocess.CompletedProcess(["helper"], 0, self.document(), "")
        _, shown, _, _ = self.run_caller(["-c", "alpha"], payload)
        self.assertIn("Published: 8", shown)
        self.assertIn("app", shown)
        self.assertIn("managed", shown)


if __name__ == "__main__":
    unittest.main()
