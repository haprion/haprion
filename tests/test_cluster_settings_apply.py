"""``haprion-cluster-settings apply`` (Fas 23): *Logs & metrics* from a file.

Compared field by field with the helper's reading, so the same file publishes
nothing; a difference is one version against the head read, carrying the
canonical document.
"""

from __future__ import annotations

import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any

from haprion.cli import cluster_settings
from tests.contract_schema import assert_contract

HEAD = "a" * 40
STORED = {
    "log_targets": [
        {"name": "loki", "address": "192.0.2.41", "port": 514, "disk_mib": 1024, "tls": False}
    ],
    "not_logged_from": [],
    "metrics": {"port": 8405, "sources": ["198.51.100.0/24"]},
    "peers": None,
}
SAME = """log_targets:
  loki: {address: 192.0.2.41, port: 514, disk_mib: 1024, tls: false}
metrics: {port: 8405, sources: [198.51.100.0/24]}
"""


class TheSettingsFromAFile(unittest.TestCase):
    def run_apply(self, text: str, *extra: str) -> tuple[int, str, list[dict[str, Any]]]:
        published: list[dict[str, Any]] = []

        def read(cluster: str, request_id: str) -> subprocess.CompletedProcess[str]:
            answer = {
                "schema_version": 1,
                "ok": True,
                "outcome": "done",
                "operation": "cluster_settings",
                "cluster": cluster,
                "request_id": request_id,
                "result": {"cluster": cluster, "head": HEAD, "stored": True, **STORED},
                "warnings": [],
                "error": None,
            }
            return subprocess.CompletedProcess([], 0, json.dumps(answer), "")

        def publish(request: str) -> subprocess.CompletedProcess[str]:
            sent = json.loads(request)
            published.append(sent)
            answer = {
                "schema_version": 1,
                "ok": True,
                "outcome": "done",
                "operation": "changes_publish",
                "cluster": sent["cluster"],
                "request_id": sent["request_id"],
                "result": {"changed": True, "version": 8, "hash": "b" * 40},
                "warnings": [],
                "error": None,
            }
            return subprocess.CompletedProcess([], 0, json.dumps(answer), "")

        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "settings.yaml"
            path.write_text(text)
            out = io.StringIO()
            code = cluster_settings.main(
                ["apply", "-c", "alpha", str(path), *extra],
                stream_out=out,
                stream_err=io.StringIO(),
                run_helper=read,
                run_publish=publish,
            )
        return code, out.getvalue(), published

    def test_what_is_stored_publishes_nothing(self) -> None:
        code, out, published = self.run_apply(SAME, "--json")

        self.assertEqual((code, published), (0, []))
        self.assertFalse(
            assert_contract("haprion-cluster-settings-apply", out)["result"]["changed"]
        )

    def test_a_difference_is_one_version_against_the_head_read(self) -> None:
        code, out, published = self.run_apply(SAME.replace("8405", "8406"), "--json")

        self.assertEqual(code, 0)
        (sent,) = published
        self.assertEqual(sent["parameters"]["expected_head"], HEAD)
        self.assertIn("port: 8406", sent["parameters"]["settings"])
        answer = assert_contract("haprion-cluster-settings-apply", out)
        self.assertTrue(answer["result"]["deployment_required"])

    def test_check_publishes_nothing(self) -> None:
        code, out, published = self.run_apply(SAME.replace("8405", "8406"), "--check")

        self.assertEqual((code, published), (0, []))
        self.assertIn("Would change", out)

    def test_a_wrong_file_is_named_before_anything_is_asked(self) -> None:
        code, out, published = self.run_apply("metrics: {port: x}\n", "--json")

        self.assertEqual((code, published), (65, []))
        self.assertEqual(
            assert_contract("haprion-cluster-settings-apply", out)["error"]["code"],
            "settings_invalid",
        )
