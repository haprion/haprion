from __future__ import annotations

import json
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from subprocess import CompletedProcess
from unittest import mock

from haproxy_ui import snapshot


class SnapshotTests(unittest.TestCase):
    def test_status_capture_keeps_only_display_fields_and_drops_helper_stderr(self) -> None:
        completed = CompletedProcess(
            args=[],
            returncode=0,
            stdout=json.dumps(
                {
                    "operation": "status",
                    "cluster": "edge",
                    "outcome": "done",
                    "result": {
                        "nodes": [
                            {
                                "name": "edge-a",
                                "mgmt_host": "edge-a.example",
                                "reachable": True,
                                "status_ok": True,
                                "current": True,
                                "status": {
                                    "haproxy": {"active": True},
                                    "keepalived": {"active": True, "state": "MASTER"},
                                    "vip": {"owner": True},
                                    "release": {"version": 24, "hash": "not-copied"},
                                    "config_validation": {"valid": True},
                                    "stats_ok": True,
                                    "runtime": {"version": "3.2", "uptime_sec": 40},
                                    "certificates": {"private": "not-copied"},
                                },
                            }
                        ],
                        "summary": {"configured_nodes": 2, "reachable_nodes": 2},
                    },
                }
            ),
            stderr="sensitive helper failure text",
        )
        document = snapshot._status_document("edge", completed)
        node = document["result"]["nodes"][0]
        self.assertEqual(node["status"]["release"], {"version": 24})
        self.assertNotIn("certificates", node["status"])
        self.assertNotIn("sensitive", json.dumps(document))

    def test_malformed_helper_output_becomes_a_safe_unavailable_reading(self) -> None:
        document = snapshot._status_document(
            "edge", CompletedProcess(args=[], returncode=1, stdout="not json", stderr="private")
        )
        self.assertEqual(document, {"outcome": "failed", "result": {"nodes": [], "summary": {}}})

    def test_a_valid_local_snapshot_becomes_normal_view_rows(self) -> None:
        document = {
            "schema_version": 1,
            "source": "production",
            "captured_at": "2026-08-29T12:00:00Z",
            "clusters": [
                {
                    "cluster": "edge",
                    "status": {"outcome": "done", "result": {"nodes": [], "summary": {}}},
                    "inventory": {"outcome": "done", "result": {"proxies": []}},
                }
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / snapshot.SNAPSHOT_NAME
            path.write_text(json.dumps(document), encoding="utf-8")
            loaded = snapshot.load_production_snapshot(path, require_secure=False)
        self.assertEqual(loaded.clusters, ("edge",))
        self.assertEqual(loaded.status_rows[0].observed_at, datetime(2026, 8, 29, 12, tzinfo=UTC))
        self.assertEqual(loaded.inventory_rows[0].result, {"proxies": []})

    def test_capture_uses_status_helper_and_published_tree_without_worktree_reads(self) -> None:
        runtime = mock.Mock()
        cluster = mock.Mock(config_path="/repo", publish_path="/published", node_path="node-a")
        runtime.clusters = {"edge": cluster}
        target = mock.Mock(hash="a" * 40, version=24)
        completed = CompletedProcess(
            args=[],
            returncode=0,
            stdout=json.dumps(
                {"operation": "status", "cluster": "edge", "outcome": "done", "result": {}}
            ),
            stderr="",
        )
        with (
            mock.patch("haproxy_ui.snapshot.load_policy", return_value=mock.Mock()),
            mock.patch("haproxy_ui.snapshot.load_runtime_config", return_value=runtime),
            mock.patch("haproxy_ui.snapshot.read_target", return_value=target),
            mock.patch("haproxy_ui.snapshot.read_tree_files", return_value={}) as tree_reader,
        ):
            document = snapshot.collect_production_snapshot(
                now=datetime(2026, 8, 29, 12, tzinfo=UTC), status_runner=lambda *_: completed
            )
        self.assertEqual(document["source"], "production")
        self.assertEqual(document["clusters"][0]["inventory"]["result"]["version"], 24)
        tree_reader.assert_called_once_with(Path("/repo"), "a" * 40)


if __name__ == "__main__":
    unittest.main()
