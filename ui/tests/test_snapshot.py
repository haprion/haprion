from __future__ import annotations

import json
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from subprocess import CompletedProcess
from unittest import mock
from uuid import UUID

from haproxy_ui import dashboard, snapshot, views


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
                    "history": {"outcome": "done", "result": {"versions": []}},
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
        self.assertEqual(loaded.history_rows[0].result, {"versions": []})

    def test_a_snapshot_taken_before_a_source_existed_still_loads(self) -> None:
        #
        # An older file has no history entry. Refusing it would take the pages
        # that do have data down with the one that does not.
        #
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
        self.assertEqual(loaded.history_rows, ())
        self.assertEqual(len(loaded.status_rows), 1)

    def test_a_captured_version_listing_is_length_capped_before_it_leaves(self) -> None:
        listing = {
            "current_version": 26,
            "total_versions": 26,
            "published_version": 24,
            "published_hash": "a" * 40,
            "unpublished": 2,
            "truncated": True,
            "versions": [
                {
                    "version": number,
                    "hash": "b" * 40,
                    "created_at": "2026-08-28T14:02:11+00:00",
                    "comment": "x" * 500,
                    "current": False,
                }
                for number in range(30, 10, -1)
            ],
        }
        reduced = snapshot._history_result(listing)

        self.assertEqual(len(reduced["versions"]), 10)
        self.assertIsNone(reduced["versions"][0]["comment"])
        self.assertEqual(reduced["published_version"], 24)

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
            request_ids: list[str] = []

            def status_runner(_cluster: str, request_id: str) -> CompletedProcess[str]:
                request_ids.append(request_id)
                return completed

            document = snapshot.collect_production_snapshot(
                now=datetime(2026, 8, 29, 12, tzinfo=UTC), status_runner=status_runner
            )
        self.assertEqual(document["source"], "production")
        self.assertEqual(document["clusters"][0]["inventory"]["result"]["version"], 24)
        tree_reader.assert_called_once_with(Path("/repo"), "a" * 40)
        self.assertIsInstance(UUID(request_ids[0]), UUID)


if __name__ == "__main__":
    unittest.main()


class SnapshotFreshnessTests(unittest.TestCase):
    """What the staleness badge measures when the data is deliberately frozen.

    A snapshot never gets newer. Judged against the wall clock every reading in
    it is stale two poll intervals after it was taken, on every page, forever -
    formally true, and it teaches the reader to stop seeing the badge. It is
    judged against the capture instead, which is the same question the badge
    answers everywhere else: were production's readings current when taken.
    """

    document = {
        "schema_version": 1,
        "source": "production",
        "captured_at": "2026-08-29T12:00:00Z",
        "clusters": [
            {
                "cluster": "edge",
                "status": {"outcome": "done", "result": {"nodes": [], "summary": {}}},
            }
        ],
    }

    def _request(self, path: Path) -> mock.Mock:
        request = mock.Mock()
        request.app.state.config_path = path
        return request

    def test_a_snapshot_is_read_with_the_clock_it_was_taken_by(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / snapshot.SNAPSHOT_NAME
            path.write_text(json.dumps(self.document), encoding="utf-8")
            config = mock.Mock(demo_fixture=False, production_snapshot=True)
            #
            # The real loader, with its permission check waived: the mode and
            # owner of a file in a temporary directory are not what this test
            # is about, and they are covered where they belong.
            #
            real_load = snapshot.load_production_snapshot

            def load(candidate: Path) -> snapshot.ProductionSnapshot:
                return real_load(candidate, require_secure=False)

            with (
                mock.patch.object(views.snapshot, "path_for_config", return_value=path),
                mock.patch.object(views.snapshot, "load_production_snapshot", load),
            ):
                clusters, rows, captured_at = views.read_source(
                    self._request(path), config, views.STATUS_SOURCE
                )

        self.assertEqual(clusters, ("edge",))
        self.assertEqual(captured_at, datetime(2026, 8, 29, 12, tzinfo=UTC))

        #
        # A whole day after the capture, which is far past two poll intervals.
        # The reading was current when it was taken, so nothing is stale.
        #
        view = dashboard.build_dashboard(
            clusters, rows, now=captured_at, stale_after=timedelta(seconds=60)
        )
        self.assertFalse(view.clusters[0].stale)

    def test_the_live_and_fixture_modes_keep_the_wall_clock(self) -> None:
        #
        # Only a snapshot carries a clock. A None here is what makes the view
        # builders fall back to datetime.now, so live readings still go stale.
        #
        config = mock.Mock(demo_fixture=True, production_snapshot=False)
        _, _, captured_at = views.read_source(
            self._request(Path("/nonexistent")), config, views.STATUS_SOURCE
        )
        self.assertIsNone(captured_at)
