"""``haproxy-list-backups``: what it reports, and what it refuses to look at.

The envelopes built here are validated against `schemas/v1`, so the test fails
if the implementation and the frozen contract drift apart - the fixtures under
`fixtures/` state what the contract allows, and this states that the code
actually produces it.
"""

from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from haproxy_mgmt import backups
from haproxy_mgmt.cli import list_backups, list_backups_helper
from haproxy_mgmt.config import Node

SCHEMA_DIR = Path(__file__).resolve().parents[1] / "schemas" / "v1"
SCHEMA_ID = "https://example.com/haproxy-manager/schemas/v1/haproxy-list-backups.schema.json"

NODES = (
    Node(name="node-a", mgmt_host="node-a.example"),
    Node(name="node-b", mgmt_host="node-b.example"),
)


def _validator() -> Draft202012Validator:
    registry = Registry()
    schema: dict[str, object] = {}
    for path in sorted(SCHEMA_DIR.glob("*.schema.json")):
        loaded = json.loads(path.read_text(encoding="utf-8"))
        registry = registry.with_resource(str(loaded["$id"]), Resource.from_contents(loaded))
        if loaded["$id"] == SCHEMA_ID:
            schema = loaded
    return Draft202012Validator(schema, registry=registry, format_checker=FormatChecker())


def _archive(directory: Path, version: str, *, size: int = 4096) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{version}.tar.gz"
    path.write_bytes(b"x" * size)
    moment = datetime.strptime(version, "%Y-%m-%d_%H-%M-%S").replace(tzinfo=UTC).timestamp()
    os.utime(path, (moment, moment))
    return path


class NodeBackupsTests(unittest.TestCase):
    def test_archives_are_newest_first_and_the_latest_link_marks_one(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            node = root / "node-a"
            _archive(node, "2026-08-27_05-00-00")
            _archive(node, "2026-08-29_05-00-00")
            _archive(node, "2026-08-28_05-00-00")
            (node / "latest").symlink_to("2026-08-29_05-00-00.tar.gz")

            reading = backups.node_backups(root, NODES[0], limit=None)

        self.assertEqual(
            [backup["version"] for backup in reading.backups],
            ["2026-08-29_05-00-00", "2026-08-28_05-00-00", "2026-08-27_05-00-00"],
        )
        self.assertEqual(reading.latest_version, "2026-08-29_05-00-00")
        self.assertEqual([backup["latest"] for backup in reading.backups], [True, False, False])

    def test_the_limit_keeps_the_newest_and_null_keeps_everything(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            node = root / "node-a"
            for day in range(20, 25):
                _archive(node, f"2026-08-{day}_05-00-00")

            limited = backups.node_backups(root, NODES[0], limit=2)
            everything = backups.node_backups(root, NODES[0], limit=None)

        self.assertEqual(
            [backup["version"] for backup in limited.backups],
            ["2026-08-24_05-00-00", "2026-08-23_05-00-00"],
        )
        self.assertEqual(len(everything.backups), 5)

    def test_only_archives_are_reported(self) -> None:
        #
        # The directory is root-owned and holds what the backup engine writes,
        # but "everything that is in there" is not a listing of backups. A
        # half-written archive is worse than an unlisted one: it would be
        # offered as something restorable.
        #
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            node = root / "node-a"
            _archive(node, "2026-08-29_05-00-00")
            _archive(node, "2026-08-28_05-00-00", size=0)
            (node / "notes.txt").write_text("not a backup", encoding="utf-8")
            (node / "2026-08-27_05-00-00.tar.gz.partial").write_bytes(b"xxxx")

            reading = backups.node_backups(root, NODES[0], limit=None)

        self.assertEqual([backup["version"] for backup in reading.backups], ["2026-08-29_05-00-00"])

    def test_a_missing_directory_is_a_fact_about_one_node(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _archive(root / "node-a", "2026-08-29_05-00-00")

            result, readings = backups.backup_list_result(root, NODES, limit=10)

        self.assertEqual(readings[0].error, None)
        self.assertEqual(readings[1].error, "backup_directory_missing")
        self.assertFalse(result["nodes"][1]["available"])
        self.assertEqual(result["nodes"][1]["backups"], [])
        #
        # The readable node still answered. One node's missing directory taking
        # the other's listing down is the failure mode this shape exists to
        # prevent - during the incident where a node is gone, the surviving
        # node's backups are the ones being looked for.
        #
        self.assertEqual(len(result["nodes"][0]["backups"]), 1)


class HelperTests(unittest.TestCase):
    def _run(self, root: Path | None, parameters: dict[str, object]) -> tuple[dict, int]:
        request = {
            "schema_version": 1,
            "operation": "list_backups",
            "cluster": "alpha",
            "request_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "parameters": parameters,
        }
        out, err = io.StringIO(), io.StringIO()

        class Policy:
            backup_root = root

        class Config:
            @staticmethod
            def cluster(_: str) -> object:
                return type("Cluster", (), {"nodes": NODES})

        original_policy = list_backups_helper.load_policy
        original_config = list_backups_helper.load_runtime_config
        list_backups_helper.load_policy = lambda *a, **k: Policy()  # type: ignore[assignment]
        list_backups_helper.load_runtime_config = lambda *a, **k: Config()  # type: ignore[assignment]
        try:
            code = list_backups_helper.main(
                [],
                input_stream=io.BytesIO(json.dumps(request).encode("utf-8")),
                output_stream=out,
                error_stream=err,
                require_root=False,
            )
        finally:
            list_backups_helper.load_policy = original_policy  # type: ignore[assignment]
            list_backups_helper.load_runtime_config = original_config  # type: ignore[assignment]
        return (json.loads(out.getvalue()) if out.getvalue() else {}), code

    def test_a_complete_reading_is_done_and_matches_the_schema(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for node in NODES:
                _archive(root / node.name, "2026-08-29_05-00-00")
                (root / node.name / "latest").symlink_to("2026-08-29_05-00-00.tar.gz")
            document, code = self._run(root, {"limit": 10})

        self.assertEqual(code, 0)
        self.assertEqual(document["outcome"], "done")
        self.assertTrue(document["ok"])
        _validator().validate(document)

    def test_one_unreadable_node_is_partial_and_matches_the_schema(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _archive(root / "node-a", "2026-08-29_05-00-00")
            document, code = self._run(root, {"limit": 10})

        self.assertEqual(code, 0)
        self.assertEqual(document["outcome"], "partial")
        self.assertFalse(document["ok"])
        self.assertEqual(document["warnings"][0]["node"], "node-b")
        self.assertIsNone(document["error"])
        _validator().validate(document)

    def test_a_policy_without_a_backup_root_fails_rather_than_guessing(self) -> None:
        document, code = self._run(None, {"limit": 10})

        self.assertEqual(code, 65)
        self.assertEqual(document["outcome"], "failed")
        self.assertEqual(document["error"]["code"], "backup_metadata_unavailable")
        _validator().validate(document)

    def test_a_limit_that_is_not_a_bounded_integer_is_refused(self) -> None:
        for value in ("10", 0, -1, True, 10_001):
            with self.subTest(value=value):
                document, code = self._run(Path("/nonexistent"), {"limit": value})
                self.assertEqual(code, 65)
                self.assertEqual(document, {})


class CommandTests(unittest.TestCase):
    def _document(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "ok": True,
            "outcome": "done",
            "operation": "list_backups",
            "cluster": "alpha",
            "request_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "result": {
                "limit": 10,
                "nodes": [
                    {
                        "name": "node-a",
                        "available": True,
                        "latest_version": "2026-08-29_05-00-00",
                        "backups": [
                            {
                                "version": "2026-08-29_05-00-00",
                                "created_at": "2026-08-29T05:00:00Z",
                                "size_bytes": 28672,
                                "latest": True,
                            }
                        ],
                        "error": None,
                    }
                ],
            },
            "warnings": [],
            "error": None,
        }

    def _run(self, argv: list[str]) -> tuple[str, str, int, list[object]]:
        seen: list[object] = []
        out, err = io.StringIO(), io.StringIO()

        def run_helper(cluster: str, request_id: str, limit: int | None):
            seen.append(limit)
            return type(
                "Completed",
                (),
                {"stdout": json.dumps(self._document()), "stderr": "", "returncode": 0},
            )

        code = list_backups.main(argv, stream_out=out, stream_err=err, run_helper=run_helper)
        return out.getvalue(), err.getvalue(), code, seen

    def test_the_listing_names_the_node_the_version_and_the_size(self) -> None:
        rendered, _, code, _ = self._run(["-c", "alpha"])

        self.assertEqual(code, 0)
        self.assertIn("=== node-a ===", rendered)
        self.assertIn("latest -> 2026-08-29_05-00-00", rendered)
        self.assertIn("28K", rendered)

    def test_all_asks_for_every_retained_backup(self) -> None:
        #
        # A null limit is the contract's way of saying "no limit", and it has to
        # survive the trip rather than becoming a large number here.
        #
        _, _, _, seen = self._run(["-c", "alpha", "--all"])
        self.assertEqual(seen, [None])

        _, _, _, seen = self._run(["-c", "alpha"])
        self.assertEqual(seen, [list_backups.DEFAULT_LIMIT])

    def test_json_mode_passes_the_envelope_through_untouched(self) -> None:
        rendered, _, code, _ = self._run(["-c", "alpha", "--json"])

        self.assertEqual(code, 0)
        self.assertEqual(json.loads(rendered), self._document())


if __name__ == "__main__":
    unittest.main()
