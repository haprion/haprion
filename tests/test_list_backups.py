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
from unittest import mock

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from haproxy_mgmt import backups
from haproxy_mgmt.cli import list_backups, list_backups_helper
from haproxy_mgmt.config import Node

SCHEMA_DIR = Path(__file__).resolve().parents[1] / "schemas" / "v1"
SCHEMA_ID = "https://example.com/haproxy-manager/schemas/v1/haproxy-list-backups.schema.json"


def _cluster(names: tuple[str, ...]):
    return type(
        "Cluster", (), {"nodes": tuple(Node(name=n, mgmt_host=f"{n}.example") for n in names)}
    )


def _config(clusters: dict):
    return type("Config", (), {"clusters": clusters})


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
            backup_timer = None

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

    def test_a_node_the_cluster_does_not_have_is_refused_not_answered_empty(self) -> None:
        #
        # The schema needs at least one node, and an empty listing would read
        # as "this node has no backups" when the truth is "this cluster has no
        # such node".
        #
        document, code = self._run(Path("/nonexistent"), {"limit": 10, "node": "node-z"})

        self.assertEqual(code, 64)
        self.assertEqual(document["outcome"], "failed")
        self.assertEqual(document["error"]["code"], "bad_input")
        _validator().validate(document)

    def test_a_node_name_that_is_not_a_name_is_refused_before_any_read(self) -> None:
        for value in ("../etc", "Node-A", 7, ""):
            with self.subTest(value=value):
                document, code = self._run(Path("/nonexistent"), {"node": value})
                self.assertEqual(code, 64)
                self.assertEqual(document, {})

    def test_one_named_node_reads_only_that_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for node in NODES:
                _archive(root / node.name, "2026-08-29_05-00-00")
            document, code = self._run(root, {"limit": 10, "node": "node-b"})

        self.assertEqual(code, 0)
        self.assertEqual([node["name"] for node in document["result"]["nodes"]], ["node-b"])
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

        def run_helper(cluster: str, request_id: str, limit: int | None, node: str | None = None):
            seen.append((cluster, limit, node))
            return type(
                "Completed",
                (),
                {"stdout": json.dumps(self._document()), "stderr": "", "returncode": 0},
            )

        code = list_backups.main(argv, stream_out=out, stream_err=err, run_helper=run_helper)
        return out.getvalue(), err.getvalue(), code, seen

    def _run_with(
        self, document: dict[str, object], argv: list[str]
    ) -> tuple[str, str, int, list[object]]:
        seen: list[object] = []
        out, err = io.StringIO(), io.StringIO()

        def run_helper(cluster: str, request_id: str, limit: int | None, node: str | None = None):
            seen.append((cluster, limit, node))
            return type(
                "Completed",
                (),
                {"stdout": json.dumps(document), "stderr": "", "returncode": 0},
            )

        code = list_backups.main(argv, stream_out=out, stream_err=err, run_helper=run_helper)
        return out.getvalue(), err.getvalue(), code, seen

    def test_the_listing_names_the_node_the_version_and_the_size(self) -> None:
        rendered, _, code, _ = self._run(["-c", "alpha"])

        self.assertEqual(code, 0)
        self.assertIn("=== node-a ===", rendered)
        self.assertIn("latest -> 2026-08-29_05-00-00.tar.gz", rendered)
        self.assertIn("28K", rendered)
        #
        # The listing names the archive, not the stamp. `version` is what the
        # envelope calls the field, and putting that word in front of an
        # operator would promise a version number where there is a filename.
        #
        self.assertIn("2026-08-29_05-00-00.tar.gz", rendered)
        self.assertIn("BACKUP", rendered)
        self.assertNotIn("VERSION", rendered)

    def test_the_schedule_is_stated_above_the_nodes(self) -> None:
        #
        # An operator reads "is anything still taking these" before reading
        # which archives exist, so the timer goes first. A directory of old
        # files looks the same whether or not something is still filling it.
        #
        document = self._document()
        assert isinstance(document["result"], dict)
        document["result"]["schedule"] = {
            "unit": "haproxy-state-backup.timer",
            "known": True,
            "enabled": True,
            "active": True,
            "calendar": "*-*-* 05:00:00",
            "next_run": "2026-08-30T03:00:00Z",
            "last_run": "2026-08-29T03:00:40Z",
            "last_result": "success",
        }
        rendered, _, code, _ = self._run_with(document, ["-c", "alpha"])

        self.assertEqual(code, 0)
        self.assertIn("Schedule: *-*-* 05:00:00 (enabled)", rendered)
        self.assertIn("(success)", rendered)
        self.assertLess(rendered.index("Schedule:"), rendered.index("=== node-a ==="))

    def test_a_disabled_timer_is_shouted_rather_than_mentioned(self) -> None:
        document = self._document()
        assert isinstance(document["result"], dict)
        document["result"]["schedule"] = {
            "unit": "haproxy-state-backup.timer",
            "known": True,
            "enabled": False,
            "active": False,
            "calendar": "*-*-* 05:00:00",
            "next_run": None,
            "last_run": None,
            "last_result": None,
        }
        rendered, _, _, _ = self._run_with(document, ["-c", "alpha"])

        self.assertIn("(DISABLED)", rendered)
        self.assertNotIn("next run", rendered)

    def test_an_installation_with_no_declared_timer_says_nothing_about_one(self) -> None:
        #
        # Printing "Schedule: unknown" would suggest something is missing. The
        # truthful reading is that this deployment never declared what takes
        # its backups.
        #
        document = self._document()
        assert isinstance(document["result"], dict)
        document["result"]["schedule"] = None
        rendered, _, _, _ = self._run_with(document, ["-c", "alpha"])

        self.assertNotIn("Schedule", rendered)

    def test_a_timer_systemd_lost_is_named_in_the_listing(self) -> None:
        document = self._document()
        assert isinstance(document["result"], dict)
        document["result"]["schedule"] = {
            "unit": "haproxy-state-backup.timer",
            "known": False,
            "enabled": False,
            "active": False,
            "calendar": None,
            "next_run": None,
            "last_run": None,
            "last_result": None,
        }
        rendered, _, _, _ = self._run_with(document, ["-c", "alpha"])

        self.assertIn("haproxy-state-backup.timer is not known to systemd", rendered)

    def test_all_asks_for_every_retained_backup(self) -> None:
        #
        # A null limit is the contract's way of saying "no limit", and it has to
        # survive the trip rather than becoming a large number here.
        #
        _, _, _, seen = self._run(["-c", "alpha", "--all"])
        self.assertEqual(seen, [("alpha", None, None)])

        _, _, _, seen = self._run(["-c", "alpha"])
        self.assertEqual(seen, [("alpha", list_backups.DEFAULT_LIMIT, None)])

    def test_a_failed_envelope_is_reported_as_what_the_helper_said(self) -> None:
        #
        # The reader has to be sent to the cause, not to the reader. A failed
        # envelope carries a structured reason - a missing backup_root, most
        # often - and reporting it as "invalid result" would send someone
        # looking for a bug in the helper that just answered them.
        #
        out, err = io.StringIO(), io.StringIO()

        def run_helper(cluster: str, request_id: str, limit: int | None, node: str | None = None):
            document = {
                "schema_version": 1,
                "ok": False,
                "outcome": "failed",
                "operation": "list_backups",
                "cluster": "alpha",
                "request_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "result": None,
                "warnings": [],
                "error": {
                    "code": "backup_metadata_unavailable",
                    "message": "the runtime policy declares no backup_root",
                    "node": None,
                    "details": None,
                },
            }
            return type(
                "Completed", (), {"stdout": json.dumps(document), "stderr": "", "returncode": 65}
            )

        code = list_backups.main(
            ["-c", "alpha"], stream_out=out, stream_err=err, run_helper=run_helper
        )

        self.assertEqual(code, 65)
        self.assertIn("backup_metadata_unavailable", err.getvalue())
        self.assertIn("no backup_root", err.getvalue())
        self.assertNotIn("invalid result", err.getvalue())

    def _with_clusters(self, clusters: dict, argv: list[str]):
        with (
            mock.patch.object(list_backups, "load_policy", lambda *a, **k: object()),
            mock.patch.object(
                list_backups, "load_runtime_config", lambda *a, **k: _config(clusters)
            ),
        ):
            return self._run(argv)

    def test_a_node_is_asked_for_by_name(self) -> None:
        clusters = {"alpha": _cluster(("node-a", "node-b"))}
        _, _, _, seen = self._with_clusters(clusters, ["-c", "alpha", "--node", "node-a"])
        self.assertEqual(seen, [("alpha", list_backups.DEFAULT_LIMIT, "node-a")])

    def test_a_short_name_is_resolved_to_the_node_it_can_only_mean(self) -> None:
        #
        # The shell version took "a02" from a table of aliases compiled into
        # it. The same convenience without the table: a name that ends exactly
        # one node's name is that node.
        #
        clusters = {"alpha": _cluster(("gateway-a01", "gateway-a02"))}
        _, _, code, seen = self._with_clusters(clusters, ["--node", "a02"])

        self.assertEqual(code, 0)
        self.assertEqual(seen, [("alpha", list_backups.DEFAULT_LIMIT, "gateway-a02")])

    def test_a_short_name_that_fits_two_nodes_is_refused_not_guessed(self) -> None:
        #
        # A listing for the wrong node during an incident is worse than a
        # question, and the operator is one keystroke from being exact.
        #
        clusters = {
            "beta": _cluster(("gateway-b02",)),
            "alpha": _cluster(("gateway-a02",)),
        }
        _, err, code, seen = self._with_clusters(clusters, ["--node", "02"])

        self.assertEqual(code, 64)
        self.assertEqual(seen, [])
        self.assertIn("gateway-a02", err)
        self.assertIn("gateway-b02", err)

    def test_an_exact_name_is_never_shadowed_by_a_longer_one(self) -> None:
        #
        # "node-a" ends "extra-node-a" too. An exact match is the answer, or a
        # node could not be asked for by its own name.
        #
        clusters = {"alpha": _cluster(("node-a", "extra-node-a"))}
        _, _, code, seen = self._with_clusters(clusters, ["--node", "node-a"])

        self.assertEqual(code, 0)
        self.assertEqual(seen, [("alpha", list_backups.DEFAULT_LIMIT, "node-a")])

    def test_without_a_cluster_every_configured_cluster_is_asked(self) -> None:
        #
        # The shell implementation this replaces listed every node with no
        # arguments, and that is how the maintainer reads it. The envelope is
        # one cluster's answer, so the command asks once per cluster rather
        # than inventing a document that spans them.
        #
        clusters = {"alpha": _cluster(("node-a",)), "beta": _cluster(("node-b",))}
        with (
            mock.patch.object(list_backups, "load_policy", lambda *a, **k: object()),
            mock.patch.object(
                list_backups, "load_runtime_config", lambda *a, **k: _config(clusters)
            ),
        ):
            _, _, _, seen = self._run([])

        self.assertEqual([entry[0] for entry in seen], ["alpha", "beta"])

    def test_clusters_are_separated_by_a_blank_line(self) -> None:
        clusters = {"alpha": _cluster(("node-a",)), "beta": _cluster(("node-b",))}
        with (
            mock.patch.object(list_backups, "load_policy", lambda *a, **k: object()),
            mock.patch.object(
                list_backups, "load_runtime_config", lambda *a, **k: _config(clusters)
            ),
        ):
            rendered, _, _, _ = self._run([])

        #
        # Without it the second cluster's heading sits directly under the first
        # cluster's last backup and reads as part of it.
        #
        self.assertIn(".tar.gz\n\nCluster:", rendered)

    def test_a_node_without_a_cluster_asks_only_the_cluster_that_has_it(self) -> None:
        #
        # A node belongs to one cluster. Asking all of them would make each
        # other cluster answer "no such node" - a listing of errors for a
        # question that had one right answer.
        #
        clusters = {"alpha": _cluster(("node-a",)), "beta": _cluster(("node-b",))}
        with (
            mock.patch.object(list_backups, "load_policy", lambda *a, **k: object()),
            mock.patch.object(
                list_backups, "load_runtime_config", lambda *a, **k: _config(clusters)
            ),
        ):
            _, err, code, seen = self._run(["--node", "node-b"])
            _, missing_err, missing_code, missing_seen = self._run(["--node", "node-z"])

        self.assertEqual([entry[0] for entry in seen], ["beta"])
        self.assertEqual(missing_seen, [])
        self.assertEqual(missing_code, 64)
        self.assertIn("node-z", missing_err)

    def test_json_mode_passes_the_envelope_through_untouched(self) -> None:
        rendered, _, code, _ = self._run(["-c", "alpha", "--json"])

        self.assertEqual(code, 0)
        self.assertEqual(json.loads(rendered), self._document())


if __name__ == "__main__":
    unittest.main()
