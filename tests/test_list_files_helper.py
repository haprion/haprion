"""The `list_files` reading: the lists root keeps, for the poller (B534, PW02).

Pinned here: the answer is revision and digest per file, in its contract; a
blocklist's secret is never in it; a path list the poller does not know carries
its content; a directory that cannot be read is a failure; and the reading is
one of the manager's in `haprion-readings-helper`.
"""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from haprion import blocklist_store, blocklists, exit_codes, path_lists
from haprion.blocklist_store import Stored
from haprion.cli import list_files_helper, readings_helper
from tests.contract_schema import assert_contract

REQUEST_ID = "ffffffff-ffff-4fff-8fff-ffffffffffff"
SECRET = "tok"  # noqa: S105 - a test value the answer must not hold


def request(*, cluster: str | None = None, parameters: dict[str, Any] | None = None) -> bytes:
    return json.dumps(
        {
            "schema_version": 1,
            "operation": "list_files",
            "cluster": cluster,
            "request_id": REQUEST_ID,
            "parameters": parameters or {},
        }
    ).encode()


class TheReading(unittest.TestCase):
    def setUp(self) -> None:
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.paths = root / "path-lists"
        self.blocks = root / "blocklists"
        self.paths.mkdir()
        self.blocks.mkdir()

    def run_helper(self, body: bytes) -> tuple[int, Any]:
        output = io.StringIO()
        code = list_files_helper.main(
            [],
            input_stream=io.BytesIO(body),
            output_stream=output,
            error_stream=io.StringIO(),
            require_root=False,
            path_list_directory=self.paths,
            blocklist_directory=self.blocks,
        )
        return code, json.loads(output.getvalue()) if output.getvalue() else None

    def keep(self) -> None:
        path_lists.write(
            path_lists.path_list("scanners", ["/.env"], "Scanners", 3),
            directory=self.paths,
            require_secure=False,
        )
        path_lists.write(
            path_lists.path_list("taken", ["/.git", "/x"], "", 1),
            directory=self.paths,
            require_secure=False,
        )
        item = blocklists.definition(
            name="community",
            url="https://example.com/list.txt",
            every_hours=24,
            authorization="basic",
            username="admin",
        )
        blocklist_store.write(
            Stored(definition=item, secret=SECRET, revision=2),
            directory=self.blocks,
            require_secure=False,
        )

    def test_answers_revision_and_digest_in_its_contract_without_the_secret(self) -> None:
        self.keep()

        code, document = self.run_helper(request(parameters={"known_path_lists": ["scanners"]}))

        self.assertEqual(code, 0)
        assert_contract("haprion-list-files", json.dumps(document))
        result = document["result"]
        self.assertEqual([entry["name"] for entry in result["path_lists"]], ["scanners", "taken"])
        known, unknown = result["path_lists"]
        self.assertEqual(known["revision"], 3)
        self.assertNotIn("paths", known)
        self.assertEqual((unknown["description"], unknown["paths"]), ("", ["/.git", "/x"]))
        (block,) = result["blocklists"]
        self.assertEqual(block["revision"], 2)
        self.assertEqual(len(block["digest"]), 64)
        self.assertNotIn(SECRET, json.dumps(document))

    def test_no_directory_is_an_empty_answer_and_an_unreadable_one_a_failure(self) -> None:
        code, document = self.run_helper(request())
        self.assertEqual((code, document["result"]), (0, {"path_lists": [], "blocklists": []}))

        self.paths.rmdir()
        self.paths.write_text("not a directory")
        code, document = self.run_helper(request())
        self.assertEqual(code, exit_codes.IO_ERROR)
        self.assertEqual(document["error"]["code"], "files_unreadable")
        assert_contract("haprion-list-files", json.dumps(document))

    def test_a_cluster_or_a_wrong_parameter_is_refused(self) -> None:
        for body in (
            request(cluster="alpha"),
            request(parameters={"known_path_lists": "scanners"}),
            request(parameters={"known_path_lists": [1]}),
        ):
            code, document = self.run_helper(body)
            self.assertEqual(code, exit_codes.USAGE)
            self.assertEqual(document["error"]["code"], "bad_input")

    def test_it_is_one_of_the_managers_readings(self) -> None:
        self.assertIn("list_files", readings_helper.READINGS)
        self.assertIn("list_files", readings_helper.MANAGER_READINGS)


if __name__ == "__main__":
    unittest.main()
