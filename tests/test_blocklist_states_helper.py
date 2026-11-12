"""The `blocklist_states` reading: the refresh timer's state, for the poller (B496, 13; B500).

What is pinned here is that the answer is the state file the timer writes -
read with the timer's own reader, so the two cannot drift - that no file is
an empty answer and an unreadable one a failure, and that the reading is one
of the manager's in `haprion-readings-helper`.
"""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from haprion import blocklist_store, exit_codes
from haprion.blocklist_store import ListState
from haprion.cli import blocklist_states_helper, readings_helper
from tests.contract_schema import assert_contract

REQUEST_ID = "ffffffff-ffff-4fff-8fff-ffffffffffff"


def request(*, cluster: str | None = None, parameters: dict[str, Any] | None = None) -> bytes:
    return json.dumps(
        {
            "schema_version": 1,
            "operation": "blocklist_states",
            "cluster": cluster,
            "request_id": REQUEST_ID,
            "parameters": parameters or {},
        }
    ).encode()


class TheReading(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))

    def run_helper(self, body: bytes) -> tuple[int, Any]:
        output = io.StringIO()
        code = blocklist_states_helper.main(
            [],
            input_stream=io.BytesIO(body),
            output_stream=output,
            error_stream=io.StringIO(),
            require_root=False,
            state_directory=self.directory,
        )
        return code, json.loads(output.getvalue()) if output.getvalue() else None

    def test_answers_the_timer_s_state_by_name_in_its_contract(self) -> None:
        blocklist_store.write_state(
            {
                "drop": ListState(
                    fetched_at="2026-11-11T18:00:01+00:00",
                    attempted_at="2026-11-12T06:00:01+00:00",
                    failed_at="2026-11-12T06:00:01+00:00",
                    error="x" * 600,
                    entries=1204,
                ),
                "community": ListState(
                    fetched_at="2026-11-12T06:00:02+00:00",
                    attempted_at="2026-11-12T06:00:02+00:00",
                    entries=14812,
                    skipped=2,
                ),
            },
            directory=self.directory,
        )

        code, document = self.run_helper(request())

        self.assertEqual(code, 0)
        assert_contract("haprion-blocklist-states", json.dumps(document))
        lists = document["result"]["lists"]
        self.assertEqual([entry["name"] for entry in lists], ["community", "drop"])
        self.assertEqual(lists[0]["fetched_at"], "2026-11-12T06:00:02Z")
        self.assertEqual((lists[0]["entries"], lists[0]["skipped"]), (14812, 2))
        self.assertEqual(len(lists[1]["error"]), 500)

    def test_no_state_file_is_no_list(self) -> None:
        code, document = self.run_helper(request())

        self.assertEqual(code, 0)
        self.assertEqual(document["result"], {"lists": []})

    def test_a_state_that_cannot_be_read_fails_the_reading(self) -> None:
        (self.directory / blocklist_store.STATE_FILE).write_text("{not json")

        code, document = self.run_helper(request())

        self.assertEqual(code, exit_codes.IO_ERROR)
        assert_contract("haprion-blocklist-states", json.dumps(document))
        self.assertEqual(document["error"]["code"], "state_unreadable")

    def test_a_cluster_or_a_parameter_is_refused(self) -> None:
        code, document = self.run_helper(request(cluster="alpha"))
        self.assertEqual(code, exit_codes.USAGE)
        assert_contract("haprion-blocklist-states", json.dumps(document))

        code, _ = self.run_helper(request(parameters={"since": "2026-11-12T06:00:00Z"}))
        self.assertEqual(code, exit_codes.REFUSED)


class AManagerReading(unittest.TestCase):
    def test_is_asked_with_a_null_cluster_beside_the_certificates(self) -> None:
        output = io.StringIO()
        body = json.dumps(
            {
                "schema_version": 1,
                "operation": "readings",
                "cluster": None,
                "request_id": REQUEST_ID,
                "parameters": {"reads": {"blocklist_states": {}}},
            }
        ).encode()

        def answered(argv: list[str], **kwargs: Any) -> int:
            return blocklist_states_helper.main(
                argv, **kwargs, state_directory=Path("/nonexistent/blocklists")
            )

        code = readings_helper.main(
            [],
            input_stream=io.BytesIO(body),
            output_stream=output,
            error_stream=io.StringIO(),
            require_secure=False,
            require_root=False,
            readings={"blocklist_states": answered},
        )

        self.assertEqual(code, 0)
        reading = json.loads(output.getvalue())["result"]["reads"]["blocklist_states"]
        self.assertEqual(reading["exit_code"], 0)
        self.assertEqual(reading["envelope"]["result"], {"lists": []})


if __name__ == "__main__":
    unittest.main()
