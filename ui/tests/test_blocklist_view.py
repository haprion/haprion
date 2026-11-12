"""*Blocklists* in the interface (B496, 13; B500): the poller's reading and where it is said.

Pinned here: the poller asks what the refresh timer last did in the manager's
readings call and writes it whole, and a reading that did not answer leaves
the rows as they were rather than saying nothing was ever fetched.
"""

from __future__ import annotations

import contextlib
import json
import subprocess
import unittest
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any
from unittest import mock

from haprion_ui import poller
from tests.test_poller import document


class Pool:
    def connection(self) -> Any:
        return contextlib.nullcontext(mock.Mock())


def manager_readings(states: Any, *, exit_code: int = 0) -> Any:
    """The readings helper answering the certificates and, as given, the blocklists' state."""

    asked: list[Mapping[str, Any]] = []

    def run(cluster: str | None, request_id: str, reads: Mapping[str, Any]) -> Any:
        asked.append(reads)
        certs = document(
            "cert_list",
            result={"interface_served": None, "registry": {"certificates": [], "receivers": []}},
            cluster=None,
            request_id=request_id,
        )
        answer = (
            document("blocklist_states", result=states, cluster=None, request_id=request_id)
            if states is not None
            else None
        )
        outer = document(
            "readings",
            result={
                "reads": {
                    "cert_list": {"exit_code": 0, "envelope": certs, "stderr": ""},
                    "blocklist_states": {"exit_code": exit_code, "envelope": answer, "stderr": ""},
                }
            },
            cluster=None,
            request_id=request_id,
        )
        return subprocess.CompletedProcess([], 0, json.dumps(outer), "")

    run.asked = asked  # type: ignore[attr-defined]
    return run


STATES = {
    "lists": [
        {
            "name": "community",
            "fetched_at": "2026-11-12T06:00:02Z",
            "attempted_at": "2026-11-12T06:00:02Z",
            "failed_at": None,
            "error": "",
            "entries": 14812,
            "skipped": 2,
        },
        {
            "name": "drop",
            "fetched_at": None,
            "attempted_at": "2026-11-12T06:00:01Z",
            "failed_at": "2026-11-12T06:00:01Z",
            "error": "the source answered 503",
            "entries": 0,
            "skipped": 0,
        },
    ]
}


class ThePollerReading(unittest.TestCase):
    def poll(self, run: Any) -> mock.Mock:
        with (
            mock.patch("haprion_ui.db.record_manager_certificates"),
            mock.patch("haprion_ui.db.replace_search_entries"),
            mock.patch("haprion_ui.db.record_blocklist_states") as recorded,
        ):
            self.assertTrue(poller.poll_manager(Pool(), run, blocklists=True))
        return recorded

    def test_is_asked_with_the_certificates_and_written_whole(self) -> None:
        run = manager_readings(STATES)
        recorded = self.poll(run)

        self.assertEqual(sorted(run.asked[0]), ["blocklist_states", "cert_list"])
        self.assertEqual(run.asked[0]["blocklist_states"], {})
        (states,) = recorded.call_args.args[1:]
        self.assertEqual([state.name for state in states], ["community", "drop"])
        self.assertEqual(states[0].fetched_at, datetime(2026, 11, 12, 6, 0, 2, tzinfo=UTC))
        self.assertEqual((states[0].entries, states[0].skipped), (14812, 2))
        self.assertIsNone(states[1].fetched_at)
        self.assertEqual(states[1].error, "the source answered 503")

    def test_a_reading_that_did_not_answer_leaves_the_rows(self) -> None:
        recorded = self.poll(manager_readings(None, exit_code=74))
        recorded.assert_not_called()

    def test_without_the_flag_it_is_not_asked(self) -> None:
        run = manager_readings(STATES)
        with (
            mock.patch("haprion_ui.db.record_manager_certificates"),
            mock.patch("haprion_ui.db.replace_search_entries"),
            mock.patch("haprion_ui.db.record_blocklist_states") as recorded,
        ):
            poller.poll_manager(Pool(), run)

        self.assertEqual(sorted(run.asked[0]), ["cert_list"])
        recorded.assert_not_called()


if __name__ == "__main__":
    unittest.main()
