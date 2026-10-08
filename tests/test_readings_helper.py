"""`haproxy-readings-helper`: the poller's manager-local readings in one call (N2, 2026-10-08)."""

from __future__ import annotations

import io
import json
import unittest
from typing import Any, BinaryIO, TextIO

from haproxy_mgmt.cli import readings_helper


def request(**reads: Any) -> io.BytesIO:
    return io.BytesIO(
        readings_helper.build_request(
            "alpha", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", reads
        ).encode()
    )


class Recorded:
    """A reading's helper: what it was sent, and an answer in its own words."""

    def __init__(self, operation: str, *, code: int = 0, fail: bool = False) -> None:
        self.operation, self.code, self.fail = operation, code, fail
        self.sent: dict[str, Any] | None = None

    def __call__(
        self,
        argv: list[str],
        *,
        input_stream: BinaryIO,
        output_stream: TextIO,
        error_stream: TextIO,
        **_: Any,
    ) -> int:
        if self.fail:
            raise OSError("the repository went away")
        self.sent = json.loads(input_stream.read())
        if self.code:
            error_stream.write("ERROR: refused\n")
            return self.code
        output_stream.write(
            json.dumps(
                {"operation": self.operation, "cluster": "alpha", "outcome": "done", "result": {}}
            )
        )
        return 0


class OneCallForTheLocalReadings(unittest.TestCase):
    def run_helper(self, stream: io.BytesIO, readings: dict[str, Any]) -> tuple[int, Any, str]:
        out, err = io.StringIO(), io.StringIO()
        code = readings_helper.main(
            [],
            input_stream=stream,
            output_stream=out,
            error_stream=err,
            require_root=False,
            require_secure=False,
            readings=readings,
        )
        return code, json.loads(out.getvalue()) if out.getvalue() else None, err.getvalue()

    def test_each_reading_gets_the_request_its_own_helper_always_got(self) -> None:
        listing, objects = Recorded("list"), Recorded("objects")

        code, answer, _ = self.run_helper(
            request(list={"limit": 1000, "diffs": ["a" * 40]}, objects={}),
            {"list": listing, "objects": objects},
        )

        self.assertEqual(code, 0)
        self.assertEqual(answer["operation"], "readings")
        self.assertEqual(
            listing.sent,
            {
                "schema_version": 1,
                "operation": "list",
                "cluster": "alpha",
                "request_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "parameters": {"limit": 1000, "diffs": ["a" * 40]},
            },
        )
        reads = answer["result"]["reads"]
        self.assertEqual(reads["objects"]["envelope"]["operation"], "objects")
        self.assertEqual((reads["list"]["exit_code"], reads["list"]["stderr"]), (0, ""))

    def test_a_reading_that_fails_is_its_own_answer_and_the_others_still_come(self) -> None:
        code, answer, _ = self.run_helper(
            request(network={}, cert_list={}, objects={}),
            {
                "network": Recorded("network"),
                "cert_list": Recorded("cert_list", code=78),
                "objects": Recorded("objects", fail=True),
            },
        )

        self.assertEqual(code, 0)
        reads = answer["result"]["reads"]
        self.assertEqual(reads["network"]["exit_code"], 0)
        self.assertEqual(
            (reads["cert_list"]["exit_code"], reads["cert_list"]["envelope"]), (78, None)
        )
        self.assertIn("refused", reads["cert_list"]["stderr"])
        self.assertEqual(reads["objects"]["exit_code"], 70)
        self.assertIn("the repository went away", reads["objects"]["stderr"])

    def test_only_the_six_readings_can_be_asked_for(self) -> None:
        code, answer, errors = self.run_helper(
            request(inventory={}), dict(readings_helper.READINGS)
        )

        self.assertEqual(code, 65)
        self.assertIsNone(answer)
        self.assertIn("unknown reading", errors)

    def test_the_six_are_the_poller_s_manager_local_helpers(self) -> None:
        self.assertEqual(
            sorted(readings_helper.READINGS),
            ["cert_list", "cluster_settings", "list", "list_backups", "network", "objects"],
        )


if __name__ == "__main__":
    unittest.main()
