from __future__ import annotations

import io
import json
import unittest
import uuid
from pathlib import Path

from haprion import exit_codes
from haprion.cli.caller import looked_up
from haprion.envelope import Message, envelope, failure


class EnvelopeTests(unittest.TestCase):
    def test_a_cluster_that_is_not_an_id_is_not_named(self) -> None:
        """K07: `cluster` is null until a valid cluster is resolved; the raw `-c` is not echoed."""

        for typed in ("Bad Cluster!", "", "-x", "A", "a" * 64):
            with self.subTest(typed=typed):
                failed = failure(
                    operation="inventory",
                    cluster=typed,
                    request_id="r1",
                    code="bad_input",
                    message="no",
                    exit_code=exit_codes.USAGE,
                )
                self.assertIsNone(failed["cluster"])
        kept = envelope(operation="inventory", outcome="done", cluster="alpha", result={})
        self.assertEqual(kept["cluster"], "alpha")

    def test_a_cluster_that_failed_its_lookup_is_not_named(self) -> None:
        out = io.StringIO()

        def resolve(_cluster: str) -> Path:
            raise SystemExit(exit_codes.USAGE)

        with self.assertRaises(SystemExit):
            looked_up(resolve, "nosuch", operation="inventory", json_mode=True, writer=out)

        self.assertIsNone(json.loads(out.getvalue())["cluster"])

    def test_done(self) -> None:
        result = envelope(
            operation="inventory", outcome="done", cluster="alpha", result={"items": []}
        )
        self.assertTrue(result["ok"])
        self.assertIsNone(result["error"])
        uuid.UUID(result["request_id"])

    def test_partial_requires_warning(self) -> None:
        with self.assertRaises(ValueError):
            envelope(operation="status", outcome="partial", cluster="alpha", result={})
        result = envelope(
            operation="status",
            outcome="partial",
            cluster="alpha",
            result={},
            warnings=(Message("node_unavailable", "One node is unavailable", node="node-b"),),
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["warnings"][0]["node"], "node-b")

    def test_failed_requires_error(self) -> None:
        with self.assertRaises(ValueError):
            envelope(operation="inventory", outcome="failed", cluster="alpha", result=None)
        result = envelope(
            operation="inventory",
            outcome="failed",
            cluster="alpha",
            result=None,
            error=Message("inventory_unavailable", "Inventory could not be read"),
        )
        self.assertEqual(result["error"]["code"], "inventory_unavailable")


if __name__ == "__main__":
    unittest.main()
