from __future__ import annotations

import unittest
import uuid

from haproxy_mgmt.envelope import Message, envelope


class EnvelopeTests(unittest.TestCase):
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
