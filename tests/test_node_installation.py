"""The node reports both its declared API and the bytes actually installed."""

from __future__ import annotations

import hashlib
import json
import re
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "install/node/haproxy-node-status"
READING = re.compile(r"^def read_installation\(\):.*?(?=^def run\()", re.DOTALL | re.MULTILINE)


class NodeInstallationReadingTests(unittest.TestCase):
    def setUp(self) -> None:
        found = READING.search(SCRIPT.read_text())
        assert found, "the installation reader is no longer where the test extracts it from"
        self.source = found.group(0)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.sbin = self.root / "sbin"
        self.sbin.mkdir()
        self.metadata = self.root / "node-installation.json"

    def read(self) -> dict[str, object]:
        namespace: dict[str, object] = {
            "Path": Path,
            "hashlib": hashlib,
            "json": json,
            "re": re,
            "NODE_INSTALLATION": self.metadata,
            "SBIN": self.sbin,
            "MAX_INSTALLATION_BYTES": 64 * 1024,
            "SHA256": re.compile(r"^[0-9a-f]{64}$"),
        }
        exec(self.source, namespace)  # noqa: S102 - verbatim function from the node script
        return namespace["read_installation"]()  # type: ignore[operator,no-any-return]

    def install(self, content: bytes = b"script\n") -> None:
        script = self.sbin / "haproxy-node-status"
        script.write_bytes(content)
        self.metadata.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "node_api": 1,
                    "scripts": {"haproxy-node-status": hashlib.sha256(content).hexdigest()},
                }
            )
        )

    def test_matching_metadata_reports_a_current_bundle(self) -> None:
        self.install()
        result = self.read()
        self.assertEqual(result["node_api"], 1)
        self.assertIs(result["scripts_current"], True)

    def test_a_changed_script_is_not_hidden_by_its_metadata(self) -> None:
        self.install()
        (self.sbin / "haproxy-node-status").write_bytes(b"changed\n")
        result = self.read()
        self.assertIs(result["scripts_current"], False)

    def test_missing_or_malformed_metadata_is_unknown(self) -> None:
        self.assertEqual(self.read(), {"node_api": None, "scripts_current": False, "scripts": {}})
        self.metadata.write_text("{}")
        self.assertEqual(self.read(), {"node_api": None, "scripts_current": False, "scripts": {}})


if __name__ == "__main__":
    unittest.main()
