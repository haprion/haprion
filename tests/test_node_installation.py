"""The node reports both its declared API and the bytes actually installed."""

from __future__ import annotations

import hashlib
import json
import re
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "install/node/haproxy-node-status"
INSTALLER = Path(__file__).resolve().parents[1] / "install/04-node-prepare"
READING = re.compile(r"^def read_installation\(\):.*?(?=^def run\()", re.DOTALL | re.MULTILINE)
NODE_SCRIPTS = (
    "haproxy-pull-deploy",
    "haproxy-cert-pull",
    "haproxy-cert-trigger",
    "haproxy-node-status",
    "haproxy-health-probe",
    "haproxy-keepalived-state",
    "haproxy-state-export",
    "haproxy-traffic-log-read",
)


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
            "NODE_SCRIPTS": NODE_SCRIPTS,
        }
        exec(self.source, namespace)  # noqa: S102 - verbatim function from the node script
        return namespace["read_installation"]()  # type: ignore[operator,no-any-return]

    def install(self, content: bytes = b"script\n") -> None:
        for name in NODE_SCRIPTS:
            (self.sbin / name).write_bytes(content)
        self.metadata.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "node_api": 1,
                    "scripts": {name: hashlib.sha256(content).hexdigest() for name in NODE_SCRIPTS},
                }
            )
        )

    def test_matching_metadata_reports_a_current_bundle(self) -> None:
        self.install()
        result = self.read()
        self.assertEqual(result["node_api"], 1)
        self.assertIs(result["scripts_current"], True)

    def test_installer_and_status_attest_the_same_node_bundle(self) -> None:
        match = re.search(r"^SCRIPTS=\(\n(.*?)^\)", INSTALLER.read_text(), re.MULTILINE | re.DOTALL)
        assert match is not None
        installed = tuple(re.findall(r"^\s+(haproxy-[a-z0-9-]+)$", match.group(1), re.MULTILINE))
        self.assertEqual(installed, NODE_SCRIPTS)

    def test_a_changed_script_is_not_hidden_by_its_metadata(self) -> None:
        self.install()
        (self.sbin / "haproxy-node-status").write_bytes(b"changed\n")
        result = self.read()
        self.assertIs(result["scripts_current"], False)

    def test_missing_or_malformed_metadata_is_unknown(self) -> None:
        result = self.read()
        self.assertIsNone(result["node_api"])
        self.assertIs(result["scripts_current"], False)
        self.assertEqual(set(result["scripts"]), set(NODE_SCRIPTS))
        self.assertTrue(all(row["installed_sha256"] is None for row in result["scripts"].values()))
        self.metadata.write_text("{}")
        self.assertEqual(self.read(), result)

    def test_missing_metadata_still_inventories_installed_scripts(self) -> None:
        (self.sbin / "haproxy-node-status").write_bytes(b"installed\n")
        result = self.read()
        self.assertEqual(
            result["scripts"]["haproxy-node-status"]["installed_sha256"],
            hashlib.sha256(b"installed\n").hexdigest(),
        )
        self.assertIsNone(result["scripts"]["haproxy-node-status"]["expected_sha256"])


if __name__ == "__main__":
    unittest.main()
