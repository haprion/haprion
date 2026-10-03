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
    "haproxy-cert-remove",
    "haproxy-cert-trigger",
    "haproxy-node-status",
    "haproxy-health-probe",
    "haproxy-keepalived-state",
    "haproxy-state-export",
    "haproxy-traffic-log-read",
    "haproxy-traffic-log-enable",
    "haproxy-traffic-log-prune",
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

    def test_installer_does_not_repermission_the_system_lock_directory(self) -> None:
        installer = INSTALLER.read_text()

        self.assertNotRegex(installer, r"ensure_dir\s+/run/lock")
        self.assertIn('[[ -d /run/lock ]] || die "/run/lock is missing"', installer)

    def test_release_root_denies_unprivileged_service_accounts(self) -> None:
        self.assertIn("ensure_dir /etc/haproxy/releases root:root 750", INSTALLER.read_text())

    def test_only_the_waf_engine_passes_through_the_release_root(self) -> None:
        """26-10-03: the engine's DynamicUser could not reach /etc/haproxy/waf through it."""

        installer = INSTALLER.read_text()
        # Pass, not list, and only for a group with no members.
        self.assertIn("a+ /etc/haproxy/releases - - - - group:${WAF_ENGINE_GROUP}:--x", installer)
        self.assertIn('WAF_ENGINE_GROUP="haproxy-waf"', installer)
        self.assertIn("has members; only the WAF engine may pass", installer)
        # Given to the engine beside its package, which names no account of ours.
        self.assertIn(
            'WAF_ENGINE_DROPIN="/etc/systemd/system/coraza-spoa.service.d/haproxy-manager.conf"',
            installer,
        )
        self.assertIn("SupplementaryGroups=${WAF_ENGINE_GROUP}", installer)
        # After the directory exists, so a fresh node gets the entry too.
        self.assertLess(
            installer.index("ensure_dir /etc/haproxy/releases root:root 750"),
            installer.index('systemd-tmpfiles --create "$WAF_ENGINE_TMPFILES"'),
        )

    def test_the_service_accounts_own_nothing_in_their_homes(self) -> None:
        """B131: a key file or dotfile the account could write is its way out of the forced command."""

        installer = INSTALLER.read_text()
        account = installer[
            installer.index("ensure_account() {") : installer.index(
                'ensure_account "$TRIGGER_USER"'
            )
        ]

        self.assertIn('ensure_dir "$home" root:root 755', account)
        self.assertIn('ensure_dir "${home}/.ssh" root:root 755', account)
        self.assertIn("install -o root -g root -m 644 /dev/null", account)
        self.assertIn('chown root:root "$keys"', account)
        self.assertIn("! -name .ssh ! -user root -print0", account)
        self.assertNotIn("--create-home", account)
        self.assertNotIn('-o "$user"', account)

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
