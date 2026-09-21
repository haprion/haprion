from __future__ import annotations

import re
import unittest
from pathlib import Path

from haproxy_mgmt.backup_archive import REQUIRED_PATHS

BASE = Path(__file__).resolve().parents[1]


def shell_array(text: str, name: str) -> tuple[str, ...]:
    matched = re.search(rf"^{name}=\(\n(?P<body>.*?)^\)", text, re.MULTILINE | re.DOTALL)
    if matched is None:
        raise AssertionError(f"{name} is missing")
    return tuple(line.strip() for line in matched.group("body").splitlines() if line.strip())


class StateExportContractTests(unittest.TestCase):
    def test_export_and_installer_name_the_same_node_bundle(self) -> None:
        installer = (BASE / "install/04-node-prepare").read_text(encoding="utf-8")
        exporter = (BASE / "install/node/haproxy-state-export").read_text(encoding="utf-8")
        self.assertEqual(shell_array(exporter, "DR_SCRIPTS"), shell_array(installer, "SCRIPTS"))

    def test_every_node_bundle_script_is_required_by_the_archive_validator(self) -> None:
        installer = (BASE / "install/04-node-prepare").read_text(encoding="utf-8")
        expected = {
            f"rootfs/usr/local/sbin/{name}" for name in shell_array(installer, "SCRIPTS")
        }
        self.assertLessEqual(expected, REQUIRED_PATHS)

    def test_only_forced_command_accounts_are_required_to_have_authorized_keys(self) -> None:
        installer = (BASE / "install/04-node-prepare").read_text(encoding="utf-8")
        exporter = (BASE / "install/node/haproxy-state-export").read_text(encoding="utf-8")
        self.assertIn('BACKUP_SERVICE_ACCOUNTS=\\"${TRIGGER_USER}', installer)
        required_keys = exporter.split("# The manifest is the archive's content contract.", 1)[0]
        self.assertIn("for user in $BACKUP_SERVICE_ACCOUNTS; do", required_keys)


if __name__ == "__main__":
    unittest.main()
