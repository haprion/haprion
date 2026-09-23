from __future__ import annotations

import re
import tempfile
import unittest
from pathlib import Path

from haproxy_mgmt import restore_source
from haproxy_mgmt.backup_archive import ArchiveError
from tests.restore_fixture import FILES, SERVICE_ACCOUNTS, build

BASE = Path(__file__).resolve().parents[1]
EXPORTER = BASE / "install/node/haproxy-state-export"


class TheRootsAreTheExportersOwn(unittest.TestCase):
    def test_every_literal_copy_path_is_an_export_root_in_the_same_order(self) -> None:
        text = EXPORTER.read_text(encoding="utf-8")
        literal = tuple(re.findall(r"^copy_path (/[^\s$]+)$", text, re.MULTILINE))
        self.assertEqual(literal, restore_source.EXPORT_ROOTS)

    def test_the_dynamic_roots_are_the_ones_the_exporter_loops_over(self) -> None:
        text = EXPORTER.read_text(encoding="utf-8")
        self.assertIn("for f in /etc/ssh/ssh_host_*; do", text)
        self.assertIn('copy_path "/usr/local/sbin/${script}"', text)
        self.assertIn('copy_path "$home/.ssh"', text)
        self.assertIn(
            "printf '%s\\n' \"${extras[@]}\" | sed '/^$/d' > \"$META/extra-paths.txt\"", text
        )


class ReadingAnArchive(unittest.TestCase):
    def read(self, **kwargs: object) -> restore_source.RestoreSource:
        work = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, work)
        return restore_source.read(build(work, **kwargs))  # type: ignore[arg-type]

    def test_parents_created_by_mkdir_are_never_owned(self) -> None:
        source = self.read()
        owned = {entry.path for entry in source.owned()}
        for parent in ("/etc", "/root", "/home", "/home/operator", "/var/lib/svc-backup"):
            self.assertNotIn(parent, owned)
            self.assertIn(parent, source.parents())
        # The parents really were recorded as 0700 - the trap this guards.
        self.assertEqual(source.entry("/etc").mode, 0o700)  # type: ignore[union-attr]

    def test_copied_paths_and_everything_below_them_are_owned(self) -> None:
        owned = {entry.path: entry for entry in self.read().owned()}
        for path in (
            "/etc/netplan",
            "/etc/netplan/50-cloud-init.yaml",
            "/etc/haproxy-manager/keys/config-pull",
            "/root/.ssh",
            "/home/operator/.ssh/authorized_keys",
            "/var/lib/svc-backup/.ssh/authorized_keys",
            "/etc/ssh/ssh_host_ed25519_key",
            "/usr/local/sbin/haproxy-pull-deploy",
            "/etc/default/grub.d/99-local.cfg",
        ):
            self.assertIn(path, owned)
        self.assertEqual(owned["/etc/netplan"].mode, 0o755)
        self.assertEqual(owned["/etc/netplan/50-cloud-init.yaml"].mode, 0o600)

    def test_a_directory_holding_only_an_extra_path_is_a_parent(self) -> None:
        source = self.read()
        self.assertIn("/etc/default/grub.d", source.parents())
        self.assertEqual(source.extra_paths, ("/etc/default/grub.d/99-local.cfg",))

    def test_accounts_carry_ids_groups_hashes_and_the_service_mark(self) -> None:
        accounts = {account.name: account for account in self.read().accounts}
        operator = accounts["operator"]
        self.assertEqual(
            (operator.uid, operator.gid, operator.home), (1000, 1000, "/home/operator")
        )
        self.assertEqual(operator.groups, ("operator", "sudo"))
        self.assertTrue(operator.password_hash and operator.password_hash.startswith("$y$"))
        self.assertFalse(operator.service)
        self.assertEqual({name for name, a in accounts.items() if a.service}, set(SERVICE_ACCOUNTS))
        self.assertIn("haproxy-logread", accounts["svc-logread"].groups)

    def test_groups_carry_their_ids(self) -> None:
        groups = {group.name: group.gid for group in self.read().groups}
        self.assertEqual(groups["haproxy-logread"], 985)

    def test_os_release_and_hostname(self) -> None:
        source = self.read()
        self.assertEqual(source.hostname, "node-a")
        self.assertEqual(source.os_release["ID"], "ubuntu")
        self.assertEqual(source.os_release["VERSION_ID"], "26.04")

    def test_content_is_read_on_demand(self) -> None:
        source = self.read()
        entry = source.entry("/etc/hostname")
        assert entry is not None
        self.assertEqual(restore_source.content(source, entry), b"node-a\n")

    def test_an_archive_that_fails_validation_is_refused(self) -> None:
        files = dict(FILES)
        del files["/etc/hosts"]
        with self.assertRaises(ArchiveError):
            self.read(files=files)

    def test_a_node_conf_without_service_accounts_is_refused(self) -> None:
        files = dict(FILES)
        files["/etc/haproxy-manager/node.conf"] = ('CLUSTER="alpha"\n', 0o600)
        with self.assertRaisesRegex(ArchiveError, "BACKUP_SERVICE_ACCOUNTS"):
            self.read(files=files)


class ParsingIsStrict(unittest.TestCase):
    def test_account_names_that_could_escape_are_refused(self) -> None:
        with self.assertRaises(ArchiveError):
            restore_source._name("../x", "account")
        with self.assertRaises(ArchiveError):
            restore_source._name("a b", "account")

    def test_a_relative_home_is_refused(self) -> None:
        with self.assertRaises(ArchiveError):
            restore_source._absolute("home/x", "home directory")


if __name__ == "__main__":
    unittest.main()
