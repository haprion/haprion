from __future__ import annotations

import ipaddress
import shutil
import tempfile
import unittest
from pathlib import Path

import yaml

from haproxy_mgmt import restore_plan, restore_source
from haproxy_mgmt.restore_plan import PlanError, Target, TestProfile
from tests.restore_fixture import FILES, NETPLAN, build

TARGET = Target(
    os_release={"ID": "ubuntu", "VERSION_ID": "26.04", "VERSION_CODENAME": "resolute"},
    interface="eth0",
    mac="02:00:00:00:00:99",
)
PROFILE = TestProfile(
    hostname="node-test",
    address=ipaddress.IPv4Interface("192.0.2.29/24"),
    vip=ipaddress.IPv4Interface("198.51.100.254/32"),
)


class Planning(unittest.TestCase):
    def source(
        self, files: dict[str, tuple[str, int]] | None = None
    ) -> restore_source.RestoreSource:
        work = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, work)
        return restore_source.read(build(work, files=files))

    def data(self, plan: restore_plan.RestorePlan, path: str) -> str:
        for file in (*plan.files, *plan.network):
            if file.path == path:
                assert file.data is not None, f"{path} was not rewritten"
                return file.data.decode()
        raise AssertionError(f"{path} is not in the plan")

    def untouched(self, plan: restore_plan.RestorePlan, path: str) -> bool:
        return any(file.path == path and file.data is None for file in plan.files)


class ANewVm(Planning):
    def test_the_node_keeps_its_own_identity(self) -> None:
        plan = restore_plan.build(self.source(), "new_vm", TARGET)
        self.assertEqual(plan.hostname, "node-a")
        self.assertEqual(str(plan.address), "192.0.2.21/24")
        self.assertEqual(plan.keepalived, "start")
        for path in ("/etc/hostname", "/etc/hosts", "/etc/keepalived/keepalived.conf"):
            self.assertTrue(self.untouched(plan, path), path)
        self.assertTrue(self.untouched(plan, "/etc/ssh/ssh_host_ed25519_key"))

    def test_the_only_rewrite_binds_netplan_to_the_targets_mac(self) -> None:
        plan = restore_plan.build(self.source(), "new_vm", TARGET)
        self.assertEqual(
            [(r.field, r.old, r.new) for r in plan.rewrites],
            [("match.macaddress", "02:00:00:00:00:0a", "02:00:00:00:00:99")],
        )
        document = yaml.safe_load(self.data(plan, "/etc/netplan/50-cloud-init.yaml"))
        eth0 = document["network"]["ethernets"]["eth0"]
        self.assertEqual(eth0["match"]["macaddress"], "02:00:00:00:00:99")
        self.assertEqual(eth0["addresses"], ["192.0.2.21/24"])

    def test_netplan_and_roots_keys_are_held_back_for_their_own_moment(self) -> None:
        plan = restore_plan.build(self.source(), "new_vm", TARGET)
        paths = {file.path for file in plan.files}
        self.assertFalse(any(path.startswith("/etc/netplan") for path in paths))
        self.assertNotIn("/root/.ssh/authorized_keys", paths)
        self.assertIn("/root/.ssh", paths)
        assert plan.root_keys is not None
        self.assertEqual(plan.root_keys.path, "/root/.ssh/authorized_keys")
        self.assertNotIn("/etc/netplan", plan.equal_directories)
        self.assertIn("/etc/sudoers.d", plan.equal_directories)

    def test_parents_are_never_planned_as_files(self) -> None:
        plan = restore_plan.build(self.source(), "new_vm", TARGET)
        paths = {file.path for file in plan.files}
        for parent in ("/etc", "/home", "/root", "/etc/default/grub.d"):
            self.assertNotIn(parent, paths)
            self.assertIn(parent, plan.parents)

    def test_a_different_interface_name_stops_the_plan(self) -> None:
        target = Target(os_release={}, interface="ens18", mac=TARGET.mac)
        with self.assertRaisesRegex(PlanError, "renaming a live interface"):
            restore_plan.build(self.source(), "new_vm", target)

    def test_an_unusable_mac_stops_the_plan(self) -> None:
        target = Target(os_release={}, interface="eth0", mac="02:00:00:00:00")
        with self.assertRaises(PlanError):
            restore_plan.build(self.source(), "new_vm", target)

    def test_a_profile_outside_test_mode_is_refused(self) -> None:
        with self.assertRaises(PlanError):
            restore_plan.build(self.source(), "new_vm", TARGET, PROFILE)
        with self.assertRaises(PlanError):
            restore_plan.build(self.source(), "test", TARGET)

    def test_the_summary_carries_no_contents(self) -> None:
        summary = restore_plan.build(self.source(), "new_vm", TARGET).summary()
        text = repr(summary)
        self.assertNotIn("$y$", text)
        self.assertNotIn("host private", text)
        operator = next(a for a in summary["accounts"] if a["name"] == "operator")
        self.assertTrue(operator["has_password"])


class TestMode(Planning):
    def plan(self) -> restore_plan.RestorePlan:
        return restore_plan.build(self.source(), "test", TARGET, PROFILE)

    def test_identity_is_rewritten_field_by_field(self) -> None:
        plan = self.plan()
        self.assertEqual(plan.hostname, "node-test")
        self.assertEqual(str(plan.address), "192.0.2.29/24")
        self.assertEqual(self.data(plan, "/etc/hostname"), "node-test\n")
        hosts = self.data(plan, "/etc/hosts")
        self.assertIn("node-test.example.com node-test", hosts)
        self.assertNotIn("node-a", hosts)
        document = yaml.safe_load(self.data(plan, "/etc/netplan/50-cloud-init.yaml"))
        self.assertEqual(document["network"]["ethernets"]["eth0"]["addresses"], ["192.0.2.29/24"])

    def test_keepalived_can_never_join_the_production_cluster(self) -> None:
        plan = self.plan()
        self.assertEqual(plan.keepalived, "mask")
        conf = self.data(plan, "/etc/keepalived/keepalived.conf")
        self.assertIn("unicast_src_ip 192.0.2.29", conf)
        self.assertIn("198.51.100.254/32", conf)
        self.assertNotIn("192.0.2.20/24", conf)
        self.assertNotIn("include /etc/keepalived/addresses.conf", conf)
        self.assertEqual(self.data(plan, "/etc/keepalived/addresses.conf"), "198.51.100.254/32\n")

    def test_the_test_node_keeps_its_own_host_keys(self) -> None:
        paths = {file.path for file in self.plan().files}
        self.assertFalse(any(path.startswith("/etc/ssh/ssh_host_") for path in paths))
        self.assertIn("/etc/ssh/sshd_config", paths)

    def test_every_rewrite_is_listed(self) -> None:
        fields = {(r.path, r.field) for r in self.plan().rewrites}
        self.assertEqual(
            fields,
            {
                ("/etc/netplan/50-cloud-init.yaml", "match.macaddress"),
                ("/etc/netplan/50-cloud-init.yaml", "addresses"),
                ("/etc/hostname", "hostname"),
                ("/etc/hosts", "hostname"),
                ("/etc/keepalived/keepalived.conf", "unicast_src_ip"),
                ("/etc/keepalived/keepalived.conf", "virtual_ipaddress"),
                ("/etc/keepalived/keepalived.conf", "include"),
                ("/etc/keepalived/addresses.conf", "addresses"),
            },
        )

    def test_the_old_address_list_is_shown_without_its_comments(self) -> None:
        rewrite = next(r for r in self.plan().rewrites if r.path.endswith("addresses.conf"))
        self.assertEqual(rewrite.old, "192.0.2.30/24 dev eth0, 192.0.2.31/24 dev eth0")

    def test_a_test_address_outside_the_nodes_network_is_refused(self) -> None:
        profile = TestProfile(
            hostname="node-test",
            address=ipaddress.IPv4Interface("203.0.113.29/24"),
            vip=PROFILE.vip,
        )
        with self.assertRaisesRegex(PlanError, "not in the node's network"):
            restore_plan.build(self.source(), "test", TARGET, profile)


class NetplanShapes(Planning):
    def test_two_addresses_are_refused(self) -> None:
        files = dict(FILES)
        files["/etc/netplan/50-cloud-init.yaml"] = (
            NETPLAN.replace("- 192.0.2.21/24", "- 192.0.2.21/24\n        - 192.0.2.23/24"),
            0o600,
        )
        with self.assertRaisesRegex(PlanError, "exactly one address"):
            restore_plan.build(self.source(files), "new_vm", TARGET)


if __name__ == "__main__":
    unittest.main()
