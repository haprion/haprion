from __future__ import annotations

import ipaddress
import re
import shutil
import tempfile
import unittest
from pathlib import Path

import yaml

from haproxy_mgmt import restore_plan, restore_source
from haproxy_mgmt.restore_plan import PlanError, Target, TestProfile
from tests.restore_fixture import FILES, NETPLAN, build

BASE = Path(__file__).resolve().parents[1]
NODE_PREPARE = BASE / "install/04-node-prepare"

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
        self.assertEqual(plan.equal_directories, ())

    def test_only_the_products_own_file_comes_back_to_a_directory_it_shares(self) -> None:
        """B178: the image's files there are the target's, not the archive's."""

        plan = restore_plan.build(self.source(), "new_vm", TARGET)
        paths = {file.path for file in plan.files}
        self.assertIn("/etc/sudoers.d/haproxy-node", paths)
        self.assertIn("/etc/sysctl.d/60-haproxy.conf", paths)
        for path in (
            "/etc/sudoers.d/90-cloud-init-users",
            "/etc/sysctl.d/99-cloudimg-ipv6.conf",
            "/etc/ssh/sshd_config.d/60-cloudimg-settings.conf",
            "/etc/ssh/sshd_config",
        ):
            self.assertNotIn(path, paths)
            self.assertIn(path, plan.left_out)
        # The target's directories keep their own mode; only the file is written.
        for directory in ("/etc/sudoers.d", "/etc/sysctl.d", "/etc/ssh/sshd_config.d"):
            self.assertNotIn(directory, paths)
            self.assertNotIn(directory, plan.left_out)

    def test_the_archives_apt_files_are_left_out_and_shown(self) -> None:
        plan = restore_plan.build(self.source(), "new_vm", TARGET)
        self.assertIn("/etc/apt/sources.list.d/haproxy.sources", plan.left_out)
        self.assertIn("/etc/apt/sources.list.d/haproxy.sources", plan.summary()["left_out"])

    def test_an_operators_file_named_as_an_extra_path_comes_back(self) -> None:
        files = dict(FILES)
        files["/etc/sudoers.d/svc-app"] = ("svc-app ALL=(root) NOPASSWD: /bin/true\n", 0o440)
        work = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, work)
        archive = build(work, files=files, extra_paths=("/etc/sudoers.d/svc-app",))
        plan = restore_plan.build(restore_source.read(archive), "new_vm", TARGET)
        self.assertIn("/etc/sudoers.d/svc-app", {file.path for file in plan.files})
        self.assertNotIn("/etc/sudoers.d/svc-app", plan.left_out)

    def test_what_the_node_bundle_writes_is_not_taken_from_the_archive(self) -> None:
        """B178/B180: the running release's scripts, not the ones the node ran then."""

        plan = restore_plan.build(self.source(), "new_vm", TARGET)
        paths = {file.path for file in plan.files}
        self.assertFalse(any(path.startswith("/usr/local/sbin/") for path in paths))
        self.assertNotIn("/etc/haproxy-manager/node-installation.json", paths)
        self.assertIn("/usr/local/sbin/haproxy-pull-deploy", plan.from_bundle)
        self.assertIn("/etc/haproxy-manager/node-installation.json", plan.from_bundle)
        # node.conf and the pull key are the node's own and do come back.
        self.assertIn("/etc/haproxy-manager/node.conf", paths)
        self.assertIn("/etc/haproxy-manager/keys/config-pull", paths)
        self.assertFalse(plan.traffic_log)

    def test_the_traffic_log_is_turned_on_again_rather_than_copied(self) -> None:
        files = dict(FILES)
        files[restore_plan.TRAFFIC_LOG_RULE] = ("# rule\n", 0o644)
        files["/etc/systemd/system/haproxy-traffic-log-prune.timer"] = ("[Timer]\n", 0o644)
        plan = restore_plan.build(self.source(files), "new_vm", TARGET)
        self.assertTrue(plan.traffic_log)
        paths = {file.path for file in plan.files}
        self.assertNotIn(restore_plan.TRAFFIC_LOG_RULE, paths)
        self.assertIn("/etc/systemd/system/haproxy-traffic-log-prune.timer", plan.from_bundle)

    def test_rollback_copies_of_the_old_node_stay_behind(self) -> None:
        files = dict(FILES)
        files["/etc/haproxy-manager/node.conf.replaced-20260101-120000"] = ("old\n", 0o600)
        plan = restore_plan.build(self.source(files), "new_vm", TARGET)
        self.assertIn("/etc/haproxy-manager/node.conf.replaced-20260101-120000", plan.left_out)

    def test_an_operators_own_script_is_not_taken_for_the_bundles(self) -> None:
        files = dict(FILES)
        files["/usr/local/sbin/site-report"] = ("#!/bin/sh\n", 0o755)
        work = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, work)
        archive = build(work, files=files, extra_paths=("/usr/local/sbin/site-report",))
        plan = restore_plan.build(restore_source.read(archive), "new_vm", TARGET)
        self.assertIn("/usr/local/sbin/site-report", {file.path for file in plan.files})
        self.assertNotIn("/usr/local/sbin/site-report", plan.from_bundle)

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
        plan = self.plan()
        paths = {file.path for file in plan.files}
        self.assertFalse(any(path.startswith("/etc/ssh/ssh_host_") for path in paths))
        # Held back as the key the preview compared, not as the target's own file.
        self.assertFalse(any(path.startswith("/etc/ssh/ssh_host_") for path in plan.left_out))

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


class TheProductsFilesAreTheInstallersOwn(unittest.TestCase):
    def test_each_shared_directory_keeps_exactly_what_04_node_prepare_writes(self) -> None:
        text = NODE_PREPARE.read_text(encoding="utf-8")
        self.assertIn('install -o root -g root -m 440 "$tmp" /etc/sudoers.d/haproxy-node', text)
        self.assertIn('sysctl_file="/etc/sysctl.d/60-haproxy.conf"', text)
        self.assertNotIn("sshd_config", text)
        written = set(re.findall(r"/etc/(?:sudoers|sysctl)\.d/[\w.-]+", text))
        own = set().union(*restore_plan.SHARED_DIRECTORIES.values())
        self.assertEqual(written, own)


class TheBundlesFilesAreTheEnableScriptsOwn(unittest.TestCase):
    def test_the_traffic_log_files_are_the_ones_haproxy_traffic_log_enable_writes(self) -> None:
        text = (BASE / "install/node/haproxy-traffic-log-enable").read_text(encoding="utf-8")
        written = set(re.findall(r'^[A-Z_]+="(/etc/[^"]+)"$', text, re.MULTILINE))
        in_plan = {
            path
            for path in restore_plan.FROM_BUNDLE
            if not path.startswith("/etc/haproxy-manager/")
        }
        self.assertEqual(written, in_plan)
