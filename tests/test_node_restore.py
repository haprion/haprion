from __future__ import annotations

import hashlib
import io
import ipaddress
import json
import os
import shutil
import tarfile
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest import mock

from haprion import (
    cluster_lock,
    node_package,
    node_restore,
    restore_plan,
    restore_source,
    waf_engine_package,
)
from haprion.cli import node_restore as cli
from haprion.config import Node
from haprion.node_restore import Clock, Request, RestoreError
from haprion.restore_plan import Target, TestProfile
from tests.restore_fixture import build

VERSION = "2026-01-01_04-00-00"
PUBLISH_ROOT = Path("/srv/haprion/published")
FINGERPRINT = "SHA256:" + "A" * 43
TARGET_KEY = "ssh-ed25519 AAAAtargetkey"
CLUSTER = SimpleNamespace(
    cluster_id="alpha",
    nodes=(Node("node-a", "192.0.2.21"), Node("node-b", "192.0.2.22")),
    certificate_ids=("cert-a",),
)
PROFILE = TestProfile(
    hostname="node-test",
    address=ipaddress.IPv4Interface("192.0.2.29/24"),
    vip=ipaddress.IPv4Interface("198.51.100.254/32"),
)

INSPECTED: dict[str, Any] = {
    "ok": True,
    "op": "inspect",
    "os_release": {"ID": "ubuntu", "VERSION_ID": "26.04", "VERSION_CODENAME": "resolute"},
    "hostname": "temp",
    "interface": {"name": "eth0", "mac": "02:00:00:00:00:99", "addresses": ["192.0.2.120/24"]},
    "host_keys": {"ed25519": FINGERPRINT},
    "accounts": {"operator": [1000, 1000]},
    "groups": {"operator": 1000},
    "previous_restore": False,
    "installed": [],
    "network": {"netplan": ["50-cloud-init.yaml"], "ifupdown": []},
}


class FakeSession:
    calls: list[tuple[str, dict[str, Any], bytes]]
    answers: dict[str, dict[str, Any]]
    # What the run's known_hosts held when each operation was called: the host
    # key SSH would have checked, which a fake that ignored it once let through.
    trusted: dict[str, list[str]] = {}

    def __init__(self, key: Path, known_hosts: Path) -> None:
        self.key, self.known_hosts = key, known_hosts

    def call(
        self, address: str, header: dict[str, Any], payload: bytes = b"", **_: Any
    ) -> dict[str, Any]:
        FakeSession.calls.append((address, header, payload))
        FakeSession.trusted[header["op"]] = (
            self.known_hosts.read_text().splitlines() if self.known_hosts.exists() else []
        )
        return FakeSession.answers.get(header["op"], {"ok": True, "op": header["op"]})


def members(payload: bytes) -> list[str]:
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
        return ["/" + member.name for member in archive.getmembers()]


class RestoreTest(unittest.TestCase):
    engine: waf_engine_package.ReleasePackage | None = None

    def setUp(self) -> None:
        work = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, work)
        self.backups = work / "backups"
        (self.backups / "node-a").mkdir(parents=True)
        shutil.move(build(work), self.backups / "node-a" / f"{VERSION}.tar.gz")
        self.root = work / "runs"
        FakeSession.calls = []
        FakeSession.trusted = {}
        FakeSession.answers = {"inspect": dict(INSPECTED)}
        self.silent = {"192.0.2.29", "192.0.2.21"}
        carried = work / "haprion-node.deb"
        carried.write_bytes(b"the release's node package")
        self.package: node_package.ReleasePackage | None = node_package.ReleasePackage(
            path=carried,
            version="0.1.0+git20261009120000.0123456789ab",
            commit="0123456789ab" + "0" * 28,
            sha256=hashlib.sha256(carried.read_bytes()).hexdigest(),
        )

    def answering(self, address: str) -> bool:
        return address not in self.silent

    def prepare(self, *, test: bool = True, node: str = "node-a") -> str:
        request = Request(
            run=node_restore.new_run_id(),
            cluster="alpha",
            node=node,
            archive=VERSION,
            target="192.0.2.120",
            mode="test" if test else "new_vm",
            profile=PROFILE if test else None,
        )
        node_restore.prepare(self.root, request, source_of=lambda _: "192.0.2.7")
        return request.run

    def preview(self, run: str, fingerprint: str = FINGERPRINT, **kwargs: Any) -> dict[str, Any]:
        return node_restore.preview(
            self.root,
            run,
            fingerprint,
            CLUSTER,  # type: ignore[arg-type]
            self.backups,
            scan=lambda _: TARGET_KEY,
            fingerprint_of=lambda key: FINGERPRINT if key == TARGET_KEY else "SHA256:other",
            publish_root=PUBLISH_ROOT,
            answering=self.answering,
            progress=io.StringIO(),
            session_for=FakeSession,  # type: ignore[arg-type]
            package_of=lambda: self.package,
            **kwargs,
        )

    def carry_out(self, run: str, confirm: str = "node-test", **kwargs: Any) -> dict[str, Any]:
        ticks = iter(range(0, 10_000))
        clock = Clock(now=lambda: float(next(ticks)), sleep=lambda _: None)
        return node_restore.run(
            self.root,
            run,
            confirm,
            CLUSTER,  # type: ignore[arg-type]
            self.backups,
            answering=self.answering,
            progress=io.StringIO(),
            clock=clock,
            session_for=FakeSession,  # type: ignore[arg-type]
            publish_root=PUBLISH_ROOT,
            package_of=lambda: self.package,
            lock_root=self.root / "locks",
            **kwargs,
        )


class Prepare(RestoreTest):
    def test_a_run_holds_a_private_key_and_the_paste_line_limits_it(self) -> None:
        request = Request(
            run="r260101-0000aaaa",
            cluster="alpha",
            node="node-a",
            archive=VERSION,
            target="192.0.2.120",
            mode="new_vm",
            profile=None,
        )
        # 2026-01-01 04:00:00 UTC; the target accepts the key for two hours.
        prepared = node_restore.prepare(
            self.root, request, source_of=lambda _: "192.0.2.7", now=lambda: 1767240000.0
        )
        directory = self.root / "r260101-0000aaaa"
        self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
        self.assertEqual((directory / "key").stat().st_mode & 0o777, 0o600)
        self.assertIn(
            'from="192.0.2.7",restrict,expiry-time="202601010600Z" ssh-ed25519 ',
            prepared["paste"],
        )
        self.assertEqual(node_restore.prepared_at(directory), 1767240000.0)
        self.assertIn("ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub", prepared["paste"])
        # The line shows what landed: a paste that broke on the way in is seen at once.
        self.assertIn("sudo tail -n 1 /root/.ssh/authorized_keys", prepared["paste"])
        self.assertEqual(FakeSession.calls, [])

    def test_a_key_that_cannot_be_made_is_a_refusal_that_leaves_no_run(self) -> None:
        """Review 2026-09-25, finding 4: it went through the helper as a traceback."""

        request = Request(
            run="r260101-0000bbbb",
            cluster="alpha",
            node="node-a",
            archive=VERSION,
            target="192.0.2.120",
            mode="new_vm",
            profile=None,
        )
        with self.assertRaises(RestoreError) as raised:
            node_restore.prepare(
                self.root, request, source_of=lambda _: "192.0.2.7", keygen="/bin/false"
            )

        self.assertIn("one-time key could not be made", str(raised.exception))
        self.assertFalse((self.root / "r260101-0000bbbb").exists())

    def test_a_request_file_missing_a_key_is_a_refusal_in_words(self) -> None:
        with self.assertRaises(RestoreError) as raised:
            Request.from_dict({"run": "r260101-0000cccc", "cluster": "alpha"})

        self.assertIn("request.json in the run directory is incomplete", str(raised.exception))

    def test_the_archive_must_be_in_the_nodes_own_listing(self) -> None:
        node = Node("node-a", "192.0.2.21")
        self.assertTrue(node_restore.archive_path(self.backups, node, VERSION).is_file())
        with self.assertRaisesRegex(RestoreError, "no retained archive"):
            node_restore.archive_path(self.backups, node, "2026-01-02_04-00-00")
        with self.assertRaisesRegex(RestoreError, "named by its version"):
            node_restore.archive_path(self.backups, node, "../node-b/x")


class Preview(RestoreTest):
    def test_a_fingerprint_that_differs_sends_nothing(self) -> None:
        run = self.prepare()
        with self.assertRaisesRegex(RestoreError, "not the one read on its console"):
            self.preview(run, "SHA256:" + "B" * 43)
        self.assertEqual(FakeSession.calls, [])

    def test_the_preview_records_a_digest_and_the_verified_key(self) -> None:
        run = self.prepare()
        summary = self.preview(run)
        self.assertEqual(summary["problems"], [])
        self.assertEqual(summary["plan"]["hostname"], "node-test")
        self.assertEqual(len(summary["digest"]), 64)
        known = (self.root / run / "known_hosts").read_text()
        self.assertEqual(known, f"192.0.2.120 {TARGET_KEY}\n")
        self.assertEqual([c[1]["op"] for c in FakeSession.calls], ["inspect"])

    def test_the_preview_names_the_package_that_will_prepare_the_node(self) -> None:
        run = self.prepare()
        summary = self.preview(run)
        assert self.package is not None
        self.assertEqual(
            summary["node_package"],
            {"version": self.package.version, "commit": self.package.commit},
        )
        self.assertIn("/usr/sbin/haprion-pull-deploy", summary["plan"]["from_package"])

    def test_a_release_without_a_node_package_stops_the_restore(self) -> None:
        """B180: a CLI release installed without --node-package cannot prepare a node."""

        run = self.prepare()
        self.package = None
        summary = self.preview(run)
        self.assertIn("carries no node package", " ".join(summary["problems"]))
        self.assertNotIn("node_package", summary)

    def test_a_package_that_fails_verification_stops_the_restore(self) -> None:
        run = self.prepare()

        def broken() -> node_package.ReleasePackage:
            raise node_package.PackageError("package SHA-256 does not match the expected value")

        summary = node_restore.preview(
            self.root,
            run,
            FINGERPRINT,
            CLUSTER,  # type: ignore[arg-type]
            self.backups,
            scan=lambda _: TARGET_KEY,
            fingerprint_of=lambda _: FINGERPRINT,
            publish_root=PUBLISH_ROOT,
            answering=self.answering,
            progress=io.StringIO(),
            session_for=FakeSession,  # type: ignore[arg-type]
            package_of=broken,
        )
        self.assertIn("node package cannot be used", " ".join(summary["problems"]))

    def test_an_unsupported_target_is_stopped_and_debian_13_is_not(self) -> None:
        """B178: the target's own release decides, not the archive's."""

        run = self.prepare()
        FakeSession.answers["inspect"]["os_release"] = {
            "ID": "ubuntu",
            "VERSION_ID": "26.10",
            "VERSION_CODENAME": "stonking",
        }
        self.assertIn(
            "restore onto Ubuntu 26.04 or Debian 13", " ".join(self.preview(run)["problems"])
        )
        FakeSession.answers["inspect"]["os_release"] = {
            "ID": "debian",
            "VERSION_ID": "13",
            "VERSION_CODENAME": "trixie",
        }
        summary = self.preview(run)
        self.assertEqual(summary["problems"], [])
        self.assertIn("/etc/apt/preferences.d/haproxy-3.4.pref", summary["plan"]["files"])
        self.assertIn("/etc/apt/keyrings/haproxy-debian-net.asc", summary["plan"]["files"])

    def test_a_target_whose_network_is_not_netplan_is_stopped(self) -> None:
        """A restore writes Netplan; ifupdown beside it would configure the interface twice."""

        run = self.prepare()
        FakeSession.answers["inspect"]["network"] = {"netplan": [], "ifupdown": ["eth0"]}
        self.assertIn("ifupdown configures eth0", " ".join(self.preview(run)["problems"]))
        FakeSession.answers["inspect"]["network"] = {"netplan": [], "ifupdown": []}
        self.assertIn("no Netplan configuration", " ".join(self.preview(run)["problems"]))
        del FakeSession.answers["inspect"]["network"]
        self.assertIn("did not say how its network", " ".join(self.preview(run)["problems"]))

    def test_the_archive_s_apt_state_is_replaced_by_the_target_s_repository(self) -> None:
        run = self.prepare()
        files = self.preview(run)["plan"]["files"]
        self.assertIn("/etc/apt/sources.list.d/haproxy-3.4.sources", files)
        self.assertIn("/etc/apt/keyrings/haproxy-ubuntu-ppa.asc", files)
        self.assertNotIn("/etc/apt/sources.list.d/haproxy.sources", files)
        self.assertNotIn("/etc/apt/preferences.d/haproxy-3.4.pref", files)

    def test_an_archive_is_offered_for_its_own_node_only(self) -> None:
        (self.backups / "node-b").mkdir()
        shutil.copy(self.backups / "node-a" / f"{VERSION}.tar.gz", self.backups / "node-b")
        run = self.prepare(node="node-b")
        self.assertIn("not of node-b", " ".join(self.preview(run)["problems"]))

    def test_an_address_already_in_use_is_stopped(self) -> None:
        run = self.prepare()
        self.silent.discard("192.0.2.29")
        self.assertIn("already answers", " ".join(self.preview(run)["problems"]))

    def test_a_new_vm_is_stopped_while_the_node_still_answers(self) -> None:
        run = self.prepare(test=False)
        self.silent.discard("192.0.2.21")
        self.assertIn("already answers", " ".join(self.preview(run)["problems"]))

    def test_a_vm_with_haproxy_already_installed_is_not_empty(self) -> None:
        run = self.prepare()
        FakeSession.answers["inspect"]["installed"] = ["haproxy", "keepalived"]
        self.assertIn(
            "haproxy and keepalived already installed on the target",
            " ".join(self.preview(run)["problems"]),
        )
        # Unless this product restored onto it before: a rolled-back run left them.
        FakeSession.answers["inspect"]["previous_restore"] = True
        self.assertNotIn("already installed", " ".join(self.preview(run)["problems"]))

    def test_a_number_taken_on_the_target_is_named_not_a_problem(self) -> None:
        """B181: an account is its name; its number follows the target."""

        run = self.prepare()
        FakeSession.answers["inspect"]["accounts"] = {"other": [1000, 1000]}
        FakeSession.answers["inspect"]["groups"] = {"operator": 1001}
        summary = self.preview(run)
        self.assertEqual(summary["problems"], [])
        self.assertIn("account operator gets a free UID", summary["renumbered"])
        self.assertIn(
            "group operator keeps the VM's GID 1001 (archive 1000)", summary["renumbered"]
        )


class Run(RestoreTest):
    def previewed(self, *, test: bool = True) -> str:
        run = self.prepare(test=test)
        self.preview(run)
        FakeSession.calls = []
        FakeSession.trusted = {}
        FakeSession.answers["network"] = {"ok": True, "rollback_unit": "u"}
        return run

    def test_three_sessions_in_order_at_the_right_addresses(self) -> None:
        run = self.previewed()
        result = self.carry_out(run)
        self.assertEqual(result["outcome"], "done", result)
        self.assertEqual(
            [(address, header["op"]) for address, header, _ in FakeSession.calls],
            [
                ("192.0.2.120", "inspect"),
                ("192.0.2.120", "apply"),
                ("192.0.2.120", "network"),
                ("192.0.2.29", "finish"),
            ],
        )
        apply_payload = members(FakeSession.calls[1][2])
        self.assertNotIn("/root/.ssh/authorized_keys", apply_payload)
        self.assertFalse(any(path.startswith("/etc/netplan") for path in apply_payload))
        self.assertEqual(members(FakeSession.calls[2][2]), ["/etc/netplan/50-cloud-init.yaml"])
        self.assertEqual(members(FakeSession.calls[3][2]), ["/root/.ssh/authorized_keys"])
        self.assertEqual(FakeSession.calls[3][1]["certificates"], ["cert-a"])
        self.assertEqual(FakeSession.calls[3][1]["keepalived"], "mask")

    def test_a_cluster_busy_with_another_operation_is_refused_before_anything_is_written(
        self,
    ) -> None:
        run = self.previewed()
        with (
            cluster_lock.hold(CLUSTER.cluster_id, operation="deploy", root=self.root / "locks"),
            self.assertRaisesRegex(RestoreError, "another operation is already running"),
        ):
            self.carry_out(run)
        self.assertEqual(FakeSession.calls, [])
        self.assertFalse((self.root / run / "started.json").exists())

    def test_the_cluster_is_held_while_the_restore_runs(self) -> None:
        run = self.previewed()
        seen: list[bool] = []
        real_call = FakeSession.call

        def call(session: Any, *args: Any, **kwargs: Any) -> Any:
            try:
                with cluster_lock.hold(CLUSTER.cluster_id, root=self.root / "locks"):
                    seen.append(False)
            except cluster_lock.LockBusy:
                seen.append(True)
            return real_call(session, *args, **kwargs)

        with mock.patch.object(FakeSession, "call", call):
            result = self.carry_out(run)
        self.assertEqual(result["outcome"], "done", result)
        self.assertTrue(seen and all(seen), seen)

    def test_the_test_node_is_reached_with_the_key_the_operator_verified(self) -> None:
        run = self.previewed()
        self.carry_out(run)
        known = (self.root / run / "known_hosts").read_text().splitlines()
        self.assertEqual(known[-1], f"192.0.2.29 {TARGET_KEY}")

    def test_a_restored_node_is_reached_with_its_archived_key(self) -> None:
        run = self.previewed(test=False)
        result = self.carry_out(run, confirm="node-a")
        self.assertEqual(result["outcome"], "done", result)
        known = (self.root / run / "known_hosts").read_text().splitlines()
        self.assertEqual(known[-1], "192.0.2.21 ssh-ed25519 AAAA")
        self.assertEqual(FakeSession.calls[-1][0], "192.0.2.21")

    def test_a_new_vm_is_trusted_with_the_archived_key_once_apply_has_written_it(self) -> None:
        """`apply` puts the archive's host keys on the VM and reloads sshd.

        The network session that follows reaches the same temporary address,
        which now answers with the node's key. With only the key verified at the
        preview in known_hosts, SSH refused it and the first restore to a new VM
        in production mode stopped there (2026-09-25, exit 255).
        """

        run = self.previewed(test=False)
        result = self.carry_out(run, confirm="node-a")
        self.assertEqual(result["outcome"], "done", result)
        self.assertNotIn("192.0.2.120 ssh-ed25519 AAAA", FakeSession.trusted["apply"])
        self.assertIn(f"192.0.2.120 {TARGET_KEY}", FakeSession.trusted["network"])
        self.assertIn("192.0.2.120 ssh-ed25519 AAAA", FakeSession.trusted["network"])

    def test_a_test_node_keeps_its_own_key_and_is_trusted_with_that_alone(self) -> None:
        run = self.previewed()
        self.carry_out(run)
        self.assertEqual(FakeSession.trusted["network"], [f"192.0.2.120 {TARGET_KEY}"])

    def test_the_apply_header_carries_hashes_but_the_result_file_does_not(self) -> None:
        run = self.previewed()
        self.carry_out(run)
        header = FakeSession.calls[1][1]
        operator = next(a for a in header["accounts"] if a["name"] == "operator")
        self.assertTrue(operator["password_hash"].startswith("$y$"))
        self.assertNotIn("$y$", header["answers"])
        self.assertNotIn("$y$", (self.root / run / "result.json").read_text())

    def test_apply_carries_the_release_s_package_and_answers_derived_from_the_archive(
        self,
    ) -> None:
        run = self.previewed()
        self.carry_out(run)
        header, carried = FakeSession.calls[1][1], FakeSession.calls[1][2]
        assert self.package is not None
        self.assertEqual(
            header["node_package"], {"version": self.package.version, "sha256": self.package.sha256}
        )
        self.assertEqual(header["cluster"], "alpha")
        self.assertIn('NODE_PATH_alpha="node-a"', header["answers"])
        self.assertIn(f'PUBLISH_ROOT="{PUBLISH_ROOT}"', header["answers"])
        self.assertFalse(header["traffic_log"])
        self.assertIn(f"/var/lib/haprion-restore/{run}/haprion-node.deb", members(carried))
        # The package writes these in the running release's version, not the archive's.
        self.assertFalse(any(path.startswith("/usr/sbin/") for path in members(carried)))
        self.assertNotIn("/etc/haprion/node-installation.json", members(carried))

    def test_a_change_after_the_preview_refuses_before_writing(self) -> None:
        run = self.previewed()
        FakeSession.answers["inspect"]["interface"] = {
            **INSPECTED["interface"],
            "mac": "02:00:00:00:00:98",
        }
        with self.assertRaisesRegex(RestoreError, "changed after the preview"):
            self.carry_out(run)
        self.assertEqual([c[1]["op"] for c in FakeSession.calls], ["inspect"])

    def test_the_wrong_confirmation_refuses(self) -> None:
        run = self.previewed()
        with self.assertRaisesRegex(RestoreError, "confirm with"):
            self.carry_out(run, confirm="node-a")

    def test_a_run_is_carried_out_once(self) -> None:
        run = self.previewed()
        self.carry_out(run)
        with self.assertRaisesRegex(RestoreError, "already been carried out"):
            self.carry_out(run)

    def test_a_failed_apply_stops_before_the_network(self) -> None:
        run = self.previewed()
        FakeSession.answers["apply"] = {"ok": False, "error": "apt-get install exited 100"}
        result = self.carry_out(run)
        self.assertEqual((result["outcome"], result["stage"]), ("failed", "apply"))
        self.assertEqual([c[1]["op"] for c in FakeSession.calls], ["inspect", "apply"])

    never_answers = False

    def answering(self, address: str) -> bool:
        # The test address comes up once the network session has run - unless
        # the case under test is the one where it never does.
        if address in self.silent and any(c[1]["op"] == "network" for c in FakeSession.calls):
            return not self.never_answers
        return super().answering(address)

    def test_an_address_that_never_answers_waits_for_the_rollback(self) -> None:
        run = self.previewed()
        self.never_answers = True
        result = self.carry_out(run)
        self.assertEqual((result["outcome"], result["stage"]), ("failed", "network"))
        self.assertTrue(result["rolled_back"])
        self.assertNotIn("finish", [c[1]["op"] for c in FakeSession.calls])


ARCHIVED_KEY = "ssh-ed25519 AAAA"


class Overwrite(RestoreTest):
    """B172/B183: the archive over the running node itself."""

    def setUp(self) -> None:
        super().setUp()
        source = restore_source.read(self.backups / "node-a" / f"{VERSION}.tar.gz")
        same = Target(
            os_release=INSPECTED["os_release"],
            interface="eth0",
            mac="02:00:00:00:00:0a",
        )
        plan = restore_plan.build(source, "new_vm", same)
        hashes = {
            f.path: restore_plan._digest(source, f)
            for f in (*plan.files, *plan.network, *((plan.root_keys,) if plan.root_keys else ()))
            if f.kind == "file"
        }
        FakeSession.answers["inspect"] = {
            **INSPECTED,
            "hostname": "node-a",
            "interface": {
                "name": "eth0",
                "mac": "02:00:00:00:00:0a",
                "addresses": ["192.0.2.21/24"],
            },
            "installed": ["haproxy", "keepalived"],
            "hashes": hashes,
            "listing": {
                "/etc/netplan": ["/etc/netplan/50-cloud-init.yaml"],
                "/etc/haprion": [],
                "/etc/systemd/system/haproxy.service.d": [],
            },
            "product_installed": list(restore_plan.PRODUCT_PACKAGES),
        }
        self.silent = set()
        self.backup_error: str | None = None
        self.standing = node_restore.Standing(True, "node-b", True)
        self.checks = node_restore.OverwriteChecks(
            backup=lambda: self.backup_error, standing=lambda _name: self.standing
        )

    def prepare_overwrite(self, target: str = "192.0.2.21") -> str:
        request = Request(
            run=node_restore.new_run_id(),
            cluster="alpha",
            node="node-a",
            archive=VERSION,
            target=target,
            mode="new_vm",
            profile=None,
        )
        node_restore.prepare(self.root, request, source_of=lambda _: "192.0.2.7")
        return request.run

    def preview_overwrite(
        self, run: str, key: str = ARCHIVED_KEY, fingerprint: str = FINGERPRINT
    ) -> dict[str, Any]:
        return node_restore.preview(
            self.root,
            run,
            fingerprint,
            CLUSTER,  # type: ignore[arg-type]
            self.backups,
            scan=lambda _: key,
            fingerprint_of=lambda _key: FINGERPRINT,
            publish_root=PUBLISH_ROOT,
            answering=self.answering,
            progress=io.StringIO(),
            session_for=FakeSession,  # type: ignore[arg-type]
            package_of=lambda: self.package,
            checks=self.checks,
        )

    def previewed(self) -> str:
        run = self.prepare_overwrite()
        self.preview_overwrite(run)
        FakeSession.calls = []
        FakeSession.trusted = {}
        return run

    def test_a_node_equal_to_its_archive_is_shown_so_and_takes_a_backup(self) -> None:
        summary = self.preview_overwrite(self.prepare_overwrite())
        self.assertEqual(summary["problems"], [])
        self.assertEqual(summary["plan"]["changed"], [])
        self.assertTrue(summary["plan"]["network_unchanged"])
        self.assertEqual(summary["overwrite"]["backup"], "done")
        self.assertTrue(summary["overwrite"]["vip_owner"])
        self.assertEqual(FakeSession.calls[0][1]["list"][0], "/etc/netplan")
        # So the agent can leave this run's one-time key out of root's keys.
        self.assertRegex(FakeSession.calls[0][1]["run"], r"^r\d{6}-[0-9a-f]{8}$")

    def test_the_archived_host_key_makes_it_the_node_itself(self) -> None:
        """B184: one restore as the node; the key it answers with says which case."""

        run = self.prepare_overwrite()
        summary = self.preview_overwrite(run)
        self.assertEqual(summary["plan"]["mode"], "overwrite")
        stored = node_restore.read_json(self.root / run / "request.json")
        self.assertEqual(stored["mode"], "overwrite")

    def test_the_node_itself_needs_no_fingerprint(self) -> None:
        summary = self.preview_overwrite(self.prepare_overwrite(), fingerprint="")
        self.assertEqual(summary["plan"]["mode"], "overwrite")
        self.assertEqual(summary["target"]["fingerprint"], FINGERPRINT)

    def test_without_a_fingerprint_a_new_vm_is_refused_before_anything_is_sent(self) -> None:
        run = self.prepare_overwrite(target="192.0.2.120")
        with self.assertRaisesRegex(RestoreError, "give the fingerprint read on its console"):
            self.preview_overwrite(run, key=TARGET_KEY, fingerprint="")
        self.assertEqual(FakeSession.calls, [])

    def test_another_host_key_is_a_new_vm_in_its_place(self) -> None:
        run = self.prepare_overwrite(target="192.0.2.120")
        FakeSession.answers["inspect"] = dict(INSPECTED)
        self.silent = {"192.0.2.21"}
        summary = self.preview_overwrite(run, key=TARGET_KEY)
        self.assertEqual(summary["plan"]["mode"], "new_vm")
        self.assertNotIn("overwrite", summary)

    def test_the_node_itself_is_reached_at_its_own_address(self) -> None:
        summary = self.preview_overwrite(self.prepare_overwrite(target="192.0.2.120"))
        self.assertTrue(any("its own address" in p for p in summary["problems"]))

    def test_an_empty_vm_already_on_the_nodes_address_is_a_new_vm(self) -> None:
        run = self.prepare_overwrite()
        FakeSession.answers["inspect"] = dict(INSPECTED)
        summary = self.preview_overwrite(run, key=TARGET_KEY)
        self.assertEqual((summary["plan"]["mode"], summary["problems"]), ("new_vm", []))

    def test_a_machine_that_is_neither_the_node_nor_empty_is_stopped(self) -> None:
        run = self.prepare_overwrite()
        FakeSession.answers["inspect"] = {**INSPECTED, "installed": ["haproxy"]}
        summary = self.preview_overwrite(run, key=TARGET_KEY)
        self.assertEqual(summary["plan"]["mode"], "new_vm")
        self.assertTrue(any("empty VM" in p for p in summary["problems"]))

    def test_an_overwrite_needs_the_clusters_checks(self) -> None:
        run = self.prepare_overwrite()
        self.checks = None  # type: ignore[assignment]
        with self.assertRaisesRegex(RestoreError, "backup and status"):
            self.preview_overwrite(run)

    def test_an_unchanged_network_is_not_applied(self) -> None:
        run = self.previewed()
        result = self.carry_out(run, confirm="node-a", checks=self.checks)
        self.assertEqual(result["outcome"], "done", result)
        self.assertEqual(
            [(address, header["op"]) for address, header, _ in FakeSession.calls],
            [("192.0.2.21", "inspect"), ("192.0.2.21", "apply"), ("192.0.2.21", "finish")],
        )
        apply, finish = FakeSession.calls[1][1], FakeSession.calls[2][1]
        self.assertTrue(apply["overwrite"])
        self.assertEqual(apply["packages"], [])
        self.assertIn("/etc/haprion/node-installation.json", apply["keep"])
        self.assertEqual((finish["overwrite"], finish["network"]), (True, False))

    def test_a_failed_backup_needs_the_operators_tick(self) -> None:
        self.backup_error = "node-b: unreachable"
        run = self.previewed()
        with self.assertRaisesRegex(RestoreError, "no state backup"):
            self.carry_out(run, confirm="node-a", checks=self.checks)
        result = self.carry_out(run, confirm="node-a", checks=self.checks, backup_failed_ok=True)
        self.assertEqual(result["outcome"], "done", result)

    def test_the_vip_holder_with_a_sick_neighbour_needs_the_operators_tick(self) -> None:
        run = self.previewed()
        self.standing = node_restore.Standing(True, "node-b", False, "HAProxy active False")
        with self.assertRaisesRegex(RestoreError, "WILL break live traffic"):
            self.carry_out(run, confirm="node-a", checks=self.checks)
        self.assertEqual([c[1]["op"] for c in FakeSession.calls], ["inspect"])
        result = self.carry_out(run, confirm="node-a", checks=self.checks, break_traffic=True)
        self.assertEqual(result["outcome"], "done", result)

    def test_a_backup_node_with_a_sick_neighbour_goes_ahead(self) -> None:
        run = self.previewed()
        self.standing = node_restore.Standing(False, "node-b", False)
        result = self.carry_out(run, confirm="node-a", checks=self.checks)
        self.assertEqual(result["outcome"], "done", result)

    def test_an_apply_the_node_put_back_is_failed_and_rolled_back(self) -> None:
        run = self.previewed()
        FakeSession.answers["apply"] = {"ok": False, "rolled_back": True, "error": "x; put back"}
        result = self.carry_out(run, confirm="node-a", checks=self.checks)
        self.assertEqual((result["outcome"], result["stage"]), ("failed", "apply"))
        self.assertTrue(result["rolled_back"])

    def test_a_network_that_never_comes_up_is_put_back_with_the_files(self) -> None:
        FakeSession.answers["inspect"]["hashes"]["/etc/netplan/50-cloud-init.yaml"] = "0" * 64
        run = self.previewed()
        FakeSession.answers["network"] = {"ok": True, "rollback_unit": "u"}
        fired: list[bool] = []
        ticks = iter(range(0, 100_000))

        def sleep(seconds: float) -> None:
            # The long wait is the one for the rollback timer; after it the node answers.
            if seconds > 10:
                fired.append(True)

        def answering(_address: str) -> bool:
            ops = [c[1]["op"] for c in FakeSession.calls]
            return "network" not in ops or bool(fired)

        result = node_restore.run(
            self.root,
            run,
            "node-a",
            CLUSTER,  # type: ignore[arg-type]
            self.backups,
            answering=answering,
            progress=io.StringIO(),
            clock=Clock(now=lambda: float(next(ticks)), sleep=sleep),
            session_for=FakeSession,  # type: ignore[arg-type]
            publish_root=PUBLISH_ROOT,
            package_of=lambda: self.package,
            lock_root=self.root / "locks",
            checks=self.checks,
        )
        self.assertEqual((result["outcome"], result["stage"]), ("failed", "network"), result)
        self.assertEqual(FakeSession.calls[-1][1], {"op": "rollback", "run": run})
        self.assertTrue(result["rolled_back"])
        self.assertIn("node was rolled back", result["error"])


class Timed(RestoreTest):
    def answering(self, address: str) -> bool:
        # The test address answers once the network session has run, as in Run.
        if address in self.silent and any(c[1]["op"] == "network" for c in FakeSession.calls):
            return True
        return super().answering(address)

    def later(self, run: str, seconds: float) -> float:
        return node_restore.prepared_at(self.root / run) + seconds


class TheHour(Timed):
    """B182: an hour from prepare to run, then the run and its key are gone."""

    def test_a_preview_past_the_hour_is_refused_and_removes_the_run(self) -> None:
        run = self.prepare()
        after = self.later(run, node_restore.START_WINDOW + 1)
        with self.assertRaisesRegex(RestoreError, "more than an hour ago"):
            self.preview(run, now=lambda: after)
        self.assertFalse((self.root / run).exists())
        self.assertEqual(FakeSession.calls, [])

    def test_a_run_past_the_hour_is_refused_and_one_within_it_is_carried_out(self) -> None:
        run = self.prepare()
        self.preview(run)
        FakeSession.answers["network"] = {"ok": True, "rollback_unit": "u"}
        within = self.later(run, node_restore.START_WINDOW - 1)
        self.assertEqual(self.carry_out(run, now=lambda: within)["outcome"], "done")
        other = self.prepare()
        self.preview(other)
        after = self.later(other, node_restore.START_WINDOW + 1)
        with self.assertRaisesRegex(RestoreError, "has expired"):
            self.carry_out(other, now=lambda: after)

    def test_discard_removes_the_key_and_says_whether_there_was_one(self) -> None:
        run = self.prepare()
        self.assertTrue(node_restore.discard(self.root, run))
        self.assertFalse((self.root / run).exists())
        self.assertFalse(node_restore.discard(self.root, run))
        with self.assertRaisesRegex(RestoreError, "not usable"):
            node_restore.discard(self.root, "../elsewhere")

    def test_a_run_being_worked_on_is_neither_discarded_nor_swept(self) -> None:
        run = self.prepare()
        after = self.later(run, node_restore.START_WINDOW + 1)
        with node_restore._Held(self.root / run, wait=True):
            with self.assertRaisesRegex(RestoreError, "being worked on"):
                node_restore.discard(self.root, run)
            self.assertEqual(node_restore.sweep(self.root, after), [])
        self.assertEqual(node_restore.sweep(self.root, after), [run])

    def test_the_sweep_takes_only_runs_past_their_hour(self) -> None:
        old, fresh = self.prepare(), self.prepare()
        (self.root / old / "prepared.json").write_text('{"at": 1000}\n')
        self.assertEqual(node_restore.sweep(self.root, time.time()), [old])
        self.assertTrue((self.root / fresh).is_dir())

    def test_a_run_from_before_the_hour_existed_is_timed_by_its_request(self) -> None:
        run = self.prepare()
        (self.root / run / "prepared.json").unlink()
        os.utime(self.root / run / "request.json", (1000, 1000))
        self.assertEqual(node_restore.prepared_at(self.root / run), 1000.0)
        self.assertEqual(node_restore.sweep(self.root, time.time()), [run])

    def test_a_missing_root_is_nothing_to_sweep(self) -> None:
        self.assertEqual(node_restore.sweep(self.root / "absent", time.time()), [])


class Status(Timed):
    """How a run stands, for a job that lost its answer (review 2026-09-25, track 8)."""

    def previewed(self) -> str:
        run = self.prepare()
        self.preview(run)
        FakeSession.answers["network"] = {"ok": True, "rollback_unit": "u"}
        return run

    def test_a_run_not_yet_started_and_one_that_stopped_mid_run(self) -> None:
        run = self.prepare()
        self.assertEqual(node_restore.status(self.root, run), {"run": run, "state": "not_started"})
        (self.root / run / "started.json").write_text('{"at": 1000}\n')
        self.assertEqual(node_restore.status(self.root, run), {"run": run, "state": "stopped"})

    def test_a_run_a_step_is_working_in_is_running(self) -> None:
        run = self.prepare()
        with node_restore._Held(self.root / run, wait=True):
            self.assertEqual(node_restore.status(self.root, run)["state"], "running")

    def test_a_finished_run_answers_what_the_run_answered(self) -> None:
        run = self.previewed()
        carried = self.carry_out(run)
        standing = node_restore.status(self.root, run)
        self.assertEqual((standing["state"], standing["outcome"], standing["error"]),
                         ("finished", "done", None))  # fmt: skip
        self.assertEqual(
            standing["result"], {k: v for k, v in carried.items() if k not in {"outcome", "error"}}
        )

    def test_a_failed_run_carries_its_error(self) -> None:
        run = self.previewed()
        FakeSession.answers["apply"] = {"ok": False, "error": "apt-get install exited 100"}
        self.carry_out(run)
        standing = node_restore.status(self.root, run)
        self.assertEqual((standing["outcome"], standing["error"]),
                         ("failed", "apt-get install exited 100"))  # fmt: skip
        self.assertEqual(standing["result"]["stage"], "apply")

    def test_a_session_that_breaks_after_writing_began_is_a_failure_in_that_session(
        self,
    ) -> None:
        """Not the refusal that says nothing was written: apply had run."""

        run = self.previewed()
        original = FakeSession.call

        def call(session: FakeSession, address: str, header: dict[str, Any], *a: Any,
                 **k: Any) -> dict[str, Any]:  # fmt: skip
            if header["op"] == "network":
                raise RestoreError("the network session did not finish in time")
            return original(session, address, header, *a, **k)

        with mock.patch.object(FakeSession, "call", call):
            result = self.carry_out(run)
        self.assertEqual((result["outcome"], result["stage"]), ("failed", "network"))
        self.assertIn("network", result["sessions"])
        self.assertFalse(result["rolled_back"])
        self.assertEqual(node_restore.status(self.root, run)["outcome"], "failed")

    def test_the_hour_takes_the_key_and_keeps_the_outcome_for_a_week(self) -> None:
        run = self.previewed()
        self.carry_out(run)
        hour = self.later(run, node_restore.START_WINDOW + 1)
        self.assertEqual(node_restore.sweep(self.root, hour), [])
        self.assertEqual(
            sorted(p.name for p in (self.root / run).iterdir()),
            ["prepared.json", "request.json", "result.json", "started.json"],
        )
        self.assertEqual(node_restore.status(self.root, run)["outcome"], "done")
        week = self.later(run, node_restore.RESULT_KEPT + 1)
        self.assertEqual(node_restore.sweep(self.root, week), [run])
        with self.assertRaisesRegex(RestoreError, "no restore run"):
            node_restore.status(self.root, run)

    def test_a_step_past_the_hour_keeps_the_outcome_too(self) -> None:
        run = self.previewed()
        self.carry_out(run)
        after = self.later(run, node_restore.START_WINDOW + 1)
        with self.assertRaisesRegex(RestoreError, "more than an hour ago"):
            self.preview(run, now=lambda: after)
        self.assertFalse((self.root / run / "key").exists())
        self.assertEqual(node_restore.status(self.root, run)["state"], "finished")

    def test_a_run_that_never_began_writing_still_goes_whole_at_the_hour(self) -> None:
        run = self.prepare()
        self.assertEqual(node_restore.sweep(self.root, self.later(run, 3601)), [run])

    def test_an_unusable_run_id_is_refused(self) -> None:
        with self.assertRaisesRegex(RestoreError, "not usable"):
            node_restore.status(self.root, "../elsewhere")

    def test_the_command_line_reads_the_same_standing(self) -> None:
        run = self.previewed()
        self.carry_out(run)
        out = io.StringIO()
        code = cli.main(["status", "--run", run, "--json"], run_root=self.root,
                        output_stream=out, require_root=False)  # fmt: skip
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out.getvalue()), node_restore.status(self.root, run))
        text = io.StringIO()
        cli.main(["status", "--run", run], run_root=self.root, output_stream=text,
                 require_root=False)  # fmt: skip
        self.assertIn(f"restore {run}: done", text.getvalue())
        other = self.prepare()
        text = io.StringIO()
        cli.main(["status", "--run", other], run_root=self.root, output_stream=text,
                 require_root=False)  # fmt: skip
        self.assertIn("never began writing", text.getvalue())


class Cli(unittest.TestCase):
    def test_usage_errors_are_64(self) -> None:
        errors = io.StringIO()
        self.assertEqual(cli.main([], error_stream=errors, require_root=False), 64)
        self.assertEqual(cli.main(["prepare", "-c", "alpha"], error_stream=errors), 64)
        self.assertEqual(
            cli.main(
                ["prepare", "-c", "a", "--node", "n", "--archive", "v", "--target", "192.0.2.1",
                 "--test-hostname", "x"],
                error_stream=errors,
            ),
            64,
        )  # fmt: skip

    def test_the_command_line_refuses_what_the_helper_refuses(self) -> None:
        # One check for both callers: a test address without its prefix is the
        # same mistake typed in a terminal or in the form.
        errors = io.StringIO()
        code = cli.main(
            ["prepare", "-c", "alpha", "--node", "node-a", "--archive", VERSION,
             "--target", "192.0.2.120", "--test", "--test-hostname", "node-test",
             "--test-address", "192.0.2.29", "--test-vip", "198.51.100.254/32"],
            error_stream=errors,
            require_root=False,
        )  # fmt: skip
        self.assertEqual(code, 64)
        self.assertIn("address/prefix", errors.getvalue())

    def test_the_whole_fingerprint_line_is_accepted_as_the_form_accepts_it(self) -> None:
        if os.geteuid() == 0:
            self.skipTest("running as root")
        errors = io.StringIO()
        line = "256 SHA256:" + "A" * 43 + " root@node-test (ED25519)"
        # Past the parameter check (64) to the root check (77): the line was read.
        run = ["preview", "--run", "r260101-0000aaaa", "--fingerprint"]
        self.assertEqual(cli.main([*run, line], error_stream=errors), 77)
        self.assertEqual(cli.main([*run, "256 SHA256:short x"], error_stream=errors), 64)

    def test_it_must_run_as_root(self) -> None:
        if os.geteuid() == 0:
            self.skipTest("running as root")
        errors = io.StringIO()
        code = cli.main(["discard", "--run", "r260101-0000aaaa"], error_stream=errors)
        self.assertEqual(code, 77)

    def test_the_preview_text_names_every_rewrite(self) -> None:
        out = io.StringIO()
        cli._text_preview(
            {
                "run": "r1",
                "digest": "x",
                "problems": [],
                "plan": {
                    "mode": "test",
                    "hostname": "node-test",
                    "address": "192.0.2.29/24",
                    "keepalived": "mask",
                    "packages": ["haproxy"],
                    "files": ["/etc/hosts"],
                    "network": ["/etc/netplan/a.yaml"],
                    "equal_directories": ["/etc/sudoers.d"],
                    "accounts": [],
                    "rewrites": [
                        {"path": "/etc/hosts", "field": "hostname", "old": "a", "new": "b"}
                    ],
                },
                "target": {
                    "hostname": "temp",
                    "interface": {"name": "eth0", "mac": "m", "addresses": ["192.0.2.120/24"]},
                    "os_release": {"ID": "ubuntu", "VERSION_ID": "26.04"},
                    "fingerprint": FINGERPRINT,
                },
                "archive": {
                    "node": "node-a",
                    "version": VERSION,
                    "os_release": {"ID": "ubuntu", "VERSION_ID": "26.04"},
                    "extra_paths": [],
                },
            },
            out,
        )
        self.assertIn("/etc/hosts hostname: a -> b", out.getvalue())
        self.assertIn("--confirm node-test", out.getvalue())


if __name__ == "__main__":
    unittest.main()


#
# B298: the WAF engine is in no repository; a node that ran it gets the one
# this manager's release carries, or the restore says why not.
#
ENGINE_VERSIONS = {"meta/package-versions.txt": "haproxy\t3.4.4-1\nhaprion-coraza-spoa\t0.9.0-7\n"}


def _with_engine(test: RestoreTest) -> None:
    archive = test.backups / "node-a" / f"{VERSION}.tar.gz"
    work = Path(tempfile.mkdtemp())
    test.addCleanup(shutil.rmtree, work)
    shutil.move(build(work, meta=ENGINE_VERSIONS), archive)
    carried = work / "haprion-coraza-spoa.deb"
    carried.write_bytes(b"the release's WAF engine package")
    test.engine = waf_engine_package.ReleasePackage(
        path=carried, version="0.9.0-7", sha256=hashlib.sha256(carried.read_bytes()).hexdigest()
    )
    patch = mock.patch.object(
        waf_engine_package,
        "release_package",
        side_effect=lambda: test.engine,
    )
    patch.start()
    test.addCleanup(patch.stop)


class WafEngineToANewVm(Run):
    def setUp(self) -> None:
        super().setUp()
        _with_engine(self)

    def test_the_preview_names_it_and_the_run_carries_it(self) -> None:
        summary = self.preview(self.prepare())
        self.assertEqual(summary["problems"], [])
        self.assertEqual(summary["waf_engine"], {"version": "0.9.0-7"})

        run = self.previewed()
        self.carry_out(run)
        header, carried = FakeSession.calls[1][1], FakeSession.calls[1][2]
        if self.engine is None:
            self.fail("no engine")
        self.assertEqual(header["waf_engine"], {"version": "0.9.0-7", "sha256": self.engine.sha256})
        self.assertIn(f"/var/lib/haprion-restore/{run}/haprion-coraza-spoa.deb", members(carried))

    def test_a_release_without_it_stops_the_restore(self) -> None:
        self.engine = None
        summary = self.preview(self.prepare())
        self.assertIn("carries no WAF engine package", " ".join(summary["problems"]))
        self.assertNotIn("waf_engine", summary)

    def test_one_that_fails_verification_stops_the_restore(self) -> None:
        def broken() -> None:
            raise waf_engine_package.PackageError(
                "package SHA-256 does not match the expected value"
            )

        with mock.patch.object(waf_engine_package, "release_package", side_effect=broken):
            summary = self.preview(self.prepare())
        self.assertIn("WAF engine package cannot be used", " ".join(summary["problems"]))


class WafEngineNotRun(Run):
    def test_a_node_without_it_gets_none(self) -> None:
        summary = self.preview(self.prepare())
        self.assertNotIn("waf_engine", summary)
        run = self.previewed()
        self.carry_out(run)
        self.assertIsNone(FakeSession.calls[1][1]["waf_engine"])


class WafEngineOverTheNode(Overwrite):
    """B183: the node's software is its own; only an engine it lacks is installed."""

    def setUp(self) -> None:
        super().setUp()
        _with_engine(self)

    def test_a_node_that_has_it_keeps_its_own(self) -> None:
        FakeSession.answers["inspect"]["product_installed"] = [
            *restore_plan.PRODUCT_PACKAGES,
            waf_engine_package.PACKAGE,
        ]
        summary = self.preview_overwrite(self.prepare_overwrite())
        self.assertEqual(summary["problems"], [])
        self.assertNotIn("waf_engine", summary)

    def test_a_node_that_lost_it_gets_it(self) -> None:
        summary = self.preview_overwrite(self.prepare_overwrite())
        self.assertEqual(summary["waf_engine"], {"version": "0.9.0-7"})
        self.assertIn(waf_engine_package.PACKAGE, FakeSession.calls[0][1]["packages"])


class TheTargetsClock(RestoreTest):
    """A VM put back from a snapshot runs days behind, and apt refuses every repository."""

    def test_a_clock_days_behind_stops_the_preview(self) -> None:
        FakeSession.answers["inspect"]["clock"] = time.time() - 18 * 86400
        summary = self.preview(self.prepare())
        self.assertIn("the target's clock is 18 d 0 h behind", " ".join(summary["problems"]))

    def test_a_clock_within_minutes_stops_nothing(self) -> None:
        FakeSession.answers["inspect"]["clock"] = time.time() + 60
        summary = self.preview(self.prepare())
        self.assertFalse(any("clock" in problem for problem in summary["problems"]))

    def test_the_sentence_says_which_way_and_how_far(self) -> None:
        self.assertIsNone(node_restore.clock_skew(1_100.0, 1_000.0, 1_001.0))
        self.assertEqual(
            node_restore.clock_skew(1_001.0 + 400, 1_000.0, 1_001.0),
            "the target's clock is 6 min ahead of this manager's; set its time first - "
            "apt and TLS judge every date against it",
        )
        self.assertIn(
            "2 h 0 min behind", node_restore.clock_skew(1_000.0 - 7200, 1_000.0, 1_001.0) or ""
        )
