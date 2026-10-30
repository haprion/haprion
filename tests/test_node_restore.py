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
    haprion_repository,
    keyring_package,
    node_package,
    node_restore,
    node_ssh,
    restore_agent,
    restore_fetch,
    restore_plan,
    restore_source,
    waf_engine_package,
)
from haprion.cli import node_restore as cli
from haprion.config import Node
from haprion.node_restore import Clock, Request, RestoreError
from haprion.restore_plan import Target, TestProfile
from tests.restore_fixture import FILES, build

VERSION = "2026-01-01_04-00-00"
PUBLISH_ROOT = Path("/srv/haprion/published")
FINGERPRINT = "SHA256:" + "A" * 43
TARGET_KEY = "ssh-ed25519 AAAAtargetkey"
CLUSTER = SimpleNamespace(
    cluster_id="alpha",
    nodes=(Node("node-a", "192.0.2.21"), Node("node-b", "192.0.2.22")),
    certificate_ids=("cert-a",),
    authority_ids=("corp-root",),
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


FETCH_KEYS = {
    "config": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIconfig",
    "cert": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIcerts",
}


class FakeAccess:
    """The manager's two pull accounts, as a list of the temporary lines in them."""

    def __init__(self) -> None:
        self.held: dict[str, tuple[str, str, dict[str, str]]] = {}
        self.log: list[str] = []
        self.refuse_revoke = False

    def grant(self, run: str, cluster: str, address: str, keys: Any) -> None:
        self.log.append(f"grant {run}")
        self.held[run] = (cluster, address, dict(keys))

    def revoke(self, run: str, cluster: str) -> None:
        self.log.append(f"revoke {run}")
        if self.refuse_revoke:
            raise restore_fetch.FetchAccessError("the lock is busy")
        self.held.pop(run, None)

    @property
    def access(self) -> node_restore.FetchAccess:
        return node_restore.FetchAccess(self.grant, self.revoke)


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
        if header["op"] == "apply" and "apply" not in FakeSession.answers:
            return {"ok": True, "op": "apply", "fetch_keys": dict(FETCH_KEYS)}
        return FakeSession.answers.get(header["op"], {"ok": True, "op": header["op"]})


def members(payload: bytes) -> list[str]:
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
        return ["/" + member.name for member in archive.getmembers()]


class RestoreTest(unittest.TestCase):
    engine: waf_engine_package.ReleasePackage | None = None
    keyring: keyring_package.ReleasePackage | None = None

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
        self.fetching = FakeAccess()
        self.silent = {"192.0.2.29", "192.0.2.21"}
        carried = work / "haprion-node.deb"
        carried.write_bytes(b"the release's node package")
        self.package: node_package.ReleasePackage | None = node_package.ReleasePackage(
            path=carried,
            version="0.1.0+git20261009120000.0123456789ab",
            commit="0123456789ab" + "0" * 28,
            sha256=hashlib.sha256(carried.read_bytes()).hexdigest(),
        )
        # The node package depends on it; a release carries it (B339).
        key = work / "haprion-archive-keyring.deb"
        key.write_bytes(b"the release's repository key package")
        self.keyring = keyring_package.ReleasePackage(
            path=key, version="2026.10.17", sha256=hashlib.sha256(key.read_bytes()).hexdigest()
        )
        patch = mock.patch.object(
            keyring_package, "release_package", side_effect=lambda: self.keyring
        )
        patch.start()
        self.addCleanup(patch.stop)

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
            **{"fetch_access": self.fetching.access, **kwargs},
        )


class Prepare(RestoreTest):
    def test_no_route_to_the_target_leaves_no_run_behind(self) -> None:
        request = Request(
            run="r260101-0000bbbb",
            cluster="alpha",
            node="node-a",
            archive=VERSION,
            target="192.0.2.120",
            mode="new_vm",
            profile=None,
        )

        def no_route(_: str) -> str:
            raise RestoreError("no route to the target")

        self.root.mkdir(mode=0o700, exist_ok=True)
        with self.assertRaises(RestoreError):
            node_restore.prepare(self.root, request, source_of=no_route)
        self.assertEqual(list(self.root.iterdir()), [])

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

    def test_a_payload_the_node_would_refuse_is_a_problem_at_the_preview(self) -> None:
        run = self.prepare()
        with mock.patch.object(restore_agent, "MAX_PAYLOAD", 100):
            problems = " ".join(self.preview(run)["problems"])
        self.assertIn("more than a restore carries", problems)
        self.assertIn("/etc/", problems, "names the largest files")

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
        # HAProxy from the PPA, and nothing else from it (review 2026-10-22, 5-15).
        self.assertIn("/etc/apt/preferences.d/haproxy-3.4.pref", files)

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
        # The CA files its pools verify against go with it (lab 26-10-26).
        self.assertEqual(FakeSession.calls[3][1]["authorities"], ["corp-root"])
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

    def test_apply_keeps_sshd_on_the_temporary_address(self) -> None:
        """R2 26-10-27 (F22): the network session reaches the target where apply found it."""

        for test in (False, True):
            with self.subTest(test=test):
                FakeSession.calls.clear()
                run = self.previewed(test=test)
                self.carry_out(run, confirm="node-test" if test else "node-a")
                apply = next(c for c in FakeSession.calls if c[1]["op"] == "apply")
                self.assertEqual(apply[1]["temporary_address"], "192.0.2.120")

    def test_a_test_node_keeps_its_own_key_and_is_trusted_with_that_alone(self) -> None:
        run = self.previewed()
        self.carry_out(run)
        self.assertEqual(FakeSession.trusted["network"], [f"192.0.2.120 {TARGET_KEY}"])

    def test_a_test_run_sends_no_password_hash_and_says_so(self) -> None:
        run = self.prepare()
        summary = self.preview(run)
        self.assertEqual(summary["plan"]["passwords"], "not restored in test mode")
        self.assertFalse(any(a["has_password"] for a in summary["plan"]["accounts"]))
        FakeSession.calls = []
        self.carry_out(run)
        header = next(c[1] for c in FakeSession.calls if c[1]["op"] == "apply")
        self.assertTrue(header["accounts"])
        self.assertTrue(all(a["password_hash"] is None for a in header["accounts"]))

    def test_the_apply_header_carries_hashes_but_the_result_file_does_not(self) -> None:
        run = self.previewed(test=False)
        self.carry_out(run, confirm="node-a")
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
        # Reached at its own address, sshd has nothing temporary to keep.
        self.assertIsNone(apply["temporary_address"])
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

    def broken_apply(self, rollback: dict[str, Any]) -> dict[str, Any]:
        run = self.previewed()
        original = FakeSession.call

        def call(session: FakeSession, address: str, header: dict[str, Any], *a: Any,
                 **k: Any) -> dict[str, Any]:  # fmt: skip
            if header["op"] == "apply":
                raise RestoreError("the apply session did not finish in time")
            return original(session, address, header, *a, **k)

        FakeSession.answers["rollback"] = rollback
        with mock.patch.object(FakeSession, "call", call):
            return self.carry_out(run, confirm="node-a", checks=self.checks)

    def test_an_apply_that_breaks_from_our_side_puts_the_node_back(self) -> None:
        result = self.broken_apply({"ok": True})
        self.assertEqual((result["outcome"], result["stage"]), ("failed", "apply"))
        self.assertTrue(result["rolled_back"], result)
        self.assertEqual([c[1]["op"] for c in FakeSession.calls][-1], "rollback")
        self.assertIn("put back", result["error"])

    def test_a_rollback_that_fails_says_where_keepalived_and_the_copy_are(self) -> None:
        result = self.broken_apply({"ok": False, "error": "no copy"})
        self.assertFalse(result["rolled_back"])
        self.assertIn("keepalived may be stopped on node-a", result["error"])
        self.assertIn("/before/", result["error"])

    def test_a_failure_before_anything_was_sent_asks_for_no_rollback(self) -> None:
        run = self.previewed()
        with mock.patch.object(
            node_restore, "payload", side_effect=RestoreError("the archive cannot read x")
        ):
            result = self.carry_out(run, confirm="node-a", checks=self.checks)
        self.assertEqual(result["outcome"], "failed", result)
        self.assertNotIn("rollback", [c[1]["op"] for c in FakeSession.calls])
        self.assertNotIn("keepalived", result["error"])

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


class TheTestVmFetches(Timed):
    """B398: a test restore lets its VM's new fetch keys in for the run, and only for it."""

    def previewed(self, *, test: bool = True) -> str:
        run = self.prepare(test=test)
        self.preview(run)
        FakeSession.calls = []
        FakeSession.trusted = {}
        FakeSession.answers["network"] = {"ok": True, "rollback_unit": "u"}
        return run

    def at_finish(self, run: str, **kwargs: Any) -> tuple[dict[str, Any], dict[str, Any]]:
        """The run's result, and what the manager held when the VM's finish session began."""

        seen: dict[str, Any] = {}
        original = FakeSession.call

        def call(session: FakeSession, address: str, header: dict[str, Any], *a: Any,
                 **k: Any) -> dict[str, Any]:  # fmt: skip
            if header["op"] == "finish":
                seen.update(self.fetching.held)
            return original(session, address, header, *a, **k)

        with mock.patch.object(FakeSession, "call", call):
            return self.carry_out(run, **kwargs), seen

    def test_the_keys_are_in_while_it_fetches_and_out_after_finish(self) -> None:
        run = self.previewed()

        result, seen = self.at_finish(run)

        self.assertEqual(result["outcome"], "done", result)
        self.assertEqual(seen, {run: ("alpha", "192.0.2.29", dict(FETCH_KEYS))})
        self.assertEqual(self.fetching.held, {})
        self.assertFalse((self.root / run / "fetch-keys.json").exists())

    def test_they_are_asked_for_before_anything_is_written(self) -> None:
        run = self.previewed()
        FakeSession.calls = []

        with self.assertRaisesRegex(RestoreError, "needs the manager's fetch access"):
            self.carry_out(run, fetch_access=None)
        self.assertEqual(FakeSession.calls[:0], [])
        self.assertFalse((self.root / run / "started.json").exists())

    def test_a_failure_takes_them_out_too(self) -> None:
        run = self.previewed()
        FakeSession.answers["network"] = {"ok": False, "error": "netplan refused"}

        result = self.carry_out(run)

        self.assertEqual((result["outcome"], result["stage"]), ("failed", "network"))
        self.assertEqual(self.fetching.held, {})
        self.assertFalse((self.root / run / "fetch-keys.json").exists())

    def test_a_vm_that_reports_something_else_than_keys_is_not_let_in(self) -> None:
        run = self.previewed()
        FakeSession.answers["apply"] = {
            "ok": True,
            "fetch_keys": {"config": 'command="/bin/sh" ssh-ed25519 AAAA'},
        }

        result = self.carry_out(run)

        self.assertEqual((result["outcome"], result["stage"]), ("failed", "apply"))
        self.assertEqual(self.fetching.held, {})

    def test_keys_that_will_not_come_out_leave_the_run_for_the_sweep(self) -> None:
        run = self.previewed()
        self.fetching.refuse_revoke = True

        result = self.carry_out(run)

        self.assertEqual(result["outcome"], "done")
        self.assertNotIn("warning", result)
        self.assertIn("still out", result["sessions"]["finish"]["warnings"][-1])
        self.assertIn(run, self.fetching.held)
        kept = node_restore.status(self.root, run)["result"]["sessions"]["finish"]["warnings"]
        self.assertIn("still out", kept[-1])
        # A caller that cannot take them out leaves the run where it is.
        past = self.later(run, node_restore.START_WINDOW + 1)
        self.assertEqual(node_restore.sweep(self.root, past), [])
        self.assertTrue((self.root / run).is_dir())
        # One that can does, and then the run goes with its key.
        self.fetching.refuse_revoke = False
        node_restore.sweep(self.root, past, fetch_access=self.fetching.access)
        self.assertEqual(self.fetching.held, {})
        self.assertFalse((self.root / run / "fetch-keys.json").exists())

    def test_a_run_that_died_is_swept_and_discarded_with_its_keys(self) -> None:
        for how in ("sweep", "discard"):
            with self.subTest(how=how):
                run = self.previewed()
                (self.root / run / "fetch-keys.json").write_text('{"cluster": "alpha"}')
                self.fetching.held[run] = ("alpha", "192.0.2.29", dict(FETCH_KEYS))
                if how == "sweep":
                    gone = node_restore.sweep(
                        self.root,
                        self.later(run, node_restore.START_WINDOW + 1),
                        fetch_access=self.fetching.access,
                    )
                    self.assertIn(run, gone)
                else:
                    node_restore.discard(self.root, run, fetch_access=self.fetching.access)
                self.assertEqual(self.fetching.held, {})
                self.assertFalse((self.root / run).exists())

    def test_a_discard_that_cannot_take_them_out_keeps_the_run(self) -> None:
        run = self.previewed()
        (self.root / run / "fetch-keys.json").write_text('{"cluster": "alpha"}')
        self.fetching.refuse_revoke = True

        with self.assertRaisesRegex(RestoreError, "could not be taken out"):
            node_restore.discard(self.root, run, fetch_access=self.fetching.access)
        self.assertTrue((self.root / run).is_dir())

    def test_a_restore_onto_a_new_vm_lets_nobody_in(self) -> None:
        run = self.previewed(test=False)

        result = self.carry_out(run, confirm="node-a")

        self.assertEqual(result["outcome"], "done", result)
        self.assertEqual(self.fetching.log, [])


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


class TheNeighbourCheckIsForAnyNumberOfNodes(unittest.TestCase):
    """A cluster of three joined its other two into one name no node has, so a healthy
    pair read as sick and the run asked for a tick that was not true."""

    @staticmethod
    def standing(sick: frozenset[str] = frozenset()) -> node_restore.Standing:
        names = ("node-a", "node-b", "node-c")

        def entry(name: str) -> dict[str, Any]:
            up = name not in sick
            return {
                "name": name,
                "status_ok": up,
                "reachable": up,
                "status": {"haproxy": {"active": up}, "keepalived": {"active": up}},
            }

        report = mock.Mock()
        report.result = {"nodes": [entry(name) for name in names]}
        cluster = SimpleNamespace(nodes=tuple(SimpleNamespace(name=n) for n in names), vip="x")
        policy = SimpleNamespace(status_identity=object())
        with (
            mock.patch.object(node_restore, "collect", return_value=report),
            mock.patch.object(
                node_restore,
                "parse_status",
                return_value=SimpleNamespace(
                    node=lambda name: SimpleNamespace(owns_vip=name == "node-a")
                ),
            ),
        ):
            checks = node_restore.overwrite_checks("alpha", cluster, policy)  # type: ignore[arg-type]
            return checks.standing("node-a")

    def test_two_healthy_neighbours_are_healthy(self) -> None:
        standing = self.standing()
        self.assertTrue(standing.neighbour_healthy, standing)
        self.assertEqual(standing.neighbour, "node-b, node-c")

    def test_one_sick_neighbour_leaves_the_other_to_take_the_vip(self) -> None:
        standing = self.standing(frozenset({"node-b"}))
        self.assertTrue(standing.neighbour_healthy, standing)
        self.assertEqual(standing.neighbour, "node-c")

    def test_no_healthy_neighbour_says_why_for_each(self) -> None:
        standing = self.standing(frozenset({"node-b", "node-c"}))
        self.assertFalse(standing.neighbour_healthy)
        self.assertIn("node-b: reachable False", standing.detail)
        self.assertIn("node-c: reachable False", standing.detail)


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

    def test_a_disk_error_is_said_as_the_helper_says_it(self) -> None:
        errors = io.StringIO()
        with mock.patch.object(
            node_restore, "status", side_effect=OSError(28, "No space left on device")
        ):
            code = cli.main(
                ["status", "--run", "r260101-0000aaaa"], error_stream=errors, require_root=False
            )
        self.assertEqual(code, 1)
        self.assertIn("the restore could not continue", errors.getvalue())

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


class KeyringToANewVm(Run):
    """B339: the node package depends on the key package; a new VM without the
    repository gets the release's, or the restore says why not before it writes."""

    def test_the_run_carries_it(self) -> None:
        self.assertEqual(self.preview(self.prepare())["problems"], [])
        run = self.previewed()
        self.carry_out(run)
        header, carried = FakeSession.calls[1][1], FakeSession.calls[1][2]
        assert self.keyring is not None
        self.assertEqual(
            header["keyring"], {"version": "2026.10.17", "sha256": self.keyring.sha256}
        )
        self.assertIn(
            f"/var/lib/haprion-restore/{run}/haprion-archive-keyring.deb", members(carried)
        )

    def test_a_release_without_it_stops_the_restore(self) -> None:
        self.keyring = None
        summary = self.preview(self.prepare())
        self.assertIn(
            "carries none; install the release with --keyring-package",
            " ".join(summary["problems"]),
        )


#
# A node installed from the project's repository (B339): the new VM gets the
# repository, and the engine and the key come from there, as new as it has them.
#
HAPRION_SOURCE = (
    "Types: deb\nURIs: https://haprion.github.io/haprion/\nSuites: deb13\n"
    "Components: main\nSigned-By: /usr/share/keyrings/haprion-archive-keyring.asc\n"
)


class FromTheRepository(Run):
    def setUp(self) -> None:
        super().setUp()
        _with_engine(self)
        archive = self.backups / "node-a" / f"{VERSION}.tar.gz"
        work = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, work)
        files = {**FILES, haprion_repository.SOURCE_PATH: (HAPRION_SOURCE, 0o644)}
        shutil.move(build(work, files=files, meta=ENGINE_VERSIONS), archive)

    def test_the_target_gets_the_repository_and_no_carried_engine_or_key(self) -> None:
        summary = self.preview(self.prepare())
        self.assertEqual(summary["problems"], [])
        self.assertNotIn("waf_engine", summary)
        run = self.previewed()
        self.carry_out(run)
        header, carried = FakeSession.calls[1][1], FakeSession.calls[1][2]
        self.assertIsNone(header["waf_engine"])
        self.assertIsNone(header["keyring"])
        written = members(carried)
        self.assertIn(haprion_repository.SOURCE_PATH, written)
        self.assertIn(haprion_repository.KEY_PATH, written)
        self.assertNotIn(f"/var/lib/haprion-restore/{run}/haprion-coraza-spoa.deb", written)

    def test_a_release_without_carried_packages_does_not_matter(self) -> None:
        self.engine = None
        self.keyring = None
        self.assertEqual(self.preview(self.prepare())["problems"], [])


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


class TheSessionReadsTheTargetsAnswerWithinABudget(unittest.TestCase):
    """Code review 26-10-22, 4-5: the restore target's answer is read as any node's."""

    def session(self, answer: str) -> node_restore.Session:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        ssh = root / "ssh"
        ssh.write_text(f"#!/bin/sh\ncat > {root}/request\necho 'working' >&2\n{answer}\n")
        ssh.chmod(0o755)
        self.request = root / "request"
        patcher = mock.patch.object(node_ssh, "SSH", str(ssh))
        patcher.start()
        self.addCleanup(patcher.stop)
        return node_restore.Session(key=root / "key", known_hosts=root / "known_hosts")

    def test_the_request_goes_out_and_the_last_line_comes_back(self) -> None:
        session = self.session("""echo '{"ok": true}'""")
        progress = io.StringIO()

        result = session.call("192.0.2.10", {"op": "probe"}, b"payload", progress=progress)

        self.assertEqual(result, {"ok": True})
        self.assertEqual(self.request.read_bytes(), b'{"op":"probe"}\npayload')
        self.assertIn("working", progress.getvalue())

    def test_a_document_nested_past_the_parser_is_no_answer(self) -> None:
        session = self.session("python3 -c 'print(\"[\" * 200000)'")

        with self.assertRaises(RestoreError):
            session.call("192.0.2.10", {"op": "probe"}, progress=io.StringIO())


if __name__ == "__main__":
    unittest.main()
