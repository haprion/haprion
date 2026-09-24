from __future__ import annotations

import io
import ipaddress
import os
import shutil
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from haproxy_mgmt import node_restore
from haproxy_mgmt.cli import node_restore as cli
from haproxy_mgmt.config import Node
from haproxy_mgmt.node_restore import Clock, Request, RestoreError
from haproxy_mgmt.restore_plan import TestProfile
from tests.restore_fixture import build

VERSION = "2026-01-01_04-00-00"
FINGERPRINT = "SHA256:" + "A" * 43
TARGET_KEY = "ssh-ed25519 AAAAtargetkey"
CLUSTER = SimpleNamespace(
    nodes=(Node("node-a", "192.0.2.21"), Node("node-b", "192.0.2.22")),
    certificate_ids=("cert-a",),
)
PROFILE = TestProfile(
    hostname="node-test",
    address=ipaddress.IPv4Interface("192.0.2.29/24"),
    vip=ipaddress.IPv4Interface("198.51.100.254/32"),
)

INSPECTED = {
    "ok": True,
    "op": "inspect",
    "os_release": {"ID": "ubuntu", "VERSION_ID": "26.04"},
    "hostname": "temp",
    "interface": {"name": "eth0", "mac": "02:00:00:00:00:99", "addresses": ["192.0.2.120/24"]},
    "host_keys": {"ed25519": FINGERPRINT},
    "accounts": {"operator": [1000, 1000]},
    "groups": {"operator": 1000},
    "previous_restore": False,
    "installed": [],
}


class FakeSession:
    calls: list[tuple[str, dict[str, Any], bytes]]
    answers: dict[str, dict[str, Any]]

    def __init__(self, key: Path, known_hosts: Path) -> None:
        self.key, self.known_hosts = key, known_hosts

    def call(
        self, address: str, header: dict[str, Any], payload: bytes = b"", **_: Any
    ) -> dict[str, Any]:
        FakeSession.calls.append((address, header, payload))
        return FakeSession.answers.get(header["op"], {"ok": True, "op": header["op"]})


def members(payload: bytes) -> list[str]:
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
        return ["/" + member.name for member in archive.getmembers()]


class RestoreTest(unittest.TestCase):
    def setUp(self) -> None:
        work = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, work)
        self.backups = work / "backups"
        (self.backups / "node-a").mkdir(parents=True)
        shutil.move(build(work), self.backups / "node-a" / f"{VERSION}.tar.gz")
        self.root = work / "runs"
        FakeSession.calls = []
        FakeSession.answers = {"inspect": dict(INSPECTED)}
        self.silent = {"192.0.2.29", "192.0.2.21"}

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

    def preview(self, run: str, fingerprint: str = FINGERPRINT) -> dict[str, Any]:
        return node_restore.preview(
            self.root,
            run,
            fingerprint,
            CLUSTER,  # type: ignore[arg-type]
            self.backups,
            scan=lambda _: TARGET_KEY,
            fingerprint_of=lambda key: FINGERPRINT if key == TARGET_KEY else "SHA256:other",
            answering=self.answering,
            progress=io.StringIO(),
            session_for=FakeSession,  # type: ignore[arg-type]
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
        prepared = node_restore.prepare(self.root, request, source_of=lambda _: "192.0.2.7")
        directory = self.root / "r260101-0000aaaa"
        self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
        self.assertEqual((directory / "key").stat().st_mode & 0o777, 0o600)
        self.assertIn('from="192.0.2.7",restrict ssh-ed25519 ', prepared["paste"])
        self.assertIn("ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub", prepared["paste"])
        # The line shows what landed: a paste that broke on the way in is seen at once.
        self.assertIn("sudo tail -n 1 /root/.ssh/authorized_keys", prepared["paste"])
        self.assertEqual(FakeSession.calls, [])

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

    def test_another_version_and_another_distribution_are_stopped(self) -> None:
        run = self.prepare()
        FakeSession.answers["inspect"]["os_release"] = {"ID": "ubuntu", "VERSION_ID": "26.10"}
        self.assertIn("another version", " ".join(self.preview(run)["problems"]))
        FakeSession.answers["inspect"]["os_release"] = {"ID": "debian", "VERSION_ID": "13"}
        self.assertIn("does not cross distributions", " ".join(self.preview(run)["problems"]))

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

    def test_a_uid_taken_on_the_target_is_a_problem(self) -> None:
        run = self.prepare()
        FakeSession.answers["inspect"]["accounts"] = {"other": [1000, 1000]}
        self.assertIn(
            "UID 1000 of operator belongs to other", " ".join(self.preview(run)["problems"])
        )


class Run(RestoreTest):
    def previewed(self, *, test: bool = True) -> str:
        run = self.prepare(test=test)
        self.preview(run)
        FakeSession.calls = []
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

    def test_the_apply_header_carries_hashes_but_the_result_file_does_not(self) -> None:
        run = self.previewed()
        self.carry_out(run)
        header = FakeSession.calls[1][1]
        operator = next(a for a in header["accounts"] if a["name"] == "operator")
        self.assertTrue(operator["password_hash"].startswith("$y$"))
        self.assertEqual(header["logread_group"], "haproxy-logread")
        self.assertNotIn("$y$", (self.root / run / "result.json").read_text())

    def test_a_change_after_the_preview_refuses_before_writing(self) -> None:
        run = self.previewed()
        FakeSession.answers["inspect"]["interface"] = dict(
            INSPECTED["interface"],
            mac="02:00:00:00:00:98",  # type: ignore[arg-type]
        )
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
        code = cli.main(["forget", "--run", "r260101-0000aaaa"], error_stream=errors)
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
