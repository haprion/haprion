"""examples/proxmox-node-rebuild: the example's steps against a fake Proxmox and a fake restore (26-11-03)."""

from __future__ import annotations

import importlib.util
import io
import json
import subprocess
import sys
import tempfile
import unittest
from collections.abc import Mapping, Sequence
from pathlib import Path
from types import ModuleType
from typing import Any

EXAMPLE = Path(__file__).resolve().parents[1] / "examples/proxmox-node-rebuild"
FINGERPRINT = "SHA256:" + "A" * 43


def load() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "proxmox_node_rebuild", EXAMPLE / "proxmox_node_rebuild.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["proxmox_node_rebuild"] = module
    spec.loader.exec_module(module)
    return module


rebuild = load()

SETTINGS = """\
PVE_API_HOSTS="pve-a.example.net"
PVE_TOKEN_FILE={token}
PVE_TEMPLATE_VMID=9000
PVE_STORAGE=vm-storage
PVE_POOL=node-rebuild
VM_CORES=1
VM_MEMORY_MB=2048
NAMESERVER=192.0.2.53
SEARCHDOMAIN=example.net
CLUSTER_ALPHA_BRIDGE=vmbr10
CLUSTER_ALPHA_GATEWAY=192.0.2.1
CLUSTER_ALPHA_TEMPORARY_ADDRESS=192.0.2.29/24
CLUSTER_ALPHA_TEST_ADDRESS=192.0.2.30/24
NODE_LB_01_CLUSTER=alpha
NODE_LB_01_VMID=801
TEST_VMID=899
TEST_VIP=203.0.113.254/32
"""
GRANTED = {
    "/pool/node-rebuild": {name: 1 for name in rebuild.POOL_PRIVILEGES},
    "/vms/9000": {"VM.Clone": 1},
    "/storage/vm-storage": {"Datastore.AllocateSpace": 1},
}


class FakeProxmox:
    """The calls the example makes, answered as Proxmox VE 9 answers them."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, Any]] = []
        self.vms: list[dict[str, Any]] = [
            {"vmid": 9000, "node": "pve-a", "template": 1, "name": "template"}
        ]
        self.granted: dict[str, dict[str, int]] = {k: dict(v) for k, v in GRANTED.items()}
        self.config: dict[str, Any] = {}
        self.scripts: list[str] = []
        self.exec_answers: list[tuple[int, str]] = []
        self.pings_failing = 0

    def __call__(self, method: str, path: str, data: Mapping[str, Any] | None) -> Any:
        self.calls.append((method, path, None if data is None else dict(data)))
        if path == "/version":
            return {"version": "9.2.21"}
        if path == "/cluster/resources":
            return self.vms
        if path == "/access/permissions":
            assert data is not None
            wanted = str(data["path"])
            return {wanted: self.granted.get(wanted, {})}
        if path.endswith("/clone"):
            assert data is not None
            self.vms.append({"vmid": data["newid"], "node": "pve-a", "template": 0})
            self.config = {
                "net0": "virtio=02:00:00:00:00:01,bridge=vmbr0,firewall=1",
                "ide2": "vm-storage:vm-801-cloudinit,media=cdrom",
                "ipconfig0": "ip=dhcp",
            }
            return "UPID:pve-a:clone"
        if path.endswith("/config") and method == "GET":
            return dict(self.config)
        if path.endswith("/config") and method == "PUT":
            assert data is not None
            for key in str(data.get("delete", "")).split(","):
                self.config.pop(key, None)
            self.config.update({k: v for k, v in data.items() if k != "delete"})
            return None
        if "/tasks/" in path:
            return {"status": "stopped", "exitstatus": "OK"}
        if path.endswith(("/status/start", "/status/shutdown")):
            return f"UPID:pve-a:{path.rsplit('/', 1)[-1]}"
        if path.endswith("/agent/ping"):
            if self.pings_failing:
                self.pings_failing -= 1
                raise rebuild.Stop("500 QEMU guest agent is not running")
            return None
        if path.endswith("/agent/exec"):
            assert data is not None
            self.scripts.append(str(data["input-data"]))
            return {"pid": len(self.scripts)}
        if path.endswith("/agent/exec-status"):
            code, out = self.exec_answers.pop(0) if self.exec_answers else (0, "")
            return {"exited": 1, "exitcode": code, "out-data": out}
        raise AssertionError(f"unexpected call {method} {path}")

    def changes(self) -> list[tuple[str, str]]:
        return [(m, p) for m, p, _ in self.calls if m in {"POST", "PUT"}]


class FakeRestore:
    """haprion-node-restore and haprion-list-backups, answering as 0.99.13 does."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.preview_code = 0

    def __call__(self, argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
        argv = list(argv)
        self.calls.append(argv)
        out, code = "", 0
        if argv[0] == "haprion-list-backups":
            out = json.dumps(
                {"result": {"nodes": [{"name": "lb-01", "latest_version": "2026-11-03_21-50-55"}]}}
            )
        elif argv[1] == "prepare":
            out = json.dumps(
                {
                    "run": "r261103-0000aaaa",
                    "paste": "echo 'key' | sudo sh -c 'cat >> /root/.ssh/authorized_keys'",
                    "from": "192.0.2.7",
                }
            )
        elif argv[1] == "preview":
            out, code = "Run r261103-0000aaaa\n  mode new_vm\n", self.preview_code
        elif argv[1] == "run":
            out = "=== restore r261103-0000aaaa: done ===\n"
        elif argv[1] == "status":
            out = json.dumps(
                {
                    "run": "r261103-0000aaaa",
                    "state": "finished",
                    "outcome": "done",
                    "result": {"address": "192.0.2.21", "hostname": "lb-01"},
                }
            )
        return subprocess.CompletedProcess(argv, code, out, "")


class ExampleTestCase(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        token = root / "token.env"
        token.write_text("PVE_API_TOKEN_ID=rebuild@pve!manager\nPVE_API_TOKEN_SECRET=x\n")
        self.settings = root / "settings.env"
        self.settings.write_text(SETTINGS.format(token=token))
        self.api = FakeProxmox()
        self.restore = FakeRestore()
        self.typed = "lb-01"
        self.answered: list[str] = []

    def main(self, *argv: str) -> tuple[int, str]:
        out = io.StringIO()
        code = rebuild.main(
            ["--settings", str(self.settings), *argv],
            out=out,
            call=self.api,
            runner=self.restore,
            ask=lambda _prompt: self.typed,
            answering=self.answer,
            sleep=lambda _seconds: None,
        )
        return code, out.getvalue()

    def answer(self, address: str) -> bool:
        self.answered.append(address)
        return True

    def steps(self) -> list[str]:
        return [argv[1] for argv in self.restore.calls if argv[0] == "haprion-node-restore"]


class Check(ExampleTestCase):
    def test_check_changes_nothing(self) -> None:
        self.api.exec_answers = []
        code, out = self.main("check", "lb-01")
        self.assertEqual(code, 0, out)
        self.assertIn("check: OK, nothing was changed", out)
        self.assertEqual(self.api.changes(), [])
        self.assertEqual(self.steps(), [])

    def test_a_taken_vmid_is_refused_before_a_clone(self) -> None:
        self.api.vms.append({"vmid": 801, "node": "pve-a", "template": 0})
        code, out = self.main("run", "lb-01")
        self.assertEqual(code, 1)
        self.assertIn("VMID 801 is taken", out)
        self.assertEqual(self.api.changes(), [])

    def test_a_missing_privilege_is_named(self) -> None:
        del self.api.granted["/pool/node-rebuild"]["VM.GuestAgent.Unrestricted"]
        code, out = self.main("check", "lb-01")
        self.assertEqual(code, 1)
        self.assertIn("lacks VM.GuestAgent.Unrestricted on /pool/node-rebuild", out)

    def test_settings_are_read_not_guessed(self) -> None:
        text = self.settings.read_text()
        for broken, said in (
            ("CLUSTER_ALPHA_TEMPORARY_ADDRESS=192.0.2.29\n", "needs its prefix"),
            ("NODE_LB_01_CLUSTER=\n", "no NODE_LB_01_CLUSTER"),
            ("this is not a setting\n", "is not KEY=value"),
        ):
            with self.subTest(said=said):
                key = broken.split("=", 1)[0]
                lines = [
                    ln for ln in text.splitlines(keepends=True) if not ln.startswith(key + "=")
                ]
                self.settings.write_text("".join(lines) + broken)
                code, out = self.main("check", "lb-01")
                self.assertEqual(code, 1)
                self.assertIn(said, out)


class Run(ExampleTestCase):
    def test_the_whole_rebuild_in_order(self) -> None:
        self.api.exec_answers = [(0, ""), (0, f"key line\n256 {FINGERPRINT} root@vm (ED25519)\n")]
        code, out = self.main("run", "lb-01")
        self.assertEqual(code, 0, out)
        self.assertEqual(self.steps(), ["prepare", "preview", "run", "status"])
        preview = next(argv for argv in self.restore.calls if argv[1:2] == ["preview"])
        self.assertEqual(preview[-1], FINGERPRINT)
        prepare = next(argv for argv in self.restore.calls if argv[1:2] == ["prepare"])
        self.assertEqual(prepare[prepare.index("--target") + 1], "192.0.2.29")
        self.assertNotIn("--test", prepare)
        clone = next(data for m, p, data in self.api.calls if p.endswith("/clone"))
        self.assertEqual(
            (clone["newid"], clone["name"], clone["pool"], clone["full"]),
            (801, "lb-01", "node-rebuild", 1),
        )
        first_put = next(data for m, p, data in self.api.calls if m == "PUT")
        self.assertEqual(first_put["net0"], "virtio=02:00:00:00:00:01,firewall=1,bridge=vmbr10")
        self.assertEqual(first_put["ipconfig0"], "ip=192.0.2.29/24,gw=192.0.2.1")
        # The pasted line ran in the guest, and cloud-init was switched off after the run.
        self.assertIn("authorized_keys", self.api.scripts[1])
        self.assertIn("cloud-init.disabled", self.api.scripts[2])
        self.assertNotIn("ide2", self.api.config)
        self.assertNotIn("ipconfig0", self.api.config)
        self.assertEqual(self.answered, ["192.0.2.21"])
        self.assertIn("done: VM 801 is lb-01", out)

    def test_the_agent_is_waited_for(self) -> None:
        self.api.pings_failing = 3
        self.api.exec_answers = [(0, ""), (0, f"256 {FINGERPRINT} root@vm (ED25519)\n")]
        code, out = self.main("run", "lb-01")
        self.assertEqual(code, 0, out)

    def test_nothing_is_restored_unless_the_name_is_typed(self) -> None:
        self.typed = "yes"
        self.api.exec_answers = [(0, ""), (0, f"256 {FINGERPRINT} root@vm (ED25519)\n")]
        code, out = self.main("run", "lb-01")
        self.assertEqual(code, 1)
        self.assertEqual(self.steps(), ["prepare", "preview", "discard"])
        self.assertIn("not confirmed", out)

    def test_a_refused_preview_discards_the_run(self) -> None:
        self.restore.preview_code = 1
        self.api.exec_answers = [(0, ""), (0, f"256 {FINGERPRINT} root@vm (ED25519)\n")]
        code, _ = self.main("run", "lb-01")
        self.assertEqual(code, 1)
        self.assertEqual(self.steps(), ["prepare", "preview", "discard"])

    def test_a_line_without_one_fingerprint_stops_before_the_preview(self) -> None:
        self.api.exec_answers = [(0, ""), (0, "sudo: a password is required\n")]
        code, _ = self.main("run", "lb-01")
        self.assertEqual(code, 1)
        self.assertEqual(self.steps(), ["prepare", "discard"])

    def test_a_test_rebuild_is_the_product_s_test_mode(self) -> None:
        self.typed = "restoretest-lb-01"
        self.api.exec_answers = [(0, ""), (0, f"256 {FINGERPRINT} root@vm (ED25519)\n")]
        code, out = self.main("run", "lb-01", "--test")
        self.assertEqual(code, 0, out)
        prepare = next(argv for argv in self.restore.calls if argv[1:2] == ["prepare"])
        self.assertEqual(
            prepare[prepare.index("--test") :],
            [
                "--test",
                "--test-hostname",
                "restoretest-lb-01",
                "--test-address",
                "192.0.2.30/24",
                "--test-vip",
                "203.0.113.254/32",
                "--json",
            ],
        )
        clone = next(data for m, p, data in self.api.calls if p.endswith("/clone"))
        self.assertEqual(clone["newid"], 899)
        run = next(argv for argv in self.restore.calls if argv[1:2] == ["run"])
        self.assertEqual(run[-1], "restoretest-lb-01")


class TheExampleShipsNoRealValues(unittest.TestCase):
    def test_the_settings_example_uses_documentation_addresses(self) -> None:
        values = rebuild.read_env(EXAMPLE / "settings.env.example")
        for key, value in values.items():
            for word in value.replace(",", " ").split():
                if word[:1].isdigit() and "." in word:
                    with self.subTest(key=key):
                        self.assertRegex(
                            word, r"^(192\.0\.2|198\.51\.100|203\.0\.113)\.\d+(/\d+)?$"
                        )


if __name__ == "__main__":
    unittest.main()
