"""haprion-node-join: the manager's one join of a new node (B317).

Held here: the document is the manager's only input, and every value in it
passes the pattern its use needs before it becomes an answer step 4 sources;
the manager is reached at the address it connected from, IPv4 only; the
one-time key is removed when step 4 has finished and kept when it stopped,
so the same block may be tried again.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
SCRIPT = BASE / "install" / "node" / "haprion-node-join"
KEY = "ssh-ed25519 " + "A" * 68
OTHER = "ssh-ed25519 " + "B" * 68


def load() -> ModuleType:
    loader = importlib.machinery.SourceFileLoader("haprion_node_join", str(SCRIPT))
    spec = importlib.util.spec_from_loader("haprion_node_join", loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


JOIN = load()


def document(**changes: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "version": 1,
        "cluster": "edge-a",
        "node_path": "edge_a",
        "vip": "192.0.2.10",
        "manager_host_key": KEY,
        "keys": {"deploy": KEY, "status": OTHER, "server_state": KEY},
    }
    base.update(changes)
    return base


class TheDocument(unittest.TestCase):
    def test_a_good_document_is_step_four_s_answers(self) -> None:
        text, cluster = JOIN.answers(document(), "198.51.100.5")
        self.assertEqual(cluster, "edge-a")
        self.assertEqual(
            text.splitlines(),
            [
                "MANAGER_HOST='198.51.100.5'",
                f"MANAGER_HOST_KEY='{KEY}'",
                "NODE_CONFIG_PULL_KEY=/root/.ssh/id_ed25519_config_pull",
                "NODE_CERT_PULL_KEY=/root/.ssh/id_ed25519_cert_pull",
                "NODE_PATH_edge_a='edge_a'",
                "VIP_edge_a='192.0.2.10'",
                "JOINED_BY_MANAGER=yes",
                f"DEPLOY_PUBKEY='{KEY}'",
                f"SERVER_STATE_PUBKEY='{KEY}'",
                f"STATUS_PUBKEY='{OTHER}'",
            ],
        )

    def test_the_collector_s_key_is_an_answer_like_the_others(self) -> None:
        keys = {"deploy": KEY, "status": OTHER, "traffic_log": OTHER}
        text, _ = JOIN.answers(document(keys=keys), "198.51.100.5")
        self.assertIn(f"TRAFFIC_LOG_PUBKEY='{OTHER}'", text.splitlines())

    def test_the_answers_source_back_as_they_were_sent(self) -> None:
        text, _ = JOIN.answers(document(), "198.51.100.5")
        with tempfile.TemporaryDirectory() as raw:
            answers = Path(raw) / "join.env"
            answers.write_text(text)
            done = subprocess.run(  # noqa: S603 - sourcing the file under test
                [
                    "/bin/bash",
                    "-c",
                    'source "$1"; printf %s "$VIP_edge_a|$STATUS_PUBKEY"',
                    "-",
                    answers,
                ],
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertEqual(done.stdout, f"192.0.2.10|{OTHER}")

    def test_anything_else_is_refused(self) -> None:
        refused: tuple[object, ...] = (
            [],
            document(version=2),
            document(extra=1),
            document(cluster="Edge"),
            document(cluster="a'; rm -rf /; '"),
            document(node_path="../x"),
            document(vip="2001:db8::1"),
            document(vip="192.0.2.10'"),
            document(manager_host_key=KEY + " comment"),
            document(keys={"deploy": KEY}),
            document(keys={"deploy": KEY, "status": KEY, "shell": KEY}),
            document(keys={"deploy": KEY, "status": "ssh-rsa " + "A" * 68}),
            document(keys={"deploy": KEY, "status": KEY + "'"}),
        )
        for bad in refused:
            with self.subTest(document=bad), self.assertRaises(JOIN.Refused):
                JOIN.answers(bad, "198.51.100.5")

    def test_the_manager_is_where_the_connection_came_from(self) -> None:
        with mock.patch.dict(os.environ, {"SSH_CONNECTION": "198.51.100.5 50022 192.0.2.21 22"}):
            self.assertEqual(JOIN.manager_address(), "198.51.100.5")
        for value in (
            "",
            "198.51.100.5 50022 192.0.2.21",
            "2001:db8::5 1 2001:db8::21 22",
            "x 1 y 2",
        ):
            with (
                self.subTest(value=value),
                mock.patch.dict(os.environ, {"SSH_CONNECTION": value}),
                self.assertRaises(JOIN.Refused),
            ):
                JOIN.manager_address()


class TheJoin(unittest.TestCase):
    """main() with a step 4 and a status that are stand-ins, as root."""

    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="join-"))
        self.addCleanup(shutil.rmtree, self.root, True)
        install = self.root / "install"
        install.mkdir()
        self.step = install / "04-node-prepare"
        self.join_dir = self.root / "lib"
        self.join_dir.mkdir()
        (self.join_dir / "join_key").write_text("private")
        (self.join_dir / "join_key.pub").write_text(KEY)
        self.keys = self.root / "authorized_keys"
        self.keys.write_text(f'restrict,command="sudo -n /usr/sbin/haprion-node-join" {KEY}\n')
        status = self.root / "status"
        status.write_text('#!/bin/sh\necho \'{"node": "node-a"}\'\n')
        status.chmod(0o755)
        patches: list[Any] = [
            mock.patch.object(JOIN, "INSTALL", install),
            mock.patch.object(JOIN, "JOIN_DIR", self.join_dir),
            mock.patch.object(JOIN, "JOIN_KEYS", self.keys),
            mock.patch.object(JOIN, "LOG", self.root / "log" / "join.log"),
            mock.patch.object(JOIN, "STATUS", str(status)),
            mock.patch.object(JOIN.os, "geteuid", return_value=0),
            mock.patch.dict(os.environ, {"SSH_CONNECTION": "198.51.100.5 50022 192.0.2.21 22"}),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

    def run_join(self, exit_code: int) -> tuple[int, str, str]:
        self.step.write_text(f'#!/bin/sh\necho "step 4 $1 $2"\nexit {exit_code}\n')
        self.step.chmod(0o755)
        stdin = io.TextIOWrapper(io.BytesIO(json.dumps(document()).encode()))
        raw_out = io.BytesIO()
        stdout, stderr = io.TextIOWrapper(raw_out), io.StringIO()
        with (
            mock.patch.object(JOIN.sys, "stdin", stdin),
            mock.patch.object(JOIN.sys, "stdout", stdout),
            mock.patch.object(JOIN.sys, "stderr", stderr),
        ):
            code = JOIN.main()
            stdout.flush()
            out = raw_out.getvalue().decode()
        return code, out, stderr.getvalue()

    def test_a_finished_step_uses_up_the_key_and_answers_with_the_status(self) -> None:
        code, out, _ = self.run_join(0)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out), {"node": "node-a"})
        self.assertEqual(self.keys.read_text(), "")
        self.assertFalse((self.join_dir / "join_key").exists())
        self.assertEqual(oct((self.join_dir / "join.env").stat().st_mode & 0o777), "0o600")
        log = (self.root / "log" / "join.log").read_text()
        self.assertIn(f"step 4 {self.join_dir / 'join.env'} edge-a", log)

    def test_a_stopped_step_keeps_the_key_and_says_why(self) -> None:
        code, out, err = self.run_join(3)
        self.assertEqual(code, 75)
        self.assertEqual(out, "")
        self.assertIn("step 4 stopped (exit 3)", err)
        self.assertIn("haprion-node-join", self.keys.read_text())
        self.assertTrue((self.join_dir / "join_key").exists())


if __name__ == "__main__":
    unittest.main()
