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


class TheOneTimeKeyOutlivesAnUpgrade(unittest.TestCase):
    """Review 26-10-24, 10-03: every configure made a new one-time key, so an
    upgrade ended a block the operator had copied, and nothing said so."""

    KEY_SCRIPT = BASE / "install" / "node" / "haprion-node-key"

    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root)
        self.key = self.root / "join_key"
        self.keys = self.root / "authorized_keys"
        subprocess.run(
            ["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.key)],
            check=True,
        )
        text = self.KEY_SCRIPT.read_text()
        start = text.index("join_key_expiry() {")
        end = text.index("\n}\n", text.index("join_key_current() {")) + 3
        self.functions = text[start:end]

    def current(self, expires: str | None) -> bool:
        public = " ".join(self.key.with_suffix(".pub").read_text().split()[:2])
        self.keys.write_text(
            ""
            if expires is None
            else f'restrict,expiry-time="{expires}Z",command="sudo -n /usr/sbin/haprion-node-join" '
            f"{public}\n"
        )
        done = subprocess.run(
            ["/bin/bash", "-c", f"set -Eeuo pipefail\n{self.functions}join_key_current"],
            env={**os.environ, "JOIN_KEY": str(self.key), "JOIN_KEYS": str(self.keys)},
            check=False,
        )
        return done.returncode == 0

    def test_an_unused_key_that_has_not_expired_is_kept(self) -> None:
        self.assertTrue(self.current("209901010000"))

    def test_a_used_or_expired_key_is_not(self) -> None:
        self.assertFalse(self.current(None))
        self.assertFalse(self.current("202001010000"))

    def test_a_new_key_is_made_only_when_there_is_none_to_keep(self) -> None:
        text = self.KEY_SCRIPT.read_text()
        keep = text.index('if [[ "$MODE" != --again ]] && join_key_current; then')
        self.assertLess(keep, text.index('rm -f "$JOIN_KEY" "${JOIN_KEY}.pub"'))
        self.assertLess(keep, text.index("ssh-keygen -t ed25519"))


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

    def test_the_address_the_manager_came_in_on_is_an_answer(self) -> None:
        text, _ = JOIN.answers(document(), "198.51.100.5", "192.0.2.21")
        self.assertIn("NODE_LISTEN_ADDRESS='192.0.2.21'", text.splitlines())
        text, _ = JOIN.answers(document(), "198.51.100.5")
        self.assertNotIn("NODE_LISTEN_ADDRESS", text)

    def test_the_collector_s_key_is_an_answer_like_the_others(self) -> None:
        keys = {"deploy": KEY, "status": OTHER, "traffic_log": OTHER}
        text, _ = JOIN.answers(document(keys=keys), "198.51.100.5")
        self.assertIn(f"TRAFFIC_LOG_PUBKEY='{OTHER}'", text.splitlines())

    def test_the_answers_source_back_as_they_were_sent(self) -> None:
        text, _ = JOIN.answers(document(), "198.51.100.5")
        with tempfile.TemporaryDirectory() as raw:
            answers = Path(raw) / "join.env"
            answers.write_text(text)
            done = subprocess.run(  # sourcing the file under test
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


class TheKeyScriptSaysWhatIsTrue(unittest.TestCase):
    """Review 26-10-30, E7 and E8: joined means joined; a bad host name is said at once."""

    KEY_SCRIPT = BASE / "install" / "node" / "haprion-node-key"

    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root)
        text = self.KEY_SCRIPT.read_text()
        start = text.index("join_key_expiry() {")
        end = text.index("\n}\n", text.index("join_key_current() {")) + 3
        names = text.index("NODE_NAME_PATTERN=")
        names_end = text.index("\n}\n", text.index("node_names() {")) + 3
        self.functions = (
            text[start:end]
            + text[
                text.index("node_state() {") : text.index("\n}\n", text.index("node_state() {")) + 3
            ]
            + text[names:names_end]
        )
        self.conf = self.root / "node.conf"
        self.key = self.root / "join_key"
        self.mark = self.root / "joined"
        self.keys = self.root / "authorized_keys"
        self.bin = self.root / "bin"
        self.bin.mkdir()

    def run_function(self, call: str, **env: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # functions from the script under test
            ["/bin/bash", "-c", f"set -Eeuo pipefail\n{self.functions}{call}"],
            env={
                **os.environ,
                "PATH": f"{self.bin}:{os.environ['PATH']}",
                "NODE_CONF": str(self.conf),
                "JOIN_KEY": str(self.key),
                "JOIN_KEYS": str(self.keys),
                "JOIN_MARK": str(self.mark),
                "MODE": "",
                **env,
            },
            capture_output=True,
            text=True,
            check=False,
        )

    def hostnames(self, short: str, full: str | None) -> None:
        fake = self.bin / "hostname"
        fake.write_text(
            "#!/bin/sh\n"
            + (f'[ "$1" = -f ] && echo {full} && exit 0\n' if full else '[ "$1" = -f ] && exit 1\n')
            + f"echo {short}\n"
        )
        fake.chmod(0o755)

    def test_a_node_with_a_conf_and_the_joined_mark_is_joined(self) -> None:
        self.conf.write_text('CLUSTER="alpha"\n')
        self.mark.touch()
        self.assertEqual(self.run_function("node_state").stdout.strip(), "joined")

    def test_the_mark_outlives_a_one_time_key_that_has_gone_stale(self) -> None:
        """Review 26-10-30, R2: a node prepared by hand keeps the key its package made."""

        self.conf.write_text('CLUSTER="alpha"\n')
        self.mark.touch()
        self.key.write_text("private")
        self.key.with_suffix(".pub").write_text("ssh-ed25519 AAAA x")
        self.keys.write_text("")
        self.assertEqual(self.run_function("node_state").stdout.strip(), "joined")

    def test_a_node_with_a_conf_and_no_mark_is_unfinished(self) -> None:
        self.conf.write_text('CLUSTER="alpha"\n')
        self.assertEqual(self.run_function("node_state").stdout.strip(), "unfinished")
        self.key.write_text("private")
        self.key.with_suffix(".pub").write_text("ssh-ed25519 AAAA x")
        self.keys.write_text("")
        self.assertEqual(self.run_function("node_state").stdout.strip(), "unfinished")

    def test_a_node_without_a_conf_or_asked_again_gets_a_block(self) -> None:
        self.assertEqual(self.run_function("node_state").stdout.strip(), "fresh")
        self.conf.write_text('CLUSTER="alpha"\n')
        self.assertEqual(self.run_function("node_state", MODE="--again").stdout.strip(), "fresh")

    def test_the_text_for_an_unfinished_node_does_not_say_joined(self) -> None:
        text = self.KEY_SCRIPT.read_text()
        unfinished = text[
            text.index("    unfinished)") : text.index("esac", text.index("    unfinished)"))
        ]
        self.assertNotIn("is joined", unfinished)
        self.assertIn("no manager has completed a", unfinished)

    def test_a_hostname_that_fails_falls_back_to_the_short_name(self) -> None:
        self.hostnames("node-a", None)
        done = self.run_function('node_names; echo "$NODE_NAME $NODE_HOST"')
        self.assertEqual((done.returncode, done.stdout.strip()), (0, "node-a node-a"))

    def test_a_host_name_that_is_not_a_node_name_is_refused(self) -> None:
        for short in ("Node-A", "1node", "node_a"):
            with self.subTest(short=short):
                self.hostnames(short, f"{short}.example.com")
                self.assertNotEqual(self.run_function("node_names").returncode, 0)

    def test_the_refusal_says_what_to_do(self) -> None:
        text = self.KEY_SCRIPT.read_text()
        self.assertIn("hostnamectl set-hostname", text)
        self.assertIn("lowercase letters, digits and hyphens", text)

    def test_both_scripts_fall_back_when_hostname_f_fails(self) -> None:
        prepare = (BASE / "install" / "04-node-prepare").read_text()
        self.assertIn("hostname -f 2>/dev/null || hostname", prepare)
        self.assertNotIn("$(hostname -f)", prepare)
        self.assertNotIn("$(hostname -f)", self.KEY_SCRIPT.read_text())


class TheArrivalAddress(unittest.TestCase):
    def test_it_is_the_connection_s_third_field(self) -> None:
        with mock.patch.dict(os.environ, {"SSH_CONNECTION": "198.51.100.5 50022 192.0.2.21 22"}):
            self.assertEqual(JOIN.arrival_address(), "192.0.2.21")
        for value in (
            "",
            "198.51.100.5 50022 192.0.2.21",
            "198.51.100.5 1 2001:db8::21 22",
            "a 1 b 2",
        ):
            with (
                self.subTest(value=value),
                mock.patch.dict(os.environ, {"SSH_CONNECTION": value}),
                self.assertRaises(JOIN.Refused),
            ):
                JOIN.arrival_address()


class TheHandPreparedNodeIsMarkedJoined(unittest.TestCase):
    """Review 26-10-30, R2: step 4 by hand leaves the mark the join leaves."""

    STEP = BASE / "install" / "04-node-prepare"

    def test_the_mark_is_a_private_file_in_the_join_directory(self) -> None:
        import re

        text = self.STEP.read_text()
        found = re.search(r"^mark_joined\(\) \{\n.*?^\}\n", text, re.MULTILINE | re.DOTALL)
        assert found is not None, "04-node-prepare has no mark_joined"
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw) / "lib"
            done = subprocess.run(  # the function from the script under test
                ["/bin/bash", "-c", f"set -Eeuo pipefail\n{found.group(0)}mark_joined"],
                env={**os.environ, "JOIN_DIR": str(directory)},
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertEqual(oct((directory / "joined").stat().st_mode & 0o777), "0o600")
            self.assertEqual(oct(directory.stat().st_mode & 0o777), "0o700")

    def test_only_the_hand_branch_runs_it(self) -> None:
        text = self.STEP.read_text()
        call = text.index("\nmark_joined\n")
        self.assertGreater(call, text.index('PREPARED_AGAIN:-}" == yes ]]; then\n    echo'))
        self.assertGreater(call, text.index('step "Enrollment block"'))
        self.assertLess(call, text.index('log "This node is prepared."'))


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
        self.assertTrue((self.join_dir / "joined").is_file())
        self.assertEqual(oct((self.join_dir / "join.env").stat().st_mode & 0o777), "0o600")
        log = (self.root / "log" / "join.log").read_text()
        self.assertIn(f"step 4 {self.join_dir / 'join.env'} edge-a", log)

    def test_a_stopped_step_keeps_the_key_and_says_why(self) -> None:
        code, out, err = self.run_join(3)
        self.assertEqual(code, 75)
        self.assertEqual(out, "")
        self.assertIn("preparing this node stopped (exit 3)", err)
        self.assertIn("haprion-node-join", self.keys.read_text())
        self.assertTrue((self.join_dir / "join_key").exists())
        self.assertFalse((self.join_dir / "joined").exists())


if __name__ == "__main__":
    unittest.main()
