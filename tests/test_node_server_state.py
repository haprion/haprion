"""The node's server state helper against a real HAProxy (Fas 20, B263).

`install/node/haproxy-server-state` is loaded from the file the node bundle
installs and pointed at a scratch directory: its own admin socket, state file,
lock and configuration, and a `systemctl` that reloads the way the packaged
unit does - SIGUSR2 to the master. HAProxy is the one on this machine, the
same 3.4 the nodes run, so what the helper is tested against is HAProxy's
answer and not a stand-in for it.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import io
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any

BASE = Path(__file__).resolve().parents[1]
HELPER = BASE / "install" / "node" / "haproxy-server-state"
TRIGGER = BASE / "install" / "node" / "haproxy-server-state-trigger"
HAPROXY = shutil.which("haproxy") or ""

WEB_A = "srv:shop.1111111111111111"
WEB_B = "srv:shop.2222222222222222"
API = "srv:api.3333333333333333"


def load_helper() -> Any:
    #
    # No bytecode: the file sits in install/node, which the node bundle ships,
    # and a __pycache__ beside it is not a node script.
    #
    sys.dont_write_bytecode = True
    loader = importlib.machinery.SourceFileLoader("haproxy_server_state", str(HELPER))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def configuration(root: Path, servers: list[tuple[str, str, int]], *, socket: bool = True) -> str:
    """A generated-looking configuration: backends with GUIDs on their servers."""

    stats = f"    stats socket {root}/manager.sock mode 600 level admin\n" if socket else ""
    lines = [
        "global",
        stats.rstrip("\n"),
        "defaults",
        "    mode http",
        "    timeout connect 2s",
        "    timeout client 5s",
        "    timeout server 5s",
        "frontend fe",
        "    bind 127.0.0.1:18580",
        "    default_backend mgd-shop-web",
        "backend mgd-shop-web",
    ]
    for index, (guid, host, port) in enumerate(servers, start=1):
        lines.append(f"    server s{index} {host}:{port} guid {guid}")
    lines += ["backend mgd-api", f"    server s1 127.0.0.1:18583 guid {API}"]
    return "\n".join(line for line in lines if line) + "\n"


@unittest.skipUnless(HAPROXY, "haproxy is not installed where the tests run")
class TheHelperKeepsAServerWhereItWasPut(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="srvstate-"))
        self.addCleanup(shutil.rmtree, self.root, True)
        (self.root / "conf.d").mkdir()
        self.config = self.root / "haproxy.cfg"
        self.write([(WEB_A, "127.0.0.1", 18581), (WEB_B, "127.0.0.1", 18582)])
        self.helper = load_helper()
        systemctl = self.root / "systemctl"
        systemctl.write_text(f'#!/bin/sh\nkill -USR2 "$(head -1 {self.root}/pid)"\n')
        systemctl.chmod(0o755)
        for name, value in (
            ("ADMIN_SOCKET", str(self.root / "manager.sock")),
            ("STATE_FILE", self.root / "state" / "server-state.json"),
            ("LOCK_FILE", str(self.root / "lock")),
            ("CONFIG", self.config),
            ("CONFIG_DIR", self.root / "conf.d"),
            ("CONFIG_PENDING", self.root / "pending"),
            ("SYSTEMCTL", str(systemctl)),
        ):
            setattr(self.helper, name, value)
        self.process = subprocess.Popen(  # noqa: S603 - fixed binary, scratch configuration
            [HAPROXY, "-W", "-f", str(self.config), "-p", str(self.root / "pid")],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.addCleanup(self.stop)
        self.wait_for_socket()

    def stop(self) -> None:
        #
        # A master still draining an old worker can outlast ten seconds on a
        # loaded gate (2026-10-09); what this cleans up is a scratch process.
        #
        self.process.send_signal(signal.SIGTERM)
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=10)

    def write(self, servers: list[tuple[str, str, int]], *, socket: bool = True) -> None:
        self.config.write_text(configuration(self.root, servers, socket=socket))

    def wait_for_socket(self) -> None:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                if "Pid:" in self.helper.ask(["show info"]):
                    return
            except self.helper.Unavailable:
                pass
            time.sleep(0.05)
        self.fail("HAProxy did not answer on the admin socket")

    def run_helper(self, *argv: str) -> tuple[int, str]:
        out = io.StringIO()
        with redirect_stdout(out):
            code = self.helper.main(list(argv))
        return code, out.getvalue()

    def state_of(self, backend: str, server: str) -> int:
        reply = self.helper.ask([f"show servers state {backend}"])
        return int(self.helper.admin_states(reply)[(backend, server)])

    def kept(self) -> dict[str, str]:
        data: dict[str, Any] = json.loads(self.helper.STATE_FILE.read_text())
        servers: dict[str, str] = data["servers"]
        return servers

    def test_a_drain_is_set_kept_and_named_by_its_guid(self) -> None:
        code, out = self.run_helper("set", WEB_B, "drain")

        self.assertEqual(code, 0, out)
        answer = json.loads(out)
        self.assertEqual(
            (answer["outcome"], answer["backend"], answer["server"]), ("done", "mgd-shop-web", "s2")
        )
        self.assertTrue(self.state_of("mgd-shop-web", "s2") & self.helper.FORCED_DRAIN)
        self.assertEqual(self.kept(), {WEB_B: "drain"})
        self.assertEqual(self.helper.STATE_FILE.stat().st_mode & 0o777, 0o600)

    def test_ready_takes_it_back_and_out_of_the_file(self) -> None:
        self.run_helper("set", WEB_A, "maint")
        code, out = self.run_helper("set", WEB_A, "ready")

        self.assertEqual(code, 0, out)
        self.assertEqual(self.state_of("mgd-shop-web", "s1"), 0)
        self.assertEqual(self.kept(), {})

    def test_a_reload_puts_it_back_on_the_new_worker(self) -> None:
        """Without the helper a reload drops it: measured, and the reason it exists."""

        self.run_helper("set", WEB_B, "drain")
        self.run_helper("set", API, "maint")
        before = self.helper.worker_pid(self.helper.ask(["show info"]))

        code, out = self.run_helper("reload")

        self.assertEqual(code, 0, out)
        self.assertNotEqual(self.helper.worker_pid(self.helper.ask(["show info"])), before)
        self.assertTrue(self.state_of("mgd-shop-web", "s2") & self.helper.FORCED_DRAIN)
        self.assertTrue(self.state_of("mgd-api", "s1") & self.helper.FORCED_MAINT)
        self.assertIn("drain on mgd-shop-web/s2", out)

    def test_the_state_follows_the_server_when_the_pool_is_reordered(self) -> None:
        self.run_helper("set", WEB_B, "drain")
        self.write([(WEB_B, "127.0.0.1", 18582), (WEB_A, "127.0.0.1", 18581)])

        self.run_helper("reload")

        self.assertTrue(self.state_of("mgd-shop-web", "s1") & self.helper.FORCED_DRAIN)
        self.assertEqual(self.state_of("mgd-shop-web", "s2"), 0)

    def test_a_server_no_longer_configured_is_forgotten(self) -> None:
        self.run_helper("set", WEB_B, "drain")
        self.write([(WEB_A, "127.0.0.1", 18581)])

        code, out = self.run_helper("reload")

        self.assertEqual(code, 0, out)
        self.assertIn(f"{WEB_B} is no longer in the configuration", out)
        self.assertEqual(self.kept(), {})

    def test_start_puts_the_kept_states_back(self) -> None:
        self.run_helper("set", WEB_A, "maint")
        self.process.send_signal(signal.SIGTERM)
        self.process.wait(timeout=10)
        self.process = subprocess.Popen(  # noqa: S603 - fixed binary, scratch configuration
            [HAPROXY, "-W", "-f", str(self.config), "-p", str(self.root / "pid")],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.wait_for_socket()
        self.assertEqual(self.state_of("mgd-shop-web", "s1"), 0)

        code, out = self.run_helper("reapply")

        self.assertEqual(code, 0, out)
        self.assertTrue(self.state_of("mgd-shop-web", "s1") & self.helper.FORCED_MAINT)

    def test_a_guid_the_running_configuration_lacks_is_refused(self) -> None:
        code, out = self.run_helper("set", "srv:gone.4444444444444444", "drain")

        self.assertEqual(code, self.helper.EXIT_UNKNOWN_SERVER)
        self.assertEqual(json.loads(out)["outcome"], "refused")
        self.assertFalse(self.helper.STATE_FILE.exists())

    def test_without_the_admin_socket_it_says_which_line_is_missing(self) -> None:
        self.helper.ADMIN_SOCKET = str(self.root / "absent.sock")

        code, out = self.run_helper("set", WEB_A, "drain")

        self.assertEqual(code, self.helper.EXIT_UNAVAILABLE)
        self.assertIn("level admin", json.loads(out)["message"])

    def test_words_that_are_not_a_request_are_refused_before_anything_runs(self) -> None:
        for argv in (
            ("set", WEB_A, "down"),
            ("set", "srv:Shop.1111111111111111", "drain"),
            ("set", "srv:shop.111", "drain"),
            ("set", WEB_A),
            ("drain", WEB_A),
        ):
            with self.subTest(argv):
                code, _out = self.run_helper(*argv)
                self.assertEqual(code, self.helper.EXIT_USAGE)


def pem(directory: Path, name: str) -> str:
    """A fresh self-signed certificate and its key, in one file as the nodes keep them."""

    key, cert = directory / f"{name}.key", directory / f"{name}.crt"
    subprocess.run(
        [
            "/usr/bin/openssl", "req", "-x509", "-newkey", "ec",
            "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-subj", "/CN=shop.example.com",
            "-days", "30", "-keyout", str(key), "-out", str(cert),
        ],
        check=True,
        capture_output=True,
    )  # fmt: skip
    return cert.read_text() + key.read_text()


@unittest.skipUnless(HAPROXY, "haproxy is not installed where the tests run")
class TheHelperReplacesACertificateWithoutAReload(unittest.TestCase):
    """Fas 20 P5: `set ssl cert` and `commit ssl cert`, against HAProxy 3.4."""

    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="sslstate-"))
        self.addCleanup(shutil.rmtree, self.root, True)
        self.certs = self.root / "certs"
        self.certs.mkdir()
        (self.certs / "shop.pem").write_text(pem(self.root, "old"))
        (self.certs / "api.pem").write_text(pem(self.root, "api"))
        (self.root / "list.txt").write_text(f"{self.certs}/shop.pem\n{self.certs}/api.pem\n")
        self.config = self.root / "haproxy.cfg"
        self.config.write_text(
            "\n".join(
                (
                    "global",
                    f"    stats socket {self.root}/manager.sock mode 600 level admin",
                    "defaults",
                    "    mode http",
                    "    timeout connect 2s",
                    "    timeout client 5s",
                    "    timeout server 5s",
                    "frontend fe",
                    f"    bind 127.0.0.1:18590 ssl crt-list {self.root}/list.txt",
                    "    http-request return status 200",
                    "",
                )
            )
        )
        self.helper = load_helper()
        for name, value in (
            ("ADMIN_SOCKET", str(self.root / "manager.sock")),
            ("LOCK_FILE", str(self.root / "lock")),
            ("CERTS_DIR", self.certs),
        ):
            setattr(self.helper, name, value)
        self.process = subprocess.Popen(  # noqa: S603 - fixed binary, scratch configuration
            [HAPROXY, "-W", "-f", str(self.config), "-p", str(self.root / "pid")],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.addCleanup(self.stop)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                self.pid = self.helper.worker_pid(self.helper.ask(["show info"]))
                if self.pid:
                    return
            except self.helper.Unavailable:
                pass
            time.sleep(0.05)
        self.fail("HAProxy did not answer on the admin socket")

    def stop(self) -> None:
        self.process.send_signal(signal.SIGTERM)
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=10)

    def run_helper(self, *argv: str) -> tuple[int, str]:
        out = io.StringIO()
        with redirect_stdout(out):
            code = self.helper.main(list(argv))
        return code, out.getvalue()

    def served(self) -> str:
        reply = self.helper.ask([f"show ssl cert {self.certs}/shop.pem"])
        found = re.search(r"^SHA1 FingerPrint: ([0-9A-F]+)$", reply, re.MULTILINE)
        return found.group(1) if found else ""

    def test_the_new_file_is_served_by_the_same_worker(self) -> None:
        new = pem(self.root, "new")
        (self.certs / "shop.pem").write_text(new)

        code, out = self.run_helper("update-certs", "shop")

        self.assertEqual(code, 0, out)
        self.assertEqual(self.served(), self.helper.fingerprint(new))
        self.assertEqual(self.helper.worker_pid(self.helper.ask(["show info"])), self.pid)

    def test_a_certificate_haproxy_does_not_hold_asks_for_a_reload(self) -> None:
        (self.certs / "other.pem").write_text(pem(self.root, "other"))

        code, out = self.run_helper("update-certs", "shop", "other")

        self.assertEqual(code, self.helper.EXIT_NOT_HELD, out)
        self.assertIn("other", out)

    def test_a_file_haproxy_refuses_is_aborted_and_the_old_one_still_served(self) -> None:
        before = self.served()
        certificate_only = pem(self.root, "new").split("-" * 5 + "BEGIN PRIVATE KEY")[0]
        (self.certs / "shop.pem").write_text(certificate_only)

        code, out = self.run_helper("update-certs", "shop")

        self.assertEqual(code, self.helper.EXIT_REFUSED, out)
        self.assertEqual(self.served(), before)
        self.assertEqual(self.helper.held_certificates()[1], set())

    def test_a_transaction_a_stopped_run_left_open_is_aborted_first(self) -> None:
        """HAProxy allows one at a time, so a leftover would block every later one."""

        new = pem(self.root, "new")
        #
        # On another certificate: one left on the same name is merely updated.
        #
        name = f"{self.certs}/api.pem"
        self.helper.ask([f"set ssl cert {name} <<\n{pem(self.root, 'stray').strip()}\n"])
        self.assertEqual(self.helper.held_certificates()[1], {name})
        (self.certs / "shop.pem").write_text(new)

        code, out = self.run_helper("update-certs", "shop")

        self.assertEqual(code, 0, out)
        self.assertIn("aborting a transaction", out)
        self.assertEqual(self.served(), self.helper.fingerprint(new))

    def test_words_that_are_not_certificate_ids_are_refused(self) -> None:
        for argv in (
            ("update-certs",),
            ("update-certs", "../etc/passwd"),
            ("update-certs", "Shop"),
        ):
            with self.subTest(argv):
                self.assertEqual(self.run_helper(*argv)[0], self.helper.EXIT_USAGE)


class TheTriggerValidatesBeforeSudo(unittest.TestCase):
    """The forced command, run with a `sudo` that only records what it was asked."""

    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="srvtrigger-"))
        self.addCleanup(shutil.rmtree, self.root, True)
        sudo = self.root / "sudo"
        sudo.write_text('#!/bin/sh\nprintf "%s\\n" "$*"\n')
        sudo.chmod(0o755)

    def trigger(self, request: str | None) -> subprocess.CompletedProcess[str]:
        env = {"PATH": f"{self.root}:{os.environ['PATH']}"}
        if request is not None:
            env["SSH_ORIGINAL_COMMAND"] = request
        return subprocess.run(  # noqa: S603 - the file under test
            ["/bin/bash", str(TRIGGER)], env=env, capture_output=True, text=True, check=False
        )

    def test_a_valid_request_reaches_the_helper_as_three_words(self) -> None:
        done = self.trigger(f"server-state {WEB_A} drain")

        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(
            done.stdout.strip(), f"-n /usr/local/sbin/haproxy-server-state set {WEB_A} drain"
        )

    def test_anything_else_is_refused_and_never_reaches_sudo(self) -> None:
        for request in (
            None,
            "",
            f"server-state {WEB_A} down",
            f"server-state {WEB_A}",
            f"server-state {WEB_A} drain extra",
            "server-state srv:shop.1111;id drain",
            f"cert-pull {WEB_A} drain",
            "server-state ../../etc/passwd drain",
        ):
            with self.subTest(request):
                done = self.trigger(request)
                self.assertEqual(done.returncode, 64)
                self.assertEqual(done.stdout, "")


INSTALLER = BASE / "install" / "04-node-prepare"
KEY_A = "ssh-ed25519 AAAAexampleKeyA"
KEY_B = "ssh-ed25519 AAAAexampleKeyB"


class TheNodeWritesTheServerStateKeyFromTheAnswers(unittest.TestCase):
    """04-node-prepare's block for SERVER_STATE_PUBKEY (B263), run on a scratch file."""

    def setUp(self) -> None:
        text = INSTALLER.read_text()
        start = text.index('if [[ -n "${SERVER_STATE_PUBKEY:-}" ]]; then')
        end = text.index("\nfi\n", start) + len("\nfi\n")
        self.root = Path(tempfile.mkdtemp(prefix="srvkeys-"))
        self.addCleanup(shutil.rmtree, self.root, True)
        self.keys = self.root / "authorized_keys"
        self.block = (
            text[start:end]
            .replace("/home/${TRIGGER_USER}/.ssh/authorized_keys", str(self.keys))
            .replace("install -o root -g root -m 644", "install -m 644")
        )

    def run_block(self, pubkey: str) -> subprocess.CompletedProcess[str]:
        script = (
            'set -Eeuo pipefail\nlog() { echo "$*"; }\ndie() { echo "DIE $*"; exit 1; }\n'
            f'SBIN=/usr/local/sbin\nSERVER_STATE_PUBKEY="{pubkey}"\n{self.block}'
        )
        return subprocess.run(  # noqa: S603 - the block under test
            ["/bin/bash", "-c", script], capture_output=True, text=True, check=False
        )

    def test_the_line_is_written_and_a_rotated_key_replaces_the_old_one(self) -> None:
        other = 'restrict,command="sudo -n /usr/local/sbin/haproxy-pull-deploy" ' + KEY_B
        self.keys.write_text(other + "\n")

        first = self.run_block(KEY_A)
        again = self.run_block(KEY_A)
        rotated = self.run_block(KEY_B)

        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        self.assertIn("ok", again.stdout)
        self.assertEqual(rotated.returncode, 0, rotated.stdout)
        lines = self.keys.read_text().splitlines()
        self.assertEqual(
            lines,
            [other, f'restrict,command="/usr/local/sbin/haproxy-server-state-trigger" {KEY_B}'],
        )

    def test_anything_but_one_ed25519_key_is_refused(self) -> None:
        self.keys.write_text("")
        for pubkey in (
            "ssh-rsa AAAAB3NzaC1yc2E",
            f"{KEY_A} comment",
            f'{KEY_A}\nrestrict,command="/bin/sh" {KEY_B}',
            'command="/bin/sh" ' + KEY_A,
        ):
            with self.subTest(pubkey):
                done = self.run_block(pubkey)
                self.assertNotEqual(done.returncode, 0)
                self.assertIn("DIE", done.stdout)
        self.assertEqual(self.keys.read_text(), "")


class TheSocketIsTheOneTheCoreNames(unittest.TestCase):
    def test_the_helper_and_the_core_template_agree(self) -> None:
        from haproxy_mgmt import cluster_definition  # noqa: PLC0415

        self.assertIn(f'ADMIN_SOCKET = "{cluster_definition.MANAGER_SOCKET}"', HELPER.read_text())


class EveryReloadGoesThroughTheHelper(unittest.TestCase):
    """A plain reload drops every kept drain; only the helper may call systemctl for it."""

    def test_no_node_script_reloads_haproxy_on_its_own(self) -> None:
        for path in sorted((BASE / "install" / "node").iterdir()):
            if path.name == HELPER.name or not path.is_file():
                continue
            code = [
                line
                for line in path.read_text().splitlines()
                if not line.lstrip().startswith("#")
                and re.search(r"systemctl\s+(reload|restart)\s+haproxy\b", line)
            ]
            with self.subTest(path.name):
                self.assertEqual(code, [])
