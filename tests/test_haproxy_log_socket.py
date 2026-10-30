"""HAProxy's log socket in its chroot, held by systemd across rsyslog restarts.

HAProxy runs chrooted in /var/lib/haproxy and logs to the socket Ubuntu's
49-haproxy.conf has rsyslog create there. rsyslog removes it when it stops, so
every restart lost the lines written in between (43 to 93 a restart on a node,
26-10-12). 04-node-prepare has systemd hold the socket instead and hand it to
rsyslog. The mechanism is tested with the real rsyslogd: this suite plays
systemd's part, holding the socket and passing it as systemd's socket
activation does, and stops rsyslog while lines are written.
"""

from __future__ import annotations

import errno
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NODE_PREPARE = ROOT / "install" / "04-node-prepare"
UBUNTU_LINE = "$AddUnixListenSocket /var/lib/haproxy/dev/log"
INPUT_WRITTEN = 'forward_rule_text "$TRAFFIC_INPUT"'
#
# What a restart costs at the busiest rate measured: rsyslog was away 65 ms
# and a node answered 25 000 requests a second (26-10-12).
#
RESTART_LINES = int(0.065 * 25_000)
#
# Moves the socket it is given to fd 3 and execs the receiver in its own
# process, so LISTEN_PID is the PID the receiver runs as.
#
HANDOVER = (
    "import os, sys\n"
    "os.dup2(int(sys.argv[1]), 3)\n"
    "os.environ['LISTEN_FDS'] = '1'\n"
    "os.environ['LISTEN_PID'] = str(os.getpid())\n"
    "os.execvp(sys.argv[2], sys.argv[2:])\n"
)


def unit_text(unit: str = "LOG_SOCKET_UNIT") -> str:
    """The socket unit 04-node-prepare holds under this variable, its paths filled in."""

    text = NODE_PREPARE.read_text(encoding="utf-8")
    found = re.search(
        rf'^ *hold_log_socket "\${unit}" "\$[A-Z_]+" "(.*?)"\n', text, re.DOTALL | re.MULTILINE
    )
    if found is None:
        raise AssertionError(f"04-node-prepare holds no socket unit for {unit}")
    path = re.search(r'^LOG_SOCKET_PATH="([^"]+)"$', text, re.MULTILINE)
    assert path is not None
    traffic = re.search(r'^TRAFFIC_SOCKET_PATH="([^"]+)"$', text, re.MULTILINE)
    assert traffic is not None
    return (
        found.group(1)
        .replace("${LOG_SOCKET_PATH}", path.group(1))
        .replace("${TRAFFIC_SOCKET_PATH}", traffic.group(1))
    )


def apparmor_rule() -> str:
    """The AppArmor rule 04-node-prepare writes for rsyslogd, its paths filled in."""

    text = NODE_PREPARE.read_text(encoding="utf-8")
    found = re.search(r'^RSYSLOG_APPARMOR_TEXT="(.*?)"\n', text, re.DOTALL | re.MULTILINE)
    if found is None:
        raise AssertionError("04-node-prepare writes no AppArmor rule for rsyslogd")
    traffic = re.search(r'^TRAFFIC_SOCKET_PATH="([^"]+)"$', text, re.MULTILINE)
    assert traffic is not None
    return (
        found.group(1)
        .replace("${TRAFFIC_SOCKET_PATH}", traffic.group(1))
        .replace("${RSYSLOG_FORWARD_RULE}", "/etc/rsyslog.d/47-haprion-forward.conf")
    )


def traffic_input(socket_path: str) -> str:
    """The rsyslog input and ruleset 04-node-prepare writes for HAProxy's traffic socket."""

    text = NODE_PREPARE.read_text(encoding="utf-8")
    found = re.search(r"TRAFFIC_INPUT=.*?<<'CONF'\n(.*?)\nCONF\n", text, re.DOTALL)
    if found is None:
        raise AssertionError("04-node-prepare writes no traffic input")
    return found.group(1).replace("@SOCKET@", socket_path)


class TheNodeHoldsTheSocket(unittest.TestCase):
    def test_the_unit_listens_where_ubuntus_rule_has_rsyslog_listen(self) -> None:
        unit = unit_text()
        self.assertEqual(
            [line for line in unit.splitlines() if line.startswith("ListenDatagram=")],
            ["ListenDatagram=" + UBUNTU_LINE.split()[-1]],
        )
        self.assertIn("Service=rsyslog.service", unit.splitlines())
        #
        # Open to every account, as rsyslog makes it: a core that runs HAProxy
        # as another account still logs there, and nothing trusts its lines.
        #
        self.assertIn("SocketMode=0666", unit.splitlines())

    def test_the_traffic_socket_is_held_for_haproxy_alone(self) -> None:
        """Review 2026-10-30, E1: only HAProxy writes the socket whose lines are trusted."""

        unit = unit_text("TRAFFIC_SOCKET_UNIT")
        self.assertEqual(
            [line for line in unit.splitlines() if line.startswith("ListenDatagram=")],
            ["ListenDatagram=/var/lib/haproxy/dev/haprion-traffic"],
        )
        for line in (
            "SocketUser=haproxy",
            "SocketGroup=haproxy",
            "SocketMode=0660",
            "Service=rsyslog.service",
        ):
            self.assertIn(line, unit.splitlines())

    def test_every_node_holds_the_traffic_socket(self) -> None:
        """Not only one whose 49-haproxy.conf listens: else rsyslog makes it, open to all.

        Fails with the socket in the ordinary unit, which a node without
        Ubuntu's listen line never gets (review 2026-10-30-igen, R1).
        """

        text = NODE_PREPARE.read_text(encoding="utf-8")
        self.assertRegex(text, r'(?m)^hold_log_socket "\$TRAFFIC_SOCKET_UNIT" ')
        check = text.index('grep -qsx "\\$AddUnixListenSocket ${LOG_SOCKET_PATH}"')
        end = text.index("\nfi\n", check)
        self.assertGreater(text.index('hold_log_socket "$TRAFFIC_SOCKET_UNIT"'), end)

    def test_haproxy_logs_the_traffic_stream_to_the_socket_only_it_can_write(self) -> None:
        """The generated `log` target is the traffic unit's socket, by its host path."""

        from haprion.traffic_stream import TRAFFIC_LOG_SOCKET

        self.assertEqual(
            ["ListenDatagram=" + TRAFFIC_LOG_SOCKET],
            [
                line
                for line in unit_text("TRAFFIC_SOCKET_UNIT").splitlines()
                if line.startswith("ListenDatagram=")
            ],
        )

    def test_the_check_names_ubuntus_line_exactly(self) -> None:
        text = NODE_PREPARE.read_text(encoding="utf-8")
        self.assertIn(
            'grep -qsx "\\$AddUnixListenSocket ${LOG_SOCKET_PATH}" /etc/rsyslog.d/49-haproxy.conf',
            text,
        )

    def test_the_queue_holds_a_restart_at_the_busiest_rate(self) -> None:
        text = NODE_PREPARE.read_text(encoding="utf-8")
        queue = re.search(r"^LOG_SOCKET_QUEUE=(\d+)$", text, re.MULTILINE)
        assert queue is not None
        self.assertGreaterEqual(int(queue.group(1)), 4 * RESTART_LINES)
        self.assertIn("net.unix.max_dgram_qlen = ${LOG_SOCKET_QUEUE}", text)
        #
        # Read when a socket is made: the setting has to come first.
        #
        self.assertLess(
            text.index("net.unix.max_dgram_qlen="), text.index('hold_log_socket "$LOG_SOCKET_UNIT"')
        )
        self.assertLess(
            text.index("net.unix.max_dgram_qlen="),
            text.index('hold_log_socket "$TRAFFIC_SOCKET_UNIT"'),
        )


class RsyslogNeverMakesTheTrafficSocketItself(unittest.TestCase):
    """Review 2026-10-30-igen2, S4: rsyslog creates a socket it is not handed, open to every account."""

    def test_the_socket_is_held_before_rsyslog_is_restarted_on_the_input(self) -> None:
        text = NODE_PREPARE.read_text(encoding="utf-8")
        held = text.index('hold_log_socket "$TRAFFIC_SOCKET_UNIT"')
        self.assertLess(held, text.index(INPUT_WRITTEN))
        self.assertLess(held, text.index("systemctl restart rsyslog.service"))
        self.assertLess(text.index("net.unix.max_dgram_qlen="), held)

    @staticmethod
    def forward_functions() -> str:
        """The forwarding rule's variables and the two functions that write it, as in the step."""

        text = NODE_PREPARE.read_text(encoding="utf-8")
        parts = [
            re.search(rf"^{name}=.*$", text, re.MULTILINE)
            for name in ("RSYSLOG_FORWARD_RULE", "RSYSLOG_FORWARD_DIR", "RSYSLOG_STATS")
        ]
        functions = [
            re.search(rf"^{name}\(\) \{{\n.*?^\}}\n", text, re.DOTALL | re.MULTILINE)
            for name in ("forward_rule_text", "traffic_input_off")
        ]
        found = [m.group(0) for m in parts + functions if m is not None]
        assert len(found) == 5
        return "TRAFFIC_LOG_ROOT=/var/log/haprion\n" + "\n".join(found)

    def run_hold(
        self, unit: str, hook: str = "", rule: list[str] | None = None
    ) -> tuple[int, list[str]]:
        """hold_log_socket with its systemctl stubbed to fail starting `unit`; what it did.

        `rule`, given, receives the lines of the forwarding rule the hook wrote.
        """

        text = NODE_PREPARE.read_text(encoding="utf-8")
        function = re.search(r"^hold_log_socket\(\) \{\n.*?^\}\n", text, re.DOTALL | re.MULTILINE)
        assert function is not None
        with tempfile.TemporaryDirectory() as raw:
            script = (
                f'did() {{ echo "$*" >>{raw}/did; }}\n'
                f'systemctl() {{ did systemctl "$@"; [[ "$1" == is-active ]] && return 1; '
                f'[[ "$1 $2" != "start {unit}" ]]; }}\n'
                f'install_file() {{ did install_file "$1"; printf "%s\\n" "$4" >{raw}/rule; }}\n'
                f'rm() {{ did rm "$@"; }}\n'
                f'die() {{ did DIE "$*"; exit 3; }}\n'
                f"{self.forward_functions()}\n"
                f"{function.group(0)}\n"
                f"hold_log_socket {unit} {raw}/socket content {hook}\n"
            )
            done = subprocess.run(["/bin/bash", "-c", script], capture_output=True, check=False)
            did = Path(raw, "did").read_text(encoding="utf-8").splitlines()
            if rule is not None and Path(raw, "rule").exists():
                rule.extend(Path(raw, "rule").read_text(encoding="utf-8").splitlines())
        return done.returncode, did

    def test_a_traffic_socket_that_does_not_start_rewrites_the_rule_without_the_input(self) -> None:
        """T1: the file also carries impstats and the external receivers' include."""

        rule: list[str] = []
        code, did = self.run_hold(
            "haprion-traffic-log.socket", 'traffic_input_off "the input is off"', rule
        )

        self.assertEqual(code, 3)
        self.assertIn("install_file /etc/rsyslog.d/47-haprion-forward.conf", did)
        self.assertNotIn("rm -f /etc/rsyslog.d/47-haprion-forward.conf", did)
        joined = "\n".join(rule)
        self.assertIn('module(load="impstats"', joined)
        self.assertIn('include(file="/etc/rsyslog.d/haprion/forward.conf" mode="optional")', joined)
        self.assertNotIn("input(", joined)
        self.assertTrue(any(line.startswith("DIE") and "the input is off" in line for line in did))
        self.assertNotIn("rsyslog runs as before", " ".join(did))
        self.assertLess(
            did.index("install_file /etc/rsyslog.d/47-haprion-forward.conf"),
            did.index("systemctl start syslog.socket rsyslog.service"),
        )

    def test_the_rule_with_the_input_is_the_rule_without_it_plus_the_input(self) -> None:
        text = NODE_PREPARE.read_text(encoding="utf-8")
        self.assertIn('"$(forward_rule_text "$TRAFFIC_INPUT")"', text)
        self.assertLess(
            text.index("traffic_input_off()"), text.index('hold_log_socket "$TRAFFIC_SOCKET_UNIT"')
        )

    def test_the_traffic_unit_names_the_input_hook_and_a_true_note(self) -> None:
        text = NODE_PREPARE.read_text(encoding="utf-8")
        self.assertIn('WantedBy=sockets.target" traffic_input_off \\\n', text)
        self.assertIn("does not make the socket itself", text)

    def test_the_ordinary_socket_still_falls_back_to_rsyslog_as_before(self) -> None:
        code, did = self.run_hold("haprion-haproxy-log.socket")

        self.assertEqual(code, 3)
        self.assertNotIn("install_file /etc/rsyslog.d/47-haprion-forward.conf", did)
        self.assertTrue(any("rsyslog runs as before" in line for line in did))


PROFILE = Path("/etc/apparmor.d/usr.sbin.rsyslogd")


class RsyslogMayReadTheTrafficSocket(unittest.TestCase):
    """rsyslogd's AppArmor profile names HAProxy's dev/log and not the traffic socket.

    Review 2026-10-30-igen, R1: step 4 writes a rule for it into the profile's
    include directory and loads it before rsyslog first restarts on the input.
    """

    def test_the_rule_names_the_traffic_socket_as_ubuntu_names_dev_log(self) -> None:
        self.assertIn("/var/lib/haproxy/dev/haprion-traffic rwl,", apparmor_rule().splitlines())

    def test_the_rule_is_loaded_before_rsyslog_restarts_on_the_input(self) -> None:
        text = NODE_PREPARE.read_text(encoding="utf-8")
        self.assertIn('RSYSLOG_APPARMOR="/etc/apparmor.d/rsyslog.d/haprion-haproxy-log"', text)
        written = text.index('install -o root -g root -m 644 /dev/stdin "$RSYSLOG_APPARMOR"')
        reloaded = text.index("/usr/lib/rsyslog/reload-apparmor-profile", written)
        self.assertLess(text.index(INPUT_WRITTEN), written)
        self.assertLess(reloaded, text.index("systemctl restart rsyslog.service"))

    @unittest.skipUnless(
        PROFILE.is_file() and shutil.which("apparmor_parser"), "no rsyslogd profile here"
    )
    def test_the_installed_profile_takes_the_rule(self) -> None:
        """Parsed into the real profile, through its `rsyslog.d` include, never loaded."""

        import fnmatch

        parser = shutil.which("apparmor_parser")
        assert parser is not None
        rules = PROFILE.read_text(encoding="utf-8")
        self.assertIn("include if exists <rsyslog.d>", rules)
        self.assertIn("/var/lib/*/dev/log", rules)
        self.assertFalse(
            fnmatch.fnmatchcase("/var/lib/haproxy/dev/haprion-traffic", "/var/lib/*/dev/log")
        )
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "rsyslog.d").mkdir()
            (Path(directory) / "rsyslog.d" / "haprion-haproxy-log").write_text(
                apparmor_rule() + "\n"
            )
            parsed = subprocess.run(
                [
                    parser, "-Q", "-T", "-p",
                    "-I", directory, "-I", str(PROFILE.parent), str(PROFILE),
                ],
                capture_output=True,
                text=True,
                check=False,
            )  # fmt: skip
        self.assertEqual(parsed.returncode, 0, parsed.stderr)
        self.assertIn("/var/lib/haproxy/dev/haprion-traffic rwl,", parsed.stdout.splitlines())


@unittest.skipUnless(shutil.which("rsyslogd"), "rsyslog is not installed here")
class RsyslogKeepsAHandedSocket(unittest.TestCase):
    """rsyslogd, a copy outside AppArmor's reach, on a socket this test holds."""

    def setUp(self) -> None:
        self.directory = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.directory, True)
        source = shutil.which("rsyslogd")
        assert source is not None
        self.binary = self.directory / "rsyslogd"
        shutil.copy2(source, self.binary)
        self.binary.chmod(0o755)
        (self.directory / "work").mkdir()
        self.path = self.directory / "log"
        self.out = self.directory / "out.log"
        self.config = self.directory / "rsyslog.conf"
        self.config.write_text(
            f'global(workDirectory="{self.directory / "work"}")\n'
            'module(load="imuxsock" SysSock.Use="off")\n'
            f"$AddUnixListenSocket {self.path}\n"
            f'action(type="omfile" file="{self.out}")\n'
        )
        self.process: subprocess.Popen[bytes] | None = None
        self.addCleanup(self.stop)

    def start(self, held: socket.socket | None) -> None:
        command = [
            str(self.binary),
            "-n",
            "-f",
            str(self.config),
            "-i",
            str(self.directory / "pid"),
        ]
        if held is None:
            self.process = subprocess.Popen(command)
        else:
            #
            # systemd's handover: the socket as fd 3, LISTEN_FDS=1, and
            # LISTEN_PID the receiver's own - the launcher's, which exec keeps.
            # Python rather than /bin/sh: dash's `3<&N` takes one digit, and
            # in a full suite the socket was fd 29 (review 26-10-13, T1).
            #
            self.process = subprocess.Popen(
                [sys.executable, "-c", HANDOVER, str(held.fileno()), *command],
                pass_fds=(held.fileno(),),
            )
        deadline = time.monotonic() + 10
        while not self.path.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertTrue(self.path.exists(), "rsyslog did not listen")
        time.sleep(0.3)

    def stop(self) -> None:
        if self.process is not None and self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            self.process.wait(timeout=10)
        self.process = None

    def send(self, first: int, count: int) -> int:
        """As HAProxy does: never waiting, a line that cannot go is lost."""

        sender = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sender.setblocking(False)
        sent = 0
        with sender:
            for number in range(first, first + count):
                try:
                    sender.sendto(
                        f"<150>Oct 12 13:30:00 node-a haproxy: line {number}".encode(),
                        str(self.path),
                    )
                    sent += 1
                except OSError as error:
                    if error.errno not in (errno.ENOENT, errno.ECONNREFUSED, errno.EAGAIN):
                        raise
        return sent

    def received(self, expected: int) -> int:
        deadline = time.monotonic() + 10
        count = 0
        while time.monotonic() < deadline:
            count = len(self.out.read_text().splitlines()) if self.out.exists() else 0
            if count >= expected:
                break
            time.sleep(0.05)
        return count

    def test_lines_written_while_rsyslog_restarts_wait_in_the_held_socket(self) -> None:
        #
        # Descriptors held open first, as a full suite in one process has
        # them: the socket then gets a two-digit number, which the handover
        # once could not pass on (review 26-10-13, T1).
        #
        for _ in range(12):
            spare = Path("/dev/null").open("rb")  # noqa: SIM115 - closed by cleanup
            self.addCleanup(spare.close)
        held = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.addCleanup(held.close)
        self.assertGreater(held.fileno(), 9)
        held.bind(str(self.path))
        inode = self.path.stat().st_ino
        self.start(held)
        self.assertEqual(self.send(0, 100), 100)
        self.stop()

        self.assertEqual(self.path.stat().st_ino, inode, "rsyslog removed the socket it was handed")
        self.assertEqual(self.send(100, 200), 200)

        self.start(held)
        self.assertEqual(self.received(300), 300)

    def test_without_the_handover_a_restart_loses_the_lines(self) -> None:
        """The failure the held socket ends: rsyslog takes its own away."""

        self.start(None)
        self.assertEqual(self.send(0, 100), 100)
        self.assertEqual(self.received(100), 100)
        self.stop()

        self.assertFalse(self.path.exists())
        self.assertEqual(self.send(100, 200), 0)

        self.start(None)
        self.assertEqual(self.received(100), 100)


@unittest.skipUnless(shutil.which("rsyslogd"), "rsyslog is not installed here")
class OnlyHAProxysSocketIsTrusted(unittest.TestCase):
    """Review 2026-10-30, E1, on a real rsyslogd: the tag alone writes nothing.

    The configuration is the shipped one - the input and ruleset of
    04-node-prepare, the day file's rule as `haprion-traffic-log-enable`
    prints it - on two sockets in a temporary directory: one for HAProxy, one
    standing for the system's /dev/log that any local account can write.
    """

    def setUp(self) -> None:
        self.directory = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.directory, True)
        source = shutil.which("rsyslogd")
        assert source is not None
        self.binary = self.directory / "rsyslogd"
        shutil.copy2(source, self.binary)
        self.binary.chmod(0o755)
        (self.directory / "work").mkdir()
        (self.directory / "days").mkdir()
        self.traffic = self.directory / "haprion-traffic"
        self.general = self.directory / "log"
        rule = subprocess.run(
            ["/bin/bash", str(ROOT / "install" / "node" / "haprion-traffic-log-enable"), "--print"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.replace("/var/log/haprion/", f"{self.directory / 'days'}/")
        self.config = self.directory / "rsyslog.conf"
        self.config.write_text(
            f'global(workDirectory="{self.directory / "work"}")\n'
            'module(load="imuxsock" SysSock.Use="off")\n'
            f"$AddUnixListenSocket {self.general}\n"
            f"{traffic_input(str(self.traffic))}\n"
            f"{rule}\n"
            f'action(type="omfile" file="{self.directory / "classic.log"}")\n'
        )
        self.process = subprocess.Popen(
            [str(self.binary), "-n", "-f", str(self.config), "-i", str(self.directory / "pid")]
        )
        self.addCleanup(self.stop)
        deadline = time.monotonic() + 10
        while not (self.traffic.exists() and self.general.exists()):
            self.assertLess(time.monotonic(), deadline, "rsyslog did not listen")
            time.sleep(0.02)
        time.sleep(0.3)

    def stop(self) -> None:
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            self.process.wait(timeout=10)

    def send(self, path: Path, text: str) -> None:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sender:
            sender.sendto(f"<150>Oct 12 13:30:00 haproxy-traffic[1]: {text}".encode(), str(path))

    def written(self, expected: int) -> list[str]:
        deadline = time.monotonic() + 10
        lines: list[str] = []
        while time.monotonic() < deadline:
            lines = [
                line
                for day in sorted((self.directory / "days").glob("traffic-*.jsonl"))
                for line in day.read_text().splitlines()
            ]
            if len(lines) >= expected:
                break
            time.sleep(0.05)
        return lines

    def test_a_line_with_the_tag_on_the_general_socket_is_not_written(self) -> None:
        self.send(self.general, '{"schema":1,"path":"/forged"}')
        self.send(self.traffic, '{"schema":1,"path":"/real"}')
        self.written(1)
        time.sleep(0.5)
        lines = self.written(1)

        self.assertEqual(lines, ['{"schema":1,"path":"/real"}'])
        self.assertFalse(
            (self.directory / "classic.log").exists(), "the tag never reaches the classic log"
        )


if __name__ == "__main__":
    unittest.main()
