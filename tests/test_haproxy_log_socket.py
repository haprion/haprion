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


def unit_text() -> str:
    text = NODE_PREPARE.read_text(encoding="utf-8")
    found = re.search(r'install_file "\$LOG_SOCKET_FILE" root:root 644 "(.*?)"\n', text, re.DOTALL)
    if found is None:
        raise AssertionError("04-node-prepare installs no log socket unit")
    path = re.search(r'^LOG_SOCKET_PATH="([^"]+)"$', text, re.MULTILINE)
    assert path is not None
    return found.group(1).replace("${LOG_SOCKET_PATH}", path.group(1))


class TheNodeHoldsTheSocket(unittest.TestCase):
    def test_the_unit_listens_where_ubuntus_rule_has_rsyslog_listen(self) -> None:
        unit = unit_text()
        self.assertIn("ListenDatagram=" + UBUNTU_LINE.split()[-1], unit.splitlines())
        self.assertIn("Service=rsyslog.service", unit.splitlines())
        self.assertIn("SocketMode=0666", unit.splitlines())

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
            text.index("net.unix.max_dgram_qlen="), text.index('systemctl start "$LOG_SOCKET_UNIT"')
        )


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


if __name__ == "__main__":
    unittest.main()
