"""The generated log profile, through real HAProxy and real rsyslog, read by the real parser.

B132. R4's four findings - the hostname before the tag, `%HP` against `%HPO`,
plain-text error lines in the JSON stream, "Proxy ... stopped" at every
reload - were all found by one local rig and none by a unit test, because each
one lives in the seam between three programs that only agree when they are
actually run together. This is that rig, kept.

The installed rsyslogd is confined by AppArmor to /etc/rsyslog.d; a copy of the
same binary under another path is not, which is the only way to run the real
parser and the real rule over files this suite owns. Two substitutions are made
and both are asserted: HAProxy's `/dev/log` becomes the rig's socket, and the
rule's `/var/log/haprion/` becomes the rig's directory. Nothing else
about the configuration is the suite's; it is the generator's output.
"""

from __future__ import annotations

import ctypes
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from datetime import UTC, datetime
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from haprion.config import Vip
from haprion.generate import generate
from haprion.proxy_model import load_proxy

from haprion_ui.traffic_logs import parse

ROOT = Path(__file__).resolve().parents[2]
ENABLE = ROOT / "install" / "node" / "haprion-traffic-log-enable"
HOSTNAME = "shop.example.com"
NODE_LOG_ROOT = "/var/log/haprion/"
_PR_SET_PDEATHSIG = 1

OBJECT = """
schema: 1
name: shop
hostnames: [{hostname}]
listen:
  protocol: http
routes:
  - path: /
    backend: web
backends:
  web:
    balance: roundrobin
    health:
      type: disabled
    servers:
      - host: 127.0.0.1
        port: {web}
"""


def die_with_the_test_run() -> None:
    ctypes.CDLL("libc.so.6", use_errno=True).prctl(_PR_SET_PDEATHSIG, signal.SIGKILL)


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_until(condition: object, what: str, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():  # type: ignore[operator]
            return
        time.sleep(0.05)
    raise AssertionError(f"{what} did not happen within {timeout}s")


def echo_server(port: int) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # the name is the library's
            body = b"web ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@unittest.skipUnless(
    shutil.which("haproxy") and shutil.which("rsyslogd"),
    "haproxy and rsyslogd are both required for the live stream test",
)
class TheStreamThroughRealHAProxyAndRealRsyslog(unittest.TestCase):
    directory: tempfile.TemporaryDirectory[str]
    root: Path
    rsyslogd: subprocess.Popen[bytes]
    haproxy: subprocess.Popen[bytes]
    backend: ThreadingHTTPServer
    port: int

    @classmethod
    def setUpClass(cls) -> None:
        cls.directory = tempfile.TemporaryDirectory()
        cls.root = Path(cls.directory.name)
        try:
            cls.start_rsyslog()
            cls.start_haproxy()
        except BaseException:
            cls.stop()
            raise

    @classmethod
    def tearDownClass(cls) -> None:
        cls.stop()

    @classmethod
    def stop(cls) -> None:
        for name in ("haproxy", "rsyslogd"):
            process = getattr(cls, name, None)
            if process is not None and process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
        backend = getattr(cls, "backend", None)
        if backend is not None:
            backend.shutdown()
            backend.server_close()
        cls.directory.cleanup()

    @classmethod
    def start_rsyslog(cls) -> None:
        printed = subprocess.run(  # noqa: S603 - a fixed argv, no shell
            [str(ENABLE), "--print"], capture_output=True, text=True, check=True
        ).stdout
        if NODE_LOG_ROOT not in printed:
            raise AssertionError("the rule no longer names the node's log root")
        rule = printed.replace(NODE_LOG_ROOT, f"{cls.root}/traffic/")
        (cls.root / "traffic").mkdir()
        (cls.root / "work").mkdir()
        configuration = cls.root / "rsyslog.conf"
        configuration.write_text(
            f'global(workDirectory="{cls.root}/work")\n'
            'module(load="imuxsock" SysSock.Use="off")\n'
            f'input(type="imuxsock" Socket="{cls.socket()}" CreatePath="on"'
            ' RateLimit.Interval="0")\n'
            f"{rule}\n"
            #
            # Everything the rule did not stop: the classic stream, as the
            # node's own 49-haproxy.conf would take it.
            #
            f'action(type="omfile" file="{cls.classic()}")\n'
        )
        source = shutil.which("rsyslogd")
        if source is None:
            raise AssertionError("rsyslogd disappeared after the skip check")
        binary = cls.root / "rsyslogd"
        shutil.copy2(source, binary)
        binary.chmod(0o755)
        cls.rsyslogd = subprocess.Popen(  # noqa: S603 - a fixed argv, no shell
            [str(binary), "-n", "-i", str(cls.root / "rsyslogd.pid"), "-f", str(configuration)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=die_with_the_test_run,
        )
        wait_until(cls.socket().exists, "the rig's log socket")

    @classmethod
    def start_haproxy(cls) -> None:
        backend_port = free_port()
        cls.backend = echo_server(backend_port)
        cls.port = free_port()
        proxy = load_proxy("shop", OBJECT.format(hostname=HOSTNAME, web=backend_port).encode())
        layer = generate(
            [proxy],
            vips={"main": Vip(name="main", address="127.0.0.1")},
            default_vip="main",
            networks={},
            ports={"http": cls.port},
            traffic_logging=True,
        )
        release = cls.root / "release"
        (release / "conf.d").mkdir(parents=True)
        (release / "haproxy.cfg").write_text(
            "global\n"
            f"    log {cls.socket()} len 2048 local0\n"
            "    maxconn 100\n"
            "    default-path config\n"
            "defaults\n"
            "    mode http\n"
            "    log global\n"
            "    timeout connect 2s\n"
            "    timeout client 5s\n"
            "    timeout server 5s\n"
        )
        targets = 0
        for name, content in layer.configuration.items():
            targets += content.count("log /dev/log")
            (release / "conf.d" / name).write_text(
                content.replace("log /dev/log", f"log {cls.socket()}")
            )
        if targets != 1:
            raise AssertionError("the generator no longer logs the profile to /dev/log once")
        binary = shutil.which("haproxy")
        if binary is None:
            raise AssertionError("haproxy disappeared after the skip check")
        cls.haproxy = subprocess.Popen(  # noqa: S603 - a fixed argv, no shell
            [binary, "-db", "-f", str(release / "haproxy.cfg"), "-f", str(release / "conf.d")],
            stderr=subprocess.DEVNULL,
            preexec_fn=die_with_the_test_run,
        )

        def listening() -> bool:
            try:
                with socket.create_connection(("127.0.0.1", cls.port), timeout=0.2):
                    return True
            except OSError:
                return False

        wait_until(listening, "haproxy")

    @classmethod
    def socket(cls) -> Path:
        return cls.root / "log"

    @classmethod
    def classic(cls) -> Path:
        return cls.root / "classic.log"

    def day_files(self) -> list[Path]:
        return sorted((self.root / "traffic").glob("*.jsonl"))

    def classic_text(self) -> str:
        return self.classic().read_text() if self.classic().exists() else ""

    def test_one_request_is_one_record_and_everything_else_is_classic(self) -> None:
        started = datetime.now(UTC)
        connection = HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            connection.putrequest("GET", "/?q=must-not-appear", skip_host=True)
            connection.putheader("Host", HOSTNAME)
            connection.endheaders()
            response = connection.getresponse()
            self.assertEqual((response.status, response.read()), (200, b"web ok"))
        finally:
            connection.close()

        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as broken:
            broken.sendall(b"GARBAGE\r\n\r\n")
            self.assertTrue(broken.recv(64).startswith(b"HTTP/1.1 400"))

        wait_until(lambda: "<BADREQ>" in self.classic_text(), "the bad request in the classic log")

        self.haproxy.send_signal(signal.SIGUSR1)
        self.haproxy.wait(timeout=5)
        wait_until(
            lambda: self.classic_text().count("stopped") >= 2, "the soft-stop in the classic log"
        )

        files = self.day_files()
        #
        # The hour's own file (B356), whichever hour the one record fell in.
        #
        hours = {f"traffic-{moment:%Y-%m-%dT%H}.jsonl" for moment in (started, datetime.now(UTC))}
        self.assertEqual(len(files), 1, files)
        self.assertIn(files[0].name, hours)
        lines = files[0].read_bytes().splitlines()
        self.assertEqual(len(lines), 1, lines)
        self.assertTrue(lines[0].startswith(b"{"), lines[0])
        self.assertNotIn(b"must-not-appear", lines[0])

        entry = parse(lines[0], "alpha", "node-a")
        self.assertEqual((entry.host, entry.path, entry.status), (HOSTNAME, "/", 200))
        self.assertEqual(entry.client, "127.0.0.1")
        self.assertTrue(entry.backend and entry.server, entry)

        classic = self.classic_text()
        self.assertNotIn('{"schema"', classic)
        self.assertIn("/?q=must-not-appear", classic)
        self.assertIn("<BADREQ>", classic)
        self.assertEqual(classic.count("stopped"), 2, classic)
