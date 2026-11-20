"""HTTP/2 to a pool, put to a real HAProxy (B517 p. 14).

The servers are a second HAProxy whose listeners speak HTTP/2 and nothing else
(`proto h2` in plain, `alpn h2` over TLS) and answer with the HTTP version the
request arrived in. A pool that spoke HTTP/1.1 to them, or a health check that
did, would leave them down and the site answering 503: an answer of
`ver=2.0` through the generated frontend proves both the traffic and the check.

Skipped where HAProxy is missing.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import time
import unittest
from http.client import HTTPConnection
from pathlib import Path

from haprion.config import Vip
from haprion.generate import generate
from haprion.proxy_model import load_proxy
from tests import spawned
from tests.spawned import NOREUSEPORT, free_port, start_haproxy
from tests.test_generate_behaviour import self_signed, write_release

HAPROXY = shutil.which("haproxy")

SERVERS = """global
{noreuseport}defaults
    mode http
    timeout connect 5s
    timeout client 10s
    timeout server 10s
frontend plain
    bind 127.0.0.1:{plain} proto h2
    http-request return status 200 content-type text/plain lf-string "ver=%[req.ver]"
frontend tls
    bind 127.0.0.1:{tls} ssl crt {pem} alpn h2
    http-request return status 200 content-type text/plain lf-string "ver=%[req.ver]"
"""

SITE = """
schema: 1
name: {name}
hostnames: [{name}.example.com]
listen:
  protocol: http
routes:
  - path: /
    backend: {name}-pool
backends:
  {name}-pool:
    balance: roundrobin
    http_version: "2"
{tls}    health:
      type: http
      path: /healthz
{check}      interval: 500ms
      fast_interval: 500ms
      rise: 1
      fall: 1
    servers:
      - host: 127.0.0.1
        port: {port}
"""


@unittest.skipUnless(HAPROXY, "haproxy is not installed here")
class APoolSpeaksHttp2(unittest.TestCase):
    directory: tempfile.TemporaryDirectory[str]
    running: list[subprocess.Popen[bytes]]
    port: int

    @classmethod
    @spawned.retry_on_taken_port
    def setUpClass(cls) -> None:
        cls.directory = tempfile.TemporaryDirectory()
        root = Path(cls.directory.name)
        certificate, key = self_signed(root, "pool", expired=False)
        pem = root / "pool.pem"
        pem.write_text(certificate.read_text() + key.read_text())
        plain, tls = free_port(), free_port()
        (root / "servers.cfg").write_text(
            SERVERS.format(noreuseport=NOREUSEPORT, plain=plain, tls=tls, pem=pem)
        )
        assert HAPROXY is not None
        cls.running = [start_haproxy(HAPROXY, ["-f", str(root / "servers.cfg")], plain)]
        over_tls = "    tls:\n      verify: none\n"
        sites = {
            "clear": SITE.format(name="clear", tls="", check="", port=plain),
            "secure": SITE.format(name="secure", tls=over_tls, check="", port=tls),
            #
            # The check in plain on the pool's TLS servers, on a port of its own:
            # the case that needs `check-proto h2`.
            #
            "mixed": SITE.format(
                name="mixed",
                tls=over_tls,
                check=f"      tls: false\n      port: {plain}\n",
                port=tls,
            ),
        }
        cls.port = free_port()
        layer = generate(
            [load_proxy(name, text.encode()) for name, text in sites.items()],
            vips={"main": Vip(name="main", address="127.0.0.1")},
            default_vip="main",
            ports={"http": cls.port},
        )
        release = root / "release"
        release.mkdir()
        try:
            cls.running.append(start_haproxy(HAPROXY, write_release(release, layer), cls.port))
        except BaseException:
            cls.tearDownClass()
            raise
        #
        # A server counts as up until its check says otherwise: asked at once,
        # a pool whose check failed answered 200 all the same. Two intervals
        # with `fall: 1` let every check decide first.
        #
        time.sleep(1.2)

    @classmethod
    def tearDownClass(cls) -> None:
        for process in cls.running:
            process.terminate()
            process.wait(timeout=5)
        cls.directory.cleanup()

    def answer(self, host: str) -> tuple[int, str]:
        """The site's answer, after its check has decided."""

        connection = HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            connection.request("GET", "/", headers={"Host": host})
            response = connection.getresponse()
            return response.status, response.read().decode()
        finally:
            connection.close()

    def test_a_plain_pool_speaks_http2_and_its_check_does_too(self) -> None:
        self.assertEqual(self.answer("clear.example.com"), (200, "ver=2.0"))

    def test_a_tls_pool_speaks_http2_by_alpn(self) -> None:
        self.assertEqual(self.answer("secure.example.com"), (200, "ver=2.0"))

    def test_a_plaintext_check_on_a_tls_pool_asks_over_http2(self) -> None:
        self.assertEqual(self.answer("mixed.example.com"), (200, "ver=2.0"))


if __name__ == "__main__":
    unittest.main()
