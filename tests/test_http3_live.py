"""HTTP/3 on a VIP, put to a real HAProxy (B280).

The generated frontend is reached two ways at once: over TCP by Python, which
must be told `alt-svc`, and over QUIC by a second HAProxy acting as the HTTP/3
client. QUIC towards a server is experimental in 3.4 and needs
`expose-experimental-directives` - in this rig's client only, never in what the
generator writes. The client's server line speaks nothing but `quic4@` with
`alpn h3`, so an answer through it is an answer over HTTP/3.

What is proved over HTTP/3 is what matters in production: the site answers,
and an object's `allow_from` still refuses - its rules are `http-request`
rules, which do not care how the request arrived.

Skipped where HAProxy is missing or built without QUIC.
"""

from __future__ import annotations

import shutil
import ssl
import subprocess
import tempfile
import unittest
from http.client import HTTPConnection, HTTPSConnection
from http.server import ThreadingHTTPServer
from pathlib import Path

from haprion.config import Vip
from haprion.generate import generate
from haprion.proxy_model import load_proxy
from tests.spawned import wait_for
from tests.test_generate_behaviour import (
    echo_server,
    free_port,
    self_signed,
    start_haproxy,
    write_release,
)

SITE = """
schema: 1
name: {name}
hostnames: [{name}.example.com]
listen:
  protocol: https
  certificate: site
  redirect_http: false
{extra}routes:
  - path: /
    backend: {name}-pool
backends:
  {name}-pool:
    balance: roundrobin
    health:
      type: disabled
    servers:
      - host: 127.0.0.1
        port: {pool}
"""

CLIENT = """
global
    expose-experimental-directives
defaults
    mode http
    timeout connect 5s
    timeout client 10s
    timeout server 10s
frontend client
    bind 127.0.0.1:{port}
    default_backend h3
backend h3
    server site quic4@127.0.0.1:{site} ssl verify none alpn h3 sni req.hdr(host)
"""


def _has_quic(binary: str) -> bool:
    built = subprocess.run([binary, "-vv"], capture_output=True, text=True, check=False).stdout
    return "+QUIC" in built


HAPROXY = shutil.which("haproxy")


@unittest.skipUnless(HAPROXY and _has_quic(HAPROXY), "haproxy with QUIC is not installed here")
class AVipServesHttp3BesideTcp(unittest.TestCase):
    directory: tempfile.TemporaryDirectory[str]
    servers: list[ThreadingHTTPServer]
    running: list[subprocess.Popen[bytes]]
    site: int
    client: int

    @classmethod
    def setUpClass(cls) -> None:
        cls.directory = tempfile.TemporaryDirectory()
        root = Path(cls.directory.name)
        open_pool, locked_pool = free_port(), free_port()
        cls.servers = [echo_server("open", open_pool), echo_server("locked", locked_pool)]
        wait_for(open_pool)
        wait_for(locked_pool)
        certificates = root / "certs"
        certificates.mkdir()
        certificate, key = self_signed(root, "site", expired=False, common_name="open.example.com")
        (certificates / "site.pem").write_text(key.read_text() + certificate.read_text())
        cls.site = free_port()
        layer = generate(
            [
                load_proxy("open", SITE.format(name="open", pool=open_pool, extra="").encode()),
                load_proxy(
                    "locked",
                    SITE.format(
                        name="locked", pool=locked_pool, extra="allow_from: [office]\n"
                    ).encode(),
                ),
            ],
            vips={"main": Vip(name="main", address="127.0.0.1", http3=True)},
            default_vip="main",
            ports={"http": free_port(), "https": cls.site},
            certificates=("site",),
            networks={"office": ("198.51.100.0/24",)},
        )
        release = root / "release"
        release.mkdir()
        assert HAPROXY is not None
        cls.running = [
            start_haproxy(HAPROXY, write_release(release, layer, certificates), cls.site)
        ]
        cls.client = free_port()
        (root / "client.cfg").write_text(CLIENT.format(port=cls.client, site=cls.site))
        cls.running.append(start_haproxy(HAPROXY, ["-f", str(root / "client.cfg")], cls.client))

    @classmethod
    def tearDownClass(cls) -> None:
        for process in cls.running:
            process.terminate()
            process.wait(timeout=5)
        for server in cls.servers:
            server.shutdown()
        cls.directory.cleanup()

    def over_http3(self, host: str) -> tuple[int, str]:
        connection = HTTPConnection("127.0.0.1", self.client, timeout=10)
        try:
            connection.putrequest("GET", "/", skip_host=True, skip_accept_encoding=True)
            connection.putheader("Host", host)
            connection.endheaders()
            response = connection.getresponse()
            return response.status, response.read().decode()
        finally:
            connection.close()

    def test_the_site_answers_over_quic(self) -> None:
        self.assertEqual(self.over_http3("open.example.com"), (200, "open /"))

    def test_an_access_rule_still_refuses_over_quic(self) -> None:
        self.assertEqual(self.over_http3("locked.example.com")[0], 403)

    def test_tcp_answers_say_where_http3_is(self) -> None:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        connection = HTTPSConnection("127.0.0.1", self.site, timeout=5, context=context)
        try:
            for host in ("open.example.com", "nobody.example.com"):
                connection.putrequest("GET", "/", skip_host=True, skip_accept_encoding=True)
                connection.putheader("Host", host)
                connection.endheaders()
                response = connection.getresponse()
                response.read()
                with self.subTest(host=host):
                    self.assertEqual(response.getheader("alt-svc"), f'h3=":{self.site}"; ma=86400')
        finally:
            connection.close()


if __name__ == "__main__":
    unittest.main()
