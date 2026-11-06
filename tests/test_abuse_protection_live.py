"""The abuse protection's error limit run for real on HAProxy (B425).

Errors are the 4xx answers the servers give. HAProxy's own refusals - the
protection's 429 included - must not count, or a client over the limit that
keeps sending stays refused by its own refusals for as long as it sends.
"""

from __future__ import annotations

import shutil
import tempfile
import threading
import time
import unittest
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from haprion.config import AbuseProtection, Vip
from haprion.generate import generate
from haprion.proxy_model import load_proxy
from tests import spawned
from tests.spawned import start_haproxy
from tests.test_generate_behaviour import free_port, write_release

WINDOW = 3


class _Application(BaseHTTPRequestHandler):
    """200 on every path but /missing, the application's own 404."""

    def do_GET(self) -> None:  # the library's name
        status = 404 if self.path == "/missing" else 200
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *_: object) -> None:
        return


@unittest.skipUnless(shutil.which("haproxy"), "haproxy is not installed here")
class ErrorLimit(unittest.TestCase):
    @spawned.retry_on_taken_port
    def setUp(self) -> None:
        application = ThreadingHTTPServer(("127.0.0.1", 0), _Application)
        self.addCleanup(application.server_close)
        self.addCleanup(application.shutdown)
        threading.Thread(target=application.serve_forever, daemon=True).start()
        proxy = load_proxy(
            "shop",
            f"""schema: 1
name: shop
hostnames: [shop.example.com]
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
        port: {application.server_address[1]}
""".encode(),
        )
        self.port = free_port()
        layer = generate(
            [proxy],
            vips={"main": Vip(name="main", address="127.0.0.1")},
            default_vip="main",
            abuse_protection=AbuseProtection(window=f"{WINDOW}s", max_errors=3),
            ports={"http": self.port},
        )
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        arguments = write_release(Path(directory.name), layer)
        binary = shutil.which("haproxy")
        assert binary is not None
        haproxy = start_haproxy(binary, arguments, self.port)
        self.addCleanup(haproxy.wait, 5)
        self.addCleanup(haproxy.terminate)

    def get(self, path: str = "/") -> int:
        connection = HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            connection.request("GET", path, headers={"Host": "shop.example.com"})
            return connection.getresponse().status
        finally:
            connection.close()

    def test_errors_from_the_servers_over_the_limit_are_refused(self) -> None:
        self.assertEqual([self.get("/missing") for _ in range(4)], [404] * 4)
        self.assertEqual(self.get(), 429)

    def test_a_client_that_keeps_sending_is_let_through_when_the_servers_give_no_errors(
        self,
    ) -> None:
        # Four 404s put the client over the limit (3); everything after is a
        # request the server would answer 200 to. Its own 429s are not errors,
        # so the refusal ends with the window although the client never pauses.
        self.assertEqual([self.get("/missing") for _ in range(4)], [404] * 4)
        deadline = time.monotonic() + WINDOW * 3
        statuses = []
        while time.monotonic() < deadline:
            statuses.append(self.get())
            if statuses[-1] == 200:
                break
            time.sleep(0.2)
        self.assertEqual(statuses[0], 429)
        self.assertEqual(statuses[-1], 200, f"still refused after {len(statuses)} requests")
        self.assertEqual(self.get(), 200)


if __name__ == "__main__":
    unittest.main()
