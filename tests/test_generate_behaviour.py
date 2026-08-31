"""What HAProxy actually does with what we generate.

The golden files prove the generator is deterministic. They cannot prove it is
right: a wrong rule frozen into a golden file is just as stable as a correct
one. This test runs the generated configuration in a real HAProxy, sends real
requests through it, and holds the result against what `route_match` says
should happen.

It exists because that difference is not theoretical. The first version of the
generator put path rewrites in the frontend, which passed `haproxy -c` and
produced golden files that looked entirely reasonable - and routed `/api/orders`
to the wrong backend, because HAProxy evaluates `http-request` rules before
`use_backend` and the rewritten path no longer matched the ACL that was about
to select the pool. Only a request through a running process shows that.

Skipped where HAProxy is not installed. A machine that cannot run the process
cannot answer the question, and a green result there would mean nothing.
"""

from __future__ import annotations

import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from haproxy_mgmt.generate import generate
from haproxy_mgmt.proxy_model import load_proxy
from haproxy_mgmt.route_match import order_routes, rewrite, select

HOSTNAME = "shop.example.com"

#
# One echo server per pool, so a response identifies both which backend HAProxy
# chose and what path that backend was handed. Health checks are off: the
# question here is routing, and a pool marked down would answer every case with
# the same 503.
#
POOLS = ("web", "api", "orders")

OBJECT = """
schema: 1
name: shop
hostnames: [{hostname}]
listen:
  protocol: http
routes:
  - path: /
    backend: web
  - path: /api
    backend: api
    strip_prefix: /api
    add_prefix: /v2
  - path: /api/v1/orders
    backend: orders
  - path: /health
    match: exact
    backend: web
backends:
  web:
    balance: roundrobin
    health:
      type: disabled
    servers:
      - host: 127.0.0.1
        port: {web}
  api:
    balance: roundrobin
    health:
      type: disabled
    servers:
      - host: 127.0.0.1
        port: {api}
  orders:
    balance: roundrobin
    health:
      type: disabled
    servers:
      - host: 127.0.0.1
        port: {orders}
"""

CORE = """
global
    daemon
    maxconn 100
defaults
    mode http
    timeout connect 2s
    timeout client 5s
    timeout server 5s
"""


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def echo_server(pool: str, port: int) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - the name is the library's
            body = f"{pool} {self.path}".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_: object) -> None:
            """Silence. The test's own output is the interesting one."""

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def wait_for(port: int, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.02)
    raise AssertionError(f"nothing accepted connections on {port}")


@unittest.skipUnless(shutil.which("haproxy"), "haproxy is not installed here")
class TheGeneratedConfigurationRoutesTheWayTheSemanticsSay(unittest.TestCase):
    servers: dict[str, ThreadingHTTPServer]
    haproxy: subprocess.Popen[bytes]
    directory: tempfile.TemporaryDirectory[str]
    port: int

    @classmethod
    def setUpClass(cls) -> None:
        ports = {pool: free_port() for pool in POOLS}
        cls.servers = {pool: echo_server(pool, port) for pool, port in ports.items()}
        for port in ports.values():
            wait_for(port)

        cls.port = free_port()
        document = OBJECT.format(hostname=HOSTNAME, **ports).encode()
        cls.proxy = load_proxy("shop", document)

        cls.directory = tempfile.TemporaryDirectory()
        root = Path(cls.directory.name)
        (root / "0000-core.cfg").write_text(CORE)
        for name, content in generate([cls.proxy], http_bind=f"127.0.0.1:{cls.port}").items():
            (root / name).write_text(content)

        arguments: list[str] = []
        for path in sorted(root.iterdir()):
            arguments += ["-f", str(path)]
        binary = shutil.which("haproxy")
        assert binary is not None
        cls.haproxy = subprocess.Popen([binary, *arguments], stderr=subprocess.DEVNULL)
        wait_for(cls.port)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.haproxy.terminate()
        cls.haproxy.wait(timeout=5)
        for server in cls.servers.values():
            server.shutdown()
        cls.directory.cleanup()

    def request(self, target: str, host: str = HOSTNAME) -> tuple[int, str]:
        """One request through the proxy, as its status and body.

        Spoken over `http.client` rather than a URL opener, because the target
        is a raw request line: `/api%2Fv1` has to arrive exactly as written,
        and anything that parses a URL first is free to normalise it and quietly
        test something other than what the case says.
        """

        connection = HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            connection.putrequest("GET", target, skip_host=True, skip_accept_encoding=True)
            connection.putheader("Host", host)
            connection.endheaders()
            response = connection.getresponse()
            return response.status, response.read().decode()
        finally:
            connection.close()

    def through_haproxy(self, target: str) -> tuple[str, str]:
        status, body = self.request(target)
        self.assertEqual(status, 200, body)
        pool, _, path = body.partition(" ")
        return pool, path

    def test_haproxy_agrees_with_the_frozen_semantics_on_every_case(self) -> None:
        """The whole point: one truth, checked against the real thing.

        Each case is a request path from the plan's frozen rules. The expected
        answer is not written down here - it is computed by `route_match`, so
        the two implementations of the semantics have to agree, and a change to
        one without the other fails.
        """

        ordered = order_routes(self.proxy.routes)
        cases = [
            "/",
            "/about",
            "/api",
            "/api/",
            "/api/orders",
            "/apix",
            "/apix/v1",
            "/api/v1/orders",
            "/api/v1/orders/17",
            "/health",
            "/health/",
            "/healthz",
            "/api/orders?id=7&sort=a%20b",
            "/shop?next=/api/v1/orders",
            "/a%20b",
            "/api%2Fv1",
        ]

        for target in cases:
            with self.subTest(target):
                route = select(ordered, target)
                assert route is not None, target

                self.assertEqual(
                    self.through_haproxy(target),
                    (route.backend, rewrite(route, target)),
                )

    def test_a_request_for_another_host_reaches_no_object(self) -> None:
        """The host ACL is a condition, not decoration.

        With no object claiming the name there is no `use_backend` that holds
        and no default, so HAProxy answers 503 itself. That is the intended
        outcome: an unclaimed hostname must not fall into whichever object
        happens to be listed first.
        """

        status, _ = self.request("/", host="other.example.net")

        self.assertEqual(status, 503)

    def test_the_host_header_may_carry_a_port_and_any_case(self) -> None:
        for host in (HOSTNAME.upper(), f"{HOSTNAME}:80", f"{HOSTNAME.upper()}:8080"):
            with self.subTest(host):
                self.assertEqual(self.request("/", host=host), (200, "web /"))


if __name__ == "__main__":
    unittest.main()
