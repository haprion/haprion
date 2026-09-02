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
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from http.client import HTTPConnection, HTTPSConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from haproxy_mgmt.config import Vip
from haproxy_mgmt.generate import NODE_CERTIFICATE_DIR, generate
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

RESTRICTED = """
schema: 1
name: locked
hostnames: [locked.example.com]
listen:
  protocol: http
allow_from: [office]
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

MAINTENANCE = """
schema: 1
name: closed
hostnames: [closed.example.com]
listen:
  protocol: http
maintenance:
  message: Back at 18:00.
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

GONE = """
schema: 1
name: gone
hostnames: [gone.example.com]
listen:
  protocol: http
unavailable:
  message: The shop is not answering.
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

PAIR = """
schema: 1
name: pair
hostnames: [pair.example.com]
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
        port: {dead}
      - host: 127.0.0.1
        port: {web}
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
        restricted = load_proxy("locked", RESTRICTED.format(web=ports["web"]).encode())
        closed = load_proxy("closed", MAINTENANCE.format(web=ports["web"]).encode())
        #
        # A pool nothing listens on, so the failure is real rather than
        # simulated: HAProxy has to try the connection and fail it.
        #
        gone = load_proxy("gone", GONE.format(web=free_port()).encode())
        #
        # Half the pool refuses connections. Health checks are off on purpose:
        # the question is what happens to a request that is already being
        # dispatched, not whether a check would eventually have removed it.
        #
        pair = load_proxy("pair", PAIR.format(dead=free_port(), web=ports["web"]).encode())
        layer = generate(
            [cls.proxy, restricted, closed, gone, pair],
            vips={"main": Vip(name="main", address="127.0.0.1")},
            default_vip="main",
            networks={"office": ("198.51.100.0/24",)},
            ports={"http": cls.port},
        )
        for name, content in layer.items():
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

    def test_a_restricted_object_refuses_a_visitor_from_outside_its_networks(self) -> None:
        """The allowlist is a deny, and it fires before routing.

        The request comes from the loopback address, which is in none of the
        named networks, so the answer has to be a refusal rather than the site.
        A restriction that quietly fell through to another rule would look like
        it worked right up until somebody checked.
        """

        status, _ = self.request("/", host="locked.example.com")

        self.assertEqual(status, 403)

    def test_an_object_in_maintenance_answers_instead_of_routing(self) -> None:
        """The pool behind it is up and answering, and is still not reached.

        Run in a frontend shared with two serving objects, because that is the
        risk the rule carries: `http-request` rules are evaluated for every
        request on the address, and one written without its host condition
        would take the whole cluster down while looking correct in isolation.
        """

        connection = HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            connection.putrequest("GET", "/", skip_host=True, skip_accept_encoding=True)
            connection.putheader("Host", "closed.example.com")
            connection.endheaders()
            response = connection.getresponse()
            body = response.read().decode()

            self.assertEqual(response.status, 503)
            self.assertEqual(body, "Back at 18:00.")
            self.assertEqual(response.getheader("cache-control"), "no-store")
        finally:
            connection.close()

    def test_a_pool_that_cannot_be_reached_answers_in_the_object_s_own_words(self) -> None:
        """The one page a site cannot serve for itself.

        Nothing is listening on the pool's port, so this is the answer HAProxy
        produces on its own behalf - and without `http-error` it would be the
        grey default that names neither the site nor a way to report it.
        """

        status, body = self.request("/", host="gone.example.com")

        self.assertEqual(status, 503)
        self.assertEqual(body, "The shop is not answering.")

    def test_a_dead_server_in_a_live_pool_costs_nobody_an_error(self) -> None:
        """What `option redispatch` buys, and it is not a small thing.

        Without it a retry goes back to the server that just refused the
        connection, and a pool of two with one dead server answers every other
        request with 503. Measured that way on 3.4.4 on this machine before the
        option was written into the generator.
        """

        for attempt in range(4):
            with self.subTest(attempt):
                status, _ = self.request("/", host="pair.example.com")

                self.assertEqual(status, 200)

    def test_the_other_objects_on_the_address_go_on_serving(self) -> None:
        self.assertEqual(self.request("/", host=HOSTNAME), (200, "web /"))

    def test_the_host_header_may_carry_a_port_and_any_case(self) -> None:
        for host in (HOSTNAME.upper(), f"{HOSTNAME}:80", f"{HOSTNAME.upper()}:8080"):
            with self.subTest(host):
                self.assertEqual(self.request("/", host=host), (200, "web /"))


if __name__ == "__main__":
    unittest.main()


HTTPS_OBJECT = """
schema: 1
name: app
hostnames: [{hostname}]
listen:
  protocol: https
  certificate: {certificate}
  redirect_http: true
  hsts:
    max_age: 31536000
    include_subdomains: true
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

CERTIFICATE = "example-com"


@unittest.skipUnless(
    shutil.which("haproxy") and shutil.which("openssl"),
    "haproxy or openssl is not installed here",
)
class TlsIsServedTheWayTheObjectAsksFor(unittest.TestCase):
    """The https half, proved by connecting rather than by reading the file.

    Three things are worth proving with a real client: that plain http is
    answered with a redirect and nothing else, that the certificate is actually
    served on the TLS listener, and that the Strict-Transport-Security header
    reaches the response - the last one because HAProxy refuses to place that
    header where the first attempt put it, and a silent placement mistake would
    look identical in the golden file.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.directory = tempfile.TemporaryDirectory()
        root = Path(cls.directory.name)
        certificates = root / "certs"
        certificates.mkdir()
        openssl = shutil.which("openssl")
        assert openssl is not None
        subprocess.run(
            [
                openssl,
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                str(certificates / "key.pem"),
                "-out",
                str(certificates / "cert.pem"),
                "-days",
                "1",
                "-nodes",
                "-subj",
                f"/CN={HOSTNAME}",
            ],
            capture_output=True,
            check=True,
        )
        (certificates / f"{CERTIFICATE}.pem").write_bytes(
            (certificates / "cert.pem").read_bytes() + (certificates / "key.pem").read_bytes()
        )

        backend = free_port()
        cls.server = echo_server("web", backend)
        wait_for(backend)

        cls.http_port = free_port()
        cls.https_port = free_port()
        document = HTTPS_OBJECT.format(
            hostname=HOSTNAME, certificate=CERTIFICATE, web=backend
        ).encode()

        (root / "0000-core.cfg").write_text(CORE)
        layer = generate(
            [load_proxy("app", document)],
            vips={"main": Vip(name="main", address="127.0.0.1")},
            default_vip="main",
            certificates=(CERTIFICATE,),
            ports={"http": cls.http_port, "https": cls.https_port},
        )
        for name, content in layer.items():
            (root / name).write_text(content.replace(NODE_CERTIFICATE_DIR, str(certificates)))

        arguments: list[str] = []
        for path in sorted(root.iterdir()):
            if path.is_file():
                arguments += ["-f", str(path)]
        binary = shutil.which("haproxy")
        assert binary is not None
        cls.haproxy = subprocess.Popen([binary, *arguments], stderr=subprocess.DEVNULL)
        wait_for(cls.https_port)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.haproxy.terminate()
        cls.haproxy.wait(timeout=5)
        cls.server.shutdown()
        cls.directory.cleanup()

    def test_plain_http_is_redirected_and_serves_nothing(self) -> None:
        connection = HTTPConnection("127.0.0.1", self.http_port, timeout=5)
        try:
            connection.putrequest("GET", "/secret", skip_host=True, skip_accept_encoding=True)
            connection.putheader("Host", HOSTNAME)
            connection.endheaders()
            response = connection.getresponse()

            self.assertEqual(response.status, 301)
            #
            # The redirect keeps the requested name and path and adds no port:
            # `redirect scheme https` rewrites the scheme only, so the browser
            # asks for the standard port. The path survives, which matters -
            # a redirect that drops it sends everybody to the front page.
            #
            self.assertEqual(response.getheader("Location"), f"https://{HOSTNAME}/secret")
        finally:
            connection.close()

    def test_the_object_is_served_over_tls_and_promises_https(self) -> None:
        context = ssl.create_default_context()
        #
        # The certificate is generated for this test and signed by nobody. The
        # question here is what HAProxy serves and which headers it adds, not
        # whether a throwaway certificate chains to a public root.
        #
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        connection = HTTPSConnection("127.0.0.1", self.https_port, timeout=5, context=context)
        try:
            connection.putrequest("GET", "/", skip_host=True, skip_accept_encoding=True)
            connection.putheader("Host", HOSTNAME)
            connection.endheaders()
            response = connection.getresponse()

            self.assertEqual(response.status, 200)
            self.assertEqual(response.read().decode(), "web /")
            self.assertEqual(
                response.getheader("Strict-Transport-Security"),
                "max-age=31536000; includeSubDomains",
            )
        finally:
            connection.close()


def header_server(port: int) -> ThreadingHTTPServer:
    """A backend that answers with the request headers it was handed.

    The only way to see what a backend actually learns about a visitor. The
    file says which headers are written; this says which ones arrive.
    """

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - the name is the library's
            body = "".join(f"{name}: {value}\n" for name, value in self.headers.items()).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_: object) -> None:
            """Silence."""

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


class WhatTheBackendLearnsAboutTheVisitor(unittest.TestCase):
    """Behind a proxy an application knows nothing it is not told.

    Measured before this was built: a request that arrived over TLS reached the
    backend as plain HTTP carrying `host`, `user-agent` and `accept`, and
    nothing else. The client address and the scheme exist only in the proxy.
    """

    @classmethod
    def setUpClass(cls) -> None:
        backend = free_port()
        cls.server = header_server(backend)
        wait_for(backend)

        cls.port = free_port()
        cls.directory = tempfile.TemporaryDirectory()
        root = Path(cls.directory.name)
        (root / "0000-core.cfg").write_text(CORE)
        document = (
            GONE.format(web=backend)
            .encode()
            .replace(b"unavailable:\n  message: The shop is not answering.\n", b"")
        )
        layer = generate(
            [load_proxy("gone", document)],
            vips={"main": Vip(name="main", address="127.0.0.1")},
            default_vip="main",
            #
            # Loopback is the address every request in this test arrives from,
            # so it stands in for the front-line proxy a cluster names.
            #
            trusted_proxies=("198.51.100.0/24",),
            ports={"http": cls.port},
        )
        for name, content in layer.items():
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
        cls.server.shutdown()
        cls.directory.cleanup()

    def headers(self, sent: dict[str, str] | None = None) -> dict[str, str]:
        connection = HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            connection.putrequest("GET", "/", skip_host=True, skip_accept_encoding=True)
            connection.putheader("Host", "gone.example.com")
            for name, value in (sent or {}).items():
                connection.putheader(name, value)
            connection.endheaders()
            body = connection.getresponse().read().decode()
        finally:
            connection.close()
        return {
            name.strip().lower(): value.strip()
            for name, _, value in (line.partition(":") for line in body.splitlines())
        }

    def test_the_backend_is_told_the_address_and_the_scheme(self) -> None:
        headers = self.headers()

        self.assertEqual(headers["x-forwarded-for"], "127.0.0.1")
        self.assertEqual(headers["x-forwarded-proto"], "http")
        self.assertEqual(headers["x-forwarded-host"], "gone.example.com")

    def test_a_header_a_visitor_sent_is_thrown_away(self) -> None:
        """They are ordinary request headers, so anybody can claim to be anybody.

        The request arrives from loopback, which is in no trusted network, so
        what it claims about itself counts for nothing.
        """

        headers = self.headers(
            {
                "X-Forwarded-For": "203.0.113.99",
                "X-Forwarded-Proto": "https",
                "X-Forwarded-Host": "bank.example.com",
            }
        )

        self.assertEqual(headers["x-forwarded-for"], "127.0.0.1")
        self.assertEqual(headers["x-forwarded-proto"], "http")
        self.assertEqual(headers["x-forwarded-host"], "gone.example.com")
