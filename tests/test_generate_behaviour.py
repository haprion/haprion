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

import ast
import base64
import hashlib
import os
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

from haproxy_mgmt.config import AbuseProtection, Vip
from haproxy_mgmt.generate import NODE_CERTIFICATE_DIR, GeneratedLayer, generate
from haproxy_mgmt.proxy_model import load_proxy
from haproxy_mgmt.route_match import order_routes, rewrite, select
from tests import spawned
from tests.spawned import wait_for

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
  - path: /legacy
    redirect:
      location: https://example.net/store
      status: 308
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
  message: Back at 18:00, refunds cost $0.
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

EDITED = """
schema: 1
name: edited
hostnames: [edited.example.com]
listen:
  protocol: http
headers:
  request:
    set:
      X-Tenant: '100% acme'
    add:
      X-Trace: '1'
    delete: [X-Debug]
  response:
    set:
      X-Frame-Options: DENY
    delete: [Server]
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
    default-path config
defaults
    mode http
    timeout connect 2s
    timeout client 5s
    timeout server 5s
"""


def write_release(root: Path, layer: GeneratedLayer, certificates: Path | None = None) -> list[str]:
    """Lay a generated layer out the way a release is, and return HAProxy's arguments.

    `conf.d` and `crt-lists` as siblings under one root, because that is the
    shape the node fetches and the shape a bind line's relative path is written
    against. Writing them flat and passing each file with `-f` would pass the
    certificate list to HAProxy as configuration, which is exactly the mistake
    the separate directory exists to make impossible.

    `default-path config` is in the core file for the same reason it has to be
    in a real cluster's: without it a relative path resolves against whatever
    directory the process happened to start in, and the node validates a copy
    of the release before installing it - two different directories, one line.
    """

    def local(content: str) -> str:
        return (
            content
            if certificates is None
            else content.replace(NODE_CERTIFICATE_DIR, str(certificates))
        )

    (root / "conf.d").mkdir(exist_ok=True)
    (root / "haproxy.cfg").write_text(CORE)
    for name, content in layer.configuration.items():
        (root / "conf.d" / name).write_text(local(content))
    if layer.certificate_lists:
        (root / "crt-lists").mkdir(exist_ok=True)
        for name, content in layer.certificate_lists.items():
            (root / "crt-lists" / name).write_text(local(content))
    return ["-f", str(root / "haproxy.cfg"), "-f", str(root / "conf.d")]


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


def start_haproxy(binary: str, arguments: list[str], port: int) -> subprocess.Popen[bytes]:
    """One HAProxy, bound to this run's lifetime and proved to be listening.

    A start that never comes up is terminated here rather than left to a
    teardown that will not be called - `setUpClass` raising means the class
    never gets one.
    """

    #
    # `-db` is what makes the process this returns the actual HAProxy. The core
    # fixture says `daemon`, as a real one does, so without this HAProxy forks
    # into the background and the child Python is holding exits at once -
    # `terminate()` then kills something that has already gone, `wait()` returns
    # cleanly, and the server itself runs on with init as its parent.
    #
    # Every spawn leaked that way, in every run, until the machine ran out of
    # memory. The flag is a harness concern and not a change to what is being
    # tested: the configuration under test is still the one with `daemon` in it.
    #
    process = subprocess.Popen(
        [binary, "-db", *arguments],
        stderr=subprocess.DEVNULL,
        #
        # The other half of the B81 fix, and the half teardown cannot provide:
        # a run that is interrupted, times out, or is killed never reaches one.
        #
        preexec_fn=spawned.die_with_the_test_run,
    )
    try:
        wait_for(port)
    except BaseException:
        process.terminate()
        process.wait(timeout=5)
        raise
    return process


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
        arguments = write_release(root, layer)
        binary = shutil.which("haproxy")
        assert binary is not None
        cls.haproxy = start_haproxy(binary, arguments, cls.port)

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

    def test_a_route_may_answer_with_a_redirect_instead_of_a_pool(self) -> None:
        """Served from a backend, so it takes part in the same longest-prefix order.

        A redirect written as an `http-request` rule in the frontend would be
        evaluated before any `use_backend`, and a short redirect path would then
        shadow a longer route that should have won.
        """

        connection = HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            connection.putrequest("GET", "/legacy", skip_host=True, skip_accept_encoding=True)
            connection.putheader("Host", HOSTNAME)
            connection.endheaders()
            response = connection.getresponse()
            response.read()

            self.assertEqual(response.status, 308)
            self.assertEqual(response.getheader("location"), "https://example.net/store")
        finally:
            connection.close()

    def test_a_longer_route_still_wins_over_a_shorter_redirect(self) -> None:
        """Segment matching, not text matching: `/legacyx` is a different path."""

        self.assertEqual(self.through_haproxy("/legacyx"), ("web", "/legacyx"))

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
            self.assertEqual(body, "Back at 18:00, refunds cost $0.")
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

        layer = generate(
            [load_proxy("app", document)],
            vips={"main": Vip(name="main", address="127.0.0.1")},
            default_vip="main",
            certificates=(CERTIFICATE,),
            ports={"http": cls.http_port, "https": cls.https_port},
        )
        arguments = write_release(root, layer, certificates)
        binary = shutil.which("haproxy")
        assert binary is not None
        cls.haproxy = start_haproxy(binary, arguments, cls.https_port)

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


@unittest.skipUnless(shutil.which("haproxy"), "haproxy is not installed here")
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
        document = (
            GONE.format(web=backend)
            .encode()
            .replace(b"unavailable:\n  message: The shop is not answering.\n", b"")
        )
        layer = generate(
            [
                load_proxy("gone", document),
                load_proxy("edited", EDITED.format(web=backend).encode()),
            ],
            vips={"main": Vip(name="main", address="127.0.0.1")},
            default_vip="main",
            #
            # Loopback is the address every request in this test arrives from,
            # so it stands in for the front-line proxy a cluster names.
            #
            trusted_proxies=("198.51.100.0/24",),
            ports={"http": cls.port},
        )
        arguments = write_release(root, layer)
        binary = shutil.which("haproxy")
        assert binary is not None
        cls.haproxy = start_haproxy(binary, arguments, cls.port)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.haproxy.terminate()
        cls.haproxy.wait(timeout=5)
        cls.server.shutdown()
        cls.directory.cleanup()

    def headers(
        self, sent: dict[str, str] | None = None, host: str = "gone.example.com"
    ) -> dict[str, str]:
        connection = HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            connection.putrequest("GET", "/", skip_host=True, skip_accept_encoding=True)
            connection.putheader("Host", host)
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


@unittest.skipUnless(shutil.which("haproxy"), "haproxy is not installed here")
class TheBrakeOnTrafficThatIsNotAVisitor(unittest.TestCase):
    """Proved by flooding a real HAProxy, not by reading the rule.

    A threshold written into a file says nothing about whether the counter it
    names is the one HAProxy increments.
    """

    @classmethod
    def setUpClass(cls) -> None:
        backend = free_port()
        cls.server = echo_server("web", backend)
        wait_for(backend)

        cls.port = free_port()
        cls.directory = tempfile.TemporaryDirectory()
        root = Path(cls.directory.name)
        document = (
            GONE.format(web=backend)
            .encode()
            .replace(b"unavailable:\n  message: The shop is not answering.\n", b"")
        )
        layer = generate(
            [load_proxy("gone", document)],
            vips={"main": Vip(name="main", address="127.0.0.1")},
            default_vip="main",
            abuse_protection=AbuseProtection(window="10s", max_requests=5),
            ports={"http": cls.port},
        )
        arguments = write_release(root, layer)
        binary = shutil.which("haproxy")
        assert binary is not None
        cls.haproxy = start_haproxy(binary, arguments, cls.port)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.haproxy.terminate()
        cls.haproxy.wait(timeout=5)
        cls.server.shutdown()
        cls.directory.cleanup()

    def status(self) -> int:
        connection = HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            connection.putrequest("GET", "/", skip_host=True, skip_accept_encoding=True)
            connection.putheader("Host", "gone.example.com")
            connection.endheaders()
            response = connection.getresponse()
            response.read()
            return int(response.status)
        finally:
            connection.close()

    def test_a_burst_is_served_until_the_threshold_and_refused_after(self) -> None:
        """429, not a silent drop: a retry loop that can read a code can be fixed."""

        answers = [self.status() for _ in range(12)]

        self.assertEqual(answers[0], 200)
        self.assertIn(429, answers)
        self.assertEqual(answers[-1], 429)


@unittest.skipUnless(shutil.which("haproxy"), "haproxy is not installed here")
class HeaderEditsReachTheTraffic(unittest.TestCase):
    """Read off a running proxy, because the file cannot prove interpretation.

    A value written into a configuration line is not the value that arrives:
    `%` is a log-format alias, and `$NAME` is expanded inside double quotes.
    Both were measured on 3.4.4 on this machine, and both decided how the
    generator quotes.
    """

    @classmethod
    def setUpClass(cls) -> None:
        backend = free_port()
        cls.server = header_server(backend)
        wait_for(backend)

        cls.port = free_port()
        cls.directory = tempfile.TemporaryDirectory()
        root = Path(cls.directory.name)
        layer = generate(
            [load_proxy("edited", EDITED.format(web=backend).encode())],
            vips={"main": Vip(name="main", address="127.0.0.1")},
            default_vip="main",
            ports={"http": cls.port},
        )
        arguments = write_release(root, layer)
        binary = shutil.which("haproxy")
        assert binary is not None
        cls.haproxy = start_haproxy(binary, arguments, cls.port)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.haproxy.terminate()
        cls.haproxy.wait(timeout=5)
        cls.server.shutdown()
        cls.directory.cleanup()

    def exchange(self, sent: dict[str, str]) -> tuple[dict[str, str], dict[str, str]]:
        connection = HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            connection.putrequest("GET", "/", skip_host=True, skip_accept_encoding=True)
            connection.putheader("Host", "edited.example.com")
            for name, value in sent.items():
                connection.putheader(name, value)
            connection.endheaders()
            response = connection.getresponse()
            body = response.read().decode()
            answered = {name.lower(): value for name, value in response.getheaders()}
        finally:
            connection.close()
        received = {
            name.strip().lower(): value.strip()
            for name, _, value in (line.partition(":") for line in body.splitlines())
        }
        return received, answered

    def test_a_percent_sign_arrives_as_one_percent_sign(self) -> None:
        """Written as `%%`, because HAProxy reads a single one as an alias."""

        received, _ = self.exchange({})

        self.assertEqual(received["x-tenant"], "100% acme")

    def test_a_header_is_added_and_another_removed_on_the_way_in(self) -> None:
        received, _ = self.exchange({"X-Debug": "please"})

        self.assertEqual(received["x-trace"], "1")
        self.assertNotIn("x-debug", received)

    def test_the_answer_is_edited_on_the_way_out(self) -> None:
        _, answered = self.exchange({})

        self.assertEqual(answered["x-frame-options"], "DENY")
        self.assertNotIn("server", answered)


TCP_OBJECT = """
schema: 1
name: db
listen:
  protocol: tcp
  port: {port}
backend: pool
backends:
  pool:
    balance: leastconn
    health:
      type: disabled
    servers:
      - host: 127.0.0.1
        port: {web}
"""


@unittest.skipUnless(shutil.which("haproxy"), "haproxy is not installed here")
class ARawPortIsForwardedAsItArrives(unittest.TestCase):
    """A tcp object proved by speaking through it, not by reading the file.

    Worth a running process because everything HTTP-shaped is *ignored* in
    `mode tcp` rather than refused - measured on 3.4.4 on this machine - so a
    configuration that reads correctly can behave nothing like it reads.
    """

    @classmethod
    def setUpClass(cls) -> None:
        backend = free_port()
        cls.server = echo_server("web", backend)
        wait_for(backend)

        cls.port = free_port()
        cls.directory = tempfile.TemporaryDirectory()
        root = Path(cls.directory.name)
        layer = generate(
            [load_proxy("db", TCP_OBJECT.format(port=cls.port, web=backend).encode())],
            vips={"main": Vip(name="main", address="127.0.0.1")},
            default_vip="main",
        )
        arguments = write_release(root, layer)
        binary = shutil.which("haproxy")
        assert binary is not None
        cls.haproxy = start_haproxy(binary, arguments, cls.port)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.haproxy.terminate()
        cls.haproxy.wait(timeout=5)
        cls.server.shutdown()
        cls.directory.cleanup()

    def test_the_stream_reaches_the_pool_untouched(self) -> None:
        """The backend behind it happens to speak HTTP; the proxy does not care."""

        connection = HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            connection.putrequest("GET", "/raw", skip_host=True, skip_accept_encoding=True)
            connection.putheader("Host", "anything.example.com")
            connection.endheaders()
            response = connection.getresponse()
            body = response.read().decode()
        finally:
            connection.close()

        self.assertEqual((response.status, body), (200, "web /raw"))

    def test_no_forwarded_header_is_added_on_the_way(self) -> None:
        """`option forwardfor` is HTTP-only, and writing it would be ignored anyway."""

        directory = Path(self.directory.name)
        written = (directory / "conf.d" / "1001-db.cfg").read_text()

        self.assertIn("mode tcp", written)
        self.assertNotIn("forwardfor", written)


BACKEND_TLS = """
schema: 1
name: secure
hostnames: [secure.example.com]
listen:
  protocol: http
routes:
  - path: /
    backend: web
backends:
  web:
    balance: roundrobin
    tls:
      verify: {verify}
    health:
      type: disabled
    servers:
      #
      # A name rather than the address, because `verify` requires one: the
      # generator sends it as SNI, and the model refuses a verified pool that
      # has only an address to send. `localhost` is the same machine either
      # way, so what these cases measure is unchanged.
      #
      - host: localhost
        port: {web}
"""


BACKEND_TLS_POLICY = """
schema: 1
name: secure
hostnames: [secure.example.com]
listen:
  protocol: http
routes:
  - path: /
    backend: web
backends:
  web:
    balance: roundrobin
    tls:
      verify: none
      policy: {policy}
    health:
      type: disabled
    servers:
      - host: 127.0.0.1
        port: {web}
"""


def self_signed(
    directory: Path, name: str, *, expired: bool, common_name: str = "127.0.0.1"
) -> tuple[Path, Path]:
    """A certificate no trust store knows, optionally already out of date.

    Two separate reasons a peer should be rejected, and `verify none` ignores
    both. Proving them apart matters because they fail differently in the
    world: an unknown issuer is a deployment that was never finished, and an
    expired certificate is one that was and then lapsed.
    """

    openssl = shutil.which("openssl")
    assert openssl is not None
    key = directory / f"{name}-key.pem"
    certificate = directory / f"{name}-cert.pem"
    validity = (
        ["-not_before", "20200101000000Z", "-not_after", "20200102000000Z"]
        if expired
        else ["-days", "1"]
    )
    subprocess.run(
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(key),
            "-out",
            str(certificate),
            "-nodes",
            "-subj",
            f"/CN={common_name}",
            "-addext",
            f"subjectAltName=DNS:{common_name}"
            if not common_name[0].isdigit()
            else f"subjectAltName=IP:{common_name}",
            *validity,
        ],
        capture_output=True,
        check=True,
    )
    return certificate, key


def plain_server(port: int) -> ThreadingHTTPServer:
    """The same answers over no TLS at all.

    A management port that speaks plain HTTP on a machine whose traffic port
    speaks TLS - which is an ordinary thing for an appliance to do, and the
    reason `no-check-ssl` has to be expressible.
    """

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - the name is the library's
            body = b"reached"
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


def tls_server(port: int, certificate: Path, key: Path) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - the name is the library's
            body = b"reached"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_: object) -> None:
            """Silence."""

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # The same floor the probe holds its own connections to, so this backend
    # answers the way a real one would rather than however OpenSSL was built.
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=str(certificate), keyfile=str(key))
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@unittest.skipUnless(
    shutil.which("haproxy") and shutil.which("openssl"),
    "haproxy or openssl is not installed here",
)
class ReachingAPoolOverTls(unittest.TestCase):
    """What `verify` actually decides, proved against a real TLS backend.

    The generator writes one of two lines and there is no third: `ssl verify
    none` for `verify: none`, and `ssl verify required ca-file @system-ca` for
    `verify: system`. Reading the file cannot tell whether the second one is
    enforced - HAProxy refuses `verify required` without a CA outright, so a
    silent "verifying nothing" is not among the outcomes - but only a
    connection can show that the first really does accept what the second
    rejects.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.directory = tempfile.TemporaryDirectory()
        cls.root = Path(cls.directory.name)
        cls.servers: list[ThreadingHTTPServer] = []
        cls.running: list[subprocess.Popen[bytes]] = []

    @classmethod
    def tearDownClass(cls) -> None:
        for process in cls.running:
            process.terminate()
            process.wait(timeout=5)
        for server in cls.servers:
            server.shutdown()
        cls.directory.cleanup()

    def reach(self, *, verify: str, expired: bool) -> int:
        """One request through a proxy whose pool speaks TLS, as a status."""

        name = f"{verify}-{'expired' if expired else 'unknown'}"
        certificate, key = self_signed(self.root, name, expired=expired)
        backend = free_port()
        server = tls_server(backend, certificate, key)
        self.servers.append(server)
        wait_for(backend)

        port = free_port()
        root = self.root / name
        root.mkdir()
        layer = generate(
            [load_proxy("secure", BACKEND_TLS.format(verify=verify, web=backend).encode())],
            vips={"main": Vip(name="main", address="127.0.0.1")},
            default_vip="main",
            ports={"http": port},
        )
        arguments = write_release(root, layer)
        binary = shutil.which("haproxy")
        assert binary is not None
        self.running.append(start_haproxy(binary, arguments, port))

        connection = HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            connection.putrequest("GET", "/", skip_host=True, skip_accept_encoding=True)
            connection.putheader("Host", "secure.example.com")
            connection.endheaders()
            return int(connection.getresponse().status)
        finally:
            connection.close()

    def test_verify_none_accepts_a_certificate_no_trust_store_knows(self) -> None:
        self.assertEqual(self.reach(verify="none", expired=False), 200)

    def test_verify_none_accepts_an_expired_certificate_too(self) -> None:
        """The cost of the setting, stated rather than assumed.

        `none` is not "check the dates but not the issuer" - it is no check at
        all, and a pool whose certificate lapsed keeps being served.
        """

        self.assertEqual(self.reach(verify="none", expired=True), 200)

    def test_verify_system_refuses_an_issuer_the_system_does_not_trust(self) -> None:
        """503, because the connection to the pool is what fails."""

        self.assertEqual(self.reach(verify="system", expired=False), 503)

    def test_verify_system_refuses_an_expired_certificate(self) -> None:
        self.assertEqual(self.reach(verify="system", expired=True), 503)


CHECKED_ON_ITS_OWN_PORT = """
schema: 1
name: secure
hostnames: [secure.example.com]
listen:
  protocol: http
routes:
  - path: /
    backend: web
backends:
  web:
    balance: roundrobin
    tls:
      verify: none
    health:
      type: http
      path: /
      port: {health}
    servers:
      - host: 127.0.0.1
        port: {web}
"""


PLAINTEXT_CHECK_ON_A_TLS_POOL = """
schema: 1
name: secure
hostnames: [secure.example.com]
listen:
  protocol: http
routes:
  - path: /
    backend: web
backends:
  web:
    balance: roundrobin
    tls:
      verify: none
    health:
      type: http
      tls: false
      path: /
      port: {health}
    servers:
      - host: 127.0.0.1
        port: {web}
"""


@unittest.skipUnless(
    shutil.which("haproxy") and shutil.which("openssl"),
    "haproxy or openssl is not installed here",
)
class CheckingATlsPoolOnAnotherPort(unittest.TestCase):
    """A pool over TLS, checked on a port of its own.

    HAProxy sends checks over TLS on its own when the check goes to the traffic
    port, and stops doing so the moment the check is given a port - documented
    under `ssl` in 3.4.4 on this machine. A management port on a TLS pool is an
    ordinary thing to configure, and without `check-ssl` the probe arrives as
    plaintext at a port that speaks TLS: every server is marked down and the
    pool answers 503 while the file reads as though it should work.

    Proved against a real HAProxy rather than by reading the emitted line,
    because what is at stake is not the word on the server line but whether the
    servers come up.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.directory = tempfile.TemporaryDirectory()
        cls.root = Path(cls.directory.name)
        cls.servers: list[ThreadingHTTPServer] = []
        cls.running: list[subprocess.Popen[bytes]] = []

    @classmethod
    def tearDownClass(cls) -> None:
        for process in cls.running:
            process.terminate()
            process.wait(timeout=5)
        for server in cls.servers:
            server.shutdown()
        cls.directory.cleanup()

    def test_the_pool_is_served_because_the_check_speaks_tls_too(self) -> None:
        certificate, key = self_signed(self.root, "checked", expired=False)
        web = free_port()
        health = free_port()
        for port in (web, health):
            server = tls_server(port, certificate, key)
            self.servers.append(server)
            wait_for(port)

        port = free_port()
        root = self.root / "checked"
        root.mkdir()
        layer = generate(
            [
                load_proxy(
                    "secure",
                    CHECKED_ON_ITS_OWN_PORT.format(web=web, health=health).encode(),
                )
            ],
            vips={"main": Vip(name="main", address="127.0.0.1")},
            default_vip="main",
            ports={"http": port},
        )
        arguments = write_release(root, layer)
        binary = shutil.which("haproxy")
        assert binary is not None
        self.running.append(start_haproxy(binary, arguments, port))

        #
        # Two checks at two seconds have to pass before a server rises, so the
        # first request after the proxy accepts connections is too early to say
        # anything either way.
        #
        deadline = time.monotonic() + 15
        status = 0
        while time.monotonic() < deadline:
            connection = HTTPConnection("127.0.0.1", port, timeout=5)
            try:
                connection.putrequest("GET", "/", skip_host=True, skip_accept_encoding=True)
                connection.putheader("Host", "secure.example.com")
                connection.endheaders()
                status = int(connection.getresponse().status)
            finally:
                connection.close()
            if status == 200:
                break
            time.sleep(0.5)
        self.assertEqual(status, 200)

    def test_a_plaintext_check_port_on_a_tls_pool_brings_the_servers_up(self) -> None:
        """The combination that could not be written before `no-check-ssl`.

        An appliance whose traffic port speaks TLS and whose management port
        does not. Without the opt-out the check is sent as TLS to a plaintext
        port, which is `L6RSP` and a server marked down - so a 200 here says
        the word did what it says.
        """

        certificate, key = self_signed(self.root, "opted-out", expired=False)
        web = free_port()
        health = free_port()
        self.servers.append(tls_server(web, certificate, key))
        wait_for(web)
        self.servers.append(plain_server(health))
        wait_for(health)

        port = free_port()
        root = self.root / "opted-out"
        root.mkdir()
        layer = generate(
            [
                load_proxy(
                    "secure",
                    PLAINTEXT_CHECK_ON_A_TLS_POOL.format(web=web, health=health).encode(),
                )
            ],
            vips={"main": Vip(name="main", address="127.0.0.1")},
            default_vip="main",
            ports={"http": port},
        )
        arguments = write_release(root, layer)
        binary = shutil.which("haproxy")
        assert binary is not None
        self.running.append(start_haproxy(binary, arguments, port))

        deadline = time.monotonic() + 15
        status = 0
        while time.monotonic() < deadline:
            connection = HTTPConnection("127.0.0.1", port, timeout=5)
            try:
                connection.putrequest("GET", "/", skip_host=True, skip_accept_encoding=True)
                connection.putheader("Host", "secure.example.com")
                connection.endheaders()
                status = int(connection.getresponse().status)
            finally:
                connection.close()
            if status == 200:
                break
            time.sleep(0.5)
        self.assertEqual(status, 200)


UPGRADE = """
schema: 1
name: live
hostnames: [live.example.com]
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


def upgrade_server(port: int) -> socket.socket:
    """A backend that speaks the upgrade and then just moves bytes.

    Raw sockets rather than a WebSocket library: what is being measured is
    HAProxy's behaviour once the connection stops being a series of requests,
    and framing the payload would only add something else that can fail.

    `/slow` is the other half of the case - an ordinary response that arrives
    too late - and it is served on the same backend so that both outcomes come
    from one configuration.
    """

    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(8)

    def serve() -> None:
        while True:
            try:
                client, _ = listener.accept()
            except OSError:
                return
            threading.Thread(target=handle, args=(client,), daemon=True).start()

    def handle(client: socket.socket) -> None:
        with client:
            client.settimeout(30)
            request = b""
            try:
                while b"\r\n\r\n" not in request:
                    chunk = client.recv(4096)
                    if not chunk:
                        return
                    request += chunk
            except OSError:
                return

            if b"upgrade: websocket" in request.lower():
                #
                # The accept value is computed rather than canned, because
                # HAProxy checks the response as well as the request: a 101
                # without it is rejected as an invalid answer and the client
                # sees 502 instead of a tunnel.
                #
                key = ""
                for line in request.decode("latin-1").splitlines():
                    name, _, value = line.partition(":")
                    if name.strip().lower() == "sec-websocket-key":
                        key = value.strip()
                accept = base64.b64encode(
                    hashlib.sha1(  # noqa: S324 - the value the protocol specifies
                        (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()
                    ).digest()
                ).decode()
                client.sendall(
                    b"HTTP/1.1 101 Switching Protocols\r\n"
                    b"Upgrade: websocket\r\n"
                    b"Connection: Upgrade\r\n"
                    b"Sec-WebSocket-Accept: " + accept.encode() + b"\r\n\r\n"
                )
                try:
                    while True:
                        data = client.recv(4096)
                        if not data:
                            return
                        client.sendall(data)
                except OSError:
                    return

            #
            # Deliberately later than the shortened server timeout below, so
            # the request that is not a tunnel is cut while this one waits.
            #
            time.sleep(3)
            body = b"late"
            try:
                client.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                    b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
                )
            except OSError:
                #
                # Expected in the case this branch exists for: HAProxy has
                # already given up on the response and closed the connection,
                # which is the outcome being measured.
                #
                return

    threading.Thread(target=serve, daemon=True).start()
    return listener


@unittest.skipUnless(shutil.which("haproxy"), "haproxy is not installed here")
class AnUpgradedConnectionLivesOnTheTunnelTimeout(unittest.TestCase):
    """What keeps a WebSocket open, proved without waiting an hour for it.

    An upgraded connection stops being a series of requests, and `timeout
    server` would otherwise close it while it is idle and perfectly healthy.
    The generator writes `timeout tunnel 1h` into every http backend for
    exactly this, and there is no switch for it in the interface - a site that
    upgrades gets it because every site does.

    The generated `timeout server 50s` is shortened to 1s here, and nothing
    else is touched. Waiting out the real value would make this a minute-long
    test measuring the same thing, and the tunnel timeout is left exactly as
    the generator wrote it - it is the value under test.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.backend = free_port()
        cls.listener = upgrade_server(cls.backend)
        wait_for(cls.backend)

        cls.port = free_port()
        cls.directory = tempfile.TemporaryDirectory()
        root = Path(cls.directory.name)
        layer = generate(
            [load_proxy("live", UPGRADE.format(web=cls.backend).encode())],
            vips={"main": Vip(name="main", address="127.0.0.1")},
            default_vip="main",
            ports={"http": cls.port},
        )
        for name, content in layer.configuration.items():
            shortened = content.replace("timeout server 50s", "timeout server 1s")
            assert "timeout tunnel 1h" in content or "1001-" not in name
            (root / name).write_text(shortened)

        arguments: list[str] = []
        for path in sorted(root.iterdir()):
            arguments += ["-f", str(path)]
        binary = shutil.which("haproxy")
        assert binary is not None
        cls.haproxy = start_haproxy(binary, arguments, cls.port)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.haproxy.terminate()
        cls.haproxy.wait(timeout=5)
        cls.listener.close()
        cls.directory.cleanup()

    def test_an_ordinary_response_is_cut_by_the_server_timeout(self) -> None:
        """The control. Without it the case below proves only that bytes move."""

        connection = HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            connection.putrequest("GET", "/slow", skip_host=True, skip_accept_encoding=True)
            connection.putheader("Host", "live.example.com")
            connection.endheaders()

            self.assertEqual(connection.getresponse().status, 504)
        finally:
            connection.close()

    def test_an_upgraded_connection_outlives_it_and_keeps_carrying_bytes(self) -> None:
        client = socket.create_connection(("127.0.0.1", self.port), timeout=10)
        #
        # A complete handshake, key and version included. HAProxy checks the
        # shape of a websocket upgrade and answers 400 to one that is missing
        # them - so an abbreviated request here would test the refusal rather
        # than the tunnel.
        #
        # The key is generated, which is what the protocol says it is: sixteen
        # random bytes, base64. A literal one would also be a base64 blob in a
        # repository that scans for exactly those.
        #
        key = base64.b64encode(os.urandom(16))
        try:
            client.sendall(
                b"GET / HTTP/1.1\r\n"
                b"Host: live.example.com\r\n"
                b"Connection: Upgrade\r\n"
                b"Upgrade: websocket\r\n"
                b"Sec-WebSocket-Key: " + key + b"\r\n"
                b"Sec-WebSocket-Version: 13\r\n\r\n"
            )
            answer = client.recv(4096)
            self.assertIn(b"101", answer)

            #
            # Longer than the shortened server timeout and shorter than
            # anything else in the configuration, so the only rule that can
            # keep this connection alive is the tunnel timeout.
            #
            time.sleep(2.5)

            client.sendall(b"still here")
            self.assertEqual(client.recv(4096), b"still here")
        finally:
            client.close()


UNDERSCORED = """
schema: 1
name: monitor-server-admin_web
hostnames: [admin.example.com]
listen:
  protocol: http
routes:
  - path: /
    backend: admin_web
backends:
  admin_web:
    balance: roundrobin
    servers:
      - host: 198.51.100.10
        port: 8080
"""


@unittest.skipUnless(shutil.which("haproxy"), "haproxy is not installed here")
class AnUnderscoreInAName(unittest.TestCase):
    """Proved against the running binary, not against what a manual says.

    The object's name is the filename, part of every generated proxy name and
    the seed of its GUID, so widening what it may contain is a change to an
    identity rule. Underscore was let in because people already call these
    things that - and the only answer worth having on whether HAProxy minds is
    the one its own parser gives.

    A hyphen and an underscore side by side, in both the object name and the
    backend name, because that is where the generated names concatenate them.
    """

    def test_the_generated_configuration_is_accepted(self) -> None:
        proxy = load_proxy("monitor-server-admin_web", UNDERSCORED.encode())
        layer = generate(
            [proxy],
            vips={"main": Vip(name="main", address="127.0.0.1")},
            default_vip="main",
            networks={},
            ports={"http": free_port()},
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            arguments = write_release(root, layer)
            binary = shutil.which("haproxy")
            assert binary is not None
            completed = subprocess.run(  # noqa: S603 - fixed binary, generated files
                [binary, "-c", *arguments],
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_the_name_reaches_the_generated_proxy_names_intact(self) -> None:
        """An underscore silently rewritten would make two objects collide."""

        proxy = load_proxy("monitor-server-admin_web", UNDERSCORED.encode())
        layer = generate(
            [proxy],
            vips={"main": Vip(name="main", address="127.0.0.1")},
            default_vip="main",
            networks={},
            ports={"http": free_port()},
        )
        written = "\n".join(layer.configuration.values())

        self.assertIn("monitor-server-admin_web", written)
        self.assertIn("admin_web", written)


class EveryClassThatStartsHaproxySaysSoFirst(unittest.TestCase):
    """The guard is a list, and a list nobody holds falls behind the file.

    Four classes here spawned a real HAProxy without the `skipUnless` every
    other one carries. They passed on a machine that has HAProxy and errored in
    CI, which has none - `setUpClass` asserted on the missing binary rather than
    skipping, so a runner without the program reported four broken tests instead
    of four it could not run.

    Read from the syntax rather than from the classes themselves, because the
    decorator leaves nothing to inspect where HAProxy *is* installed: it sets
    the skip flag only when its condition is false, so on this machine a guarded
    class and an unguarded one look identical at runtime.
    """

    @staticmethod
    def _starts_haproxy(node: ast.ClassDef) -> bool:
        """Whether this class calls `start_haproxy` anywhere inside it.

        The call and not the text. A first version looked for the name in the
        class's source, and the class doing the looking contains that name -
        so it found itself and nothing else could ever be added without the
        same trap.
        """

        return any(
            isinstance(inner, ast.Call)
            and isinstance(inner.func, ast.Name)
            and inner.func.id == "start_haproxy"
            for inner in ast.walk(node)
        )

    def test_a_class_that_spawns_one_is_skipped_where_there_is_none(self) -> None:
        module = ast.parse(Path(__file__).read_text(encoding="utf-8"))
        unguarded = sorted(
            node.name
            for node in module.body
            if isinstance(node, ast.ClassDef)
            and self._starts_haproxy(node)
            and not any("skipUnless" in ast.dump(decorator) for decorator in node.decorator_list)
        )

        self.assertEqual(unguarded, [], "these start HAProxy with nothing saying they may not")

    def test_the_check_would_notice_one(self) -> None:
        """A check that cannot fail is not a check."""

        unguarded = ast.parse(
            "class Bare:\n    def setUp(self):\n        start_haproxy(1, [], 2)\n"
        )

        self.assertTrue(self._starts_haproxy(unguarded.body[0]))


@unittest.skipUnless(
    shutil.which("haproxy") and shutil.which("openssl"),
    "haproxy or openssl is not installed here",
)
class HowOldAPoolMayBe(unittest.TestCase):
    """The `legacy` policy, proved against a backend that really is that old.

    It exists for one case: an appliance whose web interface speaks nothing
    above TLS 1.1 - a print server, a lights-out card, something with a decade
    on it. There is no such thing to point at in a test environment, so the
    stand-in is OpenSSL told to be one.

    Both halves of the policy are load-bearing and neither is enough alone.
    `ssl-min-ver TLSv1.1` says what HAProxy may negotiate; `@SECLEVEL=0` says
    what OpenSSL will let it. The nodes run at security level 2, which refuses
    everything below TLS 1.2 whatever the version keyword asked for, so a
    policy with only the first would be a setting that reads correctly and
    changes nothing.

    The other direction matters as much: `intermediate` is what a pool gets
    when its object names no policy, and this proves that default is a real
    floor rather than a line in a file.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.directory = tempfile.TemporaryDirectory()
        cls.root = Path(cls.directory.name)
        cls.running: list[subprocess.Popen[bytes]] = []

    @classmethod
    def tearDownClass(cls) -> None:
        for process in cls.running:
            process.terminate()
            process.wait(timeout=5)
        cls.directory.cleanup()

    def reach(self, *, policy: str) -> int:
        """One request through a proxy, to a pool that speaks only TLS 1.1."""

        certificate, key = self_signed(self.root, f"old-{policy}", expired=False)
        backend = free_port()
        self.running.append(spawned.old_tls_server(certificate, key, "-tls1_1", backend))

        port = free_port()
        root = self.root / policy
        root.mkdir()
        document = BACKEND_TLS_POLICY.format(policy=policy, web=backend)
        layer = generate(
            [load_proxy("secure", document.encode())],
            vips={"main": Vip(name="main", address="127.0.0.1")},
            default_vip="main",
            ports={"http": port},
        )
        arguments = write_release(root, layer)
        binary = shutil.which("haproxy")
        assert binary is not None
        self.running.append(start_haproxy(binary, arguments, port))

        connection = HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            connection.putrequest("GET", "/", skip_host=True, skip_accept_encoding=True)
            connection.putheader("Host", "secure.example.com")
            connection.endheaders()
            return int(connection.getresponse().status)
        finally:
            connection.close()

    def test_legacy_reaches_a_backend_that_speaks_only_tls_1_1(self) -> None:
        self.assertEqual(self.reach(policy="legacy"), 200)

    def test_intermediate_does_not(self) -> None:
        """503: the pool is refused, which is the floor doing its work."""

        self.assertEqual(self.reach(policy="intermediate"), 503)


LISTENER_POLICY = """
schema: 1
name: {name}
hostnames: [{host}]
listen:
  protocol: https
  certificate: {certificate}
{policy}routes:
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


@unittest.skipUnless(
    shutil.which("haproxy") and shutil.which("openssl"),
    "haproxy or openssl is not installed here",
)
class OneListenerTwoSetsOfTerms(unittest.TestCase):
    """A site may hold its own certificate to terms the VIP did not set.

    Several sites answer on one address through SNI and share its bind line, so
    the bind line's policy is the VIP's. HAProxy will still hold one
    certificate on that listener to different terms than the next, chosen by
    the name the client asked for - which is what lets a site with a
    requirement of its own keep sharing an address instead of needing one.

    Proved through a real handshake, because the reading that matters is
    whether a client held to TLS 1.2 is served or refused, and a configuration
    file cannot say that.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.directory = tempfile.TemporaryDirectory()
        cls.root = Path(cls.directory.name)
        cls.running: list[subprocess.Popen[bytes]] = []
        cls.port = free_port()
        backend = free_port()
        cls.backend = echo_server("web", backend)

        certificates = cls.root / "certs"
        certificates.mkdir()
        documents = []
        for name, host, policy in (
            ("strict", "strict.example.com", "  tls: modern\n"),
            ("ordinary", "ordinary.example.com", ""),
            ("capped", "capped.example.com", "  tls: tls12only\n"),
        ):
            #
            # Named for the site it serves, and not for the address. HAProxy
            # picks the crt-list entry by the name the client asked for; a
            # certificate that matches no SNI sends the connection to the first
            # entry instead, which is how a per-site policy can look like it
            # does nothing at all. Measured the hard way.
            #
            certificate, key = self_signed(cls.root, name, expired=False, common_name=host)
            (certificates / f"{name}.pem").write_bytes(certificate.read_bytes() + key.read_bytes())
            documents.append(
                load_proxy(
                    name,
                    LISTENER_POLICY.format(
                        name=name, host=host, certificate=name, policy=policy, web=backend
                    ).encode(),
                )
            )

        layer = generate(
            documents,
            vips={"main": Vip(name="main", address="127.0.0.1", tls_policy="intermediate")},
            default_vip="main",
            certificates=("strict", "ordinary", "capped"),
            ports={"https": cls.port, "http": free_port()},
        )
        arguments = write_release(cls.root, layer, certificates)
        binary = shutil.which("haproxy")
        assert binary is not None
        cls.running.append(start_haproxy(binary, arguments, cls.port))

    @classmethod
    def tearDownClass(cls) -> None:
        for process in cls.running:
            process.terminate()
            process.wait(timeout=5)
        cls.backend.shutdown()
        cls.backend.server_close()
        cls.directory.cleanup()

    def handshake(self, host: str, ceiling: ssl.TLSVersion) -> bool:
        """Whether a client that will go no higher than `ceiling` is served."""

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        #
        # Both ends of the range said rather than inherited, for the reason the
        # probe gives about its own floor: left unsaid, it is whatever OpenSSL
        # on this machine was built with, and the test would then be asserting
        # something about the machine as much as about the listener. 1.2 is the
        # project's floor everywhere, so it is the floor a client here uses.
        #
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ceiling
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            with (
                socket.create_connection(("127.0.0.1", self.port), timeout=5) as raw,
                context.wrap_socket(raw, server_hostname=host),
            ):
                return True
        except (ssl.SSLError, OSError):
            return False

    def negotiated(self, host: str) -> str | None:
        """Which version a client that would go as high as possible ended on."""

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            with (
                socket.create_connection(("127.0.0.1", self.port), timeout=5) as raw,
                context.wrap_socket(raw, server_hostname=host) as secure,
            ):
                return secure.version()
        except (ssl.SSLError, OSError):
            return None

    def test_the_vip_decides_for_a_site_that_asks_for_nothing(self) -> None:
        """`intermediate` on the bind line, so a TLS 1.2 client is served."""

        self.assertTrue(self.handshake("ordinary.example.com", ssl.TLSVersion.TLSv1_2))

    def test_a_site_that_asked_for_more_gets_it(self) -> None:
        """Same listener, same port, same connection attempt - and refused.

        This is the whole of B82b in one assertion: the terms follow the name
        the client asked for, not the address it connected to.
        """

        self.assertFalse(self.handshake("strict.example.com", ssl.TLSVersion.TLSv1_2))

    def test_and_is_still_served_to_a_client_that_can_do_what_it_asked(self) -> None:
        """Otherwise the test above would pass on a listener that served nobody."""

        self.assertTrue(self.handshake("strict.example.com", ssl.TLSVersion.TLSv1_3))

    def test_a_capped_site_holds_a_modern_client_down_to_tls_1_2(self) -> None:
        """The only policy with a ceiling, and the only one this can prove.

        Every other name here is a floor, so a client that can do more is
        served more and the difference is invisible. `tls12only` exists for a
        client that breaks on TLS 1.3, and what it promises is that a listener
        which *could* speak 1.3 does not - which is a question only a real
        handshake answers.
        """

        self.assertEqual(self.negotiated("capped.example.com"), "TLSv1.2")

    def test_the_sites_beside_it_still_reach_tls_1_3(self) -> None:
        """The ceiling follows the name asked for, not the address."""

        self.assertEqual(self.negotiated("ordinary.example.com"), "TLSv1.3")
