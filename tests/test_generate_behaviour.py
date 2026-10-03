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

from haproxy_mgmt import geo
from haproxy_mgmt.cluster_settings import ClusterSettings, Metrics
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

#
# A limit of three over two pools. The window is long enough that nothing in a
# test run ages out of it, so the fourth request is the first one refused
# whatever the machine's speed.
#
LIMITED = """
schema: 1
name: limited
hostnames: [limited.example.com]
listen:
  protocol: http
rate_limit:
  window: 1m
  max_requests: 3
routes:
  - path: /
    backend: web
  - path: /api
    backend: api
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
        #
        # The node points `/etc/haproxy/maps/` at the candidate's own maps when
        # it validates (`haproxy-pull-deploy`); this is that step.
        #
        content = content.replace("/etc/haproxy/maps/", f"{root}/maps/")
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
    (root / "maps").mkdir(exist_ok=True)
    for name, content in layer.map_files.items():
        (root / "maps" / name).write_text(content)
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
        limited = load_proxy("limited", LIMITED.format(web=ports["web"], api=ports["api"]).encode())
        layer = generate(
            [cls.proxy, restricted, closed, gone, pair, limited],
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

    def test_a_rate_limit_counts_every_path_of_the_object_and_no_other_object(self) -> None:
        """One table for the object, and only for the object.

        The requests alternate between the two pools, so a table per pool would
        let all four through. The site next to it on the same address is asked
        last, from the same source that has just been refused, and has to
        answer: a limit that spread to the shared frontend would refuse it.
        """

        statuses = [
            self.request(path, host="limited.example.com")[0] for path in ("/", "/api", "/", "/api")
        ]

        self.assertEqual(statuses, [200, 200, 200, 429])
        self.assertEqual(self.request("/")[0], 200)

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
        #
        # Every test file, not just this one. The guard read its own module
        # until 2026-09-06, which is the failure its own docstring describes -
        # a behaviour test written in a new file inherited none of it, and the
        # runner without HAProxy would have reported it broken rather than
        # skipped. There is no list of files to keep in step: the directory is
        # the list.
        #
        unguarded = sorted(
            f"{path.name}:{node.name}"
            for path in sorted(Path(__file__).parent.glob("test_*.py"))
            for node in ast.parse(path.read_text(encoding="utf-8")).body
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
        certificate, key = self_signed(
            cls.root, "shared", expired=False, common_name="*.example.com"
        )
        (certificates / "shared.pem").write_bytes(certificate.read_bytes() + key.read_bytes())
        documents = []
        for name, host, policy in (
            ("strict", "strict.example.com", "  tls: modern\n"),
            ("ordinary", "ordinary.example.com", ""),
            ("capped", "capped.example.com", "  tls: tls12only\n"),
        ):
            documents.append(
                load_proxy(
                    name,
                    LISTENER_POLICY.format(
                        name=name, host=host, certificate="shared", policy=policy, web=backend
                    ).encode(),
                )
            )

        layer = generate(
            documents,
            vips={"main": Vip(name="main", address="127.0.0.1", tls_policy="intermediate")},
            default_vip="main",
            certificates=("shared",),
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

    def handshake(self, host: str | None, ceiling: ssl.TLSVersion) -> bool:
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

    def request_status(self, sni: str | None, host: str) -> int:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with (
            socket.create_connection(("127.0.0.1", self.port), timeout=5) as raw,
            context.wrap_socket(raw, server_hostname=sni) as secure,
        ):
            secure.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
            status_line = secure.recv(4096).split(b"\r\n", 1)[0]
        return int(status_line.split()[1])

    def test_the_vip_decides_for_a_site_that_asks_for_nothing(self) -> None:
        """`intermediate` on the bind line, so a TLS 1.2 client is served."""

        self.assertTrue(self.handshake("ordinary.example.com", ssl.TLSVersion.TLSv1_2))

    def test_missing_and_unknown_sni_use_the_explicit_listener_fallback(self) -> None:
        self.assertTrue(self.handshake(None, ssl.TLSVersion.TLSv1_2))
        self.assertTrue(self.handshake("unknown.example.com", ssl.TLSVersion.TLSv1_2))

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

    def test_http_host_cannot_cross_from_another_tls_policy(self) -> None:
        self.assertEqual(self.request_status("ordinary.example.com", "strict.example.com"), 421)
        self.assertEqual(self.request_status(None, "strict.example.com"), 421)
        self.assertEqual(self.request_status("strict.example.com", "strict.example.com"), 200)


ADVANCED_SHOP = """
schema: 1
name: shop
hostnames: [shop.example.com]
listen:
  protocol: http
rate_limit:
  window: 10s
  max_requests: 1000
routes:
  - path: /
    backend: web
backends:
  web:
    balance: roundrobin
    servers:
      - host: 127.0.0.1
        port: {web}
advanced: |
  http-request track-sc2 src table shop-logins if {{ path_beg /login }}
  http-request deny deny_status 429 if {{ path_beg /login }} {{ sc_http_req_rate(2) gt 3 }}
  http-request return status 200 content-type text/plain lf-string "sc1=%[sc_http_req_rate(1)]" if {{ path /count }}

  backend shop-logins
      stick-table type ip size 1k expire 1m store http_req_rate(1m)
"""

ADVANCED_APP = """
schema: 1
name: app
hostnames: [app.example.com]
listen:
  protocol: http
routes:
  - path: /
    backend: web
backends:
  web:
    servers: []
advanced: |
  balance first
  server mine 127.0.0.1:{web}
"""

ADVANCED_RAW = """
schema: 1
name: raw
listen:
  protocol: tcp
  port: {port}
backend: pool
backends:
  pool:
    balance: roundrobin
    servers:
      - host: 127.0.0.1
        port: {web}
advanced: |
  tcp-request content reject if {{ src 127.0.0.1 }}
"""


@unittest.skipUnless(shutil.which("haproxy"), "haproxy is not installed here")
class AdvancedConfigDoesWhatItsPlacementSays(unittest.TestCase):
    """Fas 17 (B223, B224), proved through a running HAProxy.

    `haproxy -c` accepts a second `track-sc0` and a rule in the wrong place
    without a word, so the placement is only shown right by traffic: the text's
    own counter refuses on its own threshold, the text reads the object's
    counter (which it can only do if it runs after the generated rules), a pool
    written by hand serves, and a tcp object's frontend line takes effect.
    """

    @classmethod
    def setUpClass(cls) -> None:
        web = free_port()
        cls.server = echo_server("web", web)
        wait_for(web)

        cls.port = free_port()
        cls.raw = free_port()
        cls.directory = tempfile.TemporaryDirectory()
        root = Path(cls.directory.name)
        layer = generate(
            [
                load_proxy("shop", ADVANCED_SHOP.format(web=web).encode()),
                load_proxy("app", ADVANCED_APP.format(web=web).encode()),
                load_proxy("raw", ADVANCED_RAW.format(web=web, port=cls.raw).encode()),
            ],
            vips={"main": Vip(name="main", address="127.0.0.1")},
            default_vip="main",
            abuse_protection=AbuseProtection(window="10s", max_requests=1000),
            ports={"http": cls.port},
        )
        arguments = write_release(root, layer)
        binary = shutil.which("haproxy")
        assert binary is not None
        cls.haproxy = start_haproxy(binary, arguments, cls.port)
        wait_for(cls.raw)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.haproxy.terminate()
        cls.haproxy.wait(timeout=5)
        cls.server.shutdown()
        cls.directory.cleanup()

    def get(self, host: str, path: str) -> tuple[int, str]:
        connection = HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            connection.putrequest("GET", path, skip_host=True, skip_accept_encoding=True)
            connection.putheader("Host", host)
            connection.endheaders()
            response = connection.getresponse()
            return int(response.status), response.read().decode()
        finally:
            connection.close()

    def test_the_text_s_counter_refuses_on_its_own_threshold_and_nowhere_else(self) -> None:
        logins = [self.get("shop.example.com", "/login")[0] for _ in range(6)]

        self.assertEqual(logins[:3], [200, 200, 200])
        self.assertEqual(logins[-1], 429)
        self.assertEqual(self.get("shop.example.com", "/")[0], 200)

    def test_the_text_runs_after_the_object_s_rate_limit_and_reads_its_counter(self) -> None:
        self.get("shop.example.com", "/")
        status, body = self.get("shop.example.com", "/count")

        self.assertEqual(status, 200)
        self.assertRegex(body, r"^sc1=[1-9][0-9]*$")

    def test_a_pool_written_by_hand_serves(self) -> None:
        self.assertEqual(self.get("app.example.com", "/x"), (200, "web /x"))

    def test_a_tcp_object_s_frontend_line_takes_effect(self) -> None:
        with socket.create_connection(("127.0.0.1", self.raw), timeout=5) as connection:
            connection.sendall(b"GET / HTTP/1.0\r\n\r\n")
            try:
                answer = connection.recv(100)
            except ConnectionResetError:
                answer = b""

        self.assertEqual(answer, b"")


GUARDED = """
schema: 1
name: guarded
hostnames: [guarded.example.com]
listen:
  protocol: http
deny_from:
  mode: deny
  sources: [203.0.113.0/24]
deny_rules:
  - name: admin-post
    mode: deny
    path: /admin
    methods: [POST]
  - name: scanner
    mode: log
    header:
      name: User-Agent
      contains: sqlmap
  - name: internal-office
    mode: deny
    path: /internal
    source: [192.0.2.0/24]
  - name: private-but-office
    mode: deny
    path: /private
    source: [office]
    source_negate: true
  - name: sweden-only
    mode: deny
    path: /se
    source: [country:se]
    source_negate: true
max_request_body: 64k
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

OFFICE_ONLY = """
schema: 1
name: office
hostnames: [office.example.com]
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


def body_server(port: int) -> ThreadingHTTPServer:
    """Answers any method with how many body bytes reached it."""

    class Handler(BaseHTTPRequestHandler):
        def answer(self) -> None:
            received = 0
            if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
                while True:
                    size = int(self.rfile.readline().strip(), 16)
                    if size == 0:
                        self.rfile.readline()
                        break
                    received += len(self.rfile.read(size))
                    self.rfile.readline()
            else:
                received = len(self.rfile.read(int(self.headers.get("Content-Length", 0))))
            body = f"got {received}".encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_GET = do_POST = answer  # noqa: N815 - the names are the library's

        def log_message(self, *_: object) -> None:
            """Silence."""

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@unittest.skipUnless(shutil.which("haproxy"), "haproxy is not installed here")
class AccessRulesAnswerAndNameThemselvesInTheRealHaproxy(unittest.TestCase):
    """Fas 21 del A (B227), behind a trusted proxy - the case question 1 changed.

    The test connects from 127.0.0.1 and names it the trusted proxy, so every
    address condition is decided by the X-Forwarded-For the test writes. The
    rule a request met is read back from `txn.rule` itself: the harness adds
    one `http-after-response` line that copies it into a response header,
    which is a window onto the variable the traffic record logs, not a change
    to the rules under test.
    """

    servers: list[ThreadingHTTPServer]
    haproxy: subprocess.Popen[bytes]
    directory: tempfile.TemporaryDirectory[str]
    port: int

    @classmethod
    def setUpClass(cls) -> None:
        web = free_port()
        cls.servers = [body_server(web)]
        wait_for(web)
        cls.port = free_port()
        cls.directory = tempfile.TemporaryDirectory()
        root = Path(cls.directory.name)
        layer = generate(
            [
                load_proxy("guarded", GUARDED.format(web=web).encode()),
                load_proxy("office", OFFICE_ONLY.format(web=web).encode()),
            ],
            vips={"main": Vip(name="main", address="127.0.0.1")},
            default_vip="main",
            networks={"office": ("198.51.100.0/24",)},
            ports={"http": cls.port},
            trusted_proxies=("127.0.0.1",),
            #
            # Two invented countries over documentation ranges: the rule reads
            # the file the generator writes, not the database.
            #
            countries=geo.Countries(
                stamp="2026-10-01",
                networks={"SE": ("198.51.100.0/25",), "XX": ("203.0.113.0/24",)},
            ),
        )
        window = "    option httplog\n    http-after-response set-header X-Rule %[var(txn.rule)]\n"
        layer = GeneratedLayer(
            configuration={
                name: text.replace("    option httplog\n", window)
                for name, text in layer.configuration.items()
            },
            certificate_lists=layer.certificate_lists,
            map_files=layer.map_files,
        )
        arguments = write_release(root, layer)
        binary = shutil.which("haproxy")
        assert binary is not None
        cls.haproxy = start_haproxy(binary, arguments, cls.port)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.haproxy.terminate()
        cls.haproxy.wait(timeout=5)
        for server in cls.servers:
            server.shutdown()
        cls.directory.cleanup()

    def ask(
        self,
        target: str = "/",
        *,
        host: str = "guarded.example.com",
        visitor: str = "192.0.2.5",
        method: str = "GET",
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
        chunked: bool = False,
    ) -> tuple[int, str]:
        connection = HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            connection.putrequest(method, target, skip_host=True, skip_accept_encoding=True)
            connection.putheader("Host", host)
            connection.putheader("X-Forwarded-For", visitor)
            for name, value in (headers or {}).items():
                connection.putheader(name, value)
            if body is not None and not chunked:
                connection.putheader("Content-Length", str(len(body)))
            if chunked:
                connection.putheader("Transfer-Encoding", "chunked")
            connection.endheaders()
            if body is not None and chunked:
                for start in range(0, len(body), 4096):
                    piece = body[start : start + 4096]
                    connection.send(f"{len(piece):x}\r\n".encode() + piece + b"\r\n")
                connection.send(b"0\r\n\r\n")
            elif body is not None:
                connection.send(body)
            response = connection.getresponse()
            response.read()
            return response.status, response.getheader("X-Rule") or ""
        finally:
            connection.close()

    def test_a_visitor_no_rule_names_is_served_and_named_by_nothing(self) -> None:
        self.assertEqual(self.ask(), (200, ""))

    def test_deny_from_refuses_the_forwarded_address_not_the_proxy(self) -> None:
        self.assertEqual(self.ask(visitor="203.0.113.9"), (403, "deny-from:deny"))

    def test_every_condition_of_a_rule_must_hold(self) -> None:
        self.assertEqual(self.ask("/admin", method="POST", body=b"x"), (403, "admin-post:deny"))
        self.assertEqual(
            self.ask("/admin/users", method="POST", body=b"x"), (403, "admin-post:deny")
        )
        self.assertEqual(self.ask("/admin"), (200, ""))
        self.assertEqual(self.ask("/administrator", method="POST", body=b"x"), (200, ""))

    def test_a_logged_rule_lets_the_request_through_and_names_itself(self) -> None:
        self.assertEqual(
            self.ask(headers={"User-Agent": "sqlmap/1.8, like curl"}), (200, "scanner:log")
        )

    def test_a_refusal_names_itself_over_an_earlier_logged_match(self) -> None:
        self.assertEqual(
            self.ask("/admin", method="POST", body=b"x", headers={"User-Agent": "sqlmap"}),
            (403, "admin-post:deny"),
        )

    def test_a_rule_source_is_the_forwarded_address(self) -> None:
        self.assertEqual(self.ask("/internal", visitor="192.0.2.7"), (403, "internal-office:deny"))
        self.assertEqual(self.ask("/internal", visitor="198.51.100.7"), (200, ""))

    def test_all_but_these_sources_refuses_everyone_else(self) -> None:
        self.assertEqual(self.ask("/private", visitor="198.51.100.7"), (200, ""))
        self.assertEqual(
            self.ask("/private", visitor="192.0.2.5"), (403, "private-but-office:deny")
        )

    def test_a_country_is_read_from_its_file(self) -> None:
        self.assertEqual(self.ask("/se", visitor="198.51.100.7"), (200, ""))
        self.assertEqual(self.ask("/se", visitor="198.51.100.200"), (403, "sweden-only:deny"))

    def test_the_body_limit_holds_a_declared_length(self) -> None:
        self.assertEqual(self.ask(method="POST", body=b"a" * 60_000), (200, ""))
        self.assertEqual(self.ask(method="POST", body=b"a" * 70_000), (413, "body-limit:deny"))

    def test_a_long_chunked_body_is_let_through_and_marked(self) -> None:
        """A limit past the 16 kB buffer, so nothing a chunked body sends is held
        against it. Below the buffer the first chunks can already exceed the
        limit and the request is refused - which depends on what has arrived,
        and is why this case is written with a limit the buffer cannot reach."""

        self.assertEqual(
            self.ask(method="POST", body=b"a" * 200_000, chunked=True), (200, "body-unbounded:log")
        )

    def test_allow_from_reads_the_forwarded_address_behind_a_trusted_proxy(self) -> None:
        self.assertEqual(self.ask(host="office.example.com", visitor="198.51.100.7")[0], 200)
        self.assertEqual(self.ask(host="office.example.com", visitor="192.0.2.5")[0], 403)


WAF_ENGINE = Path("/usr/sbin/coraza-spoa")
WAF_RULES = Path("/usr/share/haproxy-manager/crs")

WAF_OBJECT = """
schema: 1
name: {name}
hostnames: [{name}.example.com]
listen:
  protocol: http
waf:
{waf}
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
SQLI = "/?q=1'%20OR%201=1--"
ATTACK = "1'%20OR%201=1--"
#
# Each form an exception takes: a rule on every path (the numeric Host), a
# field on one path, a field on every path, the whole request on one path.
#
BLOCKS_WITH_EXCEPTIONS = """  mode: block
  exceptions:
    - rule: 920350
    - rule: 942100
      field: ARGS:q
      paths: [/search]
    - rule: 942100
      field: ARGS:token
    - rule: 942100
      paths: [/health]
      by: admin
      at: 2026-10-03T09:10:00Z"""


@unittest.skipUnless(
    shutil.which("haproxy") and WAF_ENGINE.is_file() and WAF_RULES.is_dir(),
    "haproxy, the WAF engine or the rule set is not installed here",
)
class WafEngineAnswersInTheRealHaproxy(unittest.TestCase):
    """Fas 21 del B (B232, B233): the generated layer, the installed engine and CRS.

    Three objects: one that only looks, one that blocks and lets rules through
    in each form an exception takes (B234), one that refuses when the engine
    does not answer.
    What the engine said is read back through a response header, the same
    window as the access-rule test; the second class stops nothing and
    starts no engine at all, which is what a stopped engine looks like.
    """

    engine_running = True
    servers: list[ThreadingHTTPServer]
    haproxy: subprocess.Popen[bytes]
    engine: subprocess.Popen[bytes] | None
    directory: tempfile.TemporaryDirectory[str]
    port: int

    @classmethod
    def setUpClass(cls) -> None:
        web = free_port()
        cls.servers = [body_server(web)]
        wait_for(web)
        cls.port = free_port()
        engine_port = free_port()
        cls.directory = tempfile.TemporaryDirectory()
        root = Path(cls.directory.name)
        objects = {
            "looks": "  mode: log",
            "blocks": BLOCKS_WITH_EXCEPTIONS,
            "closed": "  mode: block\n  on_engine_error: deny",
        }
        layer = generate(
            [
                load_proxy(name, WAF_OBJECT.format(name=name, waf=waf, web=web).encode())
                for name, waf in objects.items()
            ],
            vips={"main": Vip(name="main", address="127.0.0.1")},
            default_vip="main",
            ports={"http": cls.port},
        )
        waf_files = layer.waf_files

        def local(text: str) -> str:
            return text.replace("/etc/haproxy/waf/", f"{root}/waf/").replace(
                "127.0.0.1:9520", f"127.0.0.1:{engine_port}"
            )

        window = (
            "    option httplog\n"
            "    http-after-response set-header X-Rule %[var(txn.rule)]\n"
            "    http-after-response set-header X-Waf %[var(txn.coraza.rule_ids)]\n"
            "    http-after-response set-header X-Waf-Id %[var(txn.coraza.id)]\n"
        )
        layer = GeneratedLayer(
            configuration={
                name: local(text.replace("    option httplog\n", window))
                for name, text in layer.configuration.items()
            },
            certificate_lists=layer.certificate_lists,
        )
        (root / "waf" / "crs").mkdir(parents=True)
        for name, text in waf_files.items():
            (root / "waf" / name).write_text(local(text))
        shutil.copy(WAF_RULES / "crs-setup.conf.example", root / "waf" / "crs" / "crs-setup.conf")
        shutil.copytree(WAF_RULES / "rules", root / "waf" / "crs" / "rules")
        arguments = write_release(root, layer)
        cls.engine = None
        if cls.engine_running:
            cls.engine = subprocess.Popen(
                [str(WAF_ENGINE), "-config", str(root / "waf" / "coraza.yaml")],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                preexec_fn=spawned.die_with_the_test_run,
            )
            wait_for(engine_port)
        binary = shutil.which("haproxy")
        assert binary is not None
        cls.haproxy = start_haproxy(binary, arguments, cls.port)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.haproxy.terminate()
        cls.haproxy.wait(timeout=5)
        if cls.engine is not None:
            cls.engine.terminate()
            cls.engine.wait(timeout=5)
        for server in cls.servers:
            server.shutdown()
        cls.directory.cleanup()

    def ask(self, target: str, *, name: str, body: bytes | None = None) -> tuple[int, str, str]:
        connection = HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            connection.putrequest(
                "GET" if body is None else "POST", target, skip_host=True, skip_accept_encoding=True
            )
            connection.putheader("Host", f"{name}.example.com")
            if body is not None:
                connection.putheader("Content-Type", "application/x-www-form-urlencoded")
                connection.putheader("Content-Length", str(len(body)))
            connection.endheaders()
            if body is not None:
                connection.send(body)
            response = connection.getresponse()
            response.read()
            return (
                response.status,
                response.getheader("X-Rule") or "",
                response.getheader("X-Waf") or "",
            )
        finally:
            connection.close()

    def test_an_ordinary_request_is_served_and_named_by_nothing(self) -> None:
        for name in ("looks", "blocks", "closed"):
            with self.subTest(name):
                self.assertEqual(self.ask("/?q=hello", name=name), (200, "", ""))

    def test_a_looking_object_lets_an_attack_through_and_names_the_rules(self) -> None:
        status, rule, rules = self.ask(SQLI, name="looks")
        self.assertEqual((status, rule), (200, "crs:log"))
        self.assertIn("942100", rules.split(","))

    def test_a_blocking_object_refuses_an_attack_in_the_query_and_in_the_body(self) -> None:
        self.assertEqual(self.ask(SQLI, name="blocks")[:2], (403, "crs:deny"))
        status, rule, rules = self.ask(
            "/form", name="blocks", body=b"name=x' UNION SELECT password FROM users--"
        )
        self.assertEqual((status, rule), (403, "crs:deny"))
        self.assertIn("942100", rules.split(","))

    def test_an_excluded_rule_no_longer_counts(self) -> None:
        # A Host that is an address is CRS 920350; `blocks` has turned it off.
        connection = HTTPConnection("127.0.0.1", self.port, timeout=5)
        connection.request("GET", "/", headers={"Host": "blocks.example.com"})
        self.assertEqual(connection.getresponse().status, 200)
        connection.close()

    def test_an_exception_lets_through_exactly_what_it_names(self) -> None:
        for target, status in (
            (f"/search?q={ATTACK}", 200),  # the field, on its path
            (f"/search?id={ATTACK}", 403),  # another field on that path
            (f"/other?q={ATTACK}", 403),  # the field on another path
            (f"/search/../admin?q={ATTACK}", 403),  # not /search once normalised
            (f"/search/?q={ATTACK}", 403),
            (f"/%73earch?q={ATTACK}", 200),  # /search once decoded
            (f"/anywhere?token={ATTACK}", 200),  # a field on every path
            (f"/health?a={ATTACK}", 200),  # the whole request on one path
            (f"/health/x?a={ATTACK}", 403),
        ):
            with self.subTest(target):
                self.assertEqual(self.ask(target, name="blocks")[0], status)

    def test_the_engine_hands_its_transaction_id_back_to_haproxy(self) -> None:
        connection = HTTPConnection("127.0.0.1", self.port, timeout=5)
        connection.request("GET", SQLI, headers={"Host": "looks.example.com"})
        response = connection.getresponse()
        response.read()
        connection.close()
        # `<object>.<uuid>`, set by HAProxy, taken by the engine and handed back.
        self.assertRegex(
            response.getheader("X-Waf-Id") or "",
            "^looks\\.[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[0-9a-f]{4}-[0-9a-f]{12}$",
        )


class WafEngineThatDoesNotAnswer(WafEngineAnswersInTheRealHaproxy):
    """The same layer with no engine: `on_engine_error` decides (B232)."""

    engine_running = False

    def test_an_ordinary_request_is_served_and_named_by_nothing(self) -> None:
        self.assertEqual(self.ask("/?q=hello", name="looks"), (200, "waf-engine:log", ""))

    def test_a_looking_object_lets_an_attack_through_and_names_the_rules(self) -> None:
        self.skipTest("the engine is not running")

    def test_a_blocking_object_refuses_an_attack_in_the_query_and_in_the_body(self) -> None:
        self.skipTest("the engine is not running")

    def test_an_excluded_rule_no_longer_counts(self) -> None:
        self.skipTest("the engine is not running")

    def test_an_exception_lets_through_exactly_what_it_names(self) -> None:
        self.skipTest("the engine is not running")

    def test_the_engine_hands_its_transaction_id_back_to_haproxy(self) -> None:
        self.skipTest("the engine is not running")

    def test_open_lets_through_and_says_so_closed_refuses(self) -> None:
        self.assertEqual(self.ask(SQLI, name="blocks"), (200, "waf-engine:log", ""))
        self.assertEqual(self.ask(SQLI, name="closed"), (503, "waf-engine:deny", ""))


class TheWafLayerIsWrittenOnlyWhereItIsUsed(unittest.TestCase):
    """What the generator writes for the engine, without running it (B230, B232)."""

    def layer(self, waf: str | None, **options: object) -> GeneratedLayer:
        text = WAF_OBJECT.format(name="shop", waf=waf or "", web=8080)
        if waf is None:
            text = text.replace("waf:\n\n", "")
        return generate(
            [load_proxy("shop", text.encode())],
            vips={"main": Vip(name="main", address="192.0.2.1")},
            default_vip="main",
            **options,  # type: ignore[arg-type]
        )

    def test_a_cluster_without_the_engine_gets_no_trace_of_it(self) -> None:
        layer = self.layer(None)
        self.assertEqual(layer.waf_files, {})
        self.assertNotIn("1000-waf.cfg", layer.configuration)
        self.assertNotIn("spoe", layer.configuration["1000-frontends.cfg"])

    def test_an_object_with_the_engine_off_is_generated_as_one_without_it(self) -> None:
        """`mode: off` keeps the settings and exceptions in the object (26-10-03);
        the release carries no trace of the engine, so a node needs none."""

        layer = self.layer("  mode: off\n  paranoia: 2\n  exceptions: [{rule: 920350}]")
        self.assertEqual(layer.waf_files, {})
        self.assertNotIn("1000-waf.cfg", layer.configuration)
        self.assertNotIn("spoe", layer.configuration["1000-frontends.cfg"])
        self.assertNotIn("coraza", layer.configuration["1000-frontends.cfg"])

    def test_each_object_is_an_application_and_an_unknown_name_inspects_nothing(self) -> None:
        layer = self.layer("  paranoia: 3\n  exceptions: [{rule: 920350}]")
        engine = layer.waf_files["coraza.yaml"]
        self.assertIn("default_application: _unknown", engine)
        self.assertIn("  - name: shop\n", engine)
        self.assertIn("setvar:tx.blocking_paranoia_level=3", engine)
        self.assertLess(
            engine.index("Include /etc/haproxy/waf/crs/rules/*.conf"),
            engine.index("SecRuleRemoveById 920350"),
        )
        self.assertIn("  - name: _unknown\n    directives: |\n      SecRuleEngine Off", engine)
        self.assertIn("bind: 127.0.0.1:9520", engine)
        self.assertIn(
            "filter spoe engine coraza config /etc/haproxy/waf/spoe.conf",
            layer.configuration["1000-frontends.cfg"],
        )

    def test_exceptions_on_paths_come_before_the_rule_set_and_on_every_path_after(self) -> None:
        engine = self.layer(
            "  exceptions:\n"
            "    - {rule: 942100, field: ARGS:q, paths: [/search, /find]}\n"
            "    - {rule: 941100, paths: [/contact]}\n"
            "    - {rule: 942100, field: 'REQUEST_HEADERS:User-Agent'}\n"
            "    - {rule: 913100}"
        ).waf_files["coraza.yaml"]
        rule_set = engine.index("Include /etc/haproxy/waf/crs/crs-setup.conf")
        for line in (
            'SecRule REQUEST_FILENAME "@streq /find" "id:210000,phase:1,pass,nolog,'
            't:none,t:urlDecodeUni,t:normalisePath,ctl:ruleRemoveTargetById=942100;ARGS:q"',
            'SecRule REQUEST_FILENAME "@streq /search" "id:210001,phase:1,pass,nolog,'
            't:none,t:urlDecodeUni,t:normalisePath,ctl:ruleRemoveTargetById=942100;ARGS:q"',
            'SecRule REQUEST_FILENAME "@streq /contact" "id:210002,phase:1,pass,nolog,'
            't:none,t:urlDecodeUni,t:normalisePath,ctl:ruleRemoveById=941100"',
        ):
            self.assertLess(engine.index(line), rule_set)
        for line in (
            'SecRuleUpdateTargetById 942100 "!REQUEST_HEADERS:User-Agent"',
            "SecRuleRemoveById 913100",
        ):
            self.assertGreater(engine.index(line), rule_set)

    def test_nothing_else_may_take_the_engine_s_port(self) -> None:
        with self.assertRaisesRegex(Exception, "WAF engine"):
            self.layer(
                "  mode: log", settings=ClusterSettings(metrics=Metrics(9520, ("192.0.2.0/24",)))
            )
