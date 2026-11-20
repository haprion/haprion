"""The request ID and the client's protocol, put to a real HAProxy (B517 p. 1 and 6, B523).

One request is followed from the client through the generated frontend to the
backend and into the traffic record: the backend answers with the
`X-Request-ID` headers it received, and the record is read off the log socket
as the node would write it. An ID a visitor sends is replaced; one a trusted
proxy sends is kept when it came once and in the accepted form. The record
says which TLS and HTTP version the client used, over TCP and over QUIC (a
second HAProxy is the HTTP/3 client, as in `test_http3_live`).

Skipped where HAProxy is missing or built without QUIC.
"""

from __future__ import annotations

import json
import re
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

from haprion.config import Vip
from haprion.generate import generate
from haprion.proxy_model import load_proxy
from tests import spawned
from tests.spawned import free_port, start_haproxy, wait_for
from tests.test_generate_behaviour import self_signed, write_release
from tests.test_http3_live import CLIENT

HAPROXY = shutil.which("haproxy")
QUIC = (
    bool(HAPROXY)
    and "USE_QUIC=1"
    in subprocess.run(  # the installed haproxy
        [HAPROXY or "haproxy", "-vv"], capture_output=True, text=True, check=False
    ).stdout
)

SITE = """
schema: 1
name: {name}
hostnames: [{name}.example.com]
listen:
  protocol: {protocol}
{listen}{extra}routes:
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
TLS_LISTEN = "  certificate: site\n  redirect_http: false\n"
UUID7 = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
TRUSTED = "127.0.0.2"


def id_server(port: int) -> ThreadingHTTPServer:
    """Answers with every `X-Request-ID` it received, joined by `|`."""

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # the name is the library's
            body = "|".join(self.headers.get_all("X-Request-ID") or []).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_: object) -> None:
            """Silence. The test's own output is the interesting one."""

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@unittest.skipUnless(QUIC, "haproxy is not installed here, or has no QUIC")
class TheRequestIdFollowsTheRequest(unittest.TestCase):
    directory: tempfile.TemporaryDirectory[str]
    server: ThreadingHTTPServer
    running: list[subprocess.Popen[bytes]]
    sink: socket.socket
    http: int
    https: int
    client: int

    @classmethod
    @spawned.retry_on_taken_port
    def setUpClass(cls) -> None:
        cls.directory = tempfile.TemporaryDirectory()
        root = Path(cls.directory.name)
        pool = free_port()
        cls.server = id_server(pool)
        wait_for(pool)
        certificates = root / "certs"
        certificates.mkdir()
        certificate, key = self_signed(root, "site", expired=False, common_name="open.example.com")
        (certificates / "site.pem").write_text(key.read_text() + certificate.read_text())
        cls.http, cls.https = free_port(), free_port()

        def site(name: str, protocol: str, extra: str = "") -> bytes:
            listen = TLS_LISTEN if protocol == "https" else ""
            return SITE.format(
                name=name, protocol=protocol, listen=listen, extra=extra, pool=pool
            ).encode()

        layer = generate(
            [
                load_proxy("open", site("open", "https")),
                load_proxy("plain", site("plain", "http")),
                load_proxy("locked", site("locked", "http", "allow_from: [office]\n")),
            ],
            vips={"main": Vip(name="main", address="127.0.0.1", http3=True)},
            default_vip="main",
            ports={"http": cls.http, "https": cls.https},
            certificates=("site",),
            networks={"office": ("198.51.100.0/24",)},
            trusted_proxies=(f"{TRUSTED}/32",),
            traffic_logging=True,
        )
        release = root / "release"
        release.mkdir()
        arguments = write_release(release, layer, certificates)
        cls.sink = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        cls.sink.bind(str(root / "log.sock"))
        cls.sink.settimeout(0.2)
        frontends = release / "conf.d" / "1000-frontends.cfg"
        frontends.write_text(
            frontends.read_text().replace(
                "log /var/lib/haproxy/dev/haprion-traffic ", f"log {root / 'log.sock'} "
            )
        )
        assert HAPROXY is not None
        cls.running = [start_haproxy(HAPROXY, arguments, cls.https)]
        cls.client = free_port()
        (root / "client.cfg").write_text(
            CLIENT.format(port=cls.client, other=free_port(), site=cls.https)
        )
        try:
            cls.running.append(start_haproxy(HAPROXY, ["-f", str(root / "client.cfg")], cls.client))
        except BaseException:
            cls.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls) -> None:
        for process in cls.running:
            process.terminate()
            process.wait(timeout=5)
        cls.server.shutdown()
        cls.server.server_close()
        cls.sink.close()
        cls.directory.cleanup()

    def plain(
        self,
        path: str,
        *,
        host: str = "plain.example.com",
        source: str = "127.0.0.1",
        ids: tuple[str, ...] = (),
    ) -> tuple[int, str]:
        connection = HTTPConnection("127.0.0.1", self.http, timeout=5, source_address=(source, 0))
        try:
            connection.putrequest("GET", path, skip_host=True, skip_accept_encoding=True)
            connection.putheader("Host", host)
            for value in ids:
                connection.putheader("X-Request-ID", value)
            connection.endheaders()
            response = connection.getresponse()
            return response.status, response.read().decode()
        finally:
            connection.close()

    def over_tls(self, path: str, version: ssl.TLSVersion) -> str:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = context.maximum_version = version
        connection = HTTPSConnection("127.0.0.1", self.https, timeout=5, context=context)
        try:
            connection.putrequest("GET", path, skip_host=True, skip_accept_encoding=True)
            connection.putheader("Host", "open.example.com")
            connection.endheaders()
            return connection.getresponse().read().decode()
        finally:
            connection.close()

    def record(self, path: str) -> dict[str, object]:
        """The traffic record of the last request for `path`, as the nodes log it."""

        found: dict[str, object] = {}
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            try:
                datagram = self.sink.recv(65536).decode()
            except TimeoutError:
                if found:
                    break
                continue
            entry = json.loads(datagram[datagram.index("{") :])
            if entry.get("path") == path:
                found = entry
        self.assertTrue(found, f"no traffic record for {path}")
        return found

    def test_the_backend_and_the_record_carry_one_generated_id(self) -> None:
        status, received = self.plain("/one")
        record = self.record("/one")

        self.assertEqual(status, 200)
        self.assertRegex(received, UUID7)
        self.assertEqual(record["request_id"], received)
        self.assertEqual((record["tls"], record["http"]), ("", "1.1"))

    def test_two_requests_get_two_ids_in_the_order_they_came(self) -> None:
        _, first = self.plain("/first")
        _, second = self.plain("/second")

        self.assertNotEqual(first, second)
        #
        # Version 7 orders by the millisecond: two IDs of one millisecond differ
        # in random bits after it, in either order (seen 26-11-20).
        #
        self.assertLessEqual(first[:13], second[:13])

    def test_an_id_a_visitor_sends_is_replaced(self) -> None:
        _, received = self.plain("/forged", ids=("chosen-by-the-visitor",))

        self.assertRegex(received, UUID7)
        self.assertEqual(self.record("/forged")["request_id"], received)

    def test_a_trusted_proxy_keeps_its_id(self) -> None:
        _, received = self.plain("/kept", source=TRUSTED, ids=("edge-4711.a:b=c+d/e",))

        self.assertEqual(received, "edge-4711.a:b=c+d/e")
        self.assertEqual(self.record("/kept")["request_id"], received)

    def test_a_trusted_proxy_loses_an_id_sent_twice_or_out_of_form(self) -> None:
        for path, ids in (
            ("/twice", ("one", "two")),
            ("/comma", ("one,two",)),
            ("/spaced", ("has space",)),
            ("/long", ("x" * 129,)),
        ):
            with self.subTest(path=path):
                _, received = self.plain(path, source=TRUSTED, ids=ids)
                self.assertRegex(received, UUID7)

    def test_a_refused_request_has_an_id_in_its_record(self) -> None:
        status, _ = self.plain("/refused", host="locked.example.com")
        record = self.record("/refused")

        self.assertEqual(status, 403)
        self.assertRegex(str(record["request_id"]), UUID7)
        self.assertEqual(record["backend"], record["frontend"])

    def test_the_record_says_which_tls_version_the_client_used(self) -> None:
        for path, version, said in (
            ("/tls12", ssl.TLSVersion.TLSv1_2, "TLSv1.2"),
            ("/tls13", ssl.TLSVersion.TLSv1_3, "TLSv1.3"),
        ):
            with self.subTest(said=said):
                received = self.over_tls(path, version)
                record = self.record(path)
                self.assertEqual((record["tls"], record["http"]), (said, "1.1"))
                self.assertEqual(record["request_id"], received)

    def test_the_record_says_http3_over_quic(self) -> None:
        connection = HTTPConnection("127.0.0.1", self.client, timeout=10)
        try:
            connection.putrequest("GET", "/quic", skip_host=True, skip_accept_encoding=True)
            connection.putheader("Host", "open.example.com")
            connection.endheaders()
            received = connection.getresponse().read().decode()
        finally:
            connection.close()
        record = self.record("/quic")

        self.assertEqual((record["tls"], record["http"]), ("TLSv1.3", "3.0"))
        self.assertEqual(record["request_id"], received)


if __name__ == "__main__":
    unittest.main()
