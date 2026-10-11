"""A pool verified against the cluster's own CA, put to a real HAProxy (B276).

The claim: `verify: ca` lets HAProxy trust a server whose certificate the
organisation's own CA issued - which the node's trust store does not know -
and nothing else. Three answers from one HAProxy and one pool, the CA file
the only thing changed between them: the right CA answers 200, the node's
trust store answers 503, and another CA answers 503.

Skipped where HAProxy or openssl is missing, like every behaviour test here.
"""

from __future__ import annotations

import shutil
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from haprion.config import Vip
from haprion.generate import generate
from haprion.proxy_model import load_proxy
from tests.spawned import wait_for
from tests.test_cert_import import Pki
from tests.test_generate_behaviour import free_port, start_haproxy, write_release

#
# A name that resolves without DNS, so the pool can be named rather than
# addressed - which verification requires.
#
POOL_NAME = "localhost"

OBJECT = """
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
    servers:
      - host: {name}
        port: {web}
"""


def tls_server(port: int, certificate: Path, key: Path, chain: Path) -> ThreadingHTTPServer:
    """A pool member serving a certificate the organisation's CA issued."""

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

    served = certificate.parent / f"{certificate.stem}-served.pem"
    served.write_text(certificate.read_text() + chain.read_text())
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=str(served), keyfile=str(key))
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@unittest.skipUnless(
    shutil.which("haproxy") and shutil.which("openssl"),
    "haproxy or openssl is not installed here",
)
class APoolIsTrustedThroughTheClustersOwnCa(unittest.TestCase):
    directory: tempfile.TemporaryDirectory[str]
    root: Path
    pki: Pki
    other: Pki
    web: int
    server: ThreadingHTTPServer
    running: list[subprocess.Popen[bytes]]

    @classmethod
    def setUpClass(cls) -> None:
        cls.directory = tempfile.TemporaryDirectory()
        cls.root = Path(cls.directory.name)
        cls.pki = Pki(cls.root / "corp", names=(POOL_NAME,))
        cls.other = Pki(cls.root / "other", names=(POOL_NAME,))
        cls.web = free_port()
        cls.server = tls_server(cls.web, cls.pki.leaf, cls.pki.leaf_key, cls.pki.intermediate)
        wait_for(cls.web)
        cls.running = []

    @classmethod
    def tearDownClass(cls) -> None:
        for process in cls.running:
            process.terminate()
            process.wait(timeout=5)
        cls.server.shutdown()
        cls.directory.cleanup()

    def serving(self, verify: str, ca_file: Path | None) -> int:
        port = free_port()
        case = self.root / f"case{len(self.running)}"
        certificates = case / "certs"
        (certificates / "ca").mkdir(parents=True)
        authorities: tuple[str, ...] = ()
        if ca_file is not None:
            (certificates / "ca" / "corp-root.pem").write_text(ca_file.read_text())
            authorities = ("corp-root",)
        document = OBJECT.format(verify=verify, name=POOL_NAME, web=self.web)
        if verify == "ca":
            document = document.replace("verify: ca", "verify: ca\n      ca: corp-root")
        layer = generate(
            [load_proxy("secure", document.encode())],
            vips={"main": Vip(name="main", address="127.0.0.1")},
            default_vip="main",
            ports={"http": port},
            authorities=authorities,
        )
        arguments = write_release(case, layer, certificates)
        binary = shutil.which("haproxy")
        assert binary is not None
        self.running.append(start_haproxy(binary, arguments, port))
        return port

    def answered(self, port: int) -> int:
        deadline = time.monotonic() + 10
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
                return status
            time.sleep(0.3)
        return status

    def test_the_organisations_root_is_trusted(self) -> None:
        self.assertEqual(self.answered(self.serving("ca", self.pki.root)), 200)

    def test_the_node_trust_store_does_not_know_it(self) -> None:
        self.assertEqual(self.answered(self.serving("system", None)), 503)

    def test_another_ca_is_not_trusted(self) -> None:
        self.assertEqual(self.answered(self.serving("ca", self.other.root)), 503)


if __name__ == "__main__":
    unittest.main()
