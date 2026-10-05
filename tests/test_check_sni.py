"""Whether a health check can send a server name, measured rather than argued.

The model refuses to let a check carry SNI, and the reason recorded for it is
an incident: a verified pool failed its handshake until `sni` was added to the
server line, and `check-sni` was found not to help. From that, the rule became
general - checks send no name, so a check cannot verify one.

The solution review's L5 said that conclusion is broader than its evidence.
HAProxy 3.4 documents `check-sni` and `verifyhost`, and describes automatic SNI
in some http-check cases; none of that explains the incident, but it does mean
"a check cannot send a name" is a claim about this HAProxy that nobody had put
to it.

So this puts it to it. A TLS backend that refuses a handshake carrying no
server name is the instrument: if the check reaches it, a name was sent. There
is no reading of a configuration file that answers this, and no amount of
documentation either - the question is what this binary does.

Skipped where HAProxy or openssl is missing, like every behaviour test here. A
machine that cannot run the process cannot answer the question, and a green
result there would mean nothing.
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

from haproxy_mgmt.config import Vip
from haproxy_mgmt.generate import generate
from haproxy_mgmt.proxy_model import load_proxy
from tests.spawned import wait_for
from tests.test_generate_behaviour import free_port, self_signed, start_haproxy, write_release

#
# A name the certificate is issued for, so that the only thing being measured
# is whether it arrives - not whether it matches.
#
POOL_NAME = "pool.example.net"

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
      verify: none
    health:
      type: http
      path: /
    servers:
      - host: 127.0.0.1
        port: {web}
"""


def sni_only_server(
    port: int, certificate: Path, key: Path, seen: list[str | None]
) -> ThreadingHTTPServer:
    """A TLS server that refuses a handshake carrying no server name.

    The refusal is the measurement. A backend that merely recorded the name
    would leave "no name arrived" and "the check never connected" looking the
    same from the other end.
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

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=str(certificate), keyfile=str(key))

    def record(sock: ssl.SSLObject, name: str | None, _: ssl.SSLContext) -> int | None:
        seen.append(name)
        #
        # `unrecognized_name` is what a server sends when it will not serve
        # what was asked for, and no name at all is exactly that case here.
        #
        return None if name else ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME

    context.sni_callback = record
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@unittest.skipUnless(
    shutil.which("haproxy") and shutil.which("openssl"),
    "haproxy or openssl is not installed here",
)
class WhatACheckSendsInItsHandshake(unittest.TestCase):
    """The claim under test: HAProxy's own check sends no server name."""

    directory: tempfile.TemporaryDirectory[str]
    root: Path
    servers: list[ThreadingHTTPServer]
    running: list[subprocess.Popen[bytes]]

    @classmethod
    def setUpClass(cls) -> None:
        cls.directory = tempfile.TemporaryDirectory()
        cls.root = Path(cls.directory.name)
        cls.servers = []
        cls.running = []

    @classmethod
    def tearDownClass(cls) -> None:
        for process in cls.running:
            process.terminate()
            process.wait(timeout=5)
        for server in cls.servers:
            server.shutdown()
        cls.directory.cleanup()

    def serving(self, extra: str = "") -> tuple[int, list[str | None]]:
        """One HAProxy in front of a pool that insists on being named.

        `extra` is appended to the generated server line, which is how a word
        the generator does not write can still be put to this HAProxy.
        """

        certificate, key = self_signed(
            self.root, f"sni{len(self.servers)}", expired=False, common_name=POOL_NAME
        )
        seen: list[str | None] = []
        web = free_port()
        self.servers.append(sni_only_server(web, certificate, key, seen))
        wait_for(web)

        port = free_port()
        root = self.root / f"case{len(self.running)}"
        root.mkdir()
        layer = generate(
            [load_proxy("secure", OBJECT.format(web=web).encode())],
            vips={"main": Vip(name="main", address="127.0.0.1")},
            default_vip="main",
            ports={"http": port},
        )
        if extra:
            files = dict(layer.configuration)
            name = next(key for key in files if key.startswith("1001-"))
            files[name] = (
                "\n".join(
                    line + extra if line.strip().startswith("server ") else line
                    for line in files[name].splitlines()
                )
                #
                # The generated files end in a newline and HAProxy refuses one
                # that does not - "Missing LF on last line, file might have
                # been truncated". Splitting and joining drops it.
                #
                + "\n"
            )
            layer = type(layer)(
                configuration=files,
                certificate_lists=layer.certificate_lists,
                object_parts=layer.object_parts,
            )
        arguments = write_release(root, layer)
        binary = shutil.which("haproxy")
        assert binary is not None
        self.running.append(start_haproxy(binary, arguments, port))
        return port, seen

    def answered(self, port: int) -> int:
        """What the site answers once the checks have had time to decide.

        Two checks at two seconds have to pass before a server rises, so the
        first request after the proxy accepts connections says nothing.
        """

        deadline = time.monotonic() + 15
        status = 0
        while time.monotonic() < deadline:
            status = self.status(port)
            if status == 200:
                return status
            time.sleep(0.5)
        return status

    def status(self, port: int) -> int:
        connection = HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            connection.putrequest("GET", "/", skip_host=True, skip_accept_encoding=True)
            connection.putheader("Host", "secure.example.com")
            connection.endheaders()
            return int(connection.getresponse().status)
        finally:
            connection.close()

    def checked(self, seen: list[str | None], count: int) -> None:
        """Wait until the pool has seen `count` handshakes from the checks."""

        deadline = time.monotonic() + 15
        while len(seen) < count:
            if time.monotonic() > deadline:
                self.fail(f"the pool saw {len(seen)} checks, not {count}")
            time.sleep(0.1)

    def test_a_name_on_the_server_line_does_not_reach_the_check(self) -> None:
        """The incident, reproduced at last, and it is not what it was read as.

        `sni` makes traffic carry the name. The check goes on sending none, so
        against a pool that insists on one the check fails, every server is
        marked down and the site answers 503 - while the pool itself is
        perfectly healthy and answers any client that names it.

        Measured on HAProxy 3.4.4 on this machine, 2026-09-06.
        """

        port, seen = self.serving(f" sni str({POOL_NAME})")

        #
        # Waiting for a 200 that never comes would wait out the deadline. The
        # generated line has `rise 2`: had two of these checks carried a name
        # the server would be up, and the third is there so that the second's
        # result is in before the site is asked.
        #
        self.checked(seen, 3)
        self.assertEqual(self.status(port), 503)
        self.assertEqual({name for name in seen}, {None})

    def test_check_sni_is_what_makes_the_check_carry_one(self) -> None:
        """And this is the half the general rule got wrong.

        The rule in the model is that a check cannot send a name, so a check
        cannot verify one - written from an incident where adding `sni` did not
        help and `check-sni` was recorded as not working. On this version it
        works: the same pool that refuses a nameless handshake comes up, and
        the name it saw is the one the check was told to send.

        This does not by itself say the model should change - that is a
        decision about what an object may ask for, and it is B105's. What it
        does say is that "a check cannot send a name" is not a fact about this
        HAProxy, so no decision may keep resting on it.

        Measured on HAProxy 3.4.4 on this machine, 2026-09-06.
        """

        port, seen = self.serving(f" sni str({POOL_NAME}) check-sni {POOL_NAME}")

        self.assertEqual(self.answered(port), 200)
        self.assertEqual({name for name in seen}, {POOL_NAME})
