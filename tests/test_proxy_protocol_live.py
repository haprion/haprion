"""A tcp pool told the client's address in a PROXY v2 header, put to a real HAProxy (B279).

The pool member here is the strict kind the form warns about: it reads a
PROXY v2 header first and closes any connection that opens without one. So
two things are proved by one server - that traffic carries the client's own
address rather than the node's, and that the health check carries a header
too, without which every server would stand down.

The client connects from 127.0.0.2 and HAProxy from 127.0.0.1, so the
address the server reports can only have come from the header.
"""

from __future__ import annotations

import contextlib
import ipaddress
import shutil
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path

from haprion.config import Vip
from haprion.generate import generate
from haprion.proxy_model import load_proxy
from tests.spawned import wait_for
from tests.test_generate_behaviour import free_port, start_haproxy, write_release

SIGNATURE = b"\r\n\r\n\x00\r\nQUIT\n"

OBJECT = """
schema: 1
name: mail
listen:
  protocol: tcp
  port: {port}
backend: pool
backends:
  pool:
    balance: roundrobin
    proxy_protocol: v2
    health:
      type: tcp
      interval: 1s
    servers:
      - host: 127.0.0.1
        port: {pool}
"""


def _exactly(connection: socket.socket, count: int) -> bytes:
    data = b""
    while len(data) < count:
        chunk = connection.recv(count - len(data))
        if not chunk:
            break
        data += chunk
    return data


class StrictServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    headers = 0


class Handler(socketserver.BaseRequestHandler):
    """Read the PROXY v2 header, answer with the address in it; no header, no answer."""

    def handle(self) -> None:
        connection = self.request
        connection.settimeout(5)
        head = _exactly(connection, 16)
        if len(head) < 16 or head[:12] != SIGNATURE:
            return
        length = int.from_bytes(head[14:16], "big")
        block = _exactly(connection, length)
        server = self.server
        assert isinstance(server, StrictServer)
        server.headers += 1
        if head[13] >> 4 != 1 or len(block) < 12:
            #
            # LOCAL, or not TCP over IPv4: what a health check may send. It is
            # still a header, which is what this server insists on.
            #
            return
        source = ipaddress.IPv4Address(block[:4])
        #
        # A health check sends the header and closes; the answer then has
        # nobody to reach, which is not this test's business.
        #
        with contextlib.suppress(OSError):
            connection.sendall(f"src={source}\n".encode())


@unittest.skipUnless(shutil.which("haproxy"), "haproxy is not installed here")
class ATcpPoolHearsTheClientsAddress(unittest.TestCase):
    directory: tempfile.TemporaryDirectory[str]
    server: StrictServer
    haproxy: subprocess.Popen[bytes]
    port: int

    @classmethod
    def setUpClass(cls) -> None:
        pool = free_port()
        cls.server = StrictServer(("127.0.0.1", pool), Handler)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        wait_for(pool)
        cls.port = free_port()
        cls.directory = tempfile.TemporaryDirectory()
        layer = generate(
            [load_proxy("mail", OBJECT.format(port=cls.port, pool=pool).encode())],
            vips={"main": Vip(name="main", address="127.0.0.1")},
            default_vip="main",
        )
        arguments = write_release(Path(cls.directory.name), layer)
        binary = shutil.which("haproxy")
        assert binary is not None
        cls.haproxy = start_haproxy(binary, arguments, cls.port)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.haproxy.terminate()
        cls.haproxy.wait(timeout=5)
        cls.server.shutdown()
        cls.server.server_close()
        cls.directory.cleanup()

    def answer(self) -> str:
        with socket.create_connection(
            ("127.0.0.1", self.port), timeout=5, source_address=("127.0.0.2", 0)
        ) as client:
            return client.recv(256).decode()

    def test_the_server_reads_the_clients_address_not_the_nodes(self) -> None:
        self.assertEqual(self.answer(), "src=127.0.0.2\n")

    def test_the_check_sends_a_header_and_keeps_the_pool_up(self) -> None:
        """Three seconds is three checks; a pool marked down would refuse the next client."""

        before = self.server.headers
        time.sleep(3.5)

        self.assertGreaterEqual(self.server.headers - before, 3)
        self.assertEqual(self.answer(), "src=127.0.0.2\n")


if __name__ == "__main__":
    unittest.main()
