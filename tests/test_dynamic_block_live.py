"""Dynamic blocking run for real: two HAProxy nodes sharing their tables (B271).

The golden files hold what the generator writes and `haproxy -c` that HAProxy
takes it; neither says that it blocks. Here the generated configuration runs on
two local HAProxy processes, 127.0.0.1 and 127.0.0.2 with the same ports, as two
nodes of one cluster sharing counters over `peers`. Visitors are told apart by
the loopback address they connect from.

Held: an address over the request limit is blocked, on the other node too; a
request over the limit during the block starts its time again; errors from the
application are a trigger of their own; an exempt address is never blocked; a
tcp object closes a blocked address's connection; and an unblock has to clear
both nodes and the count as well, or the address is blocked again at once.
Expiry is HAProxy's own `expire`, measured at 20 s during the investigation; the
shortest block the model takes is a minute, too long to wait for here.
"""

from __future__ import annotations

import http.client
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from haprion import cluster_settings
from haprion.config import Vip
from haprion.generate import block_tables, generate
from haprion.proxy_model import load_proxy

NODES = (("node-a", "127.0.0.1"), ("node-b", "127.0.0.2"))
ATTACKER = "127.0.0.10"
GUESSER = "127.0.0.11"
EXEMPT = "127.0.0.20"
TCP_CLIENT = "127.0.0.30"
UNTIL = 5.0


def _free_port() -> int:
    """A port free on both node addresses."""

    while True:
        with socket.socket() as first:
            first.bind((NODES[0][1], 0))
            port = int(first.getsockname()[1])
            with socket.socket() as second:
                try:
                    second.bind((NODES[1][1], port))
                except OSError:
                    continue
            return port


class _Application(BaseHTTPRequestHandler):
    """200 on every path but /missing, which is the application's own 404."""

    def do_GET(self) -> None:  # noqa: N802 - the standard library's name
        status = 404 if self.path == "/missing" else 200
        body = b"application\n"
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_: object) -> None:
        return


def _until(check: Callable[[], bool]) -> bool:
    deadline = time.monotonic() + UNTIL
    while time.monotonic() < deadline:
        if check():
            return True
        time.sleep(0.1)
    return check()


@unittest.skipUnless(shutil.which("haproxy"), "haproxy is not installed here")
class TwoNodesBlock(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)

        self.application = ThreadingHTTPServer(("127.0.0.1", 0), _Application)
        self.addCleanup(self.application.server_close)
        self.addCleanup(self.application.shutdown)
        threading.Thread(target=self.application.serve_forever, daemon=True).start()
        backend_port = int(self.application.server_address[1])

        self.http_port, self.tcp_port, peers_port = _free_port(), _free_port(), _free_port()
        shop = load_proxy(
            "shop",
            f"""schema: 1
name: shop
hostnames: [shop.example.com]
listen:
  protocol: http
dynamic_block:
  window: 10s
  max_requests: 5
  max_errors: 3
  block_for: 1m
  exempt: [{EXEMPT}]
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
        port: {backend_port}
""".encode(),
        )
        db = load_proxy(
            "db",
            f"""schema: 1
name: db
listen:
  protocol: tcp
  port: {self.tcp_port}
dynamic_block:
  window: 10s
  max_new_connections: 3
  block_for: 1m
backend: pool
backends:
  pool:
    balance: roundrobin
    health:
      type: disabled
    servers:
      - host: 127.0.0.1
        port: {backend_port}
""".encode(),
        )
        settings = cluster_settings.load_document(f"peers:\n  port: {peers_port}\n".encode())
        binary = shutil.which("haproxy")
        assert binary is not None
        self.sockets: dict[str, Path] = {}
        for node, address in NODES:
            directory = self.root / node
            (directory / "conf.d").mkdir(parents=True)
            self.sockets[address] = directory / "admin.sock"
            (directory / "haproxy.cfg").write_text(
                "global\n"
                "    default-path config\n"
                "    tune.stick-counters 5\n"
                f"    stats socket {directory / 'admin.sock'} mode 600 level admin\n"
                "defaults\n"
                "    mode http\n"
                "    timeout connect 2s\n"
                "    timeout client 5s\n"
                "    timeout server 5s\n"
            )
            files = generate(
                [shop, db],
                vips={"main": Vip(name="main", address=address)},
                default_vip="main",
                ports={"http": self.http_port, "https": _free_port()},
                settings=settings,
                peer_nodes=NODES,
            ).configuration
            for name, content in files.items():
                (directory / "conf.d" / name).write_text(content)
            process = subprocess.Popen(  # noqa: S603 - the local haproxy, a generated config
                [
                    binary,
                    "-db",
                    "-L",
                    node,
                    "-f",
                    str(directory / "haproxy.cfg"),
                    "-f",
                    str(directory / "conf.d"),
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.STDOUT,
            )
            self.addCleanup(process.wait, 5)
            self.addCleanup(process.terminate)
            self.assertTrue(
                _until(self.sockets[address].exists),
                f"{node} did not start",
            )
        self.assertTrue(_until(self.peers_connected), "the nodes did not connect")

    def runtime(self, node: str, command: str) -> str:
        with socket.socket(socket.AF_UNIX) as connection:
            connection.connect(str(self.sockets[node]))
            connection.sendall(command.encode() + b"\n")
            answer = b""
            while chunk := connection.recv(65536):
                answer += chunk
        return answer.decode()

    def peers_connected(self) -> bool:
        return all("ESTA" in self.runtime(node, "show peers") for _, node in NODES)

    def blocked(self, node: str, name: str = "shop") -> dict[str, int]:
        """Each blocked address on one node, with the milliseconds left."""

        found: dict[str, int] = {}
        for line in self.runtime(node, f"show table {block_tables(name)[1]}").splitlines():
            fields = dict(part.split("=", 1) for part in line.split() if "=" in part)
            if "key" in fields and "exp" in fields:
                found[fields["key"]] = int(fields["exp"])
        return found

    def get(self, node: str, source: str, path: str = "/") -> int:
        connection = http.client.HTTPConnection(
            node, self.http_port, timeout=5, source_address=(source, 0)
        )
        try:
            connection.request("GET", path, headers={"Host": "shop.example.com"})
            response = connection.getresponse()
            response.read()
            return response.status
        finally:
            connection.close()

    def unblock(self, address: str, name: str = "shop") -> None:
        """What the node helper does: count and block cleared on every node, twice."""

        counted, blocked = block_tables(name)
        for _ in range(2):
            for _, node in NODES:
                self.runtime(node, f"clear table {counted} key {address}")
                self.runtime(node, f"clear table {blocked} key {address}")

    def test_over_the_limit_is_blocked_on_both_nodes_and_extended(self) -> None:
        a, b = NODES[0][1], NODES[1][1]
        self.assertEqual([self.get(a, ATTACKER) for _ in range(5)], [200] * 5)
        self.assertEqual(self.get(a, ATTACKER), 404)
        self.assertEqual(self.get(a, "127.0.0.12"), 200, "a neighbour is served")

        self.assertTrue(_until(lambda: ATTACKER in self.blocked(b)), "the block reached node B")
        self.assertEqual(self.get(b, ATTACKER), 404)
        left = self.blocked(b)[ATTACKER]
        self.assertLessEqual(left, 60_000)

        time.sleep(2)
        self.assertEqual(self.get(a, ATTACKER), 404)
        self.assertTrue(
            _until(lambda: self.blocked(b).get(ATTACKER, 0) > left - 500),
            "a request during the block started its time again on node B",
        )

    def test_an_unblock_clears_both_nodes_and_the_count(self) -> None:
        a, b = NODES[0][1], NODES[1][1]
        for _ in range(6):
            self.get(a, ATTACKER)
        self.assertTrue(_until(lambda: ATTACKER in self.blocked(b)))

        self.unblock(ATTACKER)
        self.assertNotIn(ATTACKER, self.blocked(a))
        self.assertNotIn(ATTACKER, self.blocked(b))
        self.assertEqual(self.get(a, ATTACKER), 200)
        self.assertEqual(self.get(b, ATTACKER), 200)

    def test_application_errors_start_a_block(self) -> None:
        a = NODES[0][1]
        self.assertEqual([self.get(a, GUESSER, "/missing") for _ in range(4)], [404] * 4)
        self.assertEqual(self.get(a, GUESSER), 404, "the valid page is blocked now")
        self.assertIn(GUESSER, self.blocked(a))

    def test_an_exempt_address_is_never_blocked(self) -> None:
        a = NODES[0][1]
        self.assertEqual([self.get(a, EXEMPT) for _ in range(12)], [200] * 12)
        self.assertNotIn(EXEMPT, self.blocked(a))

    def test_a_tcp_object_closes_a_blocked_connection(self) -> None:
        a = NODES[0][1]

        def answered() -> bool:
            with socket.create_connection(
                (a, self.tcp_port), timeout=5, source_address=(TCP_CLIENT, 0)
            ) as connection:
                connection.sendall(b"GET / HTTP/1.0\r\nHost: db\r\n\r\n")
                try:
                    return connection.recv(64).startswith(b"HTTP/1.0 200")
                except ConnectionResetError:
                    return False

        self.assertEqual([answered() for _ in range(3)], [True] * 3)
        self.assertFalse(answered())
        self.assertIn(TCP_CLIENT, self.blocked(a, "db"))


if __name__ == "__main__":
    unittest.main()
