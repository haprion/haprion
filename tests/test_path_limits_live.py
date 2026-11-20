"""Path limits run for real: two HAProxy nodes sharing their tables (B517, 11; B520).

The golden files hold what the generator writes and `haproxy -c` that HAProxy
takes it; neither says that a limit refuses. Here the generated configuration
runs on two local HAProxy processes, 127.0.0.1 and 127.0.0.2 with the same
ports, as two nodes of one cluster sharing counters over `peers`. Visitors are
told apart by the loopback address they connect from.

Held: a limited path is refused past its count, on the other node too; the
ways a path can be written differently count as the path; a path with a dot
segment is refused; the most specific limit counts a request and the others do
not; a limited path's requests count on the object's rate limit as well; and
behind a trusted proxy the visitor is counted, never the proxy.
"""

from __future__ import annotations

import http.client
import re
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
from haprion.generate import generate, path_limit_table
from haprion.proxy_model import load_proxy
from tests import spawned

NODES = (("node-a", "127.0.0.1"), ("node-b", "127.0.0.2"))
PROXY = "127.0.0.50"
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
    def do_GET(self) -> None:  # the standard library's name
        body = b"application\n"
        self.send_response(200)
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
class TwoNodesLimitPaths(unittest.TestCase):
    @spawned.retry_on_taken_port
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)

        self.application = ThreadingHTTPServer(("127.0.0.1", 0), _Application)
        self.addCleanup(self.application.server_close)
        self.addCleanup(self.application.shutdown)
        threading.Thread(target=self.application.serve_forever, daemon=True).start()
        backend_port = int(self.application.server_address[1])

        self.http_port, peers_port = _free_port(), _free_port()
        shop = load_proxy(
            "shop",
            f"""schema: 1
name: shop
hostnames: [shop.example.com]
listen:
  protocol: http
rate_limit:
  window: 10s
  max_requests: 6
path_limits:
  - path: /api
    max_requests: 4
    window: 10s
  - path: /login
    match: exact
    max_requests: 3
    window: 10s
  - path: /api/login
    match: exact
    max_requests: 2
    window: 1m
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
        settings = cluster_settings.load_document(f"peers:\n  port: {peers_port}\n".encode())
        binary = shutil.which("haproxy")
        assert binary is not None
        self.sockets: dict[str, Path] = {}
        self.outputs: list[Path] = []
        for node, address in NODES:
            directory = self.root / node
            (directory / "conf.d").mkdir(parents=True)
            self.sockets[address] = directory / "admin.sock"
            (directory / "haproxy.cfg").write_text(
                "global\n"
                f"{spawned.NOREUSEPORT}"
                "    default-path config\n"
                "    tune.stick-counters 6\n"
                f"    stats socket {directory / 'admin.sock'} mode 600 level admin\n"
                "defaults\n"
                "    mode http\n"
                "    timeout connect 2s\n"
                "    timeout client 5s\n"
                "    timeout server 5s\n"
            )
            files = generate(
                [shop],
                vips={"main": Vip(name="main", address=address)},
                default_vip="main",
                ports={"http": self.http_port, "https": _free_port()},
                settings=settings,
                node_addresses=NODES,
                trusted_proxies=(f"{PROXY}/32",),
            ).configuration
            for name, content in files.items():
                (directory / "conf.d" / name).write_text(content)
            self.outputs.append(directory / "haproxy.out")
            with self.outputs[-1].open("wb") as output:
                process = subprocess.Popen(  # the local haproxy, a generated config
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
                    stdout=output,
                    stderr=subprocess.STDOUT,
                )
            self.addCleanup(process.wait, 5)
            self.addCleanup(process.terminate)
            if not _until(self.sockets[address].exists):
                self._did_not_start(f"{node} did not start")
        try:
            connected = _until(self.peers_connected)
        except OSError:
            connected = False
        if not connected:
            self._did_not_start("the nodes did not connect")

    def _did_not_start(self, message: str) -> None:
        """Fail the setup; as `PortTaken` when HAProxy said a port was held."""

        said = "".join(path.read_text(errors="replace") for path in self.outputs if path.exists())
        if "cannot bind" in said or "Address already in use" in said:
            raise spawned.PortTaken(said)
        self.fail(f"{message}\n{said}")

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

    def counted(self, node: str, table: str, visitor: str) -> int:
        """How many requests one node's table holds for a visitor, 0 when it holds none."""

        found = re.search(
            rf"key=(?:::ffff:)?{re.escape(visitor)} .*?http_req_rate\(\d+\)=(\d+)",
            self.runtime(node, f"show table {table}"),
        )
        return int(found[1]) if found else 0

    def get(self, node: str, source: str, path: str, forwarded: str = "") -> int:
        connection = http.client.HTTPConnection(
            node, self.http_port, timeout=5, source_address=(source, 0)
        )
        headers = {"Host": "shop.example.com"}
        if forwarded:
            headers["X-Forwarded-For"] = forwarded
        try:
            connection.request("GET", path, headers=headers)
            response = connection.getresponse()
            response.read()
            return response.status
        finally:
            connection.close()

    def test_a_limited_path_is_refused_past_its_count_on_both_nodes(self) -> None:
        a, b = NODES[0][1], NODES[1][1]
        visitor = "127.0.0.10"
        self.assertEqual([self.get(a, visitor, "/login") for _ in range(4)], [200] * 3 + [429])
        self.assertEqual(self.get(a, "127.0.0.12", "/login"), 200, "a neighbour is served")
        table = path_limit_table("shop", 1)
        #
        # The whole count, not only the entry: under load the entry reached
        # node B before the last request's increment did (gate, 26-11-20).
        #
        self.assertTrue(
            _until(lambda: self.counted(b, table, visitor) >= 4), "the count reached node B"
        )
        self.assertEqual(self.get(b, visitor, "/login"), 429)

    def test_the_ways_of_writing_a_path_count_as_the_path(self) -> None:
        a = NODES[0][1]
        visitor = "127.0.0.13"
        answers = [
            self.get(a, visitor, path) for path in ("/LOGIN", "/login/", "/login;x", "//login")
        ]
        self.assertEqual(answers, [200, 200, 200, 429])
        self.assertEqual(self.get(a, "127.0.0.14", "/./login"), 400)
        self.assertEqual(self.get(a, "127.0.0.14", "/a/../login"), 400)

    def test_the_most_specific_limit_counts_and_the_others_do_not(self) -> None:
        a = NODES[0][1]
        visitor = "127.0.0.15"
        self.assertEqual([self.get(a, visitor, "/api/login") for _ in range(3)], [200, 200, 429])
        #
        # Three requests on /api/login so far; had they counted on /api as
        # well, its limit of four would refuse the second of these.
        #
        self.assertEqual([self.get(a, visitor, f"/api/x{n}") for n in range(5)], [200] * 4 + [429])

    def test_a_limited_path_counts_on_the_object_limit_too(self) -> None:
        a = NODES[0][1]
        visitor = "127.0.0.17"
        self.assertEqual([self.get(a, visitor, "/login") for _ in range(3)], [200] * 3)
        self.assertEqual([self.get(a, visitor, f"/page{n}") for n in range(4)], [200] * 3 + [429])

    def test_behind_a_proxy_the_visitor_is_counted(self) -> None:
        a = NODES[0][1]
        self.assertEqual(
            [self.get(a, PROXY, "/login", forwarded="192.0.2.7") for _ in range(4)],
            [200] * 3 + [429],
        )
        self.assertEqual(self.get(a, PROXY, "/login", forwarded="192.0.2.8"), 200)


if __name__ == "__main__":
    unittest.main()
