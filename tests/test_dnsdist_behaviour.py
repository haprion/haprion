"""What dnsdist actually does with what we generate (Fas 19, B249).

`dnsdist --check-config` proves the file is a configuration; it does not prove
the configuration answers whom it should, refuses whom it should, and carries
the client's address to the servers behind. This test runs the generated file
in a real dnsdist on loopback, with two small DNS servers behind it that each
answer with an address of their own and remember whether the client's subnet
came along.

Skipped where dnsdist is not installed, for the reason `test_generate_behaviour`
gives for HAProxy: a machine that cannot run the process cannot answer the
question.
"""

from __future__ import annotations

import ipaddress
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.request
from pathlib import Path

from haproxy_mgmt import dnsdist_config
from haproxy_mgmt.config import Vip
from haproxy_mgmt.generate import generate
from haproxy_mgmt.golden import cases, expected_dns
from haproxy_mgmt.proxy_model import load_proxy

DNSDIST = shutil.which("dnsdist")


def free_port() -> int:
    """A port free for both UDP and TCP, which dnsdist binds together.

    Asking UDP alone lost one run in the full gate (2026-10-06): another test
    process held the same number over TCP, dnsdist could not bind its TCP
    listener, and the answer never came.
    """

    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as stream:
            stream.bind(("127.0.0.1", 0))
            port = int(stream.getsockname()[1])
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as datagram:
                try:
                    datagram.bind(("127.0.0.1", port))
                except OSError:
                    continue
                return port


def question(name: str) -> bytes:
    header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    labels = b"".join(bytes([len(part)]) + part.encode() for part in name.split("."))
    return header + labels + b"\0" + struct.pack(">HH", 1, 1)


def ask(port: int, name: str = "www.example.com") -> tuple[int, str | None]:
    """The answer's rcode and its first A record, over UDP from 127.0.0.1."""

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(3)
        client.sendto(question(name), ("127.0.0.1", port))
        data = client.recv(4096)
    rcode = data[3] & 15
    if struct.unpack(">H", data[6:8])[0] == 0:
        return rcode, None
    return rcode, str(ipaddress.ip_address(data[-4:]))


class Server(threading.Thread):
    """Answers every A question with its own address; remembers client subnets."""

    def __init__(self, answer: str) -> None:
        super().__init__(daemon=True)
        self.answer = ipaddress.ip_address(answer).packed
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", 0))
        self.socket.settimeout(0.2)
        self.port = int(self.socket.getsockname()[1])
        self.subnets: list[str] = []
        self.stopped = threading.Event()

    def run(self) -> None:
        while not self.stopped.is_set():
            try:
                data, peer = self.socket.recvfrom(4096)
            except TimeoutError:
                continue
            end = 12
            while data[end] != 0:
                end += data[end] + 1
            end += 5
            subnet = self._subnet(data[end:])
            if subnet is not None:
                self.subnets.append(subnet)
            reply = (
                data[:2]
                + struct.pack(">HHHHH", 0x8180, 1, 1, 0, 0)
                + data[12:end]
                + b"\xc0\x0c"
                + struct.pack(">HHIH", 1, 1, 60, 4)
                + self.answer
            )
            self.socket.sendto(reply, peer)

    @staticmethod
    def _subnet(additional: bytes) -> str | None:
        """The address in an EDNS Client Subnet option (code 8), if one came."""

        if len(additional) < 11 or additional[0] != 0 or additional[1:3] != b"\x00\x29":
            return None
        options = additional[11 : 11 + struct.unpack(">H", additional[9:11])[0]]
        while len(options) >= 4:
            code, length = struct.unpack(">HH", options[:4])
            body = options[4 : 4 + length]
            if code == 8 and struct.unpack(">H", body[:2])[0] == 1:
                return str(ipaddress.ip_address(body[4:].ljust(4, b"\0")))
            options = options[4 + length :]
        return None

    def stop(self) -> None:
        self.stopped.set()
        self.join()
        self.socket.close()


def dns_object(name: str, port: int, servers: list[Server], allow: str, balance: str) -> bytes:
    members = ", ".join(f"{{host: 127.0.0.1, port: {server.port}}}" for server in servers)
    return f"""schema: 1
name: {name}
listen: {{protocol: dns, port: {port}}}
backend: {name}-dns
allow_from: [{allow}]
backends:
  {name}-dns:
    balance: {balance}
    servers: [{members}]
    health: {{type: dns, query_name: health.example.com}}
""".encode()


@unittest.skipUnless(DNSDIST, "dnsdist is not installed here")
class GeneratedConfigurationInDnsdist(unittest.TestCase):
    def setUp(self) -> None:
        self.servers = [Server("192.0.2.1"), Server("192.0.2.2")]
        for server in self.servers:
            server.start()
            self.addCleanup(server.stop)
        self.open_port, self.closed_port = free_port(), free_port()
        objects = [
            load_proxy(
                "lan", dns_object("lan", self.open_port, self.servers, "127.0.0.0/8", "roundrobin")
            ),
            load_proxy(
                "elsewhere",
                dns_object("elsewhere", self.closed_port, self.servers, "192.0.2.0/24", "chashed"),
            ),
        ]
        layer = generate(objects, vips={"main": Vip("main", "127.0.0.1")}, default_vip="main")
        directory = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, directory)
        config = directory / dnsdist_config.FILE
        config.write_text(layer.dns_files[dnsdist_config.FILE])
        checked = subprocess.run(  # noqa: S603 - the installed dnsdist, our own file
            [str(DNSDIST), "--check-config", "-C", str(config)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)
        self.assertNotIn('prio="Warning"', checked.stdout + checked.stderr)
        self.process = subprocess.Popen(  # noqa: S603 - the installed dnsdist, our own file
            [str(DNSDIST), "--supervised", "--disable-syslog", "-C", str(config)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.addCleanup(self._stop)
        self._wait_until_answering()

    def _stop(self) -> None:
        self.process.terminate()
        self.process.wait(timeout=10)

    def _wait_until_answering(self) -> None:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            try:
                if ask(self.open_port)[0] == 0:
                    return
            except OSError:
                pass
            time.sleep(0.2)
        self.fail("dnsdist did not answer on the generated listener")

    def test_an_allowed_client_is_answered_by_the_pool_in_turn(self) -> None:
        answers = {ask(self.open_port)[1] for _ in range(6)}
        self.assertEqual(answers, {"192.0.2.1", "192.0.2.2"})

    def test_a_client_outside_allow_from_is_refused(self) -> None:
        rcode, answer = ask(self.closed_port)
        self.assertEqual((rcode, answer), (5, None))

    def test_the_client_address_travels_to_the_servers(self) -> None:
        for server in self.servers:
            server.subnets.clear()
        for _ in range(4):
            ask(self.open_port)
        carried = {subnet for server in self.servers for subnet in server.subnets}
        self.assertEqual(carried, {"127.0.0.1"})

    def test_the_counters_are_readable_on_loopback_without_a_key(self) -> None:
        ask(self.open_port)
        with urllib.request.urlopen(  # noqa: S310 - loopback, fixed port
            f"http://127.0.0.1:{dnsdist_config.STATS_PORT}/metrics", timeout=5
        ) as response:
            body = response.read().decode()
        self.assertIn('dnsdist_server_queries{server="lan-s1"', body)
        self.assertIn('dnsdist_server_status{server="elsewhere-s2"', body)


@unittest.skipUnless(DNSDIST, "dnsdist is not installed here")
class EveryGoldenDnsdistFileIsAConfiguration(unittest.TestCase):
    """The frozen files, as dnsdist reads them: no error and no warning.

    A warning is a failure here because dnsdist ignores an unknown key with
    one and exits 0 (`Unknown key, ignored`, measured on 2.1.2) - a setting
    the generator misspelt would otherwise be accepted and quietly dropped.
    """

    def test_dnsdist_accepts_them_without_a_word(self) -> None:
        checked = 0
        for case in cases():
            for name, content in expected_dns(case).items():
                with self.subTest(case.name), tempfile.TemporaryDirectory() as raw:
                    path = Path(raw) / name
                    path.write_text(content)
                    result = subprocess.run(  # noqa: S603 - the installed dnsdist, a golden file
                        [str(DNSDIST), "--check-config", "-C", str(path)],
                        capture_output=True,
                        text=True,
                        timeout=30,
                        check=False,
                    )
                    output = result.stdout + result.stderr
                    self.assertEqual(result.returncode, 0, output)
                    self.assertNotIn('prio="Warning"', output)
                    self.assertNotIn('prio="Error"', output)
                    checked += 1
        self.assertGreater(checked, 0)


if __name__ == "__main__":
    unittest.main()
