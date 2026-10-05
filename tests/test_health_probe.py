"""The node-side probe, run as a node runs it: JSON in, JSON out, no arguments.

The script is executed rather than imported, because how it is *called* is half
of what it is. It is the forced command on a key somebody else holds, so the
request is client-controlled data, and a request it should refuse must be
refused by the file itself and not by whatever imports it.

Every case here is a real connection to a real socket in this process. A probe
that says a server answered is worth nothing unless the thing that says it
actually opened the connection.
"""

from __future__ import annotations

import json
import shutil
import socket
import ssl
import subprocess as sp
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from tests import spawned

SCRIPT = Path(__file__).resolve().parents[1] / "install" / "node" / "haproxy-health-probe"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - the name is the library's
        body = b"served"
        status = {"/healthz": 200, "/moved": 302}.get(self.path, 404)
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        try:
            self.end_headers()
            self.wfile.write(body)
        except OSError:
            #
            # The probe reads the status line and hangs up, which is the point:
            # it never reads a body. Writing into the closed socket is not a
            # failure of anything being tested.
            pass

    def log_message(self, *_: object) -> None:
        """Silence."""


def ask(request: dict[str, object]) -> tuple[int, dict[str, Any]]:
    completed = sp.run(
        [str(SCRIPT)],
        input=json.dumps(request).encode(),
        capture_output=True,
        check=False,
    )
    return completed.returncode, json.loads(completed.stdout)


def target(**fields: object) -> dict[str, object]:
    entry: dict[str, object] = {"type": "http", "host": "127.0.0.1", "path": "/healthz"}
    entry.update(fields)
    return entry


class WhatTheProbeAnswers(unittest.TestCase):
    server: ThreadingHTTPServer
    port: int
    thread: threading.Thread

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.port = int(cls.server.server_address[1])
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        # `shutdown` stops the loop; the listening socket stays open until
        # `server_close`. One leaked socket per class per run, otherwise.
        cls.server.shutdown()
        cls.server.server_close()

    def probe(self, **fields: object) -> dict[str, object]:
        code, answer = ask({"schema_version": 1, "targets": [target(port=self.port, **fields)]})
        self.assertEqual(code, 0)
        result: dict[str, object] = answer["results"][0]
        return result

    def test_a_server_that_answers_is_usable(self) -> None:
        result = self.probe()
        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], 200)
        self.assertIsNone(result["error"])

    def test_a_redirect_counts_as_usable(self) -> None:
        """The range HAProxy's own check accepts, so the two agree."""

        self.assertTrue(self.probe(path="/moved")["ok"])

    def test_a_server_that_answers_wrongly_is_not_usable(self) -> None:
        """404 is the mistake this exists to catch: a check on the wrong path."""

        result = self.probe(path="/nowhere")
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], 404)
        self.assertEqual(result["error"], "answered 404")

    def test_a_tcp_probe_asks_only_whether_the_port_answers(self) -> None:
        result = self.probe(type="tcp")
        self.assertTrue(result["ok"])
        self.assertIsNone(result["status"])

    def test_a_port_nothing_listens_on_is_reported_as_refused(self) -> None:
        code, answer = ask({"schema_version": 1, "targets": [target(type="tcp", port=free_port())]})
        self.assertEqual(code, 0)
        result = answer["results"][0]
        self.assertFalse(result["ok"])
        self.assertIn("refused", str(result["error"]).lower())

    def test_plain_http_against_a_tls_expectation_fails_rather_than_hangs(self) -> None:
        result = self.probe(tls=True, verify=False)
        self.assertFalse(result["ok"])
        self.assertIsNotNone(result["error"])

    def test_the_body_never_comes_back(self) -> None:
        """A key that returned pages would be a way to read through the node."""

        self.assertNotIn("served", json.dumps(self.probe()))

    def test_every_target_is_answered_in_order(self) -> None:
        code, answer = ask(
            {
                "schema_version": 1,
                "targets": [
                    target(port=self.port),
                    target(port=self.port, path="/nowhere"),
                ],
            }
        )
        self.assertEqual(code, 0)
        self.assertEqual([entry["ok"] for entry in answer["results"]], [True, False])


class SlowServers:
    """Listeners that accept and then say nothing, or say it a byte at a time."""

    def __init__(self, count: int, *, drip: float | None = None) -> None:
        self.stop = threading.Event()
        self.listeners: list[socket.socket] = []
        for _ in range(count):
            listener = socket.socket()
            listener.bind(("127.0.0.1", 0))
            listener.listen(8)
            listener.settimeout(0.1)
            self.listeners.append(listener)
            threading.Thread(target=self._serve, args=(listener, drip), daemon=True).start()

    @property
    def ports(self) -> list[int]:
        return [int(listener.getsockname()[1]) for listener in self.listeners]

    def _serve(self, listener: socket.socket, drip: float | None) -> None:
        held = []
        while not self.stop.is_set():
            try:
                connection, _ = listener.accept()
            except OSError:
                continue
            held.append(connection)
            if drip is not None:
                threading.Thread(target=self._drip, args=(connection, drip), daemon=True).start()
        for connection in held:
            connection.close()

    def _drip(self, connection: socket.socket, every: float) -> None:
        while not self.stop.is_set():
            try:
                connection.sendall(b"H")
            except OSError:
                return
            time.sleep(every)

    def close(self) -> None:
        self.stop.set()
        for listener in self.listeners:
            listener.close()


class HowLongAProbeTakes(unittest.TestCase):
    """All targets at once, and none longer than three timeouts (review 2026-09-28).

    One after the other, twenty silent servers took 40 s at the default
    timeout - past the manager's 30 s for the node - and the answer was lost
    exactly when the whole pool was down.
    """

    def test_silent_servers_are_waited_for_together(self) -> None:
        servers = SlowServers(5)
        self.addCleanup(servers.close)
        started = time.monotonic()
        code, answer = ask(
            {
                "schema_version": 1,
                "timeout_ms": 300,
                "targets": [target(port=port) for port in servers.ports],
            }
        )
        elapsed = time.monotonic() - started
        self.assertEqual(code, 0)
        self.assertEqual([entry["port"] for entry in answer["results"]], servers.ports)
        self.assertTrue(all(not entry["ok"] for entry in answer["results"]))
        # One after the other would be 1.5 s; together it is one timeout.
        self.assertLess(elapsed, 1.2)

    def test_a_server_sending_a_byte_at_a_time_is_cut_off(self) -> None:
        # Each byte arrives inside the timeout, so only the deadline stops it.
        servers = SlowServers(1, drip=0.1)
        self.addCleanup(servers.close)
        started = time.monotonic()
        code, answer = ask(
            {"schema_version": 1, "timeout_ms": 300, "targets": [target(port=servers.ports[0])]}
        )
        elapsed = time.monotonic() - started
        self.assertEqual(code, 0)
        self.assertEqual(answer["results"][0]["error"], "no answer within 300 ms")
        self.assertLess(elapsed, 2.0)


class WhichNodeTheQuestionBelongsTo(unittest.TestCase):
    """A source address is only answerable from the node that carries it.

    In an active/passive pair the address lives on one node at a time. The other
    one can still *bind* it - `ip_nonlocal_bind` sees to that - and then fails
    the route lookup with ENETUNREACH, which reads as a pool that cannot be
    reached. It is not: the pool is fine and the question was asked in the wrong
    place. So the node checks first and says which it is.

    Both cases here use real addresses of this machine: 127.0.0.1 is carried by
    every host, and a TEST-NET-2 address is carried by none.
    """

    server: ThreadingHTTPServer
    port: int
    thread: threading.Thread

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.port = int(cls.server.server_address[1])
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        # `shutdown` stops the loop; the listening socket stays open until
        # `server_close`. One leaked socket per class per run, otherwise.
        cls.server.shutdown()
        cls.server.server_close()

    def ask_from(self, source: str) -> dict[str, Any]:
        code, answer = ask(
            {
                "schema_version": 1,
                "source": source,
                "targets": [target(port=self.port)],
            }
        )
        self.assertEqual(code, 0)
        return answer

    def test_an_address_this_node_carries_is_probed_from(self) -> None:
        answer = self.ask_from("127.0.0.1")
        self.assertTrue(answer["source_held"])
        self.assertTrue(answer["results"][0]["ok"])

    def test_an_address_it_does_not_carry_is_said_rather_than_attempted(self) -> None:
        answer = self.ask_from("198.51.100.77")
        self.assertFalse(answer["source_held"])
        self.assertEqual(answer["results"], [])
        self.assertTrue(answer["ok"])
        self.assertIsNone(answer["error"])

    def test_no_source_is_every_node_s_question(self) -> None:
        code, answer = ask({"schema_version": 1, "targets": [target(port=self.port)]})
        self.assertEqual(code, 0)
        self.assertTrue(answer["source_held"])
        self.assertTrue(answer["results"][0]["ok"])


class WhatTheProbeRefuses(unittest.TestCase):
    """The request is data from a client, and this is the whole surface."""

    def refusal(self, request: object) -> str:
        completed = sp.run(
            [str(SCRIPT)],
            input=json.dumps(request).encode(),
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 64)
        answer = json.loads(completed.stdout)
        self.assertFalse(answer["ok"])
        self.assertEqual(answer["results"], [])
        return str(answer["error"])

    def test_another_schema_version_is_refused_rather_than_guessed(self) -> None:
        self.assertIn("schema_version", self.refusal({"schema_version": 2, "targets": []}))

    def test_something_that_is_not_a_request(self) -> None:
        self.assertIn("not an object", self.refusal(["targets"]))

    def test_a_host_with_a_space_in_it(self) -> None:
        self.assertIn(
            "host",
            self.refusal(
                {"schema_version": 1, "targets": [{"type": "tcp", "host": "a b", "port": 80}]}
            ),
        )

    def test_a_port_that_is_not_a_port(self) -> None:
        for port in (0, 65536, "80", True):
            with self.subTest(port=port):
                self.assertIn(
                    "port",
                    self.refusal(
                        {
                            "schema_version": 1,
                            "targets": [{"type": "tcp", "host": "127.0.0.1", "port": port}],
                        }
                    ),
                )

    def test_a_type_nobody_asked_for(self) -> None:
        self.assertIn(
            "tcp or http",
            self.refusal(
                {
                    "schema_version": 1,
                    "targets": [{"type": "smtp", "host": "127.0.0.1", "port": 25}],
                }
            ),
        )

    def test_more_targets_than_a_pool_has(self) -> None:
        """A probe that took hundreds would be a port scanner with a key."""

        many = [{"type": "tcp", "host": "127.0.0.1", "port": 80} for _ in range(21)]
        self.assertIn("at most", self.refusal({"schema_version": 1, "targets": many}))

    def test_a_path_that_carries_a_request_of_its_own(self) -> None:
        self.assertIn(
            "path",
            self.refusal(
                {
                    "schema_version": 1,
                    "targets": [
                        {
                            "type": "http",
                            "host": "127.0.0.1",
                            "port": 80,
                            "path": "/x HTTP/1.1\r\nX-Injected: 1",
                        }
                    ],
                }
            ),
        )

    def test_arguments_are_refused_even_though_the_key_forbids_them(self) -> None:
        completed = sp.run(
            [str(SCRIPT), "--all"],
            input=b"{}",
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 64)
        self.assertIn("takes no arguments", json.loads(completed.stdout)["error"])


if __name__ == "__main__":
    unittest.main()


def self_signed(directory: Path) -> tuple[Path, Path]:
    """A certificate for 127.0.0.1. Nothing verifies it; the probe is told not to."""

    openssl = shutil.which("openssl")
    assert openssl is not None
    certificate = directory / "cert.pem"
    key = directory / "key.pem"
    sp.run(
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
            "/CN=127.0.0.1",
            "-days",
            "1",
        ],
        capture_output=True,
        check=True,
    )
    return certificate, key


@unittest.skipUnless(shutil.which("openssl"), "openssl is not installed here")
class TheHandshakeIsHAProxys(unittest.TestCase):
    """The probe names nobody in its TLS handshake, as HAProxy's check does not.

    HAProxy's manual for 3.4.4, under `verifyhost`: health checks "cannot
    provide an SNI value". A probe that sent the Host header as SNI could reach
    a backend that needs one and report it usable while the node's own check
    marks it down. A real TLS server in this process records the name each
    handshake carried.
    """

    server: ThreadingHTTPServer
    port: int
    thread: threading.Thread
    directory: tempfile.TemporaryDirectory[str]
    names: list[str | None]

    @classmethod
    def setUpClass(cls) -> None:
        cls.directory = tempfile.TemporaryDirectory()
        certificate, key = self_signed(Path(cls.directory.name))
        cls.names = []
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certificate, key)
        context.sni_callback = lambda _socket, name, _context: cls.names.append(name)
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.server.socket = context.wrap_socket(cls.server.socket, server_side=True)
        cls.port = int(cls.server.server_address[1])
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.directory.cleanup()

    def test_no_name_is_sent_even_with_a_host_header(self) -> None:
        code, answer = ask(
            {
                "schema_version": 1,
                "targets": [
                    target(port=self.port, tls=True, verify=False, host_header="app.example.com")
                ],
            }
        )

        self.assertEqual(code, 0)
        self.assertTrue(answer["results"][0]["ok"], answer)
        self.assertEqual(self.names, [None])


class HowOldATlsBackendMayBe(unittest.TestCase):
    """The floor is the probe's own, not whatever OpenSSL on the node was built with.

    `ssl.create_default_context()` leaves the lowest acceptable version to the
    build, so the same pool could answer differently on two nodes and the result
    would describe the node rather than the backend. The probe says TLS 1.2, and
    these two cases are the same request against two backends that differ only
    in how old they are willing to be.
    """

    directory: tempfile.TemporaryDirectory[str]
    certificate: Path
    key: Path

    @classmethod
    def setUpClass(cls) -> None:
        cls.directory = tempfile.TemporaryDirectory()
        cls.certificate, cls.key = self_signed(Path(cls.directory.name))

    @classmethod
    def tearDownClass(cls) -> None:
        cls.directory.cleanup()

    def probe_against(self, version: str) -> dict[str, object]:
        port = free_port()
        server = spawned.old_tls_server(self.certificate, self.key, version, port)
        try:
            code, answer = ask(
                {
                    "schema_version": 1,
                    "targets": [target(port=port, tls=True, verify=False, path="/")],
                }
            )
            self.assertEqual(code, 0)
            result: dict[str, object] = answer["results"][0]
            return result
        finally:
            server.terminate()
            server.wait(timeout=5)

    def test_a_backend_that_speaks_tls_1_2_is_reached(self) -> None:
        result = self.probe_against("-tls1_2")

        self.assertTrue(result["ok"], result["error"])
        self.assertEqual(result["status"], 200)

    def test_a_backend_that_will_go_no_higher_than_tls_1_1_is_refused(self) -> None:
        """And refused as a TLS failure, which is what it is.

        The error names the handshake rather than the pool, so somebody reading
        the health card is told the backend is too old - not that it is down.
        """

        result = self.probe_against("-tls1_1")

        self.assertFalse(result["ok"])
        self.assertIn("TLS failed", str(result["error"]))


@unittest.skipUnless(shutil.which("openssl"), "openssl is not installed here")
class AFloorTheObjectChose(unittest.TestCase):
    """The probe reaches what HAProxy would reach, and refuses what it would refuse.

    A pool whose object says `legacy` is reached by HAProxy over TLS 1.1. If the
    probe kept its own floor of TLS 1.2 it would answer that the pool is down
    while the pool is serving - and a health card is read during an incident, so
    a confident wrong answer is the expensive kind.

    The default is unchanged and stays TLS 1.2: a request from a manager too old
    to send the field means exactly what it used to mean.
    """

    directory: tempfile.TemporaryDirectory[str]
    certificate: Path
    key: Path

    @classmethod
    def setUpClass(cls) -> None:
        cls.directory = tempfile.TemporaryDirectory()
        cls.certificate, cls.key = self_signed(Path(cls.directory.name))

    @classmethod
    def tearDownClass(cls) -> None:
        cls.directory.cleanup()

    def probe(self, **fields: object) -> dict[str, object]:
        port = free_port()
        server = spawned.old_tls_server(self.certificate, self.key, "-tls1_1", port)
        try:
            code, answer = ask(
                {
                    "schema_version": 1,
                    "targets": [target(port=port, tls=True, verify=False, path="/", **fields)],
                }
            )
            self.assertEqual(code, 0)
            result: dict[str, object] = answer["results"][0]
            return result
        finally:
            server.terminate()
            server.wait(timeout=5)

    def test_a_target_that_asks_for_tls_1_1_reaches_a_tls_1_1_backend(self) -> None:
        result = self.probe(min_version="TLSv1.1")

        self.assertTrue(result["ok"], result["error"])
        self.assertEqual(result["status"], 200)

    def test_the_same_backend_is_refused_when_nothing_asks(self) -> None:
        """The default is a floor, not an absence of one."""

        result = self.probe()

        self.assertFalse(result["ok"])
        self.assertIn("TLS failed", str(result["error"]))

    def test_a_floor_that_is_not_one_of_the_names_is_refused(self) -> None:
        """And refused as a request, not attempted and reported as a failure."""

        code, answer = ask(
            {
                "schema_version": 1,
                "targets": [target(port=free_port(), tls=True, min_version="SSLv3")],
            }
        )

        self.assertEqual(code, 64)
        self.assertFalse(answer["ok"])
        self.assertIn("min_version", str(answer["error"]))
