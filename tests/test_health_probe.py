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
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

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


def ask(request: dict[str, object]) -> tuple[int, dict[str, object]]:
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
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.server.server_address[1]
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
        return answer["results"][0]

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

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        # `shutdown` stops the loop; the listening socket stays open until
        # `server_close`. One leaked socket per class per run, otherwise.
        cls.server.shutdown()
        cls.server.server_close()

    def ask_from(self, source: str) -> dict[str, object]:
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


def tls_server(certificate: Path, key: Path, ceiling: ssl.TLSVersion) -> ThreadingHTTPServer:
    """A backend that will speak nothing above `ceiling`.

    `SECLEVEL=0` because OpenSSL's own policy would otherwise refuse to offer
    the old versions at all, and the point here is a backend that offers them
    and a probe that declines - not a backend that could not be built.
    """

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1
    context.maximum_version = ceiling
    context.set_ciphers("DEFAULT@SECLEVEL=0")
    context.load_cert_chain(certfile=str(certificate), keyfile=str(key))
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@unittest.skipUnless(shutil.which("openssl"), "openssl is not installed here")
class HowOldATlsBackendMayBe(unittest.TestCase):
    """The floor is the probe's own, not whatever OpenSSL on the node was built with.

    `ssl.create_default_context()` leaves the lowest acceptable version to the
    build, so the same pool could answer differently on two nodes and the result
    would describe the node rather than the backend. The probe says TLS 1.2, and
    these two cases are the same request against two backends that differ only
    in how old they are willing to be.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.directory = tempfile.TemporaryDirectory()
        cls.certificate, cls.key = self_signed(Path(cls.directory.name))

    @classmethod
    def tearDownClass(cls) -> None:
        cls.directory.cleanup()

    def probe_against(self, ceiling: ssl.TLSVersion) -> dict[str, object]:
        server = tls_server(self.certificate, self.key, ceiling)
        try:
            code, answer = ask(
                {
                    "schema_version": 1,
                    "targets": [
                        target(
                            port=server.server_address[1],
                            tls=True,
                            verify=False,
                            path="/healthz",
                        )
                    ],
                }
            )
            self.assertEqual(code, 0)
            return answer["results"][0]
        finally:
            #
            # Both, and in this order. `shutdown` stops the loop and leaves the
            # listening socket open; a test class that starts one server per
            # case would then leak one per case. B81 was the same mistake with
            # a heavier process on the other end.
            #
            server.shutdown()
            server.server_close()

    def test_a_backend_that_speaks_tls_1_2_is_reached(self) -> None:
        result = self.probe_against(ssl.TLSVersion.TLSv1_2)

        self.assertTrue(result["ok"], result["error"])
        self.assertEqual(result["status"], 200)

    def test_a_backend_that_will_go_no_higher_than_tls_1_1_is_refused(self) -> None:
        """And refused as a TLS failure, which is what it is.

        The error names the handshake rather than the pool, so somebody reading
        the health card is told the backend is too old - not that it is down.
        """

        result = self.probe_against(ssl.TLSVersion.TLSv1_1)

        self.assertFalse(result["ok"])
        self.assertIn("TLS failed", str(result["error"]))
