"""The way an unprivileged service asks for a probe, tried against a real socket.

Not a mock. The thing that broke in production was the transport itself - a
`sudo` the caller's own unit made impossible - and a test that stubs the
transport is exactly the test that missed it. So these listen on a real unix
socket in a temporary directory and speak the real protocol over it.

What has to hold:

- the request is one document, and the write side is closed after it, because
  the helper on the other end reads its stdin to end of file
- an answer of any size comes back whole
- every way this can fail arrives as a sentence saying which failure it was.
  "Nothing is listening" and "this account may not connect" are different
  problems with different fixes, and a reader shown neither will look for the
  fault in the pool instead.
"""

from __future__ import annotations

import json
import socket
import tempfile
import threading
import unittest
from pathlib import Path

from haproxy_mgmt.probe_socket import ProbeUnavailable, ask, build_request

TARGETS = [
    {
        "host": "198.51.100.10",
        "port": 8080,
        "type": "http",
        "tls": False,
        "verify": False,
        "path": "/healthz",
        "host_header": "",
    }
]


class Listener:
    """One connection, answered the way the socket unit's instance would."""

    def __init__(self, path: str, answer: bytes | None) -> None:
        self.path = path
        #
        # None means: read the request and then say nothing at all. That is a
        # service which is running but wedged, and it must not become a page
        # that hangs.
        #
        self.answer = answer
        self.received = b""
        self.done = threading.Event()
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.bind(path)
        self.socket.listen(1)
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        try:
            connection, _ = self.socket.accept()
        except OSError:
            return
        with connection:
            while True:
                chunk = connection.recv(65536)
                if not chunk:
                    break
                self.received += chunk
            if self.answer is None:
                self.done.wait(timeout=10)
                return
            connection.sendall(self.answer)

    def close(self) -> None:
        self.done.set()
        self.socket.close()
        self.thread.join(timeout=5)


class WhatIsSentAndWhatComesBack(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = str(Path(self.directory.name) / "probe.sock")

    def test_the_request_arrives_whole_and_the_answer_comes_back(self) -> None:
        listener = Listener(self.path, b'{"ok":true}\n')
        self.addCleanup(listener.close)

        request = build_request("alpha", "r-1", TARGETS, source="192.0.2.25")
        answer = ask(request, path=self.path)

        self.assertEqual(json.loads(answer), {"ok": True})
        self.assertEqual(json.loads(listener.received), request)

    def test_the_write_side_is_closed_so_the_far_side_sees_end_of_file(self) -> None:
        """Without the half-close both ends wait for the other, forever."""

        listener = Listener(self.path, b'{"ok":true}\n')
        self.addCleanup(listener.close)

        ask(build_request("alpha", "r-1", TARGETS), path=self.path, timeout=5)
        self.assertTrue(listener.received)

    def test_an_answer_larger_than_one_read_is_reassembled(self) -> None:
        payload = json.dumps({"filler": "x" * 400_000}).encode()
        listener = Listener(self.path, payload)
        self.addCleanup(listener.close)

        answer = ask(build_request("alpha", "r-1", TARGETS), path=self.path, timeout=15)
        self.assertEqual(len(answer.encode()), len(payload))


class WhenItCannotBeAsked(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)

    def test_no_socket_at_all_says_the_service_is_not_installed(self) -> None:
        missing = str(Path(self.directory.name) / "absent.sock")
        with self.assertRaises(ProbeUnavailable) as raised:
            ask(build_request("alpha", "r-1", TARGETS), path=missing)
        self.assertIn("not installed", str(raised.exception))

    def test_a_socket_nobody_listens_on_says_the_service_is_not_running(self) -> None:
        path = str(Path(self.directory.name) / "dead.sock")
        stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        stale.bind(path)
        self.addCleanup(stale.close)

        with self.assertRaises(ProbeUnavailable) as raised:
            ask(build_request("alpha", "r-1", TARGETS), path=path)
        self.assertIn("not running", str(raised.exception))

    def test_a_service_that_never_answers_is_given_up_on_with_a_sentence(self) -> None:
        path = str(Path(self.directory.name) / "mute.sock")
        listener = Listener(path, None)
        self.addCleanup(listener.close)

        #
        # It reads the request and then holds the connection open without
        # writing. Left alone the caller would wait for as long as the page did.
        #
        with self.assertRaises(ProbeUnavailable) as raised:
            ask(build_request("alpha", "r-1", TARGETS), path=path, timeout=0.25)
        self.assertIn("did not answer in time", str(raised.exception))


class TheRequestBothCallersBuild(unittest.TestCase):
    def test_it_is_the_helper_protocol_s_shape(self) -> None:
        request = build_request("alpha", "r-1", TARGETS, source="192.0.2.25", timeout_ms=3000)
        self.assertEqual(request["operation"], "probe")
        self.assertEqual(request["schema_version"], 1)
        self.assertEqual(request["cluster"], "alpha")
        self.assertEqual(request["parameters"]["source"], "192.0.2.25")
        self.assertEqual(request["parameters"]["timeout_ms"], 3000)

    def test_the_command_line_caller_builds_the_same_document(self) -> None:
        """The interface and `haproxy-probe` must not drift apart."""

        from haproxy_mgmt.cli import probe

        self.assertIs(probe.build_request, build_request)


if __name__ == "__main__":
    unittest.main()
