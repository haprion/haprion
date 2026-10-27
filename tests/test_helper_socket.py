"""An answer from a root helper's socket is bounded in size and in time (review 2026-10-20).

The helpers are root's own; the bounds are against one that is broken. Both
ends are a real unix socket, as in `test_probe_socket`.
"""

from __future__ import annotations

import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from haprion import helper_socket


class _Answering:
    """Reads the request, then answers with `pieces`, `pause` seconds apart."""

    def __init__(self, path: str, pieces: list[bytes], pause: float) -> None:
        self.pieces, self.pause = pieces, pause
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
            while connection.recv(65536):
                pass
            try:
                for piece in self.pieces:
                    connection.sendall(piece)
                    time.sleep(self.pause)
            except OSError:
                pass

    def close(self) -> None:
        self.socket.close()
        self.thread.join(timeout=5)


class TheAnswerIsBounded(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = str(Path(directory.name) / "helper.sock")

    def serve(self, pieces: list[bytes], pause: float = 0.0) -> None:
        listener = _Answering(self.path, pieces, pause)
        self.addCleanup(listener.close)

    def test_an_answer_a_byte_at_a_time_is_given_up_on_by_the_whole_timeout(self) -> None:
        self.serve([b" "] * 200, pause=0.02)
        started = time.monotonic()
        with self.assertRaisesRegex(helper_socket.HelperSilent, "did not answer in time"):
            helper_socket.ask({}, path=self.path, timeout=0.3, what="the helper")
        self.assertLess(time.monotonic() - started, 1.5)

    def test_an_answer_past_the_limit_is_silent_not_a_refusal(self) -> None:
        self.serve([b"x" * 4096] * 8)
        with (
            mock.patch.object(helper_socket, "MAX_ANSWER_BYTES", 16 * 1024),
            self.assertRaises(helper_socket.HelperSilent) as raised,
        ):
            helper_socket.ask({}, path=self.path, timeout=5, what="the helper")
        self.assertNotIsInstance(raised.exception, helper_socket.HelperBusy)
        self.assertIn("the answer was not read", str(raised.exception))

    def test_an_answer_within_both_comes_back_whole(self) -> None:
        self.serve([b'{"ok":', b"true}"], pause=0.01)
        self.assertEqual(
            helper_socket.ask({}, path=self.path, timeout=5, what="the helper"), '{"ok":true}'
        )

    def test_a_helper_that_closes_without_a_byte_is_silent(self) -> None:
        """R2 26-10-27 (F15): a killed helper gave an empty answer and a reason with no sentence."""

        self.serve([])
        with self.assertRaisesRegex(
            helper_socket.HelperSilent, "The helper ended without answering"
        ):
            helper_socket.ask({}, path=self.path, timeout=5, what="the helper")
