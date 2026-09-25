"""A root helper that was asked and then went quiet has no verdict.

The node restore and backup services run as root behind a socket and carry on
without the worker's client. When the client gives up, writing `failed` - and
"install the socket" - described a run that may have finished on the node
(review 2026-09-25, finding 1). The client now writes no document, so the
worker records `unknown`, and says why on stderr.
"""

from __future__ import annotations

import io
import json
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from typing import Any

from haproxy_mgmt import helper_socket
from haproxy_mgmt.cli import backup_job_ask, node_restore_ask

REQUEST_ID = "11111111-1111-1111-1111-111111111111"
CLIENTS: tuple[tuple[Any, dict[str, Any]], ...] = (
    (
        node_restore_ask,
        {"operation": "node_restore", "parameters": {"run": "r260925-abcdef12", "confirm": "n1"}},
    ),
    (backup_job_ask, {"operation": "backup_run", "parameters": {}}),
)


class Silent:
    """A socket that takes the connection and the request, and never answers."""

    def __init__(self, path: Path) -> None:
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(str(path))
        self.server.listen(1)
        self.held: list[socket.socket] = []
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self) -> None:
        connection, _ = self.server.accept()
        self.held.append(connection)

    def close(self) -> None:
        for connection in self.held:
            connection.close()
        self.server.close()


class AskedThenSilent(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "helper.sock"

    def ask(self, client: Any, request: dict[str, Any]) -> tuple[int, str, str]:
        document = {
            "schema_version": 1,
            "cluster": "alpha",
            "request_id": REQUEST_ID,
            **request,
        }
        out, err = io.StringIO(), io.StringIO()
        code = client.main(
            [],
            input_stream=io.BytesIO(json.dumps(document).encode()),
            output_stream=out,
            error_stream=err,
            socket_path=str(self.path),
            timeout=0.2,
        )
        return code, out.getvalue(), err.getvalue()

    def test_silence_writes_no_document_and_says_the_outcome_is_unknown(self) -> None:
        for client, request in CLIENTS:
            with self.subTest(client=client.__name__):
                listener = Silent(self.path)
                try:
                    code, out, err = self.ask(client, request)
                finally:
                    listener.close()
                    self.path.unlink()

                self.assertEqual(code, 1)
                self.assertEqual(out, "")
                self.assertIn("[helper_silent]", err)
                self.assertIn("outcome is unknown", err)
                self.assertNotIn("Install", err)

    def test_nothing_listening_is_still_a_failure_that_names_the_unit(self) -> None:
        """Not reached is not silent: nothing ran, and `failed` is true."""

        for client, request in CLIENTS:
            with self.subTest(client=client.__name__):
                code, out, _ = self.ask(client, request)

                self.assertEqual(code, 78)
                document = json.loads(out)
                self.assertEqual(document["outcome"], "failed")
                self.assertIn("Install", document["error"]["message"])

    def test_silent_is_still_unavailable_to_a_caller_that_asks_only_that(self) -> None:
        """The probe's web caller catches the parent class and keeps working."""

        self.assertTrue(issubclass(helper_socket.HelperSilent, helper_socket.HelperUnavailable))


if __name__ == "__main__":
    unittest.main()
