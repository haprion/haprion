"""The engine's clients name themselves (26-11-17).

urllib sends `Python-urllib/3.x` unless told otherwise, and some servers refuse
it: lists.blocklist.de answered the blocklist fetch 403 and any other name 200.
The OIDC client, the NDES fetch and the blocklist fetch each built their own
opener, and none said who it was. They now share `http_answer.opener`, which
does; this refuses a module that builds an opener or calls `urlopen` beside it,
and a UI module that calls `urlopen` without naming itself, as the update check
does.
"""

from __future__ import annotations

import ast
import ssl
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import haprion
from haprion import http_answer

ROOT = Path(__file__).resolve().parents[1]
ENGINE = ROOT / "src" / "haprion"
INTERFACE = ROOT / "ui" / "src" / "haprion_ui"
CALLS = ("build_opener", "urlopen")


def _calls(path: Path) -> list[str]:
    found = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Call):
            name = getattr(node.func, "attr", None) or getattr(node.func, "id", None)
            if name in CALLS:
                found.append(f"{path.relative_to(ROOT)}:{node.lineno} {name}")
    return found


class EveryClientNamesItself(unittest.TestCase):
    def test_the_engine_opens_only_through_the_shared_opener(self) -> None:
        stray = [
            call
            for path in sorted(ENGINE.rglob("*.py"))
            if path.name != "http_answer.py"
            for call in _calls(path)
        ]
        self.assertEqual(stray, [], "use http_answer.opener, which names the client")

    def test_an_interface_request_names_itself(self) -> None:
        silent = [
            call
            for path in sorted(INTERFACE.rglob("*.py"))
            if "User-Agent" not in path.read_text(encoding="utf-8")
            for call in _calls(path)
        ]
        self.assertEqual(silent, [], "send a User-Agent, as update_check does")

    def test_the_shared_opener_sends_haprions_name(self) -> None:
        seen: list[str | None] = []

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_: Any) -> None:
                return None

            def do_GET(self) -> None:
                seen.append(self.headers.get("User-Agent"))
                self.send_response(204)
                self.end_headers()

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(
            target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
        ).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        opener = http_answer.opener(ssl.create_default_context())
        with opener.open(f"http://127.0.0.1:{server.server_address[1]}/", timeout=5):
            pass
        self.assertEqual(seen, [f"haprion/{haprion.__version__}"])


if __name__ == "__main__":
    unittest.main()
