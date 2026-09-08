from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from haproxy_ui import traffic_logs
from haproxy_ui.config import TrafficLogs
from tests.test_login import LoginTestCase, configuration


def record(**changed: object) -> bytes:
    value: dict[str, object] = {
        "schema": 1,
        "at": 1788847200,
        "client": "192.0.2.44",
        "method": "GET",
        "host": "app.example.com",
        "path": "/status",
        "frontend": "mgd-main-https",
        "backend": "mgd-app-web",
        "server": "mgd-app-web-a",
        "status": 200,
        "request_time": 1,
        "queue_time": 0,
        "connect_time": 2,
        "response_time": 3,
        "total_time": 6,
        "bytes": 123,
    }
    value.update(changed)
    return json.dumps(value).encode()


class TrafficLogReaderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def write(self, *lines: bytes) -> None:
        (self.root / "alpha--node-a.jsonl").write_bytes(b"\n".join(lines) + b"\n")

    def test_query_strings_are_not_part_of_the_contract(self) -> None:
        entry = traffic_logs.parse(record(path="/login"), "alpha", "node-a")
        self.assertEqual(entry.path, "/login")
        self.assertNotIn("?", entry.path)

    def test_malformed_and_html_are_data_not_markup(self) -> None:
        self.write(b"not json", record(path="/<script>alert(1)</script>"))
        reading = traffic_logs.read(self.root, ("alpha",))
        self.assertEqual(reading.malformed, 1)
        self.assertEqual(reading.entries[0].path, "/<script>alert(1)</script>")

    def test_filters_apply_before_the_bounded_result(self) -> None:
        self.write(
            record(at=1788847200, status=200),
            record(at=1788847201, status=503, backend="mgd-app-api"),
        )
        reading = traffic_logs.read(
            self.root, ("alpha",), limit=1, proxy="api", status="5xx", substring="503"
        )
        self.assertEqual([entry.status for entry in reading.entries], [503])

    def test_a_file_replaced_during_read_is_not_a_crash(self) -> None:
        self.write(record())
        original = traffic_logs._tail

        def rotated(path: Path) -> tuple[bytes, bool]:
            path.unlink()
            return original(path)

        traffic_logs._tail = rotated
        self.addCleanup(setattr, traffic_logs, "_tail", original)
        reading = traffic_logs.read(self.root, ("alpha",))
        self.assertTrue(reading.unavailable)
        self.assertEqual(reading.entries, ())

    def test_symlinks_are_never_followed(self) -> None:
        target = self.root / "secret"
        target.write_bytes(record())
        (self.root / "alpha--node-a.jsonl").symlink_to(target)
        reading = traffic_logs.read(self.root, ("alpha",))
        self.assertTrue(reading.unavailable)
        self.assertEqual(reading.entries, ())


class TrafficLogPageTests(LoginTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "alpha--node-a.jsonl").write_bytes(
            record(path="/<script>alert(1)</script>") + b"\n"
        )

    def test_log_text_is_escaped_by_the_page(self) -> None:
        from dataclasses import replace

        config = replace(
            configuration(),
            clusters=("alpha",),
            traffic_logs=TrafficLogs(enabled=True, directory=self.root, max_lines=500),
        )
        client = self.client(config)
        self.sign_in(client)
        page = client.get("/logs")

        self.assertEqual(page.status_code, 200)
        self.assertIn("/&lt;script&gt;alert(1)&lt;/script&gt;", page.text)
        self.assertNotIn("/<script>alert(1)</script>", page.text)


if __name__ == "__main__":
    unittest.main()
