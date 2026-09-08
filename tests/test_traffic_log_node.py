from __future__ import annotations

import importlib.util
import io
import json
import tempfile
import unittest
from datetime import date
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import ModuleType

BASE = Path(__file__).resolve().parents[1]


def load_script() -> ModuleType:
    path = BASE / "install" / "node" / "haproxy-traffic-log-read"
    spec = importlib.util.spec_from_loader(
        "traffic_log_node", SourceFileLoader("traffic_log_node", str(path))
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load node helper")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


HELPER = load_script()
TODAY = date(2026, 9, 8)


class TrafficLogNodeReaderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def call(self, request: str) -> tuple[int, dict[str, object] | None, bytes]:
        output = io.BytesIO()
        code = HELPER.serve(request, self.root, output, today=TODAY)
        if not output.getvalue():
            return code, None, b""
        line, payload = output.getvalue().split(b"\n", 1)
        return code, json.loads(line), payload

    def write(self, day: str, data: bytes) -> None:
        (self.root / f"traffic-{day}.jsonl").write_bytes(data)

    def test_only_an_exact_date_and_decimal_offset_are_accepted(self) -> None:
        for request in (
            "",
            "2026-09-08",
            "2026-09-08 -1",
            "2026-09-08 0 extra",
            "../../etc/passwd 0",
            "2026-02-30 0",
            "2026-08-25 0",
            "2026-09-09 0",
            "2026-09-08 1234567890123",
        ):
            with self.subTest(request=request):
                self.assertEqual(self.call(request), (64, None, b""))

    def test_missing_day_is_an_empty_result(self) -> None:
        code, header, payload = self.call("2026-09-08 0")
        self.assertEqual((code, payload), (0, b""))
        assert header is not None
        self.assertEqual((header["size"], header["sent"], header["eof"]), (0, 0, True))

    def test_cursor_returns_only_whole_records(self) -> None:
        first = b'{"schema":1,"path":"/one"}\n'
        second = b'{"schema":1,"path":"/two"}\n'
        self.write("2026-09-08", first + second)

        code, header, payload = self.call(f"2026-09-08 {len(first)}")

        self.assertEqual((code, payload), (0, second))
        assert header is not None
        self.assertEqual(header["offset"], len(first))
        self.assertTrue(header["eof"])

    def test_offset_beyond_a_replaced_file_requests_a_reset(self) -> None:
        self.write("2026-09-08", b"{}\n")
        code, header, payload = self.call("2026-09-08 99")
        self.assertEqual((code, payload), (0, b""))
        assert header is not None
        self.assertTrue(header["reset"])
        self.assertEqual(header["size"], 3)

    def test_symlink_is_refused(self) -> None:
        target = self.root / "elsewhere"
        target.write_bytes(b"{}\n")
        (self.root / "traffic-2026-09-08.jsonl").symlink_to(target)
        self.assertEqual(self.call("2026-09-08 0"), (65, None, b""))

    def test_incomplete_final_record_is_not_sent(self) -> None:
        self.write("2026-09-08", b"{}\nunfinished")
        code, header, payload = self.call("2026-09-08 0")
        self.assertEqual((code, payload), (0, b"{}\n"))
        assert header is not None
        self.assertFalse(header["eof"])


if __name__ == "__main__":
    unittest.main()
