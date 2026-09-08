from __future__ import annotations

import json
import tempfile
import unittest
from datetime import UTC, date, datetime
from pathlib import Path

from haproxy_ui.traffic_collector import (
    CollectorConfig,
    CollectorError,
    NodeTarget,
    Response,
    collect,
    load_config,
)

NOW = datetime(2026, 9, 8, 12, tzinfo=UTC)


class TrafficCollectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.mirror = root / "mirror"
        self.staging = root / "staging"
        self.mirror.mkdir()
        self.staging.mkdir()
        self.target = NodeTarget("alpha", "node-a", "node-a.example.com")
        self.config = CollectorConfig(
            user="svc-logread",
            key=root / "key",
            known_hosts=root / "known_hosts",
            mirror=self.mirror,
            staging=self.staging,
            nodes=(self.target,),
        )

    def response(self, wanted: date, offset: int, payload: bytes, **flags: object) -> Response:
        return Response(
            size=offset + len(payload),
            offset=offset,
            sent=len(payload),
            eof=bool(flags.get("eof", True)),
            reset=bool(flags.get("reset", False)),
            skipped_bytes=int(flags.get("skipped_bytes", 0)),
            payload=payload,
        )

    def test_new_data_is_fsynced_to_a_part_then_atomically_assembled(self) -> None:
        calls: list[tuple[date, int]] = []

        def fetch(_target: NodeTarget, wanted: date, offset: int) -> Response:
            calls.append((wanted, offset))
            payload = b'{"schema":1,"path":"/"}\n' if wanted == NOW.date() and offset == 0 else b""
            return self.response(wanted, offset, payload)

        self.assertEqual(collect(self.config, now=NOW, fetch=fetch), 0)
        self.assertEqual(
            (self.mirror / "alpha--node-a.jsonl").read_bytes(),
            b'{"schema":1,"path":"/"}\n',
        )
        meta = json.loads((self.mirror / "alpha--node-a.meta.json").read_bytes())
        self.assertEqual((meta["outcome"], meta["last_success"]), ("ok", NOW.isoformat()))
        self.assertEqual(calls[0], (NOW.date(), 0))

    def test_rerun_uses_the_committed_part_size_and_does_not_duplicate(self) -> None:
        line = b'{"schema":1}\n'

        def fetch(_target: NodeTarget, wanted: date, offset: int) -> Response:
            payload = line if wanted == NOW.date() and offset == 0 else b""
            return self.response(wanted, offset, payload)

        self.assertEqual(collect(self.config, now=NOW, fetch=fetch), 0)
        self.assertEqual(collect(self.config, now=NOW, fetch=fetch), 0)
        self.assertEqual((self.mirror / "alpha--node-a.jsonl").read_bytes(), line)

    def test_failure_preserves_the_mirror_and_last_success(self) -> None:
        line = b'{"schema":1}\n'

        def good(_target: NodeTarget, wanted: date, offset: int) -> Response:
            return self.response(
                wanted, offset, line if wanted == NOW.date() and offset == 0 else b""
            )

        self.assertEqual(collect(self.config, now=NOW, fetch=good), 0)

        def failed(_target: NodeTarget, _wanted: date, _offset: int) -> Response:
            raise CollectorError("unreachable")

        later = datetime(2026, 9, 8, 12, 1, tzinfo=UTC)
        self.assertEqual(collect(self.config, now=later, fetch=failed), 1)
        self.assertEqual((self.mirror / "alpha--node-a.jsonl").read_bytes(), line)
        meta = json.loads((self.mirror / "alpha--node-a.meta.json").read_bytes())
        self.assertEqual(meta["last_success"], NOW.isoformat())
        self.assertEqual(meta["last_attempt"], later.isoformat())

    def test_remote_reset_discards_the_local_day_without_advancing_a_cursor(self) -> None:
        part = self.staging / "alpha--node-a--2026-09-08.jsonl"
        part.write_bytes(b"old\n")

        def reset(_target: NodeTarget, wanted: date, offset: int) -> Response:
            return Response(0, offset, 0, True, True, 0, b"")

        self.assertEqual(collect(self.config, now=NOW, fetch=reset), 0)
        self.assertEqual(part.read_bytes(), b"")
        self.assertEqual((self.mirror / "alpha--node-a.jsonl").read_bytes(), b"")

    def test_configuration_refuses_duplicate_destinations_and_relative_paths(self) -> None:
        path = Path(self.temporary.name) / "collector.json"
        value = {
            "schema_version": 1,
            "user": "svc-logread",
            "key": "/etc/key",
            "known_hosts": "/etc/known_hosts",
            "mirror": "relative",
            "staging": "/srv/logs/staging",
            "nodes": [{"cluster": "alpha", "node": "node-a", "host": "node-a.example.com"}],
        }
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(CollectorError, "mirror must be absolute"):
            load_config(path, require_secure=False)

    def test_missing_or_symlinked_working_directory_is_refused(self) -> None:
        self.staging.rmdir()
        with self.assertRaisesRegex(CollectorError, "cannot stat staging"):
            collect(self.config, now=NOW, fetch=lambda *_args: None)  # type: ignore[arg-type]

        self.staging.symlink_to(self.mirror, target_is_directory=True)
        with self.assertRaisesRegex(CollectorError, "staging is not a directory or is a symlink"):
            collect(self.config, now=NOW, fetch=lambda *_args: None)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
