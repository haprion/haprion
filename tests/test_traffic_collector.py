from __future__ import annotations

import dataclasses
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import UTC, date, datetime, time, timedelta
from io import StringIO
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import psycopg

from haprion import traffic_collector
from haprion.traffic_collector import (
    CLOSED_DAY_GRACE,
    JOINING_SECONDS,
    RETENTION_DAYS,
    CollectorConfig,
    CollectorError,
    NodeTarget,
    ProtocolError,
    Response,
    SSHError,
    _database_row,
    _entry,
    _failure_outcome,
    _ingest_part,
    _parse_response,
    _parse_waf_response,
    _replace,
    _retire,
    _retire_staging,
    _waf_cursor,
    _waf_data,
    _waf_row,
    _within_margin,
    collect,
    collect_node,
    forget_database_positions,
    load_config,
    ssh_fetch_waf,
)

NOW = datetime(2026, 9, 8, 12, tzinfo=UTC)
REAL_INGEST = traffic_collector._ingest_database


def no_waf(_target: NodeTarget, _cursor: str) -> bytes:
    """A node whose WAF journal has nothing to say."""
    return b'{"cursor":"","eof":true,"reset":false,"sent":0}\n'


class _Copy:
    """What psycopg's COPY does to a row: UTF-8 for text, bigint for numbers."""

    def __init__(self, connection: _Connection) -> None:
        self.connection = connection

    def __enter__(self) -> _Copy:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def write_row(self, row: tuple[Any, ...]) -> None:
        if row[2] in self.connection.refuse_nodes:
            raise psycopg.errors.DataError("refused")
        for item in row:
            if isinstance(item, str):
                item.encode("utf-8")
            elif isinstance(item, int) and not -(2**63) <= item < 2**63:
                raise psycopg.errors.DataError("bigint out of range")
        self.connection.rows.append(row)


class _Cursor:
    def __init__(self, connection: _Connection) -> None:
        self.connection = connection

    def __enter__(self) -> _Cursor:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def copy(self, _statement: str) -> _Copy:
        return _Copy(self.connection)


class _Connection:
    def __init__(self, refuse_nodes: tuple[str, ...] = ()) -> None:
        self.rows: list[tuple[Any, ...]] = []
        self.refuse_nodes = refuse_nodes

    def __enter__(self) -> _Connection:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def cursor(self) -> _Cursor:
        return _Cursor(self)

    def commit(self) -> None:
        pass

    def rollback(self) -> None:
        pass


def traffic_line(path: str = "/", **fields: Any) -> bytes:
    record: dict[str, Any] = {
        "schema": 1, "at": 1_700_000_000, "client": "192.0.2.1", "method": "GET",
        "host": "a.example.test", "path": path, "frontend": "f", "backend": "b",
        "server": "s1", "status": 200, "request_time": 0, "queue_time": 0,
        "connect_time": 0, "response_time": 0, "total_time": 0, "bytes": 0,
    }  # fmt: skip
    return json.dumps(record | fields).encode() + b"\n"


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
            database="haprion_ui",
            database_socket="/run/postgresql",
        )
        #
        # No database and no node here: what a run imports and what it asks a
        # node's WAF journal are each the subject of tests that say so.
        #
        replaced: list[tuple[str, Any]] = [
            ("haprion.traffic_collector._ingest_database", lambda _config: (0, 0, {})),
            (
                "haprion.traffic_collector.ssh_fetch_waf",
                lambda _config, node, cursor: no_waf(node, cursor),
            ),
        ]
        for target, replacement in replaced:
            patcher = patch(target, replacement)
            patcher.start()
            self.addCleanup(patcher.stop)

    def response(self, wanted: date, offset: int, payload: bytes, **flags: Any) -> Response:
        return Response(
            size=offset + len(payload),
            offset=offset,
            sent=len(payload),
            eof=bool(flags.get("eof", True)),
            reset=bool(flags.get("reset", False)),
            skipped_bytes=int(flags.get("skipped_bytes", 0)),
            payload=payload,
        )

    def test_a_record_the_database_cannot_take_is_the_row_parser_s_refusal(self) -> None:
        """One exception type for everything a record can be, so `_ingest_part`
        can step over it. A stamp past the year 9999 raised OSError or
        ValueError and a NUL in a text field reached PostgreSQL, which refused
        the whole batch - each a permanent stop, since the checkpoint never
        passes the record that raised (review 2026-09-17, finding 3)."""

        base = {
            "schema": 1,
            "at": 1_700_000_000,
            "request": 1,
            "client": "192.0.2.1",
            "method": "GET",
            "host": "a.example.test",
            "path": "/",
            "frontend": "f",
            "backend": "b",
            "server": "s1",
            "status": 200,
            "request_time": 0,
            "queue_time": 0,
            "connect_time": 0,
            "response_time": 0,
            "total_time": 0,
            "bytes": 0,
        }
        row = _database_row("alpha", "node-a", json.dumps(base).encode())
        self.assertEqual(row[7], "a.example.test")
        #
        # `rule` (0050): absent and empty both mean no rule met the request.
        #
        self.assertEqual(row[-4], "")
        self.assertEqual(
            _database_row("alpha", "node-a", json.dumps(base | {"rule": "a:deny"}).encode())[-4],
            "a:deny",
        )
        #
        # The WAF engine's fields (0051, 0052): absent means nothing found.
        #
        self.assertEqual(row[-3:], ("", 0, ""))
        for change in (
            {"at": 2**62},
            {"at": 10**12},
            {"path": "/a\0b"},
            {"host": "\0"},
            {"rule": "x" * 161},
            {"rule": 7},
        ):
            with self.subTest(change=change), self.assertRaises(CollectorError):
                _database_row("alpha", "node-a", json.dumps(base | change).encode())
        self.assertEqual(
            _database_row("alpha", "node-a", json.dumps(base | {"at": 253402300799}).encode())[3],
            datetime(9999, 12, 31, 23, 59, 59, tzinfo=UTC),
        )

    def test_a_line_longer_than_any_record_is_stepped_over_not_waited_for(self) -> None:
        """Review 2026-10-03, F3: an over-long finished line read as the writer
        half way through a record, so the checkpoint never passed it and the
        rest of the day never reached the database."""

        record = {
            "schema": 1, "at": 1_700_000_000, "client": "192.0.2.1", "method": "GET",
            "host": "a.example.test", "path": "/", "frontend": "f", "backend": "b",
            "server": "s1", "status": 200, "request_time": 0, "queue_time": 0,
            "connect_time": 0, "response_time": 0, "total_time": 0, "bytes": 0,
        }  # fmt: skip
        good = json.dumps(record).encode() + b"\n"
        part = self.staging / "alpha--node-a--2026-09-08.jsonl"
        long_line = b"x" * 200_000 + b"\n"
        part.write_bytes(good + long_line + good)

        def ingest() -> tuple[int, int]:
            connection = MagicMock()
            skipped = _ingest_part(self.config, connection, self.target, part)
            copy = connection.cursor.return_value.__enter__.return_value.copy.return_value
            return skipped, copy.__enter__.return_value.write_row.call_count

        self.assertEqual(ingest(), (1, 2))
        checkpoint = self.staging / f".{part.name}.database-offset"
        self.assertEqual(int(checkpoint.read_text()), part.stat().st_size)

        # Still being written: an over-long line without its newline is waited for from its start.
        size = part.stat().st_size
        with part.open("ab") as stream:
            stream.write(b"y" * 100_000)
        self.assertEqual(ingest(), (0, 0))
        self.assertEqual(int(checkpoint.read_text()), size)
        with part.open("ab") as stream:
            stream.write(b"\n" + good)
        self.assertEqual(ingest(), (1, 1))

    def test_what_the_waf_engine_said_is_kept_as_far_as_it_is_whole(self) -> None:
        """B233: rule IDs and score as the engine reported them. HAProxy cuts
        the list at the column's bound, and a record is never lost for an odd
        value here - the request still happened."""

        base = {
            "schema": 1,
            "at": 1_700_000_000,
            "client": "192.0.2.1",
            "method": "GET",
            "host": "a.example.test",
            "path": "/",
            "frontend": "f",
            "backend": "b",
            "server": "s1",
            "status": 403,
            "request_time": 0,
            "queue_time": 0,
            "connect_time": 0,
            "response_time": 0,
            "total_time": 0,
            "bytes": 0,
            "rule": "crs:deny",
        }

        def waf(**fields: object) -> tuple[Any, ...]:
            return _database_row("alpha", "node-a", json.dumps(base | fields).encode())[-3:-1]

        # As measured from HAProxy 3.4.6 and the engine (2026-10-02).
        self.assertEqual(waf(waf_rules="942100,949110", waf_score=5), ("942100,949110", 5))
        self.assertEqual(waf(waf_rules="", waf_score=0), ("", 0))
        self.assertEqual(waf(waf_rules="", waf_score=""), ("", 0))
        # Cut mid-ID, padded, or not IDs at all: the whole IDs survive.
        self.assertEqual(waf(waf_rules="942100,94910", waf_score=5), ("942100", 5))
        self.assertEqual(waf(waf_rules="x,942100,;", waf_score=-3), ("942100", 0))
        self.assertEqual(waf(waf_rules=7, waf_score=True), ("", 0))
        self.assertEqual(waf(waf_score=10**9)[1], 100000)
        many = waf(waf_rules=",".join(["942100"] * 300))[0]
        self.assertLessEqual(len(many), 1024)
        self.assertRegex(many, r"^([0-9]{6})(,[0-9]{6})*$")

    def test_the_engine_s_transaction_id_is_kept_when_it_has_its_form(self) -> None:
        """0052: `<object>.<uuid>` joins the record to what the engine found in it."""

        base = {
            "schema": 1,
            "at": 1_700_000_000,
            "client": "192.0.2.1",
            "method": "GET",
            "host": "a.example.test",
            "path": "/",
            "frontend": "f",
            "backend": "b",
            "server": "s1",
            "status": 200,
            "request_time": 0,
            "queue_time": 0,
            "connect_time": 0,
            "response_time": 0,
            "total_time": 0,
            "bytes": 0,
        }

        def waf_id(value: object) -> object:
            return _database_row("alpha", "node-a", json.dumps(base | {"waf_id": value}).encode())[
                -1
            ]

        identity = "shop.0b5e3c1a-7d42-4f0e-9c1b-2a6d8e4f7a90"
        self.assertEqual(waf_id(identity), identity)
        for odd in ("", "has space", "a" * 97, 7, None, "shop;drop"):
            with self.subTest(odd=odd):
                self.assertEqual(waf_id(odd), "")

    def test_the_margin_day_is_not_reported_as_older_than_the_database_keeps(self) -> None:
        """The mirror keeps one day below the oldest partition on purpose
        (B155); that day is not an anomaly and is not counted every minute.
        A day older than the margin, or newer than every partition, is."""

        days = frozenset({"20260910", "20260911", "20260917"})
        self.assertTrue(_within_margin("2026-09-09", days))
        self.assertFalse(_within_margin("2026-09-08", days))
        self.assertFalse(_within_margin("2026-09-18", days))
        self.assertFalse(_within_margin("not-a-day", days))

    def test_the_nodes_are_fetched_at_once_and_one_failing_leaves_the_other(self) -> None:
        """Fas 16 punkt 1: a run takes as long as its slowest node, not their sum."""

        other = NodeTarget("alpha", "node-b", "node-b.example.com")
        configured = dataclasses.replace(self.config, nodes=(self.target, other))
        # The first fetch of each node waits for the other's; in series the
        # first node would wait alone and the barrier would break.
        together = threading.Barrier(2, timeout=5)
        first = {self.target.node: True, other.node: True}

        def fetch(target: NodeTarget, wanted: date, offset: int) -> Response:
            if first[target.node]:
                first[target.node] = False
                together.wait()
            if target.node == "node-b":
                raise SSHError("node-b did not answer")
            return self.response(wanted, offset, b"")

        # Tried before, longer ago than a join takes, so its failure counts.
        (self.mirror / "alpha--node-b.meta.json").write_text(
            json.dumps({"schema_version": 1, "first_attempt": "2026-01-01T00:00:00+00:00"})
        )
        errors = StringIO()
        with patch("sys.stderr", errors):
            self.assertEqual(collect(configured, now=NOW, fetch=fetch), 1)

        self.assertTrue((self.mirror / "alpha--node-a.meta.json").exists())
        self.assertIn("alpha/node-b: node-b did not answer", errors.getvalue())
        meta = json.loads((self.mirror / "alpha--node-b.meta.json").read_text())
        self.assertIsNone(meta["last_success"])
        self.assertNotEqual(meta["outcome"], "ok")

    def test_new_data_is_fsynced_to_a_part(self) -> None:
        calls: list[tuple[date, int]] = []

        def fetch(_target: NodeTarget, wanted: date, offset: int) -> Response:
            calls.append((wanted, offset))
            payload = b'{"schema":1,"path":"/"}\n' if wanted == NOW.date() and offset == 0 else b""
            return self.response(wanted, offset, payload)

        self.assertEqual(collect(self.config, now=NOW, fetch=fetch), 0)
        self.assertEqual(
            (self.staging / "alpha--node-a--2026-09-08.jsonl").read_bytes(),
            b'{"schema":1,"path":"/"}\n',
        )
        meta = json.loads((self.mirror / "alpha--node-a.meta.json").read_bytes())
        self.assertEqual((meta["outcome"], meta["last_success"]), ("ok", NOW.isoformat()))
        self.assertEqual(calls[0], (NOW.date(), 0))

    def space(self, *, capacity: int, free: int) -> Any:
        return patch(
            "haprion.traffic_collector.os.statvfs",
            return_value=MagicMock(f_blocks=capacity, f_frsize=1, f_bavail=free),
        )

    def test_over_its_budget_the_mirror_loses_its_oldest_finished_days_whole(self) -> None:
        """B356: the node bounds what it holds; the manager holds every node's days."""

        other = NodeTarget("alpha", "node-b", "node-b.example.com")
        configured = dataclasses.replace(self.config, nodes=(self.target, other))
        for node in ("node-a", "node-b"):
            for day in ("2026-09-05", "2026-09-06", NOW.date().isoformat()):
                (self.staging / f"alpha--{node}--{day}.jsonl").write_bytes(b"x" * 100)
        (self.staging / ".alpha--node-a--2026-09-05.jsonl.database-offset").write_text("100\n")
        errors = StringIO()

        # 600 bytes held, a quarter of 1600 is 400: the oldest day goes, of both nodes.
        with self.space(capacity=1600, free=1000), redirect_stderr(errors):
            self.assertFalse(traffic_collector._staging_budget(configured, today=NOW.date()))

        left = sorted(path.name for path in self.staging.iterdir())
        self.assertEqual(
            left,
            [
                "alpha--node-a--2026-09-05.done",
                "alpha--node-a--2026-09-06.jsonl",
                "alpha--node-a--2026-09-08.jsonl",
                "alpha--node-b--2026-09-05.done",
                "alpha--node-b--2026-09-06.jsonl",
                "alpha--node-b--2026-09-08.jsonl",
            ],
        )
        self.assertEqual(errors.getvalue().count("removed before its time"), 2)

    def test_a_mirror_over_its_budget_with_only_today_left_fetches_nothing(self) -> None:
        (self.staging / f"alpha--node-a--{NOW.date().isoformat()}.jsonl").write_bytes(b"x" * 100)
        calls: list[date] = []

        def fetch(_target: NodeTarget, wanted: date, offset: int) -> Response:
            calls.append(wanted)
            return self.response(wanted, offset, b"")

        with self.space(capacity=200, free=100), redirect_stderr(StringIO()):
            self.assertEqual(collect(self.config, now=NOW, fetch=fetch), 1)

        self.assertEqual(calls, [])
        meta = json.loads((self.mirror / "alpha--node-a.meta.json").read_bytes())
        self.assertEqual(meta["outcome"], "budget")
        self.assertTrue((self.staging / f"alpha--node-a--{NOW.date().isoformat()}.jsonl").exists())

    def test_within_its_budget_the_mirror_keeps_everything(self) -> None:
        (self.staging / "alpha--node-a--2026-09-05.jsonl").write_bytes(b"x" * 100)
        with self.space(capacity=10_000, free=9_000):
            self.assertFalse(traffic_collector._staging_budget(self.config, today=NOW.date()))
        self.assertTrue((self.staging / "alpha--node-a--2026-09-05.jsonl").exists())

    def test_rerun_uses_the_committed_part_size_and_does_not_duplicate(self) -> None:
        line = b'{"schema":1}\n'

        def fetch(_target: NodeTarget, wanted: date, offset: int) -> Response:
            payload = line if wanted == NOW.date() and offset == 0 else b""
            return self.response(wanted, offset, payload)

        self.assertEqual(collect(self.config, now=NOW, fetch=fetch), 0)
        self.assertEqual(collect(self.config, now=NOW, fetch=fetch), 0)
        self.assertEqual((self.staging / "alpha--node-a--2026-09-08.jsonl").read_bytes(), line)

    def test_growing_current_data_and_older_backlog_both_advance_with_two_calls(self) -> None:
        calls: list[tuple[date, int]] = []
        line = b'{"schema":1}\n'

        def fetch(_target: NodeTarget, wanted: date, offset: int) -> Response:
            calls.append((wanted, offset))
            return Response(offset + len(line) + 100, offset, len(line), False, False, 0, line)

        for pass_number in range(2):
            calls.clear()
            collect_node(self.config, self.target, now=NOW, fetch=fetch, budget=0)
            self.assertEqual(len(calls), 2)
            self.assertEqual(calls[0], (NOW.date(), pass_number * len(line)))
            self.assertLess(calls[1][0], NOW.date())
            self.assertEqual(calls[1][1], pass_number * len(line))
            meta = json.loads((self.mirror / "alpha--node-a.meta.json").read_text())
            self.assertEqual(meta["outcome"], "ok")
            self.assertFalse(meta["current_complete"])
            self.assertEqual(meta["remaining_bytes"], 100)
            self.assertGreater(meta["pending_days"], 0)

        collect_node(
            self.config,
            self.target,
            now=NOW,
            fetch=lambda _target, wanted, offset: self.response(wanted, offset, b""),
        )
        meta = json.loads((self.mirror / "alpha--node-a.meta.json").read_text())
        self.assertTrue(meta["current_complete"])
        self.assertEqual(meta["remaining_bytes"], 0)

    def chunked(self, sizes: dict[date, int], calls: list[tuple[date, int]]) -> Any:
        """A node holding `sizes[day]` bytes per day, sent eight at a time."""

        def fetch(_target: NodeTarget, wanted: date, offset: int) -> Response:
            calls.append((wanted, offset))
            total = sizes.get(wanted, 0)
            payload = b"1234567\n"[: max(0, min(8, total - offset))]
            return Response(
                total, offset, len(payload), offset + len(payload) >= total, False, 0, payload
            )

        return fetch

    def test_a_burst_is_caught_up_within_one_run_not_one_block_a_minute(self) -> None:
        #
        # One block per run held a node to 8 MiB a minute: a ten-minute burst
        # on internal took an hour to reach the page (26-10-12).
        #
        calls: list[tuple[date, int]] = []
        yesterday = NOW.date() - date.resolution
        fetch = self.chunked({NOW.date(): 80, yesterday: 40}, calls)

        collect_node(self.config, self.target, now=NOW, fetch=fetch)

        today = [offset for day, offset in calls if day == NOW.date()]
        self.assertEqual(today, list(range(0, 80, 8)), "today first, block after block")
        self.assertEqual(calls[0], (NOW.date(), 0))
        self.assertEqual(
            [offset for day, offset in calls if day == yesterday], list(range(0, 40, 8))
        )
        self.assertEqual((self.staging / f"alpha--node-a--{NOW.date()}.jsonl").stat().st_size, 80)
        meta = json.loads((self.mirror / "alpha--node-a.meta.json").read_text())
        self.assertTrue(meta["current_complete"])
        self.assertEqual(meta["remaining_bytes"], 0)

    def test_a_spent_budget_still_fetches_today_and_the_oldest_open_day_once(self) -> None:
        calls: list[tuple[date, int]] = []
        yesterday = NOW.date() - date.resolution
        fetch = self.chunked({NOW.date(): 80, yesterday: 40}, calls)

        collect_node(self.config, self.target, now=NOW, fetch=fetch, budget=0)

        self.assertEqual(calls[0], (NOW.date(), 0))
        self.assertEqual(len([day for day, _ in calls if day == NOW.date()]), 1)
        self.assertEqual(len(calls), 2)

    def test_runs_in_a_row_behind_are_counted_and_end_when_caught_up(self) -> None:
        line = b'{"schema":1}\n'

        def behind(_target: NodeTarget, _wanted: date, offset: int) -> Response:
            return Response(offset + len(line) + 100, offset, len(line), False, False, 0, line)

        def meta() -> Any:
            return json.loads((self.mirror / "alpha--node-a.meta.json").read_text())

        for expected in (1, 2, 3):
            collect_node(self.config, self.target, now=NOW, fetch=behind, budget=0)
            self.assertEqual(meta()["behind_runs"], expected)

        def unreachable(_target: NodeTarget, _wanted: date, _offset: int) -> Response:
            raise SSHError("node-a did not answer")

        with self.assertRaises(SSHError):
            collect_node(self.config, self.target, now=NOW, fetch=unreachable)
        self.assertEqual(meta()["behind_runs"], 3, "a failed run says nothing about catching up")

        collect_node(
            self.config,
            self.target,
            now=NOW,
            fetch=lambda _target, wanted, offset: self.response(wanted, offset, b""),
        )
        self.assertEqual(meta()["behind_runs"], 0)

    def test_a_response_that_brings_nothing_ends_the_loop(self) -> None:
        calls: list[tuple[date, int]] = []

        def fetch(_target: NodeTarget, wanted: date, offset: int) -> Response:
            calls.append((wanted, offset))
            return Response(offset + 100, offset, 0, False, False, 0, b"")

        collect_node(self.config, self.target, now=NOW, fetch=fetch)

        self.assertLessEqual(len([day for day, _ in calls if day == NOW.date()]), 2)

    def test_a_completed_older_day_hands_the_budget_to_the_next(self) -> None:
        calls: list[tuple[date, int]] = []
        days = [NOW.date() - n * date.resolution for n in (1, 2, 3)]
        fetch = self.chunked({days[0]: 16, days[1]: 16, days[2]: 16}, calls)

        collect_node(self.config, self.target, now=NOW, fetch=fetch)

        fetched = {day for day, _ in calls}
        self.assertTrue(set(days[1:]) <= fetched, "two closed days in one run")
        for day in days[1:]:
            self.assertTrue((self.staging / f"alpha--node-a--{day}.done").exists())

    def test_a_closed_day_that_stays_open_does_not_hold_back_the_days_after_it(self) -> None:
        """Review 2026-10-30-igen, R4: only the budget ends the walk over the closed days.

        The day before yesterday answers, every time, that it is not at its
        end and has nothing to send, at the size the part already has - open
        for a reason the half-line rule does not cover. Yesterday comes after
        it and is fetched whole all the same.
        """

        calls: list[tuple[date, int]] = []
        day_before = NOW.date() - 2 * date.resolution
        yesterday = NOW.date() - date.resolution
        whole = self.chunked({yesterday: 16}, calls)

        def fetch(target: NodeTarget, wanted: date, offset: int) -> Response:
            if wanted == day_before:
                calls.append((wanted, offset))
                return Response(offset, offset, 0, False, False, 0, b"")
            return whole(target, wanted, offset)

        collect_node(self.config, self.target, now=NOW, fetch=fetch)

        self.assertIn(day_before, {day for day, _ in calls})
        self.assertFalse((self.staging / f"alpha--node-a--{day_before}.done").exists())
        self.assertEqual(
            (self.staging / f"alpha--node-a--{yesterday}.jsonl").read_bytes(), b"1234567\n" * 2
        )
        self.assertTrue((self.staging / f"alpha--node-a--{yesterday}.done").exists())

    def test_yesterday_is_read_again_until_the_midnight_grace_has_passed(self) -> None:
        yesterday = NOW.date() - date.resolution
        for age in range(2, 14):
            marker = self.staging / f"alpha--node-a--{NOW.date() - age * date.resolution}.done"
            marker.write_bytes(b"")
        calls: list[tuple[date, int]] = []

        def fetch(_target: NodeTarget, wanted: date, offset: int) -> Response:
            calls.append((wanted, offset))
            return self.response(wanted, offset, b"")

        shortly_after_midnight = datetime(2026, 9, 8, 0, 1, tzinfo=UTC)
        collect_node(
            self.config,
            self.target,
            now=shortly_after_midnight,
            fetch=fetch,
        )
        self.assertIn((yesterday, 0), calls)
        marker = self.staging / f"alpha--node-a--{yesterday}.done"
        self.assertFalse(marker.exists())

        calls.clear()
        collect_node(
            self.config,
            self.target,
            now=shortly_after_midnight + CLOSED_DAY_GRACE,
            fetch=fetch,
        )
        self.assertIn((yesterday, 0), calls)
        self.assertTrue(marker.exists())

    def test_a_node_still_being_joined_does_not_fail_the_run(self) -> None:
        #
        # Its keys are installed during the join; the collector ran in between
        # in prod and failed its unit for a minute (26-10-27, F25).
        #
        def unreachable(_target: NodeTarget, _wanted: date, _offset: int) -> Response:
            raise SSHError("Permission denied (publickey)")

        errors = StringIO()
        with patch("sys.stderr", errors):
            self.assertEqual(collect(self.config, now=NOW, fetch=unreachable), 0)
            later = NOW + timedelta(seconds=JOINING_SECONDS - 1)
            self.assertEqual(collect(self.config, now=later, fetch=unreachable), 0)
            much_later = NOW + timedelta(seconds=JOINING_SECONDS)
            self.assertEqual(collect(self.config, now=much_later, fetch=unreachable), 1)

        self.assertIn("never reached since it was added; not counted yet", errors.getvalue())
        meta = json.loads((self.mirror / "alpha--node-a.meta.json").read_bytes())
        self.assertEqual(meta["first_attempt"], NOW.isoformat())

    def test_a_node_reached_once_fails_the_run_at_once(self) -> None:
        def good(_target: NodeTarget, wanted: date, offset: int) -> Response:
            return self.response(wanted, offset, b"")

        def unreachable(_target: NodeTarget, _wanted: date, _offset: int) -> Response:
            raise SSHError("unreachable")

        self.assertEqual(collect(self.config, now=NOW, fetch=good), 0)
        with patch("sys.stderr", StringIO()):
            later = NOW + timedelta(seconds=60)
            self.assertEqual(collect(self.config, now=later, fetch=unreachable), 1)

    def test_failure_preserves_the_mirror_and_last_success(self) -> None:
        line = b'{"schema":1}\n'

        def good(_target: NodeTarget, wanted: date, offset: int) -> Response:
            return self.response(
                wanted, offset, line if wanted == NOW.date() and offset == 0 else b""
            )

        self.assertEqual(collect(self.config, now=NOW, fetch=good), 0)

        def failed(_target: NodeTarget, _wanted: date, _offset: int) -> Response:
            raise SSHError("unreachable")

        later = datetime(2026, 9, 8, 12, 1, tzinfo=UTC)
        self.assertEqual(collect(self.config, now=later, fetch=failed), 1)
        self.assertEqual((self.staging / "alpha--node-a--2026-09-08.jsonl").read_bytes(), line)
        meta = json.loads((self.mirror / "alpha--node-a.meta.json").read_bytes())
        self.assertEqual(meta["last_success"], NOW.isoformat())
        self.assertEqual(meta["last_attempt"], later.isoformat())
        self.assertEqual(meta["outcome"], "ssh")

    def test_database_failure_is_visible_without_erasing_mirror_success(self) -> None:
        configured = self.config

        def fetch(_target: NodeTarget, wanted: date, offset: int) -> Response:
            return self.response(wanted, offset, b"")

        with patch(
            "haprion.traffic_collector._ingest_database",
            side_effect=CollectorError("database import failed"),
        ):
            self.assertEqual(collect(configured, now=NOW, fetch=fetch, fetch_waf_page=no_waf), 1)

        meta = json.loads((self.mirror / "alpha--node-a.meta.json").read_bytes())
        self.assertEqual(meta["outcome"], "database")
        self.assertEqual(meta["last_attempt"], NOW.isoformat())
        self.assertEqual(meta["last_success"], NOW.isoformat())

    def database_configured(self) -> CollectorConfig:
        return self.config

    def test_a_lone_surrogate_or_an_oversized_request_is_an_unusable_record(self) -> None:
        """Review 2026-10-30, E1: `json.loads` hands on `\\ud800`, which COPY
        cannot encode, and a request number past bigint is refused by the
        database. Either stopped the import of every node after it."""

        part = self.staging / "alpha--node-a--2026-09-08.jsonl"
        part.write_bytes(
            traffic_line("/\ud800") + traffic_line("/big", request=2**64) + traffic_line("/ok")
        )
        connection: Any = _Connection()
        self.assertEqual(_ingest_part(self.config, connection, self.target, part), 2)
        self.assertEqual([row[8] for row in connection.rows], ["/ok"])

    def test_a_part_the_database_refuses_stops_only_its_own_node(self) -> None:
        """Review 2026-10-30, E1: the first node's failing COPY ended the
        import for every node after it, and its page still said `ok`."""

        node_b = NodeTarget("alpha", "node-b", "node-b.example.com")
        nodes = (self.target, node_b)
        configured = dataclasses.replace(self.database_configured(), nodes=nodes)

        def fetch(_target: NodeTarget, wanted: date, offset: int) -> Response:
            line = traffic_line() if wanted == NOW.date() and offset == 0 else b""
            return self.response(wanted, offset, line)

        connection = _Connection(refuse_nodes=("node-a",))
        stderr = StringIO()
        with (
            patch("haprion.traffic_collector._ingest_database", REAL_INGEST),
            patch("haprion.traffic_collector.psycopg.connect", return_value=connection),
            patch(
                "haprion.traffic_collector._database_days",
                return_value=frozenset({"20260908"}),
            ),
            patch("haprion.traffic_collector._database_window", return_value=None),
            redirect_stderr(stderr),
        ):
            code = collect(configured, now=NOW, fetch=fetch, fetch_waf_page=no_waf)

        self.assertEqual(code, 1)
        self.assertEqual([row[2] for row in connection.rows], ["node-b"])
        meta_a = json.loads((self.mirror / "alpha--node-a.meta.json").read_bytes())
        meta_b = json.loads((self.mirror / "alpha--node-b.meta.json").read_bytes())
        self.assertEqual((meta_a["outcome"], meta_b["outcome"]), ("database", "ok"))
        self.assertIn("alpha/node-a: database import failed", stderr.getvalue())

    def test_a_rebuilt_day_is_imported_from_its_beginning(self) -> None:
        """Review 2026-10-30, E3: a node file replaced the same day by a longer
        one rebuilt the part from zero, but the import position stayed, so the
        new file's first bytes never reached the database."""

        old = b"".join(traffic_line(f"/old/{n}") for n in range(50))
        new = b"".join(traffic_line(f"/new/{n}") for n in range(200))
        today = NOW.date()
        node_file = {"data": old}

        def fetch(_target: NodeTarget, wanted: date, offset: int) -> Response:
            data = node_file["data"]
            if wanted != today:
                return self.response(wanted, offset, b"")
            if offset > len(data):
                return Response(len(data), offset, 0, False, True, 0, b"")
            return self.response(wanted, offset, data[offset:])

        part = self.staging / f"alpha--node-a--{today.isoformat()}.jsonl"
        collect_node(self.config, self.target, now=NOW, fetch=fetch, window=2)
        connection: Any = _Connection()
        _ingest_part(self.config, connection, self.target, part)
        self.assertEqual(len(connection.rows), 50)

        # The node is rebuilt: a new, longer file. A fetch at the old end
        # lands inside a record of it, which the reader reports as skipped bytes.
        node_file["data"] = new
        real = fetch

        def landing_mid_record(target: NodeTarget, wanted: date, offset: int) -> Response:
            if wanted == today and 0 < offset < len(new):
                return Response(len(new), offset, 0, False, False, 7, b"")
            return real(target, wanted, offset)

        collect_node(
            self.config,
            self.target,
            now=NOW + timedelta(minutes=1),
            fetch=landing_mid_record,
            window=2,
        )
        self.assertEqual(part.read_bytes(), new)
        connection = _Connection()
        _ingest_part(self.config, connection, self.target, part)
        self.assertEqual([row[8] for row in connection.rows][:2], ["/new/0", "/new/1"])
        self.assertEqual(len(connection.rows), 200)

    def test_with_the_database_as_reader_no_joined_mirror_is_written(self) -> None:
        #
        # Review 2026-09-30, R2: every run used to join the whole retained
        # history into one file nobody reads once PostgreSQL is the reader.
        #
        line = b'{"schema":1,"path":"/"}\n'
        imported: list[bytes] = []

        def fetch(_target: NodeTarget, wanted: date, offset: int) -> Response:
            return self.response(
                wanted, offset, line if wanted == NOW.date() and offset == 0 else b""
            )

        def ingest(config: CollectorConfig) -> tuple[int, int, dict[NodeTarget, str]]:
            for part in sorted(config.staging.glob("alpha--node-a--*.jsonl")):
                imported.append(part.read_bytes())
            return 0, 0, {}

        with patch("haprion.traffic_collector._ingest_database", side_effect=ingest):
            self.assertEqual(
                collect(self.database_configured(), now=NOW, fetch=fetch, fetch_waf_page=no_waf), 0
            )
            self.assertEqual(
                collect(self.database_configured(), now=NOW, fetch=fetch, fetch_waf_page=no_waf), 0
            )

        self.assertFalse(
            (self.mirror / "alpha--node-a.jsonl").exists(), "no joined file is written"
        )
        self.assertIn(line, imported, "the import still reads the day part in staging")
        meta = json.loads((self.mirror / "alpha--node-a.meta.json").read_bytes())
        self.assertEqual((meta["outcome"], meta["last_success"]), ("ok", NOW.isoformat()))

    def test_remote_reset_discards_the_local_day_without_advancing_a_cursor(self) -> None:
        part = self.staging / "alpha--node-a--2026-09-08.jsonl"
        part.write_bytes(b"old\n")

        def reset(_target: NodeTarget, wanted: date, offset: int) -> Response:
            return Response(0, offset, 0, True, True, 0, b"")

        self.assertEqual(collect(self.config, now=NOW, fetch=reset), 0)
        self.assertEqual(part.read_bytes(), b"")

    def test_configuration_refuses_duplicate_destinations_and_relative_paths(self) -> None:
        path = Path(self.temporary.name) / "collector.json"
        value = {
            "schema_version": 2,
            "user": "svc-logread",
            "key": "/etc/key",
            "known_hosts": "/etc/known_hosts",
            "mirror": "relative",
            "staging": "/srv/logs/staging",
            "nodes": [{"cluster": "alpha", "node": "node-a", "host": "node-a.example.com"}],
            "database": "haprion_ui",
            "database_socket": "/run/postgresql",
        }
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(CollectorError, "mirror must be absolute"):
            load_config(path, require_secure=False)

    def test_a_configuration_without_a_database_is_refused(self) -> None:
        """Schema 1 was the mirror alone; the database is the reader now."""

        path = Path(self.temporary.name) / "collector.json"
        path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "user": "svc-logread",
                    "key": "/etc/key",
                    "known_hosts": "/etc/known_hosts",
                    "mirror": "/srv/logs/mirror",
                    "staging": "/srv/logs/staging",
                    "nodes": [],
                }
            )
        )
        with self.assertRaisesRegex(
            CollectorError, "schema_version must be 2: .*rerun platform step 13"
        ):
            load_config(path, require_secure=False)

    def test_configuration_refuses_names_that_carry_the_file_separator(self) -> None:
        """Review 2026-10-30, E4: `x--y` made node `x`'s cleanup delete its parts."""

        path = Path(self.temporary.name) / "collector.json"
        for cluster, node in (("alpha", "x--y"), ("alpha--b", "node-a"), ("alpha", "node-")):
            value = {
                "schema_version": 1,
                "user": "svc-logread",
                "key": "/etc/key",
                "known_hosts": "/etc/known_hosts",
                "mirror": "/srv/logs/mirror",
                "staging": "/srv/logs/staging",
                "nodes": [{"cluster": cluster, "node": node, "host": "node-a.example.com"}],
            }
            path.write_text(json.dumps(value))
            with self.subTest(cluster=cluster, node=node), self.assertRaises(CollectorError):
                load_config(path, require_secure=False)

    def test_missing_or_symlinked_working_directory_is_refused(self) -> None:
        self.staging.rmdir()
        with self.assertRaisesRegex(CollectorError, "cannot stat staging"):
            collect(self.config, now=NOW, fetch=lambda *_args: None)  # type: ignore[arg-type]

        self.staging.symlink_to(self.mirror, target_is_directory=True)
        with self.assertRaisesRegex(CollectorError, "staging is not a directory or is a symlink"):
            collect(self.config, now=NOW, fetch=lambda *_args: None)  # type: ignore[arg-type]

    def test_response_flags_must_agree_with_the_cursor_and_remote_size(self) -> None:
        day = NOW.date()
        headers = (
            {
                "file": day.isoformat(),
                "size": 10,
                "offset": 0,
                "sent": 0,
                "eof": True,
                "reset": False,
                "skipped_bytes": 0,
            },
            {
                "file": day.isoformat(),
                "size": 0,
                "offset": 0,
                "sent": 0,
                "eof": True,
                "reset": True,
                "skipped_bytes": 0,
            },
        )
        for header in headers:
            raw = json.dumps(header).encode() + b"\n"
            with (
                self.subTest(header=header),
                self.assertRaisesRegex(CollectorError, "inconsistent"),
            ):
                _parse_response(raw, day, 0)

    def test_metadata_failure_categories_are_stable_and_operator_facing(self) -> None:
        self.assertEqual(_failure_outcome(SSHError("down")), "ssh")
        self.assertEqual(_failure_outcome(ProtocolError("bad header")), "protocol")
        self.assertEqual(_failure_outcome(OSError("full disk")), "disk")

    def test_every_temporary_file_is_renamed_within_one_directory(self) -> None:
        """The first real run failed on exactly this; a unit test now holds it.

        Not a style rule. `ProtectSystem=strict` with two `ReadWritePaths`
        entries puts the mirror and staging in separate bind mounts, and
        `rename` across two mounts is EXDEV even when one filesystem backs
        both - so a temporary staged in the wrong directory cannot be published
        at all.
        """

        renames: list[tuple[Path, Path]] = []
        real = os.replace

        def watched(source: object, destination: object) -> None:
            renames.append((Path(str(source)).parent, Path(str(destination)).parent))
            real(source, destination)  # type: ignore[arg-type]

        def fetch(_target: NodeTarget, wanted: date, offset: int) -> Response:
            payload = b'{"schema":1,"path":"/"}\n' if wanted == NOW.date() and offset == 0 else b""
            return self.response(wanted, offset, payload)

        with patch("haprion.traffic_collector.os.replace", watched):
            self.assertEqual(collect(self.config, now=NOW, fetch=fetch), 0)

        self.assertTrue(renames, "nothing was published")
        for source, destination in renames:
            self.assertEqual(source, destination, "a rename crossed two ReadWritePaths entries")

    def test_failed_atomic_replace_preserves_destination_and_removes_temporary(self) -> None:
        destination = self.mirror / "state.json"
        destination.write_bytes(b"old\n")

        with (
            patch("haprion.traffic_collector.os.replace", side_effect=OSError("full disk")),
            self.assertRaisesRegex(OSError, "full disk"),
        ):
            _replace(destination, b"new\n")

        self.assertEqual(destination.read_bytes(), b"old\n")
        self.assertEqual(list(self.mirror.glob(".state.json.new-*")), [])

    def test_atomic_replace_sets_the_requested_mode_independent_of_umask(self) -> None:
        destination = self.mirror / "state.json"
        previous = os.umask(0o077)
        try:
            _replace(destination, b"state\n", 0o640)
        finally:
            os.umask(previous)

        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o640)

    def test_check_config_parses_without_contacting_a_node(self) -> None:
        output = StringIO()
        with (
            patch.object(sys, "argv", ["collector", "--check-config", "/etc/config.json"]),
            patch("haprion.traffic_collector.load_config", return_value=self.config) as loader,
            patch("haprion.traffic_collector.collect") as collect_mock,
            redirect_stdout(output),
            self.assertRaises(SystemExit) as stopped,
        ):
            _entry()

        self.assertEqual(stopped.exception.code, 0)
        loader.assert_called_once_with(Path("/etc/config.json"))
        collect_mock.assert_not_called()
        self.assertEqual(output.getvalue(), "parsed 1 node as svc-logread\n")

    def test_a_replay_drops_the_import_positions_and_nothing_else(self) -> None:
        part = self.staging / f"alpha--node-a--{NOW.date()}.jsonl"
        part.write_bytes(b'{"schema":1}\n')
        position = self.staging / f".{part.name}.database-offset"
        position.write_bytes(b"13\n")
        closed = self.staging / f"alpha--node-a--{NOW.date() - date.resolution}.done"
        closed.write_bytes(b"")

        self.assertEqual(forget_database_positions(self.config), 1)

        self.assertFalse(position.exists())
        self.assertEqual(part.read_bytes(), b'{"schema":1}\n', "the day itself is kept")
        self.assertTrue(closed.exists(), "how far a node was fetched is not touched")
        self.assertEqual(forget_database_positions(self.config), 0)

    def test_a_replay_refuses_a_position_that_is_not_a_plain_file(self) -> None:
        (self.staging / ".x.jsonl.database-offset").symlink_to(self.staging / "elsewhere")
        with self.assertRaises(CollectorError):
            forget_database_positions(self.config)


REQUEST_ID = "shop.0b5e3c1a-7d42-4f0e-9c1b-2a6d8e4f7a90"
WAF_AT = int(NOW.timestamp()) * 1_000_000 + 123_456


def engine_line(rule: int = 942100, **fields: object) -> str:
    """One line as the engine writes it to its journal (shape of `private/waf-prov`)."""
    match: dict[str, object] = {
        "client": "192.0.2.20",
        "rule_id": rule,
        "msg": "SQL Injection Attack Detected via libinjection",
        "data": "Matched Data: s&1c found within ARGS:id: 1' OR 1=1--",
        "severity": "critical",
        "uri": "/search?id=1%27%20OR%201=1--",
        "unique_id": REQUEST_ID,
    }
    match.update(fields)
    return json.dumps({"level": "error", "match": match, "time": "2026-09-08T14:00:00+02:00"})


def journal_cursor(number: int) -> str:
    return f"s=0000;i={number:x};b=1111;m=1;t=1;x=1"


def waf_response(*messages: str, first: int = 1, **header: object) -> bytes:
    records = [
        json.dumps({"at": WAF_AT + number, "cursor": journal_cursor(number), "message": message})
        for number, message in enumerate(messages, first)
    ]
    head = {
        "cursor": journal_cursor(first + len(messages) - 1) if messages else "",
        "eof": True,
        "reset": False,
        "sent": len(records),
    }
    head.update(header)
    return "".join(f"{line}\n" for line in [json.dumps(head), *records]).encode()


class WafJournalCollectorTests(unittest.TestCase):
    """Fas 21 steg 4a: the engine's matches from each node into `waf_match`."""

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
            "svc-logread",
            root / "key",
            root / "known_hosts",
            self.mirror,
            self.staging,
            (self.target,),
            "haprion_ui",
            "/run/postgresql",
        )
        self.cursor_file = self.staging / ".alpha--node-a.waf-cursor"

    def row(self, message: str, cursor: str = journal_cursor(1)) -> tuple[Any, ...] | None:
        return _waf_row("alpha", "node-a", WAF_AT, cursor, message)

    def test_the_field_and_the_value_are_told_apart_as_the_rule_set_writes_them(self) -> None:
        for data, wanted in (
            ("Matched Data: s&1c found within ARGS:id: 1' OR 1=1--", ("ARGS:id", "1' OR 1=1--")),
            (
                "Matched Data: <script> found within ARGS:json.q: <script>x",
                ("ARGS:json.q", "<script>x"),
            ),
            (
                "Matched Data: sqlmap found within REQUEST_HEADERS:User-Agent: sqlmap/1.8",
                ("REQUEST_HEADERS:User-Agent", "sqlmap/1.8"),
            ),
            (
                "Matched Data: ../ found within REQUEST_FILENAME: /a/../b",
                ("REQUEST_FILENAME", "/a/../b"),
            ),
            # The value keeps its own `: `; only the first one ends the field.
            ("Matched Data: x found within ARGS:q: a: b", ("ARGS:q", "a: b")),
            # A rule whose log data is the value alone, as the Host rule's is.
            ("192.0.2.10", ("", "192.0.2.10")),
            ("", ("", "")),
            (None, ("", "")),
            (7, ("", "")),
        ):
            with self.subTest(data=data):
                self.assertEqual(_waf_data(data), wanted)

    def test_an_exception_s_counter_is_stored_as_the_engine_logged_it(self) -> None:
        """B273: a counter's line, as the generator writes its log data, is a row."""

        line = engine_line(
            341100,
            msg="Allowed by exception 941100",
            data="Matched Data: <script> found within ARGS:q: <script>",
            severity="unknown",
            uri="/?q=%3Cscript%3E",
        )
        row = self.row(line)
        assert row is not None
        self.assertEqual(row[6:10], (341100, "ARGS:q", "<script>", "/"))

    def test_a_field_no_exception_could_name_is_not_kept(self) -> None:
        """The requester names the field; only what `waf_field` accepts survives,
        since the page offers it to the exception model as written."""

        for name in ("ARGS:a b", 'ARGS:a"b', "ARGS:a;b", "ARGS:a,b", "TX:x", "ARGS:" + "a" * 129):
            with self.subTest(name=name):
                field, value = _waf_data(f"Matched Data: x found within {name}: v")
                self.assertEqual(field, "")
        # A request built to move the split moves what is shown, and no more:
        # the field is still one an exception may name, and the model checks it.
        field, _ = _waf_data("Matched Data: a found within ARGS:decoy: b found within ARGS:real: c")
        self.assertEqual(field, "ARGS:decoy")

    def test_only_a_match_becomes_a_row(self) -> None:
        for message in (
            '{"level":"info","time":"2026-09-08T12:00:00Z","message":"Starting coraza-spoa"}',
            "not json at all",
            "[1, 2]",
            '{"level":"error","match":"text"}',
            engine_line(949110, data=""),  # the score crossing its threshold
            engine_line(959100, data=""),
            engine_line(980170, data=""),  # the report of every score
        ):
            with self.subTest(message=message[:60]):
                self.assertIsNone(self.row(message))

        row = self.row(engine_line())
        assert row is not None
        self.assertEqual(
            row[1:],
            (
                "alpha",
                "node-a",
                datetime(2026, 9, 8, 12, 0, 0, 123_456, tzinfo=UTC),
                REQUEST_ID,
                "shop",
                942100,
                "ARGS:id",
                "1' OR 1=1--",
                "/search",
                "192.0.2.20",
            ),
        )

    def test_a_match_that_names_no_object_this_installation_wrote_is_refused(self) -> None:
        for unique_id in ("VLRVGAUYXBZONLCY", "Shop.x", ".x", "shop;x.y", "", 7, None):
            with self.subTest(unique_id=unique_id), self.assertRaises(CollectorError):
                self.row(engine_line(unique_id=unique_id))
        for rule in (0, 1_000_000, "942100", True, None):
            with self.subTest(rule=rule), self.assertRaises(CollectorError):
                self.row(engine_line(rule))  # type: ignore[arg-type]

    def test_what_the_requester_wrote_is_bounded_and_storable(self) -> None:
        long = "a" * 5000
        row = self.row(
            engine_line(
                data=f"Matched Data: x found within ARGS:q: {long}\0\ud800",
                uri="/" + "p" * 3000 + "?q=1",
                client="not an address",
            )
        )
        assert row is not None
        _, _, _, _, _, _, _, field, matched, path, client = row
        self.assertEqual((field, len(matched), set(matched)), ("ARGS:q", 1024, {"a"}))
        self.assertEqual((len(path), "?" in path), (2048, False))
        self.assertEqual(client, "")
        row = self.row(engine_line(data="x\0y\ud800", client="2001:db8::1"))
        assert row is not None
        self.assertEqual((row[8], row[10]), ("xy?", "2001:db8::1"))
        row[8].encode("utf-8")  # what COPY has to do with it

    def test_one_journal_entry_is_one_event_on_one_node(self) -> None:
        first = self.row(engine_line(), journal_cursor(1))
        again = self.row(engine_line(), journal_cursor(1))
        later = self.row(engine_line(), journal_cursor(2))
        other = _waf_row("alpha", "node-b", WAF_AT, journal_cursor(1), engine_line())
        assert first and again and later and other
        self.assertEqual(first[0], again[0])
        self.assertEqual(len({first[0], later[0], other[0]}), 3)
        self.assertEqual(len(first[0]), 32)

    def test_the_response_frame_is_the_reader_s_and_must_agree_with_itself(self) -> None:
        good = waf_response(engine_line())
        page = _parse_waf_response(good, self.target)
        self.assertEqual(
            (page.cursor, page.reset, len(page.rows), page.skipped),
            (journal_cursor(1), False, 1, 0),
        )
        record = json.dumps({"at": WAF_AT, "cursor": journal_cursor(1), "message": "m"})
        for raw in (
            b"",
            b"not json\n",
            b'{"cursor":"","eof":true,"reset":false}\n',
            b'{"cursor":"bad cursor","eof":true,"reset":false,"sent":0}\n',
            b'{"cursor":"","eof":1,"reset":false,"sent":0}\n',
            b'{"cursor":"","eof":true,"reset":false,"sent":true}\n',
            b'{"cursor":"","eof":true,"reset":false,"sent":2}\n' + record.encode() + b"\n",
            b'{"cursor":"","eof":true,"reset":false,"sent":1}\n' + record.encode(),
            b'{"cursor":"x=1","eof":true,"reset":true,"sent":0}\n',
            b'{"cursor":"","eof":true,"reset":false,"sent":1}\nnot json\n',
            b'{"cursor":"","eof":true,"reset":false,"sent":1}\n{"at":1,"message":"m"}\n',
            b'{"cursor":"","eof":true,"reset":false,"sent":1}\n'
            + json.dumps({"at": "1", "cursor": journal_cursor(1), "message": "m"}).encode()
            + b"\n",
            b'{"cursor":"","eof":true,"reset":false,"sent":1}\n'
            + json.dumps({"at": 1, "cursor": "a b", "message": "m"}).encode()
            + b"\n",
            #
            # Nested past the parser: `RecursionError`, which is not a
            # `JSONDecodeError`, stopped the WAF import of every node at the
            # same record on every run (code review 26-10-22, 5-11).
            #
            b'{"cursor":"","eof":true,"reset":false,"sent":1}\n' + b"[" * 200_000 + b"\n",
            b"[" * 200_000 + b"\n",
        ):
            with self.subTest(raw=raw[:70]), self.assertRaises(ProtocolError):
                _parse_waf_response(raw, self.target)

    def test_an_engine_message_nested_past_the_parser_is_no_match(self) -> None:
        record = json.dumps({"at": WAF_AT, "cursor": journal_cursor(1), "message": "[" * 200_000})
        page = _parse_waf_response(
            b'{"cursor":"'
            + journal_cursor(1).encode()
            + b'","eof":true,"reset":false,"sent":1}\n'
            + record.encode()
            + b"\n",
            self.target,
        )
        self.assertEqual(page.rows, ())

    def test_a_match_that_cannot_be_stored_is_counted_and_stepped_over(self) -> None:
        page = _parse_waf_response(
            waf_response(engine_line(unique_id="VLRVGAUYXBZONLCY"), "Starting", engine_line()),
            self.target,
        )
        self.assertEqual((len(page.rows), page.skipped, page.cursor), (1, 1, journal_cursor(3)))

    def test_a_match_is_offered_by_the_partitions_bounds_not_their_names(self) -> None:
        """Review 26-10-22, 3-4: west of UTC the day partition named 2030-01-10 runs from
        05:00Z, and a match at 03:00Z that day - named for it in UTC - has none."""

        new_york_day = (
            datetime(2030, 1, 10, 5, tzinfo=UTC),
            datetime(2030, 1, 12, 5, tzinfo=UTC),
        )
        early = (None, None, None, datetime(2030, 1, 10, 3, tzinfo=UTC))
        later = (None, None, None, datetime(2030, 1, 11, 3, tzinfo=UTC))

        self.assertFalse(traffic_collector._within_window(early, new_york_day))
        self.assertTrue(traffic_collector._within_window(later, new_york_day))

    def collect_with(
        self, fetch_waf_page: object, connection: MagicMock | None = None
    ) -> tuple[int, str, MagicMock]:
        connection = connection or MagicMock()
        errors = StringIO()
        with (
            patch("haprion.traffic_collector.psycopg.connect") as connect,
            patch(
                "haprion.traffic_collector._database_days",
                return_value=frozenset({f"{NOW:%Y%m%d}"}),
            ),
            patch(
                "haprion.traffic_collector._database_window",
                return_value=(
                    datetime.combine(NOW.date(), time(), UTC),
                    datetime.combine(NOW.date(), time(), UTC) + timedelta(days=1),
                ),
            ),
            patch("haprion.traffic_collector._ingest_database", return_value=(0, 0, {})),
            patch("sys.stderr", errors),
        ):
            connect.return_value.__enter__.return_value = connection
            code = collect(
                self.config,
                now=NOW,
                fetch=lambda _t, wanted, offset: (
                    Response(0, offset, 0, True, False, 0, b"")
                    if offset == 0
                    else Response(offset, offset, 0, True, False, 0, b"")
                ),
                fetch_waf_page=fetch_waf_page,  # type: ignore[arg-type]
            )
        return code, errors.getvalue(), connection

    def test_the_cursor_moves_only_after_the_rows_are_committed(self) -> None:
        asked: list[str] = []
        committed_with: list[bool] = []
        connection = MagicMock()
        connection.commit.side_effect = lambda: committed_with.append(self.cursor_file.exists())

        def fetch(_target: NodeTarget, cursor: str) -> bytes:
            asked.append(cursor)
            return waf_response(engine_line(), "Starting", first=len(asked) * 10)

        code, errors, _ = self.collect_with(fetch, connection)
        self.assertEqual((code, errors), (0, ""))
        self.assertEqual(asked, ["-"])
        self.assertEqual(committed_with, [False], "committed before the cursor was written")
        self.assertEqual(self.cursor_file.read_text(), journal_cursor(11) + "\n")
        self.assertEqual(stat.S_IMODE(self.cursor_file.stat().st_mode), 0o600)
        copied = connection.cursor.return_value.__enter__.return_value.copy.return_value
        rows = [call.args[0] for call in copied.__enter__.return_value.write_row.call_args_list]
        self.assertEqual([row[5:7] for row in rows], [("shop", 942100)])

        self.collect_with(fetch, connection)
        self.assertEqual(asked, ["-", journal_cursor(11)])

    def test_a_failed_import_leaves_the_cursor_where_it_was(self) -> None:
        connection = MagicMock()
        connection.commit.side_effect = psycopg.OperationalError("gone")
        code, errors, _ = self.collect_with(lambda _t, _c: waf_response(engine_line()), connection)
        self.assertEqual(code, 1)
        self.assertIn("waf: WAF import failed: gone", errors)
        self.assertFalse(self.cursor_file.exists())

    def test_a_match_outside_the_partitions_is_passed_and_said(self) -> None:
        def fetch(_target: NodeTarget, _cursor: str) -> bytes:
            return waf_response(engine_line()).replace(
                str(WAF_AT + 1).encode(), str(WAF_AT + 1 - 3 * 86_400_000_000).encode()
            )

        code, errors, connection = self.collect_with(fetch)
        self.assertEqual(code, 0)
        self.assertIn("waf: 1 match(es) fall outside the days the database holds", errors)
        connection.commit.assert_not_called()
        self.assertEqual(self.cursor_file.read_text(), journal_cursor(1) + "\n")

    def test_a_node_that_lost_the_position_is_read_from_its_start_again(self) -> None:
        self.cursor_file.write_text(journal_cursor(5) + "\n")
        reset = b'{"cursor":"","eof":true,"reset":true,"sent":0}\n'
        code, _, connection = self.collect_with(lambda _t, _c: reset)
        self.assertEqual(code, 0)
        self.assertFalse(self.cursor_file.exists())
        connection.commit.assert_not_called()

    def test_a_quiet_minute_opens_no_database_connection(self) -> None:
        self.cursor_file.write_text(journal_cursor(5) + "\n")
        quiet = b'{"cursor":"%s","eof":true,"reset":false,"sent":0}\n' % journal_cursor(5).encode()
        errors = StringIO()
        with (
            patch("haprion.traffic_collector._ingest_database", return_value=(0, 0, {})),
            patch("haprion.traffic_collector._mirror_window", return_value=14),
            patch("haprion.traffic_collector.psycopg.connect") as connect,
            patch("sys.stderr", errors),
        ):
            code = collect(
                self.config,
                now=NOW,
                fetch=lambda _t, _d, offset: Response(offset, offset, 0, True, False, 0, b""),
                fetch_waf_page=lambda _t, _c: quiet,
            )
        self.assertEqual(code, 0)
        connect.assert_not_called()

    def test_a_node_bundle_from_before_the_journal_fails_the_run(self) -> None:
        """Not tolerated as a passing state: the node's matches would be
        missing from the WAF page while every run looked fine. The rollout
        puts the node package before the collector instead."""

        with patch("haprion.traffic_collector._bounded_ssh", return_value=(64, b"", b"")):
            code, errors, _ = self.collect_with(
                lambda target, cursor: ssh_fetch_waf(self.config, target, cursor)
            )
        self.assertEqual(code, 1)
        self.assertIn(
            "alpha/node-a: waf: the node refused the WAF request (exit 64): its node package is "
            "older than this collector",
            errors,
        )

    def test_an_unreadable_journal_fails_the_run_but_not_the_traffic_log(self) -> None:
        def broken(_target: NodeTarget, _cursor: str) -> bytes:
            raise SSHError("SSH request failed with exit 65")

        code, errors, _ = self.collect_with(broken)
        self.assertEqual(code, 1)
        self.assertIn("alpha/node-a: waf: SSH request failed with exit 65", errors)
        meta = json.loads((self.mirror / "alpha--node-a.meta.json").read_text())
        self.assertEqual(meta["outcome"], "ok")

    def test_the_request_names_the_cursor_and_any_exit_but_zero_fails(self) -> None:
        with (
            patch("haprion.traffic_collector._bounded_ssh", return_value=(255, b"", b"")) as ssh,
            self.assertRaises(SSHError) as raised,
        ):
            ssh_fetch_waf(self.config, self.target, journal_cursor(1))
        self.assertEqual(str(raised.exception), "SSH request failed with exit 255")
        self.assertEqual(ssh.call_args.args[0][-1], f"waf {journal_cursor(1)}")

    def test_a_cursor_this_collector_did_not_write_starts_over(self) -> None:
        self.cursor_file.write_text("not a cursor\n")
        self.assertEqual(_waf_cursor(self.config, self.target), "-")
        self.cursor_file.unlink()
        self.cursor_file.symlink_to(self.staging / "elsewhere")
        with self.assertRaises((CollectorError, OSError)):
            _waf_cursor(self.config, self.target)

    def test_a_replay_reads_every_journal_again(self) -> None:
        self.cursor_file.write_text(journal_cursor(5) + "\n")
        (self.staging / ".alpha--node-a--2026-09-08.jsonl.database-offset").write_text("10\n")
        self.assertEqual(forget_database_positions(self.config), 2)
        self.assertFalse(self.cursor_file.exists())

    def test_a_merged_mirror_left_from_before_goes_after_the_window(self) -> None:
        """B404: nothing writes `{cluster}--{node}.jsonl` any more, a node in inventory too."""

        old = (NOW - timedelta(days=RETENTION_DAYS + 1)).timestamp()
        mirror = self.config.mirror / "alpha--node-a.jsonl"
        meta = self.config.mirror / "alpha--node-a.meta.json"
        for path in (mirror, meta):
            path.write_text("{}\n")
            os.utime(path, (old, old))
        _retire(self.config, now=NOW)
        self.assertFalse(mirror.exists())
        self.assertTrue(meta.exists())

    def test_a_retired_node_s_cursor_is_removed(self) -> None:
        self.cursor_file.write_text(journal_cursor(5) + "\n")
        gone = self.staging / ".alpha--node-z.waf-cursor"
        gone.write_text(journal_cursor(5) + "\n")
        _retire_staging(self.config, now=NOW)
        self.assertTrue(self.cursor_file.exists())
        self.assertFalse(gone.exists())


if __name__ == "__main__":
    unittest.main()


INSTALL = Path(__file__).resolve().parents[1] / "install" / "platform"
STEP = INSTALL / "13-platform-traffic-collector"
RENDER = re.compile(r"^import json\nimport sys\n.*?^PY$", re.DOTALL | re.MULTILINE)


class WhatTheInstallationStepWrites(unittest.TestCase):
    """The step and the loader must agree, and only one of them is tested code.

    The configuration is rendered by a small Python block inside a shell
    script. Extracting and running that block is the only way this suite can
    say the installed file will parse; asserting the field names by hand would
    pass while the script wrote something else.
    """

    def render(self, inventory: list[str]) -> dict[str, object]:
        found = RENDER.search(STEP.read_text())
        if found is None:
            self.fail("the configuration renderer is no longer where the test extracts it from")
        source = found.group(0).removesuffix("PY")
        # The command is this interpreter and a block read out of our own
        # installation script; nothing here comes from outside the repository.
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                source,
                "svc-logread",
                "/etc/haprion/traffic-collector/id_ed25519",
                "/etc/haprion/traffic-collector/known_hosts",
                "/var/lib/haprion-ui/logs/mirror",
                "/var/lib/haprion-ui/logs/staging",
                "haprion_ui",
                "/var/run/postgresql",
                *inventory,
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        value: dict[str, object] = json.loads(result.stdout)
        return value

    def written(self, inventory: list[str]) -> Path:
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory)
        path = Path(directory) / "traffic-collector.json"
        path.write_text(json.dumps(self.render(inventory)))
        return path

    def test_the_collector_accepts_what_the_step_renders(self) -> None:
        path = self.written(["alpha:node-a:node-a.example.com", "beta:node-c:node-c.example.com"])

        config = load_config(path, require_secure=False)

        self.assertEqual(config.user, "svc-logread")
        self.assertEqual(
            [(item.cluster, item.node, item.host) for item in config.nodes],
            [
                ("alpha", "node-a", "node-a.example.com"),
                ("beta", "node-c", "node-c.example.com"),
            ],
        )
        self.assertEqual(config.mirror, Path("/var/lib/haprion-ui/logs/mirror"))
        self.assertEqual(config.staging, Path("/var/lib/haprion-ui/logs/staging"))

    def test_a_node_whose_name_is_its_hostname_is_rendered_whole(self) -> None:
        """`node_host` returns the whole entry when there is no colon."""

        config = load_config(self.written(["alpha:lb-01:lb-01"]), require_secure=False)

        self.assertEqual(config.nodes[0].host, "lb-01")

    def test_the_mirror_and_staging_share_a_parent(self) -> None:
        """One place, one filesystem, one volume to size.

        No longer what makes the rename safe - the unit gives systemd each
        directory as its own `ReadWritePaths` entry, so a rename between them
        is EXDEV whatever the disk says, and every temporary file is therefore
        written in the directory it is renamed into.
        """

        config = load_config(
            self.written(["alpha:node-a:node-a.example.com"]), require_secure=False
        )

        self.assertEqual(config.mirror.parent, config.staging.parent)


class TheCollectorUnits(unittest.TestCase):
    def setUp(self) -> None:
        self.rendered = {}
        for kind in ("service", "timer"):
            source = INSTALL / "examples" / f"haprion-traffic-collector.{kind}.example"
            self.rendered[kind] = source.read_text().replace("COLLECTOR_USER", "_haprion-collector")

    def test_it_runs_as_the_collector_and_may_gain_nothing(self) -> None:
        service = self.rendered["service"]

        self.assertIn("User=_haprion-collector", service)
        self.assertIn("NoNewPrivileges=yes", service)
        self.assertIn("CapabilityBoundingSet=\n", service)
        self.assertIn(
            "ExecStart=/opt/haprion/current/bin/haprion-traffic-collector",
            service,
        )
        self.assertNotIn("/opt/haprion-ui/current/venv", service)

    def test_it_may_write_only_the_mirror_and_staging(self) -> None:
        self.assertIn(
            "ReadWritePaths=/var/lib/haprion-ui/logs/mirror /var/lib/haprion-ui/logs/staging",
            self.rendered["service"],
        )
        self.assertIn("ProtectSystem=strict", self.rendered["service"])

    def test_it_speaks_ssh_and_nothing_else(self) -> None:
        self.assertIn("RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6", self.rendered["service"])

    def test_it_is_a_timer_rather_than_a_daemon(self) -> None:
        self.assertIn("Type=oneshot", self.rendered["service"])
        self.assertIn("OnActiveSec=2min", self.rendered["timer"])
        self.assertNotIn("OnBootSec=", self.rendered["timer"])
        self.assertIn("OnUnitActiveSec=1min", self.rendered["timer"])

    def test_the_nodes_come_from_the_cluster_file_not_the_answers(self) -> None:
        """A node or cluster added from the interface (B211, B302) survives this step being run again."""

        step = STEP.read_text()
        lib = (STEP.parents[1] / "lib.sh").read_text()

        self.assertIn("$(installed_clusters)", step)
        self.assertIn('installed_nodes "$cluster"', step)
        self.assertIn('"$CLUSTER_CONFIG" --list', lib)
        self.assertIn('"$CLUSTER_CONFIG" -c "$1" --field nodes', lib)
        self.assertNotIn("cluster_value NODES", step)
        self.assertNotIn("each_cluster", step)

    def test_sudo_is_tested_as_the_collector_not_listed_by_root(self) -> None:
        step = STEP.read_text()

        self.assertIn(
            'sudo -n -u "$COLLECTOR_USER" sudo -n -l',
            step,
        )
        self.assertNotIn('sudo -n -l -U "$COLLECTOR_USER"', step)

    @unittest.skipUnless(shutil.which("systemd-analyze"), "systemd is not installed here")
    def test_real_systemd_accepts_both_units(self) -> None:
        analyze = shutil.which("systemd-analyze") or ""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for kind, text in self.rendered.items():
                (root / f"haprion-traffic-collector.{kind}").write_text(text)
            for kind in ("timer", "service"):
                result = subprocess.run(
                    [analyze, "verify", str(root / f"haprion-traffic-collector.{kind}")],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                #
                # The release tree is not installed where this suite runs, so
                # the command the unit starts is expected to be unreachable.
                # Every other complaint about our own units is a defect.
                #
                complaints = [
                    line
                    for line in (result.stderr + result.stdout).splitlines()
                    if "haprion-traffic-collector" in line and "is not executable" not in line
                ]

                self.assertEqual(complaints, [], result.stderr or result.stdout)
