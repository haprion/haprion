"""One node's traffic-log chain, driven end to end against disposable directories.

Plan §6 makes the ten failure cases a deliverable, and R3 asks for an executable
proof of them rather than prose. The unit suites beside this one prove the node
reader and the collector separately, each against a hand-written counterpart of
the other. That is exactly what cannot answer §6: rotation, truncation, cursor
loss and a half-finished snapshot are properties of the two halves *together*.

What it is faithful to
----------------------
The shipped programs, unmodified. The node side is
`install/node/haprion-traffic-log-read` executed as its own process, reading its
request from `SSH_ORIGINAL_COMMAND` the way sshd's forced command hands it over,
writing the real wire bytes to a pipe. The manager side is the real
`_bounded_ssh` reading that pipe, the real `_parse_response` deciding whether the
answer is coherent, and the real `collect`/`collect_node` keeping cursors, parts,
import positions and the metadata, and the real import into the database with `COPY`. The UI side is
the shipped `traffic_logs` freshness reader, loaded by path because it lives in the interface
environment and this suite runs in the engine's - it imports nothing but the standard library, so the
file that runs here is the file that runs in production.

What it is NOT faithful to, and must not be claimed to be
---------------------------------------------------------
There is no PostgreSQL. A recording connection stands in for it: rows written with `COPY` become
visible at `commit`, and a row whose identity is already there is passed over, as the
duplicate trigger does. What is proved is what the collector offers the database and when its
import position moves - not the table, its partitions or its constraints.

There is no SSH, no sshd, no key, no forced-command entry in `authorized_keys`
and no network. `_bounded_ssh` is handed a wrapper instead of `/usr/bin/ssh`, so
what is proved is the protocol, the cursor and the recovery - not the transport,
not the authentication and not the isolation. Those are R2b's and R4's, on real
machines, and nothing measured here may be reported as covering them.

The log root and the reader's idea of "today" are injected. Both are the script's
own parameters (`serve(raw, root, output, today=...)`); only `main()` hard-codes
them, and `main()` is three lines this harness deliberately does not run.
"""

from __future__ import annotations

import dataclasses
import json
import os
import shutil
import sys
import tempfile
import threading
import unittest
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import patch

from haprion.traffic_collector import (
    RETENTION_DAYS,
    CollectorConfig,
    CollectorError,
    NodeTarget,
    Response,
    _bounded_ssh,
    _ingest_database,
    _parse_response,
)

BASE = Path(__file__).resolve().parents[1]
NODE_READER = BASE / "install" / "node" / "haprion-traffic-log-read"
UI_READER = BASE / "ui" / "src" / "haprion_ui" / "traffic_logs.py"

#
# sshd's side of the forced command, and nothing more: put the request where the
# reader looks for it, then run the shipped reader. The two refusals above it are
# how a failed connection reaches the collector - ssh exits non-zero and writes
# to stderr, so that is what is imitated, not a Python exception.
#
SHIM = """\
import importlib.util, os, sys
from datetime import date
from importlib.machinery import SourceFileLoader
from pathlib import Path

script, root, today, mode, request = sys.argv[1:6]
if mode != "up":
    sys.stderr.write(mode + "\\n")
    raise SystemExit(255)
spec = importlib.util.spec_from_loader("reader", SourceFileLoader("reader", script))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
os.environ["SSH_ORIGINAL_COMMAND"] = request
raise SystemExit(
    module.serve(
        os.environ["SSH_ORIGINAL_COMMAND"],
        Path(root),
        sys.stdout.buffer,
        today=date.fromisoformat(today),
    )
)
"""

UNREACHABLE = "ssh: connect to host: Connection timed out"
HOST_KEY_CHANGED = "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED"


def load_ui_reader() -> ModuleType:
    """The interface's mirror reader, loaded from its own tree by path."""

    spec = spec_from_loader("traffic_logs", SourceFileLoader("traffic_logs", str(UI_READER)))
    if spec is None or spec.loader is None:  # pragma: no cover - a loader always yields one
        raise RuntimeError("cannot load the interface's traffic reader")
    module = module_from_spec(spec)
    # `@dataclass(slots=True)` looks its own module up in `sys.modules`, so a
    # module loaded by path has to be registered before it is executed.
    sys.modules.setdefault(spec.name, module)
    spec.loader.exec_module(module)
    return module


UI = load_ui_reader()


def load_node_prune() -> ModuleType:
    """The node's retention timer, loaded the same way as the reader."""

    path = BASE / "install" / "node" / "haprion-traffic-log-prune"
    spec = spec_from_loader("prune", SourceFileLoader("prune", str(path)))
    if spec is None or spec.loader is None:  # pragma: no cover - a loader always yields one
        raise RuntimeError("cannot load the node's prune helper")
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RecordingDatabase:
    """What the import wrote, as PostgreSQL would hold it: committed rows, once each."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.rows: list[tuple[Any, ...]] = []
        self.identities: set[bytes] = set()
        self.skipped = 0

    def commit(self, pending: list[tuple[Any, ...]]) -> None:
        with self.lock:
            for row in pending:
                #
                # The duplicate trigger: a row already stored, or earlier in
                # the same COPY, is passed over.
                #
                if row[0] not in self.identities:
                    self.identities.add(row[0])
                    self.rows.append(row)

    def snapshot(self) -> list[tuple[Any, ...]]:
        with self.lock:
            return list(self.rows)


class _Copy:
    def __init__(self, connection: _Connection) -> None:
        self.connection = connection

    def __enter__(self) -> _Copy:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def write_row(self, row: tuple[Any, ...]) -> None:
        for item in row:
            if isinstance(item, str):
                item.encode("utf-8")
        self.connection.pending.append(row)


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
    """The connection the collector opens, over the recording database."""

    def __init__(self, database: RecordingDatabase) -> None:
        self.database = database
        self.pending: list[tuple[Any, ...]] = []

    def __enter__(self) -> _Connection:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def cursor(self) -> _Cursor:
        return _Cursor(self)

    def commit(self) -> None:
        self.database.commit(self.pending)
        self.pending = []

    def rollback(self) -> None:
        self.pending = []


NO_WAF = b'{"cursor":"","eof":true,"reset":false,"sent":0}\n'


@dataclass
class Measurements:
    """What R3 is asked to measure, accumulated across a whole scenario."""

    requests: int = 0
    wire_bytes: int = 0
    payload_bytes: int = 0
    refusals: int = 0
    seconds: float = 0.0

    def note(self, wire: int, payload: int) -> None:
        self.requests += 1
        self.wire_bytes += wire
        self.payload_bytes += payload


@dataclass
class Node:
    """One node's log directory, as the rsyslog rule and the prune timer leave it."""

    root: Path
    #
    # A single counter across every day, where HAProxy has one per process. The
    # real field restarts with the process and only orders records inside one
    # node; here it has a second job - it is what makes a duplicated or lost
    # record countable across a whole mirror, which is what R3 measures.
    #
    next_request: int = 0

    def day(self, when: date) -> Path:
        return self.root / f"traffic-{when.isoformat()}.jsonl"

    def append(self, when: date, count: int, *, second: int = 0) -> bytes:
        """Append `count` distinct records, numbered so gaps and repeats are visible."""

        first = self.next_request
        at = int(datetime(when.year, when.month, when.day, tzinfo=UTC).timestamp()) + second
        lines = b"".join(
            record(at=at, request=first + index, path=f"/r{first + index}")
            for index in range(count)
        )
        with self.day(when).open("ab") as stream:
            stream.write(lines)
        self.next_request = first + count
        return lines

    def append_raw(self, when: date, data: bytes) -> None:
        with self.day(when).open("ab") as stream:
            stream.write(data)

    def truncate(self, when: date, size: int = 0) -> None:
        with self.day(when).open("r+b") as stream:
            stream.truncate(size)

    def size(self, when: date) -> int:
        path = self.day(when)
        return path.stat().st_size if path.exists() else 0


def record(*, at: int, request: int, path: str = "/", status: int = 200) -> bytes:
    """One record in the exact shape `HTTP_TRAFFIC_LOG_FORMAT` produces."""

    return (
        json.dumps(
            {
                "schema": 1,
                "at": at,
                "request": request,
                "client": "192.0.2.9",
                "method": "GET",
                "host": "example.test",
                "path": path,
                "frontend": "fe_https",
                "backend": "be_web",
                "server": "web01",
                "status": status,
                "request_time": 1,
                "queue_time": 0,
                "connect_time": 1,
                "response_time": 12,
                "total_time": 14,
                "bytes": 512,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        + b"\n"
    )


class Chain:
    """A manager and one node, wired together by the real protocol."""

    def __init__(self, root: Path, *, today: date) -> None:
        self.root = root
        self.today = today
        self.mode = "up"
        self.measured = Measurements()
        self.shim = root / "forced-command.py"
        self.shim.write_text(SHIM, encoding="utf-8")
        self.mirror = root / "mirror"
        self.staging = root / "staging"
        self.mirror.mkdir()
        self.staging.mkdir()
        node_root = root / "node"
        node_root.mkdir()
        self.node = Node(node_root)
        self.target = NodeTarget("alpha", "node-a", "node-a.example.com")
        self.config = CollectorConfig(
            user="svc-logread",
            key=root / "id_ed25519",
            known_hosts=root / "known_hosts",
            mirror=self.mirror,
            staging=self.staging,
            nodes=(self.target,),
            database="haprion_ui",
            database_socket="/run/postgresql",
        )
        self.database = RecordingDatabase()

    #
    # Transport
    #

    def fetch(self, target: NodeTarget, wanted: date, offset: int) -> Response:
        """What `ssh_fetch` does, with the wrapper standing in for `/usr/bin/ssh`."""

        argv = [
            sys.executable,
            str(self.shim),
            str(NODE_READER),
            str(self.node.root),
            self.today.isoformat(),
            self.mode,
            f"{wanted.isoformat()} {offset}",
        ]
        code, stdout, stderr = _bounded_ssh(argv)
        if code != 0:
            self.measured.refusals += 1
            detail = stderr.decode("utf-8", "replace").strip() or f"exit {code}"
            raise CollectorError(f"SSH request failed with exit {code}: {detail}")
        response = _parse_response(stdout, wanted, offset)
        self.measured.note(len(stdout), response.sent)
        return response

    @contextmanager
    def unreachable(self, reason: str = UNREACHABLE) -> Iterator[None]:
        previous, self.mode = self.mode, reason
        try:
            yield
        finally:
            self.mode = previous

    #
    # Reading back what the chain produced
    #

    def meta(self) -> dict[str, object]:
        path = self.mirror / f"{self.target.cluster}--{self.target.node}.meta.json"
        if not path.exists():
            return {}
        value = json.loads(path.read_bytes())
        return value if isinstance(value, dict) else {}

    def imported(self, node: str | None = None) -> list[tuple[Any, ...]]:
        """The rows the database holds, in the order they were committed."""

        wanted = node or self.target.node
        return [row for row in self.database.snapshot() if row[2] == wanted]

    def mirrored(self) -> list[tuple[Any, ...]]:
        return self.imported()

    def parts_size(self) -> int:
        """What the staging parts of the node hold, in bytes."""

        prefix = f"{self.target.cluster}--{self.target.node}--"
        return sum(path.stat().st_size for path in self.staging.glob(f"{prefix}*.jsonl"))

    def requests_seen(self) -> list[int]:
        """The request counters in the database, in the order they arrived, one per row."""

        return [int(row[4]) for row in self.imported()]

    def duplicates(self) -> int:
        seen = self.requests_seen()
        return len(seen) - len(set(seen))

    def gaps(self) -> int:
        """Counters missing between the lowest and the highest the database holds."""

        seen = set(self.requests_seen())
        if not seen:
            return 0
        return (max(seen) - min(seen) + 1) - len(seen)

    def ui(self, *, limit: int = 500) -> Any:
        """What the page shows: the newest rows first within its limit, and the nodes' freshness.

        The rows are the database's. The freshness is read from the collector's
        metadata as the page reads it, and the records the import could not use
        are what it skipped.
        """

        cluster = self.target.cluster
        reading = UI.read_freshness(self.mirror, (cluster,))
        entries = [
            UI.Entry(
                cluster=row[1],
                node=row[2],
                at=row[3],
                request=row[4],
                client=row[5],
                method=row[6],
                host=row[7],
                path=row[8],
                frontend=row[9],
                backend=row[10],
                server=row[11],
                status=row[12],
                request_time=row[13],
                queue_time=row[14],
                connect_time=row[15],
                response_time=row[16],
                total_time=row[17],
                bytes=row[18],
                rule=row[19],
            )
            for row in self.database.snapshot()
            if row[1] == cluster
        ]
        entries.sort(key=lambda entry: (entry.at, entry.node, entry.request), reverse=True)
        return dataclasses.replace(
            reading, entries=tuple(entries[:limit]), malformed=self.database.skipped
        )


class ChainTestCase(unittest.TestCase):
    """Base for the R3 scenarios: one disposable chain, one fixed clock."""

    TODAY = date(2026, 9, 9)
    NOW = datetime(2026, 9, 9, 12, 0, 0, tzinfo=UTC)

    def setUp(self) -> None:
        if shutil.which("python3") is None:  # pragma: no cover - the gate requires it
            self.skipTest("python3 is required to run the node reader as a process")
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.chain = Chain(Path(temporary.name), today=self.TODAY)
        self.offset = 0

    def collect(self, *, now: datetime | None = None) -> int:
        """One collector run on the scenario's clock, mirror timestamps included.

        The collector reads a mirror's modification time as when the manager
        last heard from that node, and the retirement sweep measures that
        against `now`. The files here are written by the wall clock, so a
        scenario that advances weeks would otherwise depend on the time of
        day the suite happens to run. Whatever a run writes is stamped with
        the run's own moment; what it leaves alone keeps its earlier stamp.
        """

        from haprion.traffic_collector import collect

        moment = now or self.NOW
        before = {path: path.stat().st_mtime_ns for path in self.chain.mirror.iterdir()}
        database = self.chain.database

        def ingest(config: CollectorConfig) -> tuple[int, int, dict[NodeTarget, str]]:
            skipped, expired, failed = _ingest_database(config)
            with database.lock:
                database.skipped += skipped
            return skipped, expired, failed

        today = moment.astimezone(UTC).date()
        days = frozenset(
            f"{today + timedelta(days=offset):%Y%m%d}" for offset in range(-RETENTION_DAYS - 1, 2)
        )
        with (
            patch(
                "haprion.traffic_collector.psycopg.connect",
                side_effect=lambda *_a, **_k: _Connection(database),
            ),
            patch("haprion.traffic_collector._database_days", return_value=days),
            patch("haprion.traffic_collector._database_window", return_value=None),
            patch("haprion.traffic_collector._ingest_database", ingest),
        ):
            result = collect(
                self.chain.config,
                now=moment,
                fetch=self.chain.fetch,
                fetch_waf_page=lambda _target, _cursor: NO_WAF,
            )
        stamp = int(moment.timestamp() * 1_000_000_000)
        for path in self.chain.mirror.iterdir():
            if before.get(path) != path.stat().st_mtime_ns:
                os.utime(path, ns=(stamp, stamp))
        return result

    def advance(self, days: int) -> datetime:
        """Move both clocks the same number of days, as a real midnight would.

        Cumulative, so a scenario can step twice and the second step is not
        secretly a step back.
        """

        self.offset += days
        self.chain.today = self.TODAY + timedelta(days=self.offset)
        return self.NOW + timedelta(days=self.offset)

    def settle(self, *, now: datetime | None = None) -> int:
        """Run until the backfill has claimed every closed day in the window.

        A run costs two requests until then: today, and one closed day. The
        closed days are taken oldest first, so a cold collector spends one run
        per day of the window before it reaches yesterday - measured, and the
        reason most scenarios here start from a settled chain rather than an
        empty one.
        """

        runs = 0
        while True:
            before = self.chain.measured.requests
            self.assertEqual(self.collect(now=now), 0)
            runs += 1
            if self.chain.measured.requests - before == 1:
                return runs
            self.assertLessEqual(runs, RETENTION_DAYS + 1, "the backfill never finished")

    def retire(self, *replacements: NodeTarget) -> CollectorConfig:
        """The inventory the manager reads, with the node under test taken out."""

        return dataclasses.replace(self.chain.config, nodes=replacements)

    def assertClean(self) -> None:
        """No duplicate row, no missing counter, no half-written line in a part."""

        self.assertEqual(self.chain.duplicates(), 0, "the database got a record twice")
        self.assertEqual(self.chain.gaps(), 0, "the database lacks a record")
        for path in self.chain.staging.glob("*--*--*.jsonl"):
            data = path.read_bytes()
            self.assertTrue(not data or data.endswith(b"\n"), f"{path.name} ends mid-record")

    def assertNoLitter(self) -> None:
        """Nothing half-finished is left behind in staging."""

        litter = [
            item.name
            for directory in (self.chain.staging, self.chain.mirror)
            for item in directory.iterdir()
            if item.name.startswith(".")
            and item.name != ".collector.lock"
            and not item.name.endswith(".database-offset")
        ]
        self.assertEqual(litter, [], "an interrupted run left a temporary file behind")
