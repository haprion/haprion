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
the mirror and the metadata. The UI side is the shipped `traffic_logs.read`,
loaded by path because it lives in the interface environment and this suite runs
in the engine's - it imports nothing but the standard library, so the file that
runs here is the file that runs in production.

What it is NOT faithful to, and must not be claimed to be
---------------------------------------------------------
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

import json
import os
import shutil
import sys
import tempfile
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

from haprion.traffic_collector import (
    RETENTION_DAYS,
    CollectorConfig,
    CollectorError,
    NodeTarget,
    Response,
    _bounded_ssh,
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
        )

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

    def mirror_path(self) -> Path:
        return self.mirror / f"{self.target.cluster}--{self.target.node}.jsonl"

    def meta(self) -> dict[str, object]:
        path = self.mirror / f"{self.target.cluster}--{self.target.node}.meta.json"
        if not path.exists():
            return {}
        value = json.loads(path.read_bytes())
        return value if isinstance(value, dict) else {}

    def mirrored(self) -> list[bytes]:
        path = self.mirror_path()
        return path.read_bytes().splitlines() if path.exists() else []

    def requests_seen(self) -> list[int]:
        """The request counters in the mirror, in file order, one per record."""

        seen: list[int] = []
        for line in self.mirrored():
            seen.append(int(json.loads(line)["request"]))
        return seen

    def duplicates(self) -> int:
        seen = self.requests_seen()
        return len(seen) - len(set(seen))

    def gaps(self) -> int:
        """Counters missing between the lowest and the highest the mirror holds."""

        seen = set(self.requests_seen())
        if not seen:
            return 0
        return (max(seen) - min(seen) + 1) - len(seen)

    def ui(self, **filters: object) -> Any:
        return UI.read(self.mirror, (self.target.cluster,), **filters)


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
        result = collect(self.chain.config, now=moment, fetch=self.chain.fetch)
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

        return CollectorConfig(
            user=self.chain.config.user,
            key=self.chain.config.key,
            known_hosts=self.chain.config.known_hosts,
            mirror=self.chain.mirror,
            staging=self.chain.staging,
            nodes=replacements,
        )

    def assertClean(self) -> None:
        """No duplicate record, no missing counter, no half-written line."""

        self.assertEqual(self.chain.duplicates(), 0, "the mirror repeated a record")
        self.assertEqual(self.chain.gaps(), 0, "the mirror lost a record")
        path = self.chain.mirror_path()
        if path.exists():
            data = path.read_bytes()
            self.assertTrue(not data or data.endswith(b"\n"), "the mirror ends mid-record")

    def assertNoLitter(self) -> None:
        """Nothing half-finished is left behind in staging."""

        litter = [
            item.name
            for directory in (self.chain.staging, self.chain.mirror)
            for item in directory.iterdir()
            if item.name.startswith(".") and item.name != ".collector.lock"
        ]
        self.assertEqual(litter, [], "an interrupted run left a temporary file behind")
