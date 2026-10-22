"""The manager-side node state backup engine's destructive boundaries."""

from __future__ import annotations

import fcntl
import json
import tempfile
import time
import unittest
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO
from unittest import mock

from haprion import restore_runs, state_backup
from haprion.backup_archive import ArchiveFacts
from haprion.config import DeployIdentity, Node


class StateBackupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.node = Node(name="node-a", mgmt_host="node-a.example")
        self.identity = DeployIdentity(user="svc-backup", key=Path("/root/backup-key"))

    @staticmethod
    def fetch(
        node: Node, identity: DeployIdentity, destination: BinaryIO, *, timeout: float
    ) -> state_backup.FetchResult:
        del node, identity, timeout
        destination.write(b"complete archive")
        return state_backup.FetchResult(0)

    @staticmethod
    def valid(path: Path) -> ArchiveFacts:
        return ArchiveFacts(members=40, files=30, size_bytes=path.stat().st_size, hostname="node-a")

    def test_a_complete_archive_is_committed_and_latest_is_atomic(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            with mock.patch.object(state_backup, "_directory_is_private", return_value=True):
                result = state_backup._one_node(
                    self.node,
                    self.identity,
                    root,
                    "2026-09-21_05-00-00",
                    fetch=self.fetch,
                    validator=self.valid,
                    retention=14,
                )

            directory = root / self.node.name
            archive = directory / "2026-09-21_05-00-00.tar.gz"
            self.assertEqual(result.outcome, "done")
            self.assertEqual(archive.read_bytes(), b"complete archive")
            self.assertEqual((directory / "latest").readlink(), Path(archive.name))
            self.assertEqual(list(directory.glob(".incoming-*")), [])

    def test_an_archive_for_the_other_node_is_never_committed(self) -> None:
        def wrong_node(path: Path) -> ArchiveFacts:
            return ArchiveFacts(
                members=40, files=30, size_bytes=path.stat().st_size, hostname="node-b"
            )

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            with mock.patch.object(state_backup, "_directory_is_private", return_value=True):
                result = state_backup._one_node(
                    self.node,
                    self.identity,
                    root,
                    "2026-09-21_05-00-00",
                    fetch=self.fetch,
                    validator=wrong_node,
                    retention=14,
                )

            self.assertEqual(result.error, "backup_node_mismatch")
            self.assertEqual(list((root / self.node.name).iterdir()), [])

    def test_retention_is_fourteen_archives_per_node(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            for day in range(1, 18):
                (directory / f"2026-09-{day:02d}_05-00-00.tar.gz").write_bytes(b"archive")

            state_backup._retain(directory, state_backup.RETENTION)

            kept = sorted(directory.glob("*.tar.gz"), reverse=True)
            self.assertEqual(state_backup.RETENTION, 14)
            self.assertEqual(len(kept), 14)
            self.assertEqual(kept[0].name, "2026-09-17_05-00-00.tar.gz")
            self.assertEqual(kept[-1].name, "2026-09-04_05-00-00.tar.gz")

    @staticmethod
    def _run(runs: Path, name: str, node: str, archive: str, *, at: float, **files: str) -> Path:
        directory = runs / name
        directory.mkdir(parents=True)
        (directory / "request.json").write_text(
            json.dumps({"node": node, "archive": archive}), encoding="utf-8"
        )
        (directory / "prepared.json").write_text(json.dumps({"at": at}), encoding="utf-8")
        for file, text in files.items():
            (directory / f"{file}.json").write_text(text, encoding="utf-8")
        return directory

    def test_an_archive_a_restore_run_waits_on_is_never_pruned(self) -> None:
        """Review 2026-09-25, finding 3: the oldest kept archive is a fair choice
        to restore, and the next backup - the timer's or the overwrite's own -
        must not remove it from under the prepared run."""

        now = time.time()
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw) / "archives"
            runs = Path(raw) / "restore"
            directory.mkdir()
            for day in range(1, 18):
                (directory / f"2026-09-{day:02d}_05-00-00.tar.gz").write_bytes(b"archive")
            self._run(runs, "r260925-aaaaaaaa", "n1", "2026-09-01_05-00-00", at=now - 60)
            self._run(runs, "r260925-bbbbbbbb", "n2", "2026-09-02_05-00-00", at=now - 60)
            (runs / "r260925-cccccccc").mkdir()  # no request.json: protects nothing

            held = restore_runs.waiting_on(runs, now)
            self.assertEqual(held, {("n1", "2026-09-01_05-00-00"), ("n2", "2026-09-02_05-00-00")})
            state_backup._retain(directory, 14, frozenset(v for name, v in held if name == "n1"))

            kept = {path.name for path in directory.glob("*.tar.gz")}
            self.assertEqual(len(kept), 15)
            self.assertIn("2026-09-01_05-00-00.tar.gz", kept)
            # Another node's run protects nothing here.
            self.assertNotIn("2026-09-02_05-00-00.tar.gz", kept)

    def test_only_a_run_that_can_still_restore_holds_its_archive(self) -> None:
        """Found 2026-10-09: two runs from 2026-09-25 held an archive each for two
        weeks, and the Backups page showed 15 where it promised 14."""

        now = time.time()
        hour = restore_runs.START_WINDOW
        with tempfile.TemporaryDirectory() as raw:
            runs = Path(raw)
            self._run(runs, "r260925-aaaaaaaa", "n1", "a-expired", at=now - hour - 60)
            self._run(runs, "r260925-bbbbbbbb", "n1", "b-done", at=now - 60, result="{}")
            self._run(
                runs,
                "r260925-cccccccc",
                "n1",
                "c-ended",
                at=now - 3 * hour,
                started="{}",
                result="{}",
            )
            working = self._run(runs, "r260925-dddddddd", "n1", "d-working", at=now - 2 * hour)
            self._run(runs, "r260925-eeeeeeee", "n1", "e-waiting", at=now - 60)

            with restore_runs.Held(working, wait=True):
                held = restore_runs.waiting_on(runs, now)
            self.assertEqual(held, {("n1", "d-working"), ("n1", "e-waiting")})
            # Once the step lets go, a run past its hour holds nothing either.
            self.assertEqual(restore_runs.waiting_on(runs, now), {("n1", "e-waiting")})

    def test_a_backup_puts_old_runs_away_and_keeps_its_count(self) -> None:
        now = datetime.now(UTC)
        two_weeks = 14 * 24 * 3600
        with (
            mock.patch.object(state_backup, "_key_is_private", return_value=True),
            mock.patch.object(state_backup, "_root_is_private", return_value=True),
            mock.patch.object(state_backup, "_directory_is_private", return_value=True),
            tempfile.TemporaryDirectory() as raw,
        ):
            root, runs = Path(raw) / "archives", Path(raw) / "restore"
            directory = root / self.node.name
            directory.mkdir(parents=True)
            for day in range(1, 15):
                (directory / f"2026-09-{day:02d}_05-00-00.tar.gz").write_bytes(b"archive")
            old = self._run(
                runs,
                "r260925-aaaaaaaa",
                self.node.name,
                "2026-09-01_05-00-00",
                at=now.timestamp() - two_weeks,
                started="{}",
                result="{}",
            )

            result = state_backup.run(
                "alpha",
                mock.Mock(nodes=(self.node,)),
                self.identity,
                root,
                fetch=self.fetch,
                validator=self.valid,
                now=now,
                lock_path=Path(raw) / "lock",
                restore_root=runs,
            )

            self.assertEqual(result.nodes[0].outcome, "done")
            kept = sorted(path.name for path in directory.glob("*.tar.gz"))
            self.assertEqual(len(kept), 14)
            self.assertNotIn("2026-09-01_05-00-00.tar.gz", kept)
            self.assertFalse(old.exists())

    def test_no_restore_directory_protects_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            self.assertEqual(
                restore_runs.waiting_on(Path(raw) / "missing", time.time()), frozenset()
            )

    def test_a_failed_export_never_becomes_a_backup(self) -> None:
        def failed(
            node: Node, identity: DeployIdentity, destination: BinaryIO, *, timeout: float
        ) -> state_backup.FetchResult:
            del node, identity, timeout
            destination.write(b"partial")
            return state_backup.FetchResult(1, "export failed")

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            with mock.patch.object(state_backup, "_directory_is_private", return_value=True):
                result = state_backup._one_node(
                    self.node,
                    self.identity,
                    root,
                    "2026-09-21_05-00-00",
                    fetch=failed,
                    validator=self.valid,
                    retention=14,
                )

            self.assertEqual(result.error, "node_export_failed")
            self.assertEqual(list((root / self.node.name).iterdir()), [])


class TheRunAnswersWithinItsBudget(unittest.TestCase):
    """Logic review 26-10-22, L4: 300 s a node, one after the other, under a lock
    waited for without end, went past the worker's 720 s client while every node
    was within its own limit; the job read `unknown` and the helper went on."""

    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.raw = Path(directory.name)
        self.root = self.raw / "backups"
        self.root.mkdir(mode=0o700)
        self.now = 1000.0
        self.asked: list[tuple[str, float]] = []
        for name, value in (("_key_is_private", True), ("_root_is_private", True)):
            patch = mock.patch.object(state_backup, name, return_value=value)
            patch.start()
            self.addCleanup(patch.stop)
        patch = mock.patch.object(state_backup, "_directory_is_private", return_value=True)
        patch.start()
        self.addCleanup(patch.stop)

    def clock(self) -> float:
        return self.now

    def wait(self, seconds: float) -> None:
        self.now += seconds

    def slow(
        self, node: Node, identity: DeployIdentity, destination: BinaryIO, *, timeout: float
    ) -> state_backup.FetchResult:
        del identity
        self.asked.append((node.name, timeout))
        self.now += timeout
        destination.write(b"archive")
        return state_backup.FetchResult(0)

    @staticmethod
    def valid(path: Path) -> ArchiveFacts:
        return ArchiveFacts(
            members=1, files=1, size_bytes=path.stat().st_size, hostname=path.parent.name
        )

    def backup(self, nodes: int, **kwargs: Any) -> state_backup.BackupResult:
        cluster = mock.Mock(
            nodes=tuple(Node(name=f"node-{i}", mgmt_host="node.example") for i in range(nodes))
        )
        return state_backup.run(
            "alpha",
            cluster,
            DeployIdentity(user="svc-backup", key=Path("/root/backup-key")),
            self.root,
            fetch=self.slow,
            validator=self.valid,
            now=datetime(2026, 10, 22, 12, tzinfo=UTC),
            lock_path=self.raw / "lock",
            restore_root=self.raw / "runs",
            clock=self.clock,
            wait=self.wait,
            **kwargs,
        )

    def test_nodes_past_the_budget_are_named_and_the_ones_reached_are_kept(self) -> None:
        result = self.backup(3)

        self.assertLessEqual(self.now - 1000.0, state_backup.RUN_BUDGET_SECONDS)
        self.assertEqual(self.asked, [("node-0", 300.0), ("node-1", 300.0)])
        self.assertEqual(
            [(node.name, node.outcome, node.error) for node in result.nodes],
            [
                ("node-0", "done", None),
                ("node-1", "done", None),
                ("node-2", "failed", "backup_budget_exhausted"),
            ],
        )
        self.assertTrue((self.root / "node-0" / "latest").is_symlink())

    def test_the_last_node_gets_what_is_left_not_its_whole_limit(self) -> None:
        self.backup(2, budget=450.0)

        self.assertEqual(self.asked, [("node-0", 300.0), ("node-1", 150.0)])

    def test_a_lock_held_too_long_is_busy_and_nothing_is_asked(self) -> None:
        with (self.raw / "lock").open("a+b") as other:
            fcntl.flock(other.fileno(), fcntl.LOCK_EX)
            with self.assertRaises(state_backup.BackupBusy):
                self.backup(2)
        self.assertEqual(self.asked, [])
        self.assertGreaterEqual(self.now - 1000.0, state_backup.LOCK_WAIT_SECONDS)
        self.assertLess(self.now - 1000.0, state_backup.LOCK_WAIT_SECONDS + 1)


if __name__ == "__main__":
    unittest.main()


class TheServiceTemplateCanTakeTheLock(unittest.TestCase):
    """`ProtectSystem=strict` leaves /run read-only unless the unit says otherwise.

    The engine serialises cluster runs on a lock under /run/lock. A template
    that only opens `backup_root` would fail every timer run on EROFS, and no
    unit test of the engine itself could notice.
    """

    def test_the_lock_directory_is_a_read_write_path(self) -> None:
        installer = (Path(__file__).resolve().parents[1] / "install/02-manager-config").read_text(
            encoding="utf-8"
        )
        line = next(line for line in installer.splitlines() if line.startswith("ReadWritePaths="))
        self.assertIn(str(state_backup.LOCK_PATH.parent), line.split("=", 1)[1].split())


class TheArchiveIsNamedOnTheManagersClock(unittest.TestCase):
    """B169: names sort the listing and drive retention, so they share one clock.

    The first cluster run on a manager (2026-09-21 22:54 CEST) filed itself as
    `20-54-47`, two hours before the archive the fleet-wide script had just
    taken - newer, but sorted older, and next in line to be pruned.
    """

    def test_the_stamp_follows_the_host_zone_not_utc(self) -> None:
        import os
        import time
        from datetime import UTC, datetime

        previous = os.environ.get("TZ")
        os.environ["TZ"] = "Europe/Stockholm"
        time.tzset()
        try:
            moment = datetime(2026, 9, 21, 20, 54, 47, tzinfo=UTC)
            self.assertEqual(moment.astimezone().strftime("%H-%M-%S"), "22-54-47")
            cluster = mock.Mock(nodes=())
            with (
                mock.patch.object(state_backup, "_key_is_private", return_value=True),
                mock.patch.object(state_backup, "_root_is_private", return_value=True),
                tempfile.TemporaryDirectory() as raw,
            ):
                result = state_backup.run(
                    "alpha",
                    cluster,
                    DeployIdentity(user="svc-backup", key=Path("/root/backup-key")),
                    Path(raw),
                    now=moment,
                    lock_path=Path(raw) / "lock",
                    restore_root=Path(raw) / "restore",
                )
            self.assertEqual(result.version, "2026-09-21_22-54-47")
        finally:
            if previous is None:
                del os.environ["TZ"]
            else:
                os.environ["TZ"] = previous
            time.tzset()
