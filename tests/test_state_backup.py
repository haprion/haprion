"""The manager-side node state backup engine's destructive boundaries."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from haproxy_mgmt import state_backup
from haproxy_mgmt.backup_archive import ArchiveFacts
from haproxy_mgmt.config import DeployIdentity, Node


class StateBackupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.node = Node(name="node-a", mgmt_host="node-a.example")
        self.identity = DeployIdentity(user="svc-backup", key=Path("/root/backup-key"))

    @staticmethod
    def fetch(node: Node, identity: DeployIdentity, destination) -> state_backup.FetchResult:
        del node, identity
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

    def test_a_failed_export_never_becomes_a_backup(self) -> None:
        def failed(node: Node, identity: DeployIdentity, destination) -> state_backup.FetchResult:
            del node, identity
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
                )
            self.assertEqual(result.version, "2026-09-21_22-54-47")
        finally:
            if previous is None:
                del os.environ["TZ"]
            else:
                os.environ["TZ"] = previous
            time.tzset()
