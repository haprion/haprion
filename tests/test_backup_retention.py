from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from haproxy_mgmt import backup_retention


class BackupRetentionTests(unittest.TestCase):
    def test_no_file_means_the_default_and_a_written_count_is_read_back(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "retention"
            self.assertEqual(backup_retention.read("alpha", root=root), 14)
            with mock.patch.object(backup_retention, "_private_directory", return_value=True):
                previous = backup_retention.write("alpha", 30, root=root)
                self.assertIsNone(previous)
                self.assertEqual(backup_retention.read("alpha", root=root), 30)
                self.assertEqual(
                    backup_retention.write("alpha", 7, root=root), b'{"retention":30}\n'
                )
            self.assertEqual(backup_retention.read("alpha", root=root), 7)
            self.assertEqual(oct(os.stat(root / "alpha.json").st_mode & 0o777), "0o644")
            # Whatever umask the helper runs under, the directory is readable.
            self.assertEqual(oct(os.stat(root).st_mode & 0o777), "0o755")

    def test_a_present_but_untrustworthy_file_is_an_error_not_the_default(self) -> None:
        """Pruning is destructive; "could not read it, kept fourteen" is the wrong guess."""

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            for content in (b"", b"[]", b'{"retention": "30"}', b'{"retention": 0}', b"{}"):
                (root / "alpha.json").write_bytes(content)
                with (
                    self.subTest(content=content),
                    self.assertRaises(backup_retention.RetentionError),
                ):
                    backup_retention.read("alpha", root=root)

    def test_the_bounds_and_the_cluster_id_are_enforced(self) -> None:
        for value in (0, 366, True, "14", None):
            with self.subTest(value=value), self.assertRaises(backup_retention.RetentionError):
                backup_retention.bounded(value)
        with self.assertRaises(backup_retention.RetentionError):
            backup_retention.path("../alpha")

    def test_restore_removes_what_never_existed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            file = Path(raw) / "alpha.json"
            file.write_bytes(b"x")
            backup_retention.restore(file, None)
            self.assertFalse(file.exists())


if __name__ == "__main__":
    unittest.main()
