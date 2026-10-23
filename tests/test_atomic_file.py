"""A file replaced whole or not at all, and nowhere but `haprion.atomic_file` (review 2026-10-22, 4-7).

Sixteen modules renamed files into place by hand, at three levels of care:
three never synced the file, several synced it and not its directory. The
source check refuses a rename outside the module that does it right.
"""

from __future__ import annotations

import ast
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from haprion import atomic_file

ROOT = Path(__file__).resolve().parents[1]
SOURCES = (ROOT / "src" / "haprion", ROOT / "ui" / "src" / "haprion_ui")
#
# Sent to the restore target as source text and run there with its own
# python3: it imports nothing from this package, by design.
#
STANDALONE = {"restore_agent.py"}


def _renames(path: Path) -> list[str]:
    found = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        name, owner = node.func.attr, node.func.value
        if isinstance(owner, ast.Name) and owner.id == "os" and name in {"replace", "rename"}:
            found.append(f"{path.relative_to(ROOT)}:{node.lineno} os.{name}")
        elif (
            name in {"replace", "rename"}
            and len(node.args) == 1
            and not node.keywords
            and not isinstance(node.args[0], ast.Constant)
        ):
            found.append(f"{path.relative_to(ROOT)}:{node.lineno} .{name}()")
    return found


class OnePlaceRenames(unittest.TestCase):
    def test_no_module_renames_a_file_into_place_by_hand(self) -> None:
        renamed = [
            found
            for root in SOURCES
            for path in sorted(root.rglob("*.py"))
            if path.name != "atomic_file.py" and path.name not in STANDALONE
            for found in _renames(path)
        ]
        self.assertEqual(renamed, [], "use haprion.atomic_file")


class Replacing(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.path = self.root / "file"

    def test_the_content_mode_and_nothing_left_beside_it(self) -> None:
        self.path.write_bytes(b"old")

        atomic_file.write(self.path, b"new", mode=0o640)

        self.assertEqual(self.path.read_bytes(), b"new")
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o640)
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ["file"])

    def test_an_error_leaves_the_old_file_and_no_temporary(self) -> None:
        self.path.write_bytes(b"old")

        with self.assertRaises(RuntimeError), atomic_file.replacing(self.path, mode=0o600) as out:
            out.write(b"half")
            raise RuntimeError("stopped")

        self.assertEqual(self.path.read_bytes(), b"old")
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ["file"])

    def test_the_file_and_then_its_directory_are_synced(self) -> None:
        synced: list[str] = []
        real = os.fsync

        def fsync(handle: int) -> None:
            synced.append("directory" if stat.S_ISDIR(os.fstat(handle).st_mode) else "file")
            real(handle)

        with mock.patch.object(os, "fsync", side_effect=fsync):
            atomic_file.write(self.path, b"new", mode=0o600)

        self.assertEqual(synced, ["file", "directory"])

    def test_the_mode_is_set_before_the_owner(self) -> None:
        """Root in the worker's sandbox may chown and not chmod a file it no longer owns."""

        calls: list[str] = []
        with (
            mock.patch.object(os, "fchmod", side_effect=lambda *_: calls.append("mode")),
            mock.patch.object(os, "fchown", side_effect=lambda *_: calls.append("owner")),
        ):
            atomic_file.write(self.path, b"new", mode=0o640, uid=0, gid=0)

        self.assertEqual(calls, ["mode", "owner"])

    def test_like_keeps_the_mode_of_what_it_replaces(self) -> None:
        self.path.write_bytes(b"old")
        self.path.chmod(0o604)

        atomic_file.write_like(self.path, b"new")

        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o604)

    def test_a_staged_directory_is_moved_into_place(self) -> None:
        staged = self.root / ".staged"
        staged.mkdir()
        (staged / "inside").write_text("x")

        atomic_file.move(staged, self.root / "final")

        self.assertEqual((self.root / "final" / "inside").read_text(), "x")
        self.assertFalse(staged.exists())


if __name__ == "__main__":
    unittest.main()
