"""The installers' shared shell functions, run by bash as the installers run them."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

LIB = Path(__file__).resolve().parents[1] / "install" / "lib.sh"


def stamp(days_ago: float) -> str:
    return time.strftime("%Y%m%d-%H%M%S", time.localtime(time.time() - days_ago * 86400))


class RollbackCopies(unittest.TestCase):
    """`.replaced-` copies are kept 30 days; the newest per file always stays."""

    def setUp(self) -> None:
        self.work = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.work)
        self.file = self.work / "node.conf"
        self.file.write_text("same\n")

    def copy(self, days_ago: float, path: Path | None = None) -> Path:
        copy = Path(f"{path or self.file}.replaced-{stamp(days_ago)}")
        copy.write_text("old\n")
        return copy

    def install_file(self, content: str = "same") -> str:
        owner = f"{os.getuid()}:{os.getgid()}"
        return subprocess.run(  # noqa: S603 - fixed interpreter, the repository's library
            [
                "/bin/bash",
                "-c",
                'source "$0"; install_file "$1" "$2" 600 "$3"',
                str(LIB),
                str(self.file),
                owner,
                content,
            ],
            capture_output=True,
            text=True,
            check=True,
        ).stdout

    def left(self) -> list[str]:
        return sorted(path.name for path in self.work.iterdir())

    def test_copies_past_thirty_days_go_and_the_newest_stays(self) -> None:
        old, older, recent = self.copy(40), self.copy(60), self.copy(10)
        printed = self.install_file()
        self.assertEqual(self.left(), sorted(["node.conf", recent.name]))
        self.assertIn(f"pruned   {old}", printed)
        self.assertIn(f"pruned   {older}", printed)

    def test_the_newest_copy_stays_however_old(self) -> None:
        self.copy(90)
        newest = self.copy(40)
        self.install_file()
        self.assertEqual(self.left(), sorted(["node.conf", newest.name]))

    def test_a_write_prunes_too_and_keeps_the_copy_it_just_made(self) -> None:
        self.copy(40)
        self.copy(50)
        self.install_file("changed")
        names = self.left()
        self.assertEqual(len(names), 2, names)
        self.assertEqual(self.file.read_text(), "changed\n")

    def test_only_this_file_s_dated_copies_are_touched(self) -> None:
        other = self.copy(40, self.work / "node-installation.json")
        odd = self.work / "node.conf.replaced-by-hand"
        odd.write_text("kept\n")
        self.copy(40)
        self.copy(35)
        self.install_file()
        self.assertIn(other.name, self.left())
        self.assertIn(odd.name, self.left())


if __name__ == "__main__":
    unittest.main()
