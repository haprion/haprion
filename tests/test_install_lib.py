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


def run_lib(script: str, *args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed interpreter, the repository's library
        ["/bin/bash", "-c", f'source "$0"; {script}', str(LIB), *args],
        capture_output=True,
        text=True,
        check=False,
        cwd=cwd,
    )


class AFileInADirectoryNotThereYet(unittest.TestCase):
    """/etc/haprion did not exist on a new node when the step wrote into it (Fas 18, finding 22)."""

    def test_the_directory_is_made_and_the_file_written(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            target = Path(raw) / "etc" / "haprion" / "node-installation.json"
            # Not root: chown is what the step does as root, so it is left out here.
            done = run_lib('chown() { :; }; install_file "$1" root:root 644 "{}"', str(target))
            self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
            self.assertEqual(target.read_text(), "{}\n")
            self.assertEqual(target.parent.stat().st_mode & 0o777, 0o755)


class ThePackagesOwnConfigurationFile(unittest.TestCase):
    """is_packaged_conffile: only bytes dpkg itself recorded count as the package's sample."""

    def setUp(self) -> None:
        self.work = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.work)
        self.file = self.work / "haproxy.cfg"
        self.file.write_text("global\n")
        digest = subprocess.run(  # noqa: S603 - fixed tool
            ["/usr/bin/md5sum", str(self.file)], capture_output=True, text=True, check=True
        )
        self.sample_md5 = digest.stdout.split()[0]

    def packaged(self, recorded: str) -> bool:
        # dpkg-query's ${Conffiles}: one " <path> <md5>" line per file.
        fake = 'dpkg-query() { printf " %s %s\\n" /etc/other 0000 "$FILE" "$SUM"; }; '
        done = subprocess.run(  # noqa: S603 - fixed interpreter, the repository's library
            [
                "/bin/bash",
                "-c",
                f'source "$0"; {fake} is_packaged_conffile haproxy "$FILE"',
                str(LIB),
            ],
            capture_output=True,
            text=True,
            check=False,
            env={**os.environ, "FILE": str(self.file), "SUM": recorded},
        )
        return done.returncode == 0

    def test_the_unchanged_sample_is_the_package_s(self) -> None:
        self.assertTrue(self.packaged(self.sample_md5))

    def test_a_changed_file_is_the_operator_s(self) -> None:
        self.file.write_text("global\n    maxconn 10\n")
        self.assertFalse(self.packaged(self.sample_md5))

    def test_a_link_or_an_unknown_package_is_not(self) -> None:
        self.assertFalse(self.packaged(""))
        target = self.work / "elsewhere.cfg"
        self.file.rename(target)
        self.file.symlink_to(target)
        self.assertFalse(self.packaged(self.sample_md5))


if __name__ == "__main__":
    unittest.main()
