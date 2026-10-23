"""A change cut short at any point is put back byte for byte (B247)."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from haprion import change_journal
from haprion.change_journal import FileChange, Record, RecoveryError

SRC = Path(__file__).resolve().parents[1] / "src"

#
# The child builds the same change the test describes and kills itself, with
# a signal nothing can hold, after `step` of its steps. Step 0 is right after
# the record is on disk; "mid" stops inside a file's write, after the
# temporary exists and before the rename.
#
CHILD = """
import os, signal, sys
from pathlib import Path
from haprion import change_journal
from haprion.change_journal import FileChange, Record

root, stop, mid = Path(sys.argv[1]), int(sys.argv[2]), sys.argv[3] == "mid"
files = tuple(
    FileChange(root / f"file-{n}", f"before {n}\\n".encode(), f"after {n}\\n".encode(), f"file {n}")
    for n in range(3)
)
moves = ((root / "repo", root / ".removed" / "alpha-1" / "repo"),)
created = (root / ".removed", root / ".removed" / "alpha-1")
record = Record("cluster removal", "alpha", files, moves=moves, created=created,
                made=(root / "made",))
steps = 0

def step():
    global steps
    if steps == stop:
        os.kill(os.getpid(), signal.SIGKILL)
    steps += 1

real = change_journal.write_like
def write_like(path, content):
    if mid and steps == stop:
        handle = os.open(path.parent / f".{path.name}.killed", os.O_CREAT | os.O_WRONLY, 0o600)
        os.write(handle, content[:3])
        os.kill(os.getpid(), signal.SIGKILL)
    real(path, content)
    step()
change_journal.write_like = write_like

with change_journal.transaction(record, root / "journal" / "change-journal.json"):
    step()
    for directory in created:
        directory.mkdir(mode=0o700)
        step()
    (root / "made").mkdir()
    (root / "made" / "inside").write_text("made\\n")
    step()
    for source, destination in moves:
        os.replace(source, destination)
        step()
    change_journal.apply(files)
print("finished")
"""
STEPS = 1 + 2 + 1 + 1 + 3  # record, two directories, made, one move, three files


class Site:
    def __init__(self, root: Path) -> None:
        self.root = root
        for n in range(3):
            (root / f"file-{n}").write_bytes(f"before {n}\n".encode())
        (root / "repo").mkdir()
        (root / "repo" / "HEAD").write_text("ref: refs/heads/main\n")
        (root / "journal").mkdir()
        self.journal = root / "journal" / "change-journal.json"

    def snapshot(self) -> dict[str, bytes | None]:
        return {
            str(path.relative_to(self.root)): path.read_bytes() if path.is_file() else None
            for path in sorted(self.root.rglob("*"))
        }

    def child(self, stop: int, *, mid: bool = False) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # this interpreter, the script above
            [sys.executable, "-c", CHILD, str(self.root), str(stop), "mid" if mid else "-"],
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONPATH": str(SRC)},
            timeout=60,
            check=False,
        )


class AChangeCutShort(unittest.TestCase):
    def test_a_kill_after_any_step_is_put_back_by_the_next_run(self) -> None:
        for stop in range(STEPS):
            for mid in (False, True):
                with self.subTest(stop=stop, mid=mid), tempfile.TemporaryDirectory() as raw:
                    site = Site(Path(raw))
                    before = site.snapshot()

                    done = site.child(stop, mid=mid)

                    self.assertEqual(done.returncode, -signal.SIGKILL, done.stderr)
                    self.assertTrue(site.journal.exists())
                    recovered = change_journal.recover(site.journal)
                    assert recovered is not None
                    self.assertEqual(recovered.operation, "cluster removal")
                    self.assertEqual(site.snapshot(), before)

    def test_a_change_that_runs_to_its_end_leaves_no_record(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            site = Site(Path(raw))

            done = site.child(STEPS + 1)

            self.assertEqual((done.returncode, done.stdout), (0, "finished\n"), done.stderr)
            self.assertFalse(site.journal.exists())
            self.assertEqual((site.root / "file-2").read_bytes(), b"after 2\n")
            self.assertTrue((site.root / ".removed" / "alpha-1" / "repo" / "HEAD").exists())
            self.assertIsNone(change_journal.recover(site.journal))

    def test_a_terminating_signal_waits_for_the_change_to_finish(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            path = root / "file"
            path.write_bytes(b"before\n")
            journal = root / "change-journal.json"
            script = (
                "import os, signal, sys\n"
                "from pathlib import Path\n"
                "from haprion import change_journal\n"
                "path, journal = Path(sys.argv[1]), Path(sys.argv[2])\n"
                "change = change_journal.FileChange(path, b'before\\n', b'after\\n', 'file')\n"
                "with change_journal.transaction("
                "change_journal.Record('node add', 'alpha', (change,)), journal):\n"
                "    os.kill(os.getpid(), signal.SIGTERM)\n"
                "    change_journal.apply((change,))\n"
                "print('not reached')\n"
            )
            done = subprocess.run(  # this interpreter, the script above
                [sys.executable, "-c", script, str(path), str(journal)],
                capture_output=True,
                text=True,
                env={**os.environ, "PYTHONPATH": str(SRC)},
                timeout=60,
                check=False,
            )

            # Held until the change was done, then delivered: the process ends
            # by the signal, after its record is gone and the file written.
            self.assertEqual(done.returncode, -signal.SIGTERM, done.stderr)
            self.assertEqual(done.stdout, "")
            self.assertFalse(journal.exists())
            self.assertEqual(path.read_bytes(), b"after\n")


class PuttingBack(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.path = self.root / "file"
        self.path.write_bytes(b"before\n")
        self.journal = self.root / "change-journal.json"
        self.record = Record(
            "node add", "alpha", (FileChange(self.path, b"before\n", b"after\n", "the file"),)
        )

    def test_a_failure_in_the_process_is_put_back_from_the_record(self) -> None:
        with (
            self.assertRaisesRegex(ValueError, "refused"),
            change_journal.transaction(self.record, self.journal),
        ):
            change_journal.apply(self.record.files)
            raise ValueError("refused")

        self.assertEqual(self.path.read_bytes(), b"before\n")
        self.assertFalse(self.journal.exists())

    def test_a_file_changed_since_stops_the_recovery_before_it_touches_anything(self) -> None:
        other = self.root / "other"
        other.write_bytes(b"after\n")
        record = Record(
            "node add",
            "alpha",
            (
                FileChange(other, b"before\n", b"after\n", "the other file"),
                FileChange(self.path, b"before\n", b"after\n", "the file"),
            ),
        )
        change_journal._write_record(self.journal, record)
        self.path.write_bytes(b"edited by hand\n")

        with self.assertRaisesRegex(RecoveryError, "was changed since"):
            change_journal.recover(self.journal)

        self.assertEqual(other.read_bytes(), b"after\n")
        self.assertTrue(self.journal.exists())

    def test_a_new_change_is_refused_while_an_unfinished_one_is_on_record(self) -> None:
        change_journal._write_record(self.journal, self.record)

        with (
            self.assertRaisesRegex(RecoveryError, "did not finish"),
            change_journal.transaction(self.record, self.journal),
        ):
            self.fail("ran beside an unfinished change")

        self.assertEqual(self.path.read_bytes(), b"before\n")

    def test_a_record_naming_no_cluster_is_unreadable(self) -> None:
        document = self.record.as_json()
        document["cluster"] = "../elsewhere"
        with self.assertRaisesRegex(RecoveryError, "unreadable"):
            Record.from_json(document)

    def test_the_record_is_root_only(self) -> None:
        change_journal._write_record(self.journal, self.record)
        self.assertEqual(self.journal.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
