"""One operation per cluster at a time.

The case that matters is the one that cannot be written as a single-process
test: a second holder must be refused while the first still has the lock. So the
second holder is a real subprocess, because an advisory lock is held per open
file description and a second `flock` in the same process would happily succeed.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

from haprion import exit_codes
from haprion.cluster_lock import LockBusy, hold

SOURCE = str(Path(__file__).resolve().parents[1] / "src")

CONTENDER = textwrap.dedent(
    """
    import sys
    sys.path.insert(0, {source!r})
    from pathlib import Path
    from haprion.cluster_lock import LockBusy, hold

    try:
        with hold({cluster!r}, root=Path({root!r})):
            print("acquired")
    except LockBusy as exc:
        print(f"busy: {{exc}}")
        raise SystemExit(exc.exit_code)
    """
)


def contend(cluster: str, root: Path) -> subprocess.CompletedProcess[str]:
    """Try to take the same lock from another process."""

    return subprocess.run(
        [sys.executable, "-c", CONTENDER.format(source=SOURCE, cluster=cluster, root=str(root))],
        capture_output=True,
        text=True,
        check=False,
    )


class LockTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name) / "locks"

    def test_a_second_holder_is_refused_while_the_first_holds_it(self) -> None:
        with hold("alpha", root=self.root):
            result = contend("alpha", self.root)

        self.assertEqual(result.returncode, exit_codes.BLOCKED)
        self.assertIn("another operation is already running for cluster 'alpha'", result.stdout)

    def test_the_refusal_names_who_holds_it(self) -> None:
        #
        # Best effort, but worth having: an operator told only "busy" has no way
        # to find out what to wait for.
        #
        with hold("alpha", root=self.root, operation="deploy"):
            result = contend("alpha", self.root)

        self.assertIn("deploy", result.stdout)
        self.assertIn("pid ", result.stdout)

    def test_the_lock_is_released_when_the_block_ends(self) -> None:
        with hold("alpha", root=self.root):
            pass

        result = contend("alpha", self.root)

        self.assertEqual(result.returncode, 0)
        self.assertIn("acquired", result.stdout)

    def test_the_lock_is_released_even_when_the_block_raises(self) -> None:
        with self.assertRaises(RuntimeError), hold("alpha", root=self.root):
            raise RuntimeError("deploy blew up")

        result = contend("alpha", self.root)

        self.assertEqual(result.returncode, 0)

    def test_the_two_clusters_do_not_block_each_other(self) -> None:
        #
        # Per cluster, not global: a slow rollout on one must not stop work on
        # the other, and they share nothing at deploy time.
        #
        with hold("alpha", root=self.root):
            result = contend("beta", self.root)

        self.assertEqual(result.returncode, 0)

    def test_the_holder_note_says_who_and_when(self) -> None:
        with hold("alpha", root=self.root, operation="deploy") as path:
            holder = json.loads(path.read_text())

        self.assertEqual(holder["operation"], "deploy")
        self.assertIsInstance(holder["pid"], int)
        self.assertRegex(holder["started"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")

    def test_an_unreadable_holder_note_still_gives_a_clean_refusal(self) -> None:
        #
        # The note is diagnosis, never the lock itself. Garbage in it must not
        # turn a clear "busy" into an error nobody can act on.
        #
        with hold("alpha", root=self.root) as path:
            path.write_text("not json at all")
            result = contend("alpha", self.root)

        self.assertEqual(result.returncode, exit_codes.BLOCKED)
        self.assertIn("another operation is already running", result.stdout)

    def test_a_stale_file_from_a_dead_holder_does_not_block(self) -> None:
        #
        # Why flock rather than "the file exists means locked": nothing has to be
        # cleaned up after a process that was killed.
        #
        self.root.mkdir(parents=True)
        (self.root / "alpha.lock").write_text('{"pid": 999999, "operation": "deploy"}')

        result = contend("alpha", self.root)

        self.assertEqual(result.returncode, 0)


class RaisedErrorTests(unittest.TestCase):
    def test_the_busy_error_carries_its_exit_code(self) -> None:
        self.assertEqual(LockBusy("busy").exit_code, exit_codes.BLOCKED)


if __name__ == "__main__":
    unittest.main()
