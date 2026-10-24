"""The configuration releases a node keeps (review 26-10-08, R4), run as the shell it is.

`prune_releases` is extracted from `install/node/haprion-pull-deploy` verbatim
and run against a scratch release directory, as the keepalived and WAF steps
are. What it must never remove is the release a deploy falls back to.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "install" / "node" / "haprion-pull-deploy"


class TheNodeKeepsItsNewestReleases(unittest.TestCase):
    def setUp(self) -> None:
        text = SCRIPT.read_text()
        found = re.search(r"^KEEP_RELEASES=.*?^prune_releases\(\) \{.*?^\}$", text, re.S | re.M)
        assert found, "the function is no longer where the test extracts it from"
        self.function = found.group(0)
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        self.releases = self.root / "releases"
        self.releases.mkdir()
        self.made = [self.release(f"202610{day:02d}-120000") for day in range(1, 16)]

    def release(self, name: str) -> Path:
        path = self.releases / name
        (path / "conf.d").mkdir(parents=True)
        (path / "haproxy.cfg").write_text("global\n")
        return path

    def prune(self, *, current: Path, old: Path, running: Path) -> str:
        (self.root / "current").symlink_to(current)
        finished = subprocess.run(
            [
                "/bin/bash",
                "-c",
                'set -Eeuo pipefail\nlog() { echo "$*"; }\n'
                f'RELEASE_DIR="{self.releases}"\nCURRENT="{self.root / "current"}"\n'
                f'OLD_RELEASE="{old}"\nRUNNING="{running}"\n'
                f"{self.function}\nprune_releases\n",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        return finished.stdout

    def left(self) -> list[str]:
        return sorted(path.name for path in self.releases.iterdir())

    def test_the_newest_ten_stay(self) -> None:
        newest = self.made[-1]

        output = self.prune(current=newest, old=self.made[-2], running=self.made[-2])

        self.assertEqual(self.left(), [path.name for path in self.made[-10:]])
        self.assertEqual(output.count("pruned "), 5)

    def test_the_releases_a_deploy_falls_back_to_stay_whatever_their_age(self) -> None:
        oldest, second = self.made[0], self.made[1]

        self.prune(current=self.made[-1], old=oldest, running=second)

        self.assertIn(oldest.name, self.left())
        self.assertIn(second.name, self.left())
        self.assertEqual(len(self.left()), 12)

    def test_anything_not_named_as_a_release_is_left_alone(self) -> None:
        kept = self.releases / "kept-by-hand"
        kept.mkdir()

        self.prune(current=self.made[-1], old=self.made[-2], running=self.made[-2])

        self.assertIn("kept-by-hand", self.left())

    def test_it_runs_only_after_a_deploy_that_completed(self) -> None:
        text = SCRIPT.read_text()
        calls = [match.start() for match in re.finditer(r"^\s+prune_releases$", text, re.M)]
        completions = [match.start() for match in re.finditer(r'log "Deploy complete\."', text)]

        self.assertEqual(len(calls), len(completions))
        for call, completion in zip(calls, completions, strict=True):
            self.assertLess(completion, call)


class EachDeployMakesItsOwnRelease(unittest.TestCase):
    """Review 26-10-24, 03-06: a name already there was merged into, not refused."""

    def run_it(self, releases: Path, date: str) -> subprocess.CompletedProcess[str]:
        text = SCRIPT.read_text()
        found = re.search(r"^new_release\(\) \{.*?^\}$", text, re.S | re.M)
        assert found, "the function is no longer where the test extracts it from"
        stubs = releases.parent / "bin"
        stubs.mkdir(exist_ok=True)
        for name, body in (("date", f"echo {date}"), ("sleep", "exit 0")):
            (stubs / name).write_text(f"#!/bin/sh\n{body}\n")
            (stubs / name).chmod(0o755)
        return subprocess.run(
            [
                "/bin/bash",
                "-c",
                f'set -Eeuo pipefail\nPATH="{stubs}:$PATH"\nRELEASE_DIR="{releases}"\n'
                f"{found.group(0)}\nnew_release\n",
            ],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_a_name_already_taken_is_never_merged_into(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            releases = Path(raw) / "releases"
            made = self.run_it(releases, "20261024-120000")
            self.assertEqual(made.stdout.strip(), str(releases / "20261024-120000"))
            (releases / "20261024-120000" / "haproxy.cfg").write_text("first\n")

            again = self.run_it(releases, "20261024-120000")

            self.assertNotEqual(again.returncode, 0)
            self.assertEqual(again.stdout, "")
            self.assertEqual((releases / "20261024-120000" / "haproxy.cfg").read_text(), "first\n")


class ChmodTakesManyFilesAtOnce(unittest.TestCase):
    """R6: `-exec … +` - the same modes, without a process per file."""

    def test_release_modes_are_set_in_batches(self) -> None:
        text = SCRIPT.read_text()

        self.assertIn('find "$RELEASE" -type d -exec chmod 755 {} +', text)
        self.assertIn('find "$RELEASE" -type f -exec chmod 644 {} +', text)
        self.assertNotIn("{} \\;", text)


if __name__ == "__main__":
    unittest.main()
