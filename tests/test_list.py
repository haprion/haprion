"""Listing a cluster's versions.

Two things carry weight. The table is a frozen shape - an operator reads it by
column positions, and this is where a port would silently change them. And the
version numbers are arithmetic, not stored data: the top row is the depth of the
history and each row below is one less, so a wrong count renames every version
at once.
"""

from __future__ import annotations

import io
import os
import subprocess
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from haproxy_mgmt.cli import list as list_command

#
# Fixed commit times plus a fixed zone, so the DATE column is a constant the
# golden table can state outright instead of something the test recomputes the
# same way the code does.
#
COMMIT_TIME = "2026-01-02T03:04:05+00:00"

ENVIRONMENT = {
    "GIT_AUTHOR_NAME": "Example Maintainer",
    "GIT_AUTHOR_EMAIL": "maintainer@example.com",
    "GIT_COMMITTER_NAME": "Example Maintainer",
    "GIT_COMMITTER_EMAIL": "maintainer@example.com",
    "GIT_AUTHOR_DATE": COMMIT_TIME,
    "GIT_COMMITTER_DATE": COMMIT_TIME,
}


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["/usr/bin/git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=True,
        env={**os.environ, **ENVIRONMENT},
    ).stdout.strip()


class ListFixture(unittest.TestCase):
    def setUp(self) -> None:
        zone = mock.patch.dict(os.environ, {"TZ": "UTC"})
        zone.start()
        time.tzset()
        self.addCleanup(zone.stop)
        self.addCleanup(time.tzset)

    def repository(self, root: Path, comments: list[str]) -> Path:
        repo = root / "alpha"
        (repo / "core").mkdir(parents=True)
        git(repo, "init", "-q", "-b", "main")
        for index, comment in enumerate(comments, start=1):
            (repo / "core/haproxy.cfg").write_text(f"global\n  # version {index}\n")
            git(repo, "add", "-A")
            git(repo, "commit", "-qm", comment)
        return repo

    def run_list(self, repo: Path, *argv: str) -> tuple[int, str]:
        out = io.StringIO()
        code = list_command.main(
            list(argv) or ["-c", "alpha"],
            stream_out=out,
            config_path=lambda _cluster: repo,
        )
        return code, out.getvalue()


class TableTests(ListFixture):
    def test_the_table_keeps_the_shape_the_shell_command_printed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            repo = self.repository(Path(raw), ["Initial", "Add a backend"])
            code, shown = self.run_list(repo)

        self.assertEqual(code, 0)
        self.assertEqual(
            shown,
            "\n"
            "HAProxy configuration history - alpha\n"
            "\n"
            "VERSION   DATE              COMMENT\n"
            "-------   ----------------  ----------------------------------------\n"
            "2         2026-01-02 03:04  Add a backend\n"
            "1         2026-01-02 03:04  Initial\n"
            "\n",
        )

    def test_the_newest_ten_are_shown_and_numbered_down_from_the_total(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            repo = self.repository(Path(raw), [f"Change {step}" for step in range(1, 15)])
            code, shown = self.run_list(repo)

        rows = shown.split(list_command.RULE + "\n", 1)[1].splitlines()
        numbers = [int(row.split()[0]) for row in rows if row]
        self.assertEqual(code, 0)
        self.assertEqual(numbers, list(range(14, 4, -1)))
        self.assertIn("Change 5", shown)
        self.assertNotIn("Change 4\n", shown)

    def test_a_comment_is_shown_exactly_as_it_was_written(self) -> None:
        #
        # The shell command separated the fields with "|". A comment holding one
        # was safe there only because the last field swallowed the rest; here the
        # separator is NUL, which a comment cannot contain at all.
        #
        with tempfile.TemporaryDirectory() as raw:
            repo = self.repository(Path(raw), ["Route a|b to the new pool"])
            _, shown = self.run_list(repo)

        self.assertIn("1         2026-01-02 03:04  Route a|b to the new pool\n", shown)


class FailureTests(ListFixture):
    def test_a_path_that_is_not_a_repository_is_diagnosed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            code, shown = self.run_list(Path(raw) / "absent")

        self.assertEqual(code, 68)
        self.assertIn("the configuration directory for cluster 'alpha' is missing", shown)

    def test_an_unknown_cluster_stops_before_git_is_reached(self) -> None:
        def missing(cluster: str) -> Path:
            raise list_command.CallerError(f"unknown cluster '{cluster}'.", exit_code=64)

        out = io.StringIO()
        code = list_command.main(["-c", "gamma"], stream_out=out, config_path=missing)

        self.assertEqual(code, 64)
        self.assertEqual(out.getvalue(), "ERROR: unknown cluster 'gamma'.\n")

    def test_a_history_without_a_single_version_is_named(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            repo = Path(raw) / "alpha"
            repo.mkdir()
            git(repo, "init", "-q", "-b", "main")
            code, shown = self.run_list(repo)

        self.assertEqual(code, 65)
        self.assertEqual(shown, "ERROR: cluster 'alpha' has no versions yet.\n")

    def test_the_argument_contract_is_the_shell_command_s(self) -> None:
        #
        # Usage on stdout and exit 64, both measured against the shell command
        # before it was replaced.
        #
        for argv in ([], ["alpha"], ["-c"], ["-c", "alpha", "3"], ["--all", "alpha"]):
            shown = io.StringIO()
            with self.assertRaises(SystemExit) as raised, redirect_stdout(shown):
                list_command.main(argv, stream_out=io.StringIO())
            self.assertEqual(raised.exception.code, 64)
            self.assertEqual(shown.getvalue(), list_command.USAGE)


if __name__ == "__main__":
    unittest.main()
