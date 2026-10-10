"""Listing a cluster's versions.

Two things carry weight. The table is a frozen shape - an operator reads it by
column positions, and this is where a port would silently change them. And the
version numbers are arithmetic, not stored data: the top row is the depth of the
history and each row below is one less, so a wrong count renames every version
at once.
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from haprion.cli import list as list_command
from haprion.cli.caller import CallerError

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

    def run_list(self, repo: Path, *argv: str, published: str | None = None) -> tuple[int, str]:
        out = io.StringIO()
        fields = {"publish_path": str(self.publish_root(repo, published)), "node_path": "internal"}
        code = list_command.main(
            list(argv) or ["-c", "alpha"],
            stream_out=out,
            config_path=lambda _cluster: repo,
            field=lambda _cluster, name: fields[name],
        )
        return code, out.getvalue()

    def publish_root(self, repo: Path, published: str | None) -> Path:
        """A RELEASE stamp beside the repository, written only when asked for."""

        root = repo.parent / "published"
        if published is not None:
            release = root / "current" / "internal"
            release.mkdir(parents=True, exist_ok=True)
            version = git(repo, "rev-list", "--first-parent", "--count", published)
            (release / "RELEASE").write_text(
                f"schema=1\ncluster=alpha\nversion={version}\nhash={published}\n",
                encoding="utf-8",
            )
        return root


class TableTests(ListFixture):
    def test_the_table_keeps_the_shell_commands_shape_plus_who_asked(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            repo = self.repository(Path(raw), ["Initial", "Add a backend"])
            code, shown = self.run_list(repo)

        self.assertEqual(code, 0)
        self.assertEqual(
            shown,
            "\n"
            "HAProxy configuration history - alpha\n"
            "\n"
            "VERSION   DATE              BY                COMMENT\n"
            "-------   ----------------  ----------------  ----------------------------------------\n"
            "2         2026-01-02 03:04  -                 Add a backend\n"
            "1         2026-01-02 03:04  -                 Initial\n"
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

        self.assertIn(
            "1         2026-01-02 03:04  -                 Route a|b to the new pool\n", shown
        )


class FailureTests(ListFixture):
    def test_a_path_that_is_not_a_repository_is_diagnosed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            code, shown = self.run_list(Path(raw) / "absent")

        self.assertEqual(code, 68)
        self.assertIn("the configuration directory for cluster 'alpha' is missing", shown)

    def test_an_unknown_cluster_stops_before_git_is_reached(self) -> None:
        def missing(cluster: str) -> Path:
            raise CallerError(f"unknown cluster '{cluster}'.", exit_code=64)

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


class DiffTests(ListFixture):
    """`--diff <version>`: what one version changed, as the Versions page shows it."""

    def test_a_version_is_shown_against_the_one_before_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = self.repository(Path(directory), ["Initial", "Add a backend"])
            code, out = self.run_list(repo, "-c", "alpha", "--diff", "2")
            first_code, first = self.run_list(repo, "-c", "alpha", "--diff", "1")
            missing_code, missing = self.run_list(repo, "-c", "alpha", "--diff", "9")

        self.assertEqual(code, 0)
        self.assertIn("=== core/haproxy.cfg (modified, +1 -1)", out)
        self.assertIn("-  # version 1", out)
        self.assertIn("+  # version 2", out)
        self.assertEqual(first_code, 0)
        self.assertIn("=== core/haproxy.cfg (added, +2 -0)", first)
        self.assertEqual(missing_code, 65)
        self.assertIn("has no version 9", missing)

    def test_the_version_is_a_number(self) -> None:
        for argv in (
            ["-c", "alpha", "--diff", "v2"],
            ["-c", "alpha", "--diff", "-1"],
            ["-c", "alpha", "--json", "2"],
        ):
            with (
                self.subTest(argv=argv),
                self.assertRaises(SystemExit) as raised,
                redirect_stdout(io.StringIO()),
            ):
                list_command.main(argv, stream_out=io.StringIO())
            self.assertEqual(raised.exception.code, 64)


class JsonTests(ListFixture):
    """`--json` is the same reading as the table, in the frozen envelope."""

    def test_it_marks_the_published_version_and_counts_what_waits(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            repo = self.repository(Path(raw), ["Initial", "Add a backend", "Tune timeouts"])
            second = git(repo, "rev-parse", "HEAD~1")
            code, shown = self.run_list(repo, "-c", "alpha", "--json", published=second)

        document = json.loads(shown)
        self.assertEqual(code, 0)
        self.assertEqual(document["operation"], "list")
        self.assertEqual(document["outcome"], "done")
        self.assertEqual(document["cluster"], "alpha")
        self.assertEqual(document["result"]["published_version"], 2)
        self.assertEqual(document["result"]["unpublished"], 1)
        self.assertEqual([row["version"] for row in document["result"]["versions"]], [3, 2, 1])
        self.assertEqual(
            [row["current"] for row in document["result"]["versions"]], [True, False, False]
        )
        self.assertEqual(document["result"]["current_version"], 3)
        self.assertEqual(document["result"]["total_versions"], 3)

    def test_the_json_reading_agrees_with_the_table_row_for_row(self) -> None:
        #
        # The two modes read the repository once each. This is the check that
        # they still describe the same versions, which is the whole reason the
        # result is built in one place.
        #
        with tempfile.TemporaryDirectory() as raw:
            repo = self.repository(Path(raw), ["Initial", "Add a backend"])
            _, table = self.run_list(repo)
            _, shown = self.run_list(repo, "-c", "alpha", "--json")

        rows = json.loads(shown)["result"]["versions"]
        #
        # The JSON carries the contract's timestamp and the table the operator's
        # minute-resolution one, so the versions and comments are what can be
        # compared directly - and they are what would drift.
        #
        printed = table.split(list_command.RULE + "\n", 1)[1]
        self.assertEqual([row["version"] for row in rows], [2, 1])
        for row in rows:
            self.assertIn(f"{row['version']:<9} ", printed)
            self.assertIn(row["comment"], printed)

    def test_an_unpublished_cluster_is_a_result_rather_than_a_failure(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            repo = self.repository(Path(raw), ["Initial"])
            code, shown = self.run_list(repo, "-c", "alpha", "--json")

        result = json.loads(shown)["result"]
        self.assertEqual(code, 0)
        self.assertIsNone(result["published_version"])
        self.assertEqual(result["unpublished"], 1)

    def test_a_history_without_a_version_is_an_empty_listing_not_an_error(self) -> None:
        #
        # The table names the repair for a person; a reader parsing JSON gets
        # the same fact as an empty list. Failing here would make a new cluster
        # look like an unreadable one.
        #
        with tempfile.TemporaryDirectory() as raw:
            repo = self.repository(Path(raw), [])
            code, shown = self.run_list(repo, "-c", "alpha", "--json")

        document = json.loads(shown)
        self.assertEqual(code, 0)
        self.assertEqual(document["outcome"], "done")
        self.assertEqual(document["result"]["versions"], [])

    def test_a_path_that_is_not_a_repository_is_a_failed_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            missing = Path(raw) / "alpha"
            missing.mkdir()
            code, shown = self.run_list(missing, "-c", "alpha", "--json")

        document = json.loads(shown)
        self.assertEqual(code, 68)
        self.assertEqual(document["outcome"], "failed")
        self.assertEqual(document["error"]["code"], "history_unavailable")
        self.assertFalse(document["ok"])

    def test_json_is_not_accepted_in_place_of_the_cluster_flag(self) -> None:
        with self.assertRaises(SystemExit) as raised:
            list_command.main(["--json", "alpha"])
        self.assertEqual(raised.exception.code, 64)


if __name__ == "__main__":
    unittest.main()
