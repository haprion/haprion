"""The status command, and the states production does not usually show.

Two clusters in ordinary shape prove almost nothing here: they are clean and
published, which is one branch out of several. The cases that carry weight are
the ones a person hits on a bad day - a published version that is not the last
saved one, a root helper that cannot be reached, files waiting under two
different owners - and those are built here rather than waited for.
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any
from unittest import mock

from haprion import regeneration
from haprion.cli import config_status
from tests.contract_schema import assert_contract

COMMIT_TIME = "2026-01-02T03:04:05+00:00"

ENVIRONMENT = {
    "GIT_AUTHOR_NAME": "Example Maintainer",
    "GIT_AUTHOR_EMAIL": "maintainer@example.com",
    "GIT_COMMITTER_NAME": "Example Maintainer",
    "GIT_COMMITTER_EMAIL": "maintainer@example.com",
    "GIT_AUTHOR_DATE": COMMIT_TIME,
    "GIT_COMMITTER_DATE": COMMIT_TIME,
}

HEADER = "\nConfiguration - alpha\n\n"
NOTHING_DIFFERS = {"outcome": "unchanged"}


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["/usr/bin/git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=True,
        env={**os.environ, **ENVIRONMENT},
    ).stdout.strip()


def stamp(cluster: str, version: int, commit: str) -> str:
    """A RELEASE stamp in the shape `render_release_file` writes."""

    return (
        f"schema=1\ncluster={cluster}\nversion={version}\n"
        f"hash={commit}\ntimestamp=2026-01-02T03:04:05+00:00\n"
    )


class StatusFixture(unittest.TestCase):
    def setUp(self) -> None:
        zone = mock.patch.dict(os.environ, {"TZ": "UTC"})
        zone.start()
        time.tzset()
        self.addCleanup(zone.stop)
        self.addCleanup(time.tzset)

        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.repo = Path(self.directory.name) / "alpha"
        for layer in ("core", "manual", "managed"):
            (self.repo / layer).mkdir(parents=True)
        git(self.repo, "init", "-q", "-b", "main")
        (self.repo / "core/haproxy.cfg").write_text("global\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "Initial")
        self.commit = git(self.repo, "rev-parse", "HEAD")

    def run_status(
        self,
        *argv: str,
        published: str | None = None,
        regeneration: dict[str, Any] | None = NOTHING_DIFFERS,
    ) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        code = config_status.main(
            list(argv) or ["-c", "alpha"],
            stream_out=out,
            stream_err=err,
            config_path=lambda _cluster: self.repo,
            read_published=lambda _cluster: published,
            read_regeneration=lambda _cluster: regeneration,
        )
        return code, out.getvalue(), err.getvalue()


class PublishedStateTests(StatusFixture):
    def test_a_clean_cluster_on_the_published_version(self) -> None:
        code, shown, _ = self.run_status(published=stamp("alpha", 1, self.commit))

        self.assertEqual(code, 0)
        self.assertEqual(
            shown,
            HEADER + "  Published version:  1\n"
            "  Last saved:         1   2026-01-02 03:04   Initial\n"
            "\n"
            "  Nothing unsent. Everything you have changed is published.\n"
            "\n",
        )

    def test_a_saved_version_that_was_never_published_warns(self) -> None:
        (self.repo / "core/haproxy.cfg").write_text("global\n  daemon\n")
        git(self.repo, "commit", "-qam", "Run as a daemon")

        _, shown, _ = self.run_status(published=stamp("alpha", 1, self.commit))

        self.assertIn("  Published version:  1\n", shown)
        self.assertIn("  Last saved:         2   ", shown)
        self.assertIn(
            "\n  WARNING: the most recently saved version is not the published one.\n"
            "  The nodes cannot receive version 2 until it is published again.\n",
            shown,
        )

    def test_nothing_published_yet_is_named_and_never_warns(self) -> None:
        #
        # No warning here even though the saved version is plainly not published:
        # there is no published version to compare against, and a warning about a
        # mismatch nobody can act on is noise.
        #
        _, shown, _ = self.run_status(published="state=unpublished\n")

        self.assertIn("  Published version:  nothing published yet\n", shown)
        self.assertNotIn("WARNING", shown)

    def test_an_unreachable_helper_still_reports_the_draft_state(self) -> None:
        #
        # The whole point of the split: the privileged half may fail without
        # taking the command with it. Permissions being broken is exactly when
        # someone needs the other half of the answer.
        #
        code, shown, _ = self.run_status(published=None)

        self.assertEqual(code, 0)
        self.assertIn(
            "  Published version:  could not be read (missing permission or helper)\n", shown
        )
        self.assertIn("  Last saved:         1   ", shown)
        self.assertNotIn("WARNING", shown)

    def test_a_stamp_without_a_version_reads_as_unknown_and_never_warns(self) -> None:
        _, shown, _ = self.run_status(published="schema=1\ncluster=alpha\n")

        self.assertIn("  Published version:  unknown\n", shown)
        self.assertNotIn("WARNING", shown)


def changed_regeneration() -> dict[str, Any]:
    diff = regeneration.artifact_diff(
        {"conf.d/1001-shop.cfg": b"backend shop\n  balance roundrobin\n"},
        {"conf.d/1001-shop.cfg": b"backend shop\n  balance leastconn\n"},
        "c" * 40,
    )
    return {
        "outcome": "changed",
        "files_changed": 1,
        "objects": [{"name": "shop", "change": "changed", "parts": ["backends", "routing"]}],
        "diff": diff.as_dict(),
    }


class RegenerationTests(StatusFixture):
    def test_a_publish_that_would_change_what_runs_is_said_in_one_line(self) -> None:
        _, shown, _ = self.run_status(
            published=stamp("alpha", 1, self.commit), regeneration=changed_regeneration()
        )

        self.assertIn(
            "\n  Publish and deploy to apply the update: 1 file differs; objects: shop (backends, routing)\n"
            "  Publish it with: haprion-publish -c alpha --regenerate (",
            shown,
        )
        self.assertIn(
            "may still refuse)\n  Then deploy it with: haprion-deploy -c alpha\n\n", shown
        )
        self.assertNotIn("balance leastconn", shown)

    def test_diff_prints_the_difference(self) -> None:
        _, shown, _ = self.run_status(
            "-c",
            "alpha",
            "--diff",
            published=stamp("alpha", 1, self.commit),
            regeneration=changed_regeneration(),
        )

        self.assertIn("=== conf.d/1001-shop.cfg (modified, +1 -1)\n", shown)
        self.assertIn("-  balance roundrobin\n+  balance leastconn\n", shown)

    def test_a_refusal_is_said_with_its_reason(self) -> None:
        _, shown, _ = self.run_status(
            published=stamp("alpha", 1, self.commit),
            regeneration={"outcome": "refused", "message": "shop: no longer accepted"},
        )

        self.assertIn(
            "  The installed version cannot publish this configuration again: "
            "shop: no longer accepted\n",
            shown,
        )

    def test_nothing_is_said_when_nothing_would_change(self) -> None:
        for answer in ({"outcome": "unchanged", "diff": None}, {"outcome": "unpublished"}):
            with self.subTest(answer=answer):
                _, shown, _ = self.run_status(
                    "-c",
                    "alpha",
                    "--diff",
                    published=stamp("alpha", 1, self.commit),
                    regeneration=answer,
                )
                self.assertNotIn("publish", shown.split("Nothing unsent")[0])

    def test_a_reading_that_is_missing_is_said_and_not_taken_for_nothing(self) -> None:
        _, shown, _ = self.run_status(published=stamp("alpha", 1, self.commit), regeneration=None)
        self.assertIn(
            "  Whether a publish would change what runs: could not be read "
            "(missing permission or helper)\n",
            shown,
        )

        _, shown, _ = self.run_status(
            published=stamp("alpha", 1, self.commit),
            regeneration={"outcome": "unreadable", "message": "the commit is missing"},
        )
        self.assertIn(
            "  Whether a publish would change what runs: could not be read: the commit is missing\n",
            shown,
        )

    def test_nothing_is_asked_when_nothing_is_published(self) -> None:
        asked: list[str] = []

        def read(cluster: str) -> None:
            asked.append(cluster)

        config_status.main(
            ["-c", "alpha"],
            stream_out=io.StringIO(),
            config_path=lambda _cluster: self.repo,
            read_published=lambda _cluster: "state=unpublished\n",
            read_regeneration=read,
        )
        self.assertEqual(asked, [])

    def test_the_helper_is_asked_with_sudo_n_and_a_failure_is_nothing(self) -> None:
        answer = json.dumps({"result": {"outcome": "changed", "files_changed": 2}})
        with mock.patch.object(
            subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 0, stdout=answer, stderr=""),
        ) as run:
            found = config_status.ask_regeneration("alpha")

        self.assertEqual(
            run.call_args.args[0], ["/usr/bin/sudo", "-n", config_status.REGENERATION_HELPER]
        )
        self.assertEqual(json.loads(run.call_args.kwargs["input"])["cluster"], "alpha")
        self.assertEqual(found, {"outcome": "changed", "files_changed": 2})
        for completed in (
            subprocess.CompletedProcess([], 1, stdout="", stderr=""),
            subprocess.CompletedProcess([], 0, stdout="not json", stderr=""),
        ):
            with mock.patch.object(subprocess, "run", return_value=completed):
                self.assertIsNone(config_status.ask_regeneration("alpha"))
        refused = json.dumps(
            {"error": {"code": "regeneration_unavailable", "message": "no commit"}}
        )
        with mock.patch.object(
            subprocess, "run", return_value=subprocess.CompletedProcess([], 69, stdout=refused)
        ):
            self.assertEqual(
                config_status.ask_regeneration("alpha"),
                {"outcome": "unreadable", "message": "no commit"},
            )

    def test_the_helper_is_the_one_in_the_release(self) -> None:
        self.assertEqual(
            config_status.REGENERATION_HELPER,
            "/opt/haprion/current/bin/haprion-regeneration-helper",
        )


class WaitingChangeTests(StatusFixture):
    def test_the_three_kinds_are_named_the_way_the_shell_command_named_them(self) -> None:
        (self.repo / "manual/extra.cfg").write_text("# new\n")
        (self.repo / "core/haproxy.cfg").write_text("global\n  daemon\n")
        (self.repo / "core/gone.cfg").write_text("# doomed\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "Add a file to delete later")
        (self.repo / "core/gone.cfg").unlink()
        (self.repo / "manual/extra.cfg").write_text("# new\n")

        _, shown, _ = self.run_status(published=stamp("alpha", 2, self.commit))

        self.assertIn("  Unsent - changes that have not become a version yet:\n", shown)
        self.assertIn(f"    {'core/gone.cfg':<40} deleted\n", shown)
        self.assertIn('    haprion-publish -c alpha "<comment>"\n', shown)

    def test_a_new_directory_is_listed_file_by_file(self) -> None:
        #
        # Without --untracked-files=all git collapses this into one line naming
        # the directory, and the operator cannot see what is actually waiting.
        #
        (self.repo / "manual/conf.d").mkdir()
        (self.repo / "manual/conf.d/0071-one.cfg").write_text("# one\n")
        (self.repo / "manual/conf.d/0072-two.cfg").write_text("# two\n")

        _, shown, _ = self.run_status(published=stamp("alpha", 1, self.commit))

        self.assertIn(f"    {'manual/conf.d/0071-one.cfg':<40} new\n", shown)
        self.assertIn(f"    {'manual/conf.d/0072-two.cfg':<40} new\n", shown)
        self.assertNotIn("manual/conf.d/ ", shown)

    def test_interface_owned_changes_are_reported_separately(self) -> None:
        #
        # managed/ is written by the interface and is not published from here, so
        # it must not appear in the list someone is about to publish.
        #
        (self.repo / "managed/generated.cfg").write_text("# generated\n")

        _, shown, _ = self.run_status(published=stamp("alpha", 1, self.commit))

        self.assertIn("  Nothing unsent. Everything you have changed is published.\n", shown)
        self.assertIn(
            "  Changes owned by the interface, which are not published from here:\n", shown
        )
        self.assertIn(f"    {'managed/generated.cfg':<40} new\n", shown)

    def test_both_owners_can_have_changes_at_once(self) -> None:
        (self.repo / "manual/extra.cfg").write_text("# mine\n")
        (self.repo / "managed/generated.cfg").write_text("# generated\n")

        _, shown, _ = self.run_status(published=stamp("alpha", 1, self.commit))

        waiting = shown.index("  Unsent - changes")
        interface = shown.index("  Changes owned by the interface")
        self.assertLess(waiting, interface)
        self.assertNotIn("managed/generated.cfg", shown[waiting:interface])


class JsonTests(StatusFixture):
    """K12: the command answers in a contract when asked, like the rest."""

    def test_a_clean_cluster_is_one_document(self) -> None:
        code, shown, _ = self.run_status(
            "-c", "alpha", "--json", published=stamp("alpha", 1, self.commit)
        )

        answer = assert_contract("haprion-config-status", shown)
        self.assertEqual(code, 0)
        self.assertEqual(
            answer["result"],
            {
                "published": {"state": "published", "version": "1"},
                "saved": {"version": "1", "date": "2026-01-02 03:04", "comment": "Initial"},
                "saved_is_published": True,
                "regeneration": {"outcome": "unchanged"},
                "unsent": [],
                "interface_owned": [],
            },
        )

    def test_unsent_changes_and_a_saved_version_not_published_are_in_it(self) -> None:
        (self.repo / "core/haproxy.cfg").write_text("global\n  daemon\n")
        git(self.repo, "commit", "-qam", "Run as a daemon")
        (self.repo / "manual/extra.cfg").write_text("x\n")
        (self.repo / "managed/a.yaml").write_text("x: 1\n")

        _, shown, _ = self.run_status(
            "-c", "alpha", "--json", published=stamp("alpha", 1, self.commit)
        )

        result = assert_contract("haprion-config-status", shown)["result"]
        self.assertFalse(result["saved_is_published"])
        self.assertEqual([entry["path"] for entry in result["unsent"]], ["manual/extra.cfg"])
        self.assertEqual([entry["path"] for entry in result["interface_owned"]], ["managed/a.yaml"])

    def test_nothing_published_and_an_unreadable_reading_are_said(self) -> None:
        _, shown, _ = self.run_status(
            "-c", "alpha", "--json", published="schema=1\nstate=unpublished\n", regeneration=None
        )
        result = assert_contract("haprion-config-status", shown)["result"]
        self.assertEqual(result["published"], {"state": "unpublished", "version": None})
        self.assertIsNone(result["saved_is_published"])
        self.assertEqual(result["regeneration"], {"outcome": "unknown"})

    def test_a_path_that_is_not_a_repository_is_a_document(self) -> None:
        out, err = io.StringIO(), io.StringIO()
        code = config_status.main(
            ["-c", "alpha", "--json"],
            stream_out=out,
            stream_err=err,
            config_path=lambda _cluster: Path(self.directory.name) / "nowhere",
        )

        answer = assert_contract("haprion-config-status", out.getvalue())
        self.assertEqual((code, answer["error"]["code"]), (68, "dependency_unavailable"))
        self.assertNotEqual(err.getvalue(), "")


class FailureTests(StatusFixture):
    def test_a_path_that_is_not_a_repository_is_diagnosed_on_stderr(self) -> None:
        out, err = io.StringIO(), io.StringIO()
        code = config_status.main(
            ["-c", "alpha"],
            stream_out=out,
            stream_err=err,
            config_path=lambda _cluster: Path(self.directory.name) / "absent",
            read_published=lambda _cluster: None,
            read_regeneration=lambda _cluster: None,
        )

        self.assertEqual(code, 68)
        self.assertEqual(out.getvalue(), "")
        self.assertIn("the configuration directory for cluster 'alpha' is missing", err.getvalue())

    def test_the_argument_contract_is_the_shell_command_s(self) -> None:
        for argv in ([], ["alpha"], ["-c"], ["-c", "alpha", "extra"], ["-x", "alpha"]):
            shown, said = io.StringIO(), io.StringIO()
            with (
                self.assertRaises(SystemExit) as raised,
                redirect_stdout(shown),
                redirect_stderr(said),
            ):
                config_status.main(argv, stream_out=io.StringIO())
            self.assertEqual(raised.exception.code, 64)
            self.assertEqual(shown.getvalue(), "")
            self.assertEqual(said.getvalue(), config_status.USAGE)


if __name__ == "__main__":
    unittest.main()
