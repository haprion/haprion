"""Starting a cluster's version history over.

The cases that matter are the ones where something goes wrong: the operation is
deliberate and rare, so what it does on the happy path is easy to check by hand -
what nobody will check by hand is that a failure leaves the cluster exactly as it
was.
"""

from __future__ import annotations

import os
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from haproxy_mgmt import history_reset
from haproxy_mgmt.git_command import GitError
from haproxy_mgmt.history_reset import (
    ResetError,
    history_path,
    preview,
    reset_history,
)

HAPROXY_CFG = b"global\n  daemon\ndefaults\n  mode http\n"


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["/usr/bin/git", "-C", str(repo), *args], capture_output=True, text=True, check=True
    ).stdout.strip()


class Recorder:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def __call__(self, path: Path, uid: int, gid: int) -> None:
        self.calls.append(str(path))


class ResetFixture(unittest.TestCase):
    """Builds the layout the clusters actually use: bare history, linked draft."""

    def layout(self, root: Path, versions: int = 3) -> Path:
        seed = root / "seed"
        seed.mkdir()
        git(seed, "init", "-q", "-b", "main")
        git(seed, "config", "user.name", "Example Maintainer")
        git(seed, "config", "user.email", "maintainer@example.com")
        (seed / "core").mkdir()
        (seed / "manual").mkdir()
        (seed / "manual" / "reservations.yaml").write_bytes(b"{}\n")
        (seed / ".gitignore").write_bytes(b"*.swp\n")
        for number in range(versions):
            (seed / "core" / "haproxy.cfg").write_bytes(HAPROXY_CFG + f"# {number}\n".encode())
            git(seed, "add", "-A")
            git(seed, "commit", "-qm", f"Version {number + 1}")

        history = root / "alpha.git"
        subprocess.run(
            ["/usr/bin/git", "clone", "-q", "--bare", str(seed), str(history)],
            check=True,
            capture_output=True,
        )
        git(history, "config", "user.name", "Example Maintainer")
        git(history, "config", "user.email", "maintainer@example.com")
        draft = root / "alpha"
        git(history, "worktree", "add", "-q", str(draft), "main")
        return draft

    def reset(self, draft: Path, recorder: Recorder, **overrides: object):
        arguments: dict[str, object] = {
            "stamp": "20260901-120000",
            "message": "Baseline after the build phase",
            "group_id": os.getgid(),
            "change_owner": recorder,
        }
        arguments.update(overrides)
        return reset_history(preview("alpha", draft), **arguments)  # type: ignore[arg-type]


class PreviewTests(ResetFixture):
    def test_it_reports_what_would_be_discarded(self) -> None:
        with TemporaryDirectory() as raw:
            draft = self.layout(Path(raw), versions=5)
            plan = preview("alpha", draft)
            self.assertEqual(plan.versions, 5)
            self.assertEqual(plan.commit, git(draft, "rev-parse", "HEAD"))

    def test_unpublished_work_is_refused(self) -> None:
        """Whatever is on disk becomes version 1, so it must have been reviewed."""
        with TemporaryDirectory() as raw:
            draft = self.layout(Path(raw))
            (draft / "core" / "haproxy.cfg").write_bytes(HAPROXY_CFG + b"# unsaved\n")
            with self.assertRaises(ResetError) as caught:
                preview("alpha", draft)
            self.assertIn("not published", str(caught.exception))

    def test_nothing_is_touched_by_previewing(self) -> None:
        with TemporaryDirectory() as raw:
            draft = self.layout(Path(raw))
            before = git(draft, "rev-parse", "HEAD")
            preview("alpha", draft)
            self.assertEqual(git(draft, "rev-parse", "HEAD"), before)
            self.assertTrue(history_path(draft).is_dir())


class ResetTests(ResetFixture):
    def test_the_history_starts_at_one(self) -> None:
        with TemporaryDirectory() as raw:
            draft = self.layout(Path(raw), versions=5)
            result = self.reset(draft, Recorder())
            self.assertEqual(git(draft, "rev-list", "--first-parent", "--count", "HEAD"), "1")
            self.assertEqual(result.versions_discarded, 5)

    def test_the_configuration_is_unchanged(self) -> None:
        with TemporaryDirectory() as raw:
            draft = self.layout(Path(raw))
            before = (draft / "core" / "haproxy.cfg").read_bytes()
            self.reset(draft, Recorder())
            self.assertEqual((draft / "core" / "haproxy.cfg").read_bytes(), before)
            self.assertEqual((draft / ".gitignore").read_bytes(), b"*.swp\n")

    def test_the_old_history_is_unreachable_but_archived(self) -> None:
        with TemporaryDirectory() as raw:
            draft = self.layout(Path(raw))
            plan = preview("alpha", draft)
            result = self.reset(draft, Recorder())
            self.assertTrue(result.archived_history.is_dir())
            self.assertEqual(
                git(result.archived_history, "rev-list", "--first-parent", "--count", "main"), "3"
            )
            probe = subprocess.run(
                ["/usr/bin/git", "-C", str(draft), "cat-file", "-e", plan.commit],
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(probe.returncode, 0, "the old history is still reachable")

    def test_the_layout_is_the_one_the_clusters_use(self) -> None:
        with TemporaryDirectory() as raw:
            draft = self.layout(Path(raw))
            self.reset(draft, Recorder())
            history = history_path(draft)
            self.assertEqual(git(history, "rev-parse", "--is-bare-repository"), "true")
            self.assertIn(str(draft), git(history, "worktree", "list"))
            self.assertTrue((draft / ".git").is_file())

    def test_the_identity_is_carried_over(self) -> None:
        with TemporaryDirectory() as raw:
            draft = self.layout(Path(raw))
            self.reset(draft, Recorder())
            self.assertEqual(
                git(draft, "log", "-1", "--pretty=%an <%ae>"),
                "Example Maintainer <maintainer@example.com>",
            )

    def test_ownership_is_applied_to_both_trees(self) -> None:
        with TemporaryDirectory() as raw:
            draft = self.layout(Path(raw))
            recorder = Recorder()
            self.reset(draft, recorder)
            self.assertIn(str(draft), recorder.calls)
            self.assertIn(str(history_path(draft)), recorder.calls)
            self.assertIn(str(draft / "core" / "haproxy.cfg"), recorder.calls)


class FailureTests(ResetFixture):
    def test_a_failure_puts_the_cluster_back(self) -> None:
        """The one state nobody could reason about later is a half finished reset."""
        with TemporaryDirectory() as raw:
            draft = self.layout(Path(raw))
            before_head = git(draft, "rev-parse", "HEAD")
            before_versions = git(draft, "rev-list", "--first-parent", "--count", "HEAD")
            real = history_reset.git

            def fail_on_commit(repo: Path, *args: str, **kwargs: object) -> bytes:
                if args and args[0] == "commit":
                    raise GitError("git commit failed: interrupted")
                return real(repo, *args, **kwargs)  # type: ignore[arg-type]

            with (
                patch.object(history_reset, "git", fail_on_commit),
                self.assertRaises(GitError),
            ):
                self.reset(draft, Recorder())

            self.assertEqual(git(draft, "rev-parse", "HEAD"), before_head)
            self.assertEqual(
                git(draft, "rev-list", "--first-parent", "--count", "HEAD"), before_versions
            )
            self.assertTrue(history_path(draft).is_dir())
            self.assertFalse(list(draft.parent.glob("*.pre-reset-*")), "an archive was left behind")

    def test_an_existing_archive_is_refused(self) -> None:
        with TemporaryDirectory() as raw:
            draft = self.layout(Path(raw))
            (draft.parent / "alpha.git.pre-reset-20260901-120000").mkdir()
            with self.assertRaises(ResetError) as caught:
                self.reset(draft, Recorder())
            self.assertIn("already exists", str(caught.exception))

    def test_a_missing_history_is_refused(self) -> None:
        with TemporaryDirectory() as raw:
            draft = self.layout(Path(raw))
            os.rename(history_path(draft), draft.parent / "moved-away.git")
            with self.assertRaises(ResetError):
                preview("alpha", draft)


if __name__ == "__main__":
    unittest.main()
