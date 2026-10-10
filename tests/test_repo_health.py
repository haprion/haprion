"""Is this a usable configuration repository, and if not, why.

The layouts are the point. B10 step 6 left two of them in production - an
ordinary repository and a bare repository with a linked draft area - and added
one failure mode that reads like total loss while nothing has been lost.
"""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from haprion.repo_health import describe_problem, is_repo_root


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["/usr/bin/git", "-C", str(repo), *args], capture_output=True, text=True, check=True
    ).stdout.strip()


class LayoutFixture(unittest.TestCase):
    def ordinary(self, root: Path) -> Path:
        repo = root / "alpha"
        (repo / "core").mkdir(parents=True)
        git(repo, "init", "-q", "-b", "main")
        git(repo, "config", "user.name", "Example Maintainer")
        git(repo, "config", "user.email", "maintainer@example.com")
        (repo / "core/haproxy.cfg").write_text("global\n")
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "Initial")
        return repo

    def linked(self, root: Path) -> tuple[Path, Path]:
        history = root / "alpha.git"
        draft = root / "alpha"
        git(Path("/"), "init", "--quiet", "--bare", "--initial-branch=main", str(history))
        git(history, "config", "user.name", "Example Maintainer")
        git(history, "config", "user.email", "maintainer@example.com")
        git(history, "worktree", "add", "--quiet", "--orphan", "-b", "main", str(draft))
        (draft / "core").mkdir(parents=True)
        (draft / "core/haproxy.cfg").write_text("global\n")
        git(draft, "add", "-A")
        git(draft, "commit", "-qm", "Initial")
        return history, draft


class IsRepoRootTests(LayoutFixture):
    def test_every_accepted_layout(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            self.assertTrue(is_repo_root(self.ordinary(root / "plain")))
            history, draft = self.linked(root / "split")
            self.assertTrue(is_repo_root(history))
            self.assertTrue(is_repo_root(draft))

    def test_every_rejected_layout(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = self.ordinary(root / "plain")
            for path in (repo / "core", repo / ".git", root / "absent"):
                self.assertFalse(is_repo_root(path), path)


class DescribeProblemTests(LayoutFixture):
    def test_a_missing_directory_is_named_as_missing(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            message = describe_problem("alpha", Path(raw) / "absent")
            self.assertIn("is missing", message)

    def test_a_disconnected_draft_area_says_the_files_are_intact(self) -> None:
        """The state that reads like total loss and is not."""
        with tempfile.TemporaryDirectory() as raw:
            history, draft = self.linked(Path(raw))
            subprocess.run(["/bin/mv", str(history), str(history) + ".moved"], check=True)

            message = describe_problem("alpha", draft)
            self.assertIn("no longer connected to its saved history", message)
            self.assertIn("intact; nothing has been lost", message)
            self.assertIn(str(history), message)
            self.assertIn("worktree repair", message)
            self.assertNotIn("/worktrees/", message)
            self.assertTrue((draft / "core/haproxy.cfg").is_file())

    def test_a_subdirectory_names_the_real_root(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            repo = self.ordinary(Path(raw))
            message = describe_problem("alpha", repo / "core")
            self.assertIn("not the root", message)
            self.assertIn(str(repo), message)

    def test_an_unexplained_directory_stays_plain(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            message = describe_problem("alpha", Path(raw))
            self.assertIn("is not a usable configuration repository", message)


if __name__ == "__main__":
    unittest.main()
