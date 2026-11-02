from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from haprion.git_command import _closed, git, git_bounded, trusted

REPO = Path("/srv/haprion/config/alpha")


class GitTrustsWhatRootOwns(unittest.TestCase):
    """26-11-02: a member of the configuration group reads root's repositories."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name) / "alpha"
        self.common = Path(self.tmp.name) / "alpha.git"
        self.linked = self.common / "worktrees" / "alpha"
        self.linked.mkdir(parents=True)
        self.repo.mkdir()
        (self.linked / "commondir").write_text("../..\n")
        (self.repo / ".git").write_text(f"gitdir: {self.linked}\n")

    def trust(self, *, caller: int = 1000, closed: set[Path] | None = None) -> list[str]:
        everything = {self.repo, self.repo / ".git", self.linked, self.linked / "../.."}
        allowed = everything if closed is None else closed
        with (
            mock.patch("haprion.git_command.os.geteuid", return_value=caller),
            mock.patch("haprion.git_command._closed", side_effect=lambda path: path in allowed),
        ):
            return trusted(self.repo)

    def test_a_reader_trusts_one_repository_root_owns_by_its_exact_path(self) -> None:
        self.assertEqual(self.trust(), ["-c", f"safe.directory={self.repo}"])

    def test_a_work_tree_root_owns_with_a_git_directory_it_does_not_is_not_trusted(self) -> None:
        self.assertEqual(self.trust(closed={self.repo, self.repo / ".git"}), [])

    def test_the_common_directory_counts_too(self) -> None:
        self.assertEqual(self.trust(closed={self.repo, self.repo / ".git", self.linked}), [])

    def test_a_work_tree_another_account_owns_is_never_trusted(self) -> None:
        self.assertEqual(self.trust(closed=set()), [])

    def test_root_keeps_its_own_configuration(self) -> None:
        self.assertEqual(self.trust(caller=0), [])

    def test_a_path_that_is_not_there_is_left_to_git(self) -> None:
        with mock.patch("haprion.git_command.os.geteuid", return_value=1000):
            self.assertEqual(trusted(Path(self.tmp.name) / "missing"), [])


class WhatClosedMeans(unittest.TestCase):
    def closed(self, uid: int, mode: int) -> bool:
        status = SimpleNamespace(st_uid=uid, st_mode=mode)
        with mock.patch.object(Path, "stat", return_value=status):
            return _closed(REPO)

    def test_root_owned_and_not_writable_by_others(self) -> None:
        self.assertTrue(self.closed(0, 0o40750))

    def test_a_group_or_world_writable_directory_is_not_closed(self) -> None:
        self.assertFalse(self.closed(0, 0o40770))
        self.assertFalse(self.closed(0, 0o41777))

    def test_another_owner_is_not_closed(self) -> None:
        self.assertFalse(self.closed(1001, 0o40750))


class GitRunsWithoutTheCallersGitSettings(unittest.TestCase):
    """The caller's GIT_* and personal ignore file must not steer what is read."""

    def run_git(self, **extra: object) -> mock.Mock:
        completed = SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        with (
            mock.patch.dict(
                "os.environ", {"GIT_DIR": "/elsewhere", "GIT_WORK_TREE": "/x", "HOME": "/h"}
            ),
            mock.patch("haprion.git_command.trusted", return_value=["-c", "safe.directory=/r"]),
            mock.patch("haprion.git_command.subprocess.run", return_value=completed) as run,
        ):
            git(REPO, "status", **extra)  # type: ignore[arg-type]
        return run

    def test_git_drops_inherited_git_variables_and_keeps_the_rest(self) -> None:
        env = self.run_git().call_args.kwargs["env"]
        self.assertNotIn("GIT_DIR", env)
        self.assertNotIn("GIT_WORK_TREE", env)
        self.assertEqual(env["HOME"], "/h")

    def test_an_env_the_caller_passes_wins(self) -> None:
        env = self.run_git(env={"GIT_INDEX_FILE": "/tmp/i"}).call_args.kwargs["env"]
        self.assertEqual(env, {"GIT_INDEX_FILE": "/tmp/i"})

    def test_git_puts_the_trust_and_no_personal_ignore_before_dash_c(self) -> None:
        argv = self.run_git().call_args.args[0]
        self.assertEqual(
            argv[1:7],
            ["-c", "safe.directory=/r", "-c", "core.excludesFile=/dev/null", "-C", str(REPO)],
        )

    def test_git_bounded_does_the_same(self) -> None:
        process = mock.MagicMock()
        process.__enter__.return_value = process
        process.stdout.read.return_value = b"x"
        process.stderr.read.return_value = b""
        process.wait.return_value = 0
        with (
            mock.patch.dict("os.environ", {"GIT_DIR": "/elsewhere"}),
            mock.patch("haprion.git_command.trusted", return_value=["-c", "safe.directory=/r"]),
            mock.patch("haprion.git_command.subprocess.Popen", return_value=process) as popen,
        ):
            git_bounded(REPO, "diff", limit=10)
        argv = popen.call_args.args[0]
        self.assertEqual(
            argv[1:7],
            ["-c", "safe.directory=/r", "-c", "core.excludesFile=/dev/null", "-C", str(REPO)],
        )
        self.assertNotIn("GIT_DIR", popen.call_args.kwargs["env"])


if __name__ == "__main__":
    unittest.main()
