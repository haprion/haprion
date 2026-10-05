"""What one version changed, read from a real repository."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from haproxy_mgmt import version_diff
from haproxy_mgmt.git_command import git_bounded
from haproxy_mgmt.version_diff import render
from tests.test_list_helper import git


class WhatAVersionChanged(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.repo = Path(directory.name)
        git(self.repo, "init", "--quiet", "--initial-branch=main")

    def commit(self, files: dict[str, str | None], message: str = "change") -> str:
        for name, content in files.items():
            path = self.repo / name
            if content is None:
                path.unlink()
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        git(self.repo, "add", "--all")
        git(self.repo, "commit", "--quiet", "-m", message)
        return git(self.repo, "rev-parse", "HEAD")

    def test_the_first_version_is_everything_it_holds(self) -> None:
        first = self.commit({"managed/objects/app.yaml": "name: app\nport: 80\n"})

        found = version_diff.version_diff(self.repo, first)

        self.assertIsNone(found.parent)
        [change] = found.files
        self.assertEqual(
            (change.path, change.status, change.added, change.removed),
            ("managed/objects/app.yaml", "added", 2, 0),
        )
        self.assertEqual(change.lines[0][:2], "@@")

    def test_a_later_version_is_compared_with_the_one_before_it(self) -> None:
        self.commit({"a.yaml": "port: 80\n", "gone.cfg": "x\n", "old name.cfg": "same\n" * 5})
        parent = git(self.repo, "rev-parse", "HEAD")
        second = self.commit(
            {
                "a.yaml": "port: 8080\n",
                "gone.cfg": None,
                "old name.cfg": None,
                "new name.cfg": "same\n" * 5,
            }
        )

        found = version_diff.version_diff(self.repo, second)

        self.assertEqual(found.parent, parent)
        by_path = {change.path: change for change in found.files}
        self.assertEqual(by_path["a.yaml"].status, "modified")
        self.assertIn("-port: 80", by_path["a.yaml"].lines)
        self.assertIn("+port: 8080", by_path["a.yaml"].lines)
        self.assertEqual(by_path["gone.cfg"].status, "deleted")
        self.assertEqual(by_path["new name.cfg"].status, "renamed")
        self.assertEqual(by_path["new name.cfg"].old_path, "old name.cfg")
        self.assertFalse(found.truncated)
        text = render(found)
        self.assertIn("=== old name.cfg -> new name.cfg (renamed, +0 -0)", text)

    def test_a_diff_past_its_bound_says_it_was_cut_and_still_names_every_file(self) -> None:
        self.commit({"big.cfg": "", "small.cfg": ""})
        second = self.commit({"big.cfg": "line\n" * 5000, "small.cfg": "one\n"})

        with mock.patch.object(version_diff, "MAX_DIFF_BYTES", 1000):
            found = version_diff.version_diff(self.repo, second)

        self.assertTrue(found.truncated)
        by_path = {change.path: change for change in found.files}
        self.assertEqual(by_path["big.cfg"].lines, ())
        self.assertEqual(by_path["big.cfg"].added, 5000, "counted though not shown")
        self.assertEqual(by_path["small.cfg"].lines[-1], "+one")

    def test_no_patch_is_asked_for_once_the_budget_is_spent(self) -> None:
        """Review 2026-10-03, K6. `@@ -0,0 +1 @@` and `+one`: 19 bytes, all there is."""
        self.commit({"a.cfg": "", "b.cfg": "", "big.cfg": ""})
        second = self.commit({"a.cfg": "one\n", "b.cfg": "two\n", "big.cfg": "line\n" * 10})

        with (
            mock.patch.object(version_diff, "MAX_DIFF_BYTES", 19),
            mock.patch.object(version_diff, "git_bounded", wraps=git_bounded) as read,
        ):
            found = version_diff.version_diff(self.repo, second)

        by_path = {change.path: change for change in found.files}
        self.assertEqual(by_path["a.cfg"].lines, ("@@ -0,0 +1 @@", "+one"))
        self.assertEqual((by_path["b.cfg"].lines, by_path["b.cfg"].added), ((), 1))
        self.assertEqual((by_path["big.cfg"].lines, by_path["big.cfg"].added), ((), 10))
        self.assertTrue(found.truncated)
        self.assertEqual([call.args[-1] for call in read.call_args_list], ["a.cfg"])

    def test_a_patch_past_the_budget_is_not_read_whole(self) -> None:
        self.commit({"big.cfg": ""})
        second = self.commit({"big.cfg": "line\n" * 250_000})
        answers: list[bytes | None] = []
        real = git_bounded

        def bounded(repo: Path, *args: str, limit: int) -> bytes | None:
            answers.append(real(repo, *args, limit=limit))
            return answers[-1]

        with mock.patch.object(version_diff, "git_bounded", side_effect=bounded):
            found = version_diff.version_diff(self.repo, second)

        self.assertEqual(answers, [None], "stopped past the limit rather than read to the end")
        [change] = found.files
        self.assertEqual((change.lines, change.added), ((), 250_000))
        self.assertTrue(found.truncated)

    def test_counts_hold_for_a_changed_rename_and_a_binary_file(self) -> None:
        self.commit({"old.cfg": "same\n" * 9 + "x\n"})
        (self.repo / "blob.bin").write_bytes(bytes(range(256)))
        second = self.commit({"old.cfg": None, "new.cfg": "same\n" * 9 + "y\n"})

        by_path = {c.path: c for c in version_diff.version_diff(self.repo, second).files}

        self.assertEqual(by_path["new.cfg"].status, "renamed")
        self.assertEqual((by_path["new.cfg"].added, by_path["new.cfg"].removed), (1, 1))
        self.assertIn("+y", by_path["new.cfg"].lines)
        self.assertTrue(by_path["blob.bin"].binary)
        self.assertEqual((by_path["blob.bin"].added, by_path["blob.bin"].lines), (0, ()))

    def test_only_a_full_commit_hash_names_a_version(self) -> None:
        self.commit({"a": "1\n"})
        for name in ("HEAD", "main", "abc123", "--output=/tmp/x"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                version_diff.version_diff(self.repo, name)


if __name__ == "__main__":
    unittest.main()
