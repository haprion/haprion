"""What one version changed, read from a real repository."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from haproxy_mgmt import version_diff
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

    def test_only_a_full_commit_hash_names_a_version(self) -> None:
        self.commit({"a": "1\n"})
        for name in ("HEAD", "main", "abc123", "--output=/tmp/x"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                version_diff.version_diff(self.repo, name)


if __name__ == "__main__":
    unittest.main()
