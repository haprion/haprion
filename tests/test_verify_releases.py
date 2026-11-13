"""tools/verify-releases: the automatic releases built again here and compared (B506)."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import io
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any

BASE = Path(__file__).resolve().parents[1]


def load(name: str, relative: Path) -> Any:
    loader = importlib.machinery.SourceFileLoader(name, str(relative))
    spec = importlib.util.spec_from_loader(name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    loader.exec_module(module)
    return module


VERIFY = load("verify_releases", BASE / "tools" / "verify-releases")

#
# A build that writes one package whose bytes are the tree's PAYLOAD file, so a
# release's files can be made to match the tree or not.
#
BUILD = """#!/usr/bin/env python3
import argparse, pathlib
parser = argparse.ArgumentParser()
parser.add_argument("--source"); parser.add_argument("--output-dir"); parser.add_argument("--uv")
parser.add_argument("--cache")
args = parser.parse_args()
out = pathlib.Path(args.output_dir); out.mkdir(parents=True)
payload = (pathlib.Path(args.source) / "PAYLOAD").read_bytes()
(out / "haprion-cli_1.1.1~deb13_all.deb").write_bytes(payload)
"""

#
# `gh release download <tag> ... --dir <dir>`: the files the fake release of
# that tag holds, from RELEASES/<tag>/.
#
GH = """#!/usr/bin/env python3
import os, pathlib, shutil, sys
args = sys.argv[1:]
tag = args[2]
target = pathlib.Path(args[args.index("--dir") + 1])
for path in (pathlib.Path(os.environ["RELEASES"]) / tag).iterdir():
    shutil.copy(path, target / path.name)
"""


def git(root: Path, *args: str) -> None:
    environment = dict(
        os.environ,
        GIT_AUTHOR_NAME="admin",
        GIT_AUTHOR_EMAIL="admin@example.com",
        GIT_COMMITTER_NAME="admin",
        GIT_COMMITTER_EMAIL="admin@example.com",
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_CONFIG_NOSYSTEM="1",
    )
    subprocess.run(
        ["/usr/bin/git", "-C", str(root), *args], check=True, capture_output=True, env=environment
    )


class VerifyReleasesTest(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.source = self.root / "source"
        self.releases = self.root / "releases"
        (self.source / "tools").mkdir(parents=True)
        git(self.source, "init", "--quiet", "--initial-branch=main")
        build = self.source / "tools" / "build-release-packages"
        build.write_text(BUILD, encoding="utf-8")
        build.chmod(0o755)
        self.gh = self.root / "gh"
        self.gh.write_text(GH, encoding="utf-8")
        self.gh.chmod(0o755)
        for tag, payload in (("v1.1.0", b"made by hand"), ("v1.1.1", b"one"), ("v1.1.2", b"two")):
            (self.source / "PAYLOAD").write_bytes(payload)
            git(self.source, "add", "--all")
            git(self.source, "commit", "--quiet", "--message", f"Version {tag[1:]}")
            git(self.source, "tag", tag)
            self.release(tag, payload)

    def release(self, tag: str, payload: bytes) -> None:
        directory = self.releases / tag
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "haprion-cli_1.1.1.deb13_all.deb").write_bytes(payload)

    def run_tool(self) -> tuple[int, str]:
        output = io.StringIO()
        os.environ["RELEASES"] = str(self.releases)
        self.addCleanup(os.environ.pop, "RELEASES", None)
        with redirect_stdout(output):
            status = VERIFY.main(
                [
                    "--source",
                    str(self.source),
                    "--since",
                    "v1.1.0",
                    "--work",
                    str(self.root / "work"),
                    "--uv",
                    "/usr/bin/true",
                    "--gh",
                    str(self.gh),
                ]
            )
        return status, output.getvalue()

    def test_every_release_after_the_one_made_by_hand_is_built_and_compared(self) -> None:
        status, output = self.run_tool()

        self.assertEqual(status, 0, output)
        self.assertEqual(output.splitlines(), ["v1.1.1: IDENTICAL", "v1.1.2: IDENTICAL"])

    def test_a_release_whose_files_differ_stops_the_release_made_by_hand(self) -> None:
        self.release("v1.1.2", b"something else")

        status, output = self.run_tool()

        self.assertEqual(status, 1)
        self.assertIn("v1.1.2: DIFFERENT", output)
        self.assertIn("haprion-cli_1.1.1.deb13_all.deb", output)

    def test_a_package_only_one_side_has_is_a_difference(self) -> None:
        (self.releases / "v1.1.1" / "haprion-ui_1.1.1.deb13_all.deb").write_bytes(b"extra")

        status, output = self.run_tool()

        self.assertEqual(status, 1)
        self.assertIn("in the release, not built here", output)

    def test_tags_are_taken_newer_than_since_in_version_order(self) -> None:
        git(self.source, "tag", "v1.1.10")
        git(self.source, "tag", "not-a-release")

        self.assertEqual(VERIFY.tags_after(self.source, "v1.1.1"), ["v1.1.2", "v1.1.10"])

    def test_no_release_since_is_said(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            status = VERIFY.main(
                [
                    "--source",
                    str(self.source),
                    "--since",
                    "v1.1.2",
                    "--work",
                    str(self.root / "work"),
                    "--uv",
                    "/usr/bin/true",
                ]
            )

        self.assertEqual(status, 0)
        self.assertIn("no release after v1.1.2", output.getvalue())

    def test_the_work_tree_is_removed_after_the_build(self) -> None:
        self.run_tool()

        listed = subprocess.run(
            ["/usr/bin/git", "-C", str(self.source), "worktree", "list"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        self.assertEqual(len(listed.splitlines()), 1)


if __name__ == "__main__":
    unittest.main()
