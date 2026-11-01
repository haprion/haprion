"""`tools/node-step-changed`: does the node's preparation step differ between two revisions?"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
TOOL = BASE / "tools" / "node-step-changed"

TABLE = """\
INSTALL_DIR = "/usr/share/haprion-node/install"
CONTENTS = {
    f"{INSTALL_DIR[1:]}/04-node-prepare": ("install/04-node-prepare", 0o755),
    f"{INSTALL_DIR[1:]}/accounts.sh": ("install/accounts.sh", 0o644),
    "usr/sbin/haprion-node-status": ("install/node/haprion-node-status", 0o755),
}
"""


#
# The node status script as the node digests with it: the function, between the
# two markers the tool cuts it by.
#
STATUS = """\
import hashlib


def step_digest(directory):
    lines = b""
    for path in sorted(p for p in directory.rglob("*") if p.is_file()):
        name = "./" + str(path.relative_to(directory))
        lines += f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {name}\\n".encode()
    return hashlib.sha256(lines).hexdigest()


def read_preparation():
    return None
"""


def load_tool() -> Any:
    loader = importlib.machinery.SourceFileLoader("node_step_changed", str(TOOL))
    spec = importlib.util.spec_from_loader("node_step_changed", loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class TheNodeStepBetweenTwoRevisions(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = load_tool()
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.repo = Path(directory.name)
        self.write("src/haprion/node_package.py", TABLE)
        self.write("install/04-node-prepare", "prepare\n")
        self.write("install/accounts.sh", "readonly A=alpha\n")
        self.write("install/node/haprion-node-status", STATUS)
        self.write("install/manager-only", "manager\n")
        self.commit("one")
        self.tool.ROOT = self.repo

    def git(self, *arguments: str) -> str:
        done = subprocess.run(  # fixed executable, a temporary repository
            ["/usr/bin/git", "-C", str(self.repo), *arguments],
            capture_output=True,
            text=True,
            check=True,
        )
        return done.stdout.strip()

    def write(self, name: str, text: str) -> None:
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def commit(self, message: str) -> str:
        if not (self.repo / ".git").exists():
            self.git("init", "-q")
        self.git("add", "-A")
        self.git(
            "-c",
            "user.name=tester",
            "-c",
            "user.email=tester@example.com",
            "commit",
            "-q",
            "-m",
            message,
        )
        return self.git("rev-parse", "HEAD")

    def run_tool(self, *revisions: str) -> tuple[int, str]:
        import contextlib
        import io

        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            code = self.tool.main(list(revisions))
        return code, out.getvalue()

    def test_a_file_outside_the_step_changes_nothing(self) -> None:
        first = self.git("rev-parse", "HEAD")
        self.write("install/manager-only", "other\n")
        self.write("install/node/haprion-node-status", STATUS + "\n# a comment below\n")
        second = self.commit("two")
        self.assertEqual(self.run_tool(first, second)[0], 0)

    def test_a_changed_digest_function_is_a_changed_step(self) -> None:
        """26-11-01: the digest of an old tag is its own, not today's."""

        first = self.git("rev-parse", "HEAD")
        self.write(
            "install/node/haprion-node-status",
            STATUS.replace("return hashlib.sha256(lines)", "return hashlib.sha256(b'v2' + lines)"),
        )
        second = self.commit("two")
        code, out = self.run_tool(first, second)
        self.assertEqual(code, 1, out)
        self.assertIn("changed  the digest function", out)
        # A revision is digested with its own function, whichever the working tree has.
        self.assertNotEqual(
            self.tool.digest_of({"a": b"x"}, self.tool.step_digest_function(first)),
            self.tool.digest_of({"a": b"x"}, self.tool.step_digest_function(second)),
        )

    def test_a_changed_file_in_the_step_is_named(self) -> None:
        first = self.git("rev-parse", "HEAD")
        self.write("install/accounts.sh", "readonly A=beta\n")
        second = self.commit("two")
        code, out = self.run_tool(first, second)
        self.assertEqual(code, 1)
        self.assertIn("changed  accounts.sh", out)
        self.assertNotIn("04-node-prepare", out)

    def test_a_file_added_to_the_table_is_added_to_the_step(self) -> None:
        first = self.git("rev-parse", "HEAD")
        self.write("install/helper.sh", "helper\n")
        self.write(
            "src/haprion/node_package.py",
            TABLE.replace(
                "}\n", '    f"{INSTALL_DIR[1:]}/helper.sh": ("install/helper.sh", 0o644),\n}\n'
            ),
        )
        second = self.commit("two")
        code, out = self.run_tool(first, second)
        self.assertEqual(code, 1)
        self.assertIn("added    helper.sh", out)

    def test_the_second_revision_defaults_to_head(self) -> None:
        first = self.git("rev-parse", "HEAD")
        self.write("install/04-node-prepare", "prepare again\n")
        self.commit("two")
        self.assertEqual(self.run_tool(first)[0], 1)
        self.assertEqual(self.run_tool("HEAD")[0], 0)

    def test_neither_revision_may_be_an_option(self) -> None:
        for revisions in (("-x",), ("HEAD", "--output=elsewhere"), ("HEAD", "-p")):
            with (
                self.subTest(revisions=revisions),
                mock.patch.object(self.tool, "git", side_effect=AssertionError("git was run")),
            ):
                code, shown = self.run_tool(*revisions)
                self.assertEqual(code, 2)
                self.assertIn("Whether the node's preparation step differs", shown)

    def test_a_revision_that_does_not_exist_is_an_error_not_an_answer(self) -> None:
        self.assertEqual(self.run_tool("no-such-revision")[0], 2)
        self.assertEqual(self.run_tool()[0], 2)

    def test_the_digest_is_the_one_a_node_computes(self) -> None:
        files = self.tool.step_files("HEAD")
        digest = self.tool.digest_of(files, self.tool.step_digest_function("HEAD"))
        with tempfile.TemporaryDirectory() as raw:
            for name, content in files.items():
                (Path(raw) / name).write_bytes(content)
            done = subprocess.run(  # fixed interpreter, the repository's library
                [
                    "/bin/bash",
                    "-c",
                    f'source "{BASE / "install/node-installation.sh"}"; step_digest "$1"',
                    "-",
                    raw,
                ],
                capture_output=True,
                text=True,
                check=True,
            )
        self.assertEqual(done.stdout.strip(), digest)


class TheRealTable(unittest.TestCase):
    def test_this_checkout_has_a_step_directory_to_digest(self) -> None:
        tool = load_tool()
        files = tool.step_files("HEAD")
        self.assertIn("04-node-prepare", files)
        self.assertIn("node-lib.sh", files)


if __name__ == "__main__":
    unittest.main()
