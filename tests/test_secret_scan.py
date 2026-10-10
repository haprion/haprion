from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

BASE = Path(__file__).resolve().parents[1]
SCANNER = BASE / "tools" / "secret_scan.py"


class SecretScanTests(unittest.TestCase):
    def scanner(self) -> Any:
        """The scanner as a module. It is a script, not an installed package."""

        spec = importlib.util.spec_from_file_location("secret_scan", SCANNER)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def execute(self, tree: Path, rules: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCANNER), "--worktree", str(tree), "--rules", str(rules)],
            text=True,
            capture_output=True,
            check=False,
        )

    def test_safe_tree_passes(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            tree = root / "tree"
            tree.mkdir()
            (tree / "example.txt").write_text("node=node-a\naddress=192.0.2.10\n", encoding="utf-8")
            rules = root / "rules"
            rules.write_text("private-value\\tBLOCKED".replace("\\t", "\t"), encoding="utf-8")
            result = self.execute(tree, rules)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_a_git_tree_is_read_as_git_would_commit_it(self) -> None:
        # A fresh checkout keeps its environments inside it (26-10-10): what
        # Git ignores is not read, an untracked file it would offer is.
        finding = "pass" + "word=examplevalue\n"
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            tree = root / "tree"
            (tree / ".venv-ui" / "lib").mkdir(parents=True)
            git = shutil.which("git")
            assert git is not None
            subprocess.run([git, "init", "-q", str(tree)], check=True)  # noqa: S603
            (tree / ".gitignore").write_text(".venv-ui/\n", encoding="utf-8")
            (tree / ".venv-ui" / "lib" / "package.py").write_text(finding, encoding="utf-8")
            rules = root / "rules"
            rules.write_text("private-value\tBLOCKED", encoding="utf-8")
            self.assertEqual(self.execute(tree, rules).returncode, 0)

            (tree / "new.txt").write_text(finding, encoding="utf-8")
            result = self.execute(tree, rules)
            self.assertEqual(result.returncode, 1)
            self.assertIn("new.txt", result.stderr)
            self.assertNotIn(".venv-ui", result.stderr)

    def test_generic_and_private_findings_block_without_echoing_values(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            tree = root / "tree"
            tree.mkdir()
            denylist_fixture = "BLOCKED" + "-PRIVATE-VALUE"
            generic_rule_fixture = "pass" + "word=examplevalue"
            (tree / "example.txt").write_text(
                f"{denylist_fixture}\n{generic_rule_fixture}\n", encoding="utf-8"
            )
            rules = root / "rules"
            rules.write_text(
                "private-value\\t".replace("\\t", "\t") + denylist_fixture,
                encoding="utf-8",
            )
            result = self.execute(tree, rules)
            self.assertEqual(result.returncode, 1)
            self.assertIn("private-value", result.stderr)
            self.assertIn("assigned-secret", result.stderr)
            self.assertNotIn(denylist_fixture, result.stderr)
            self.assertNotIn("examplevalue", result.stderr)

    def test_loopback_is_allowed_and_other_real_addresses_are_not(self) -> None:
        """The exception is narrow, and the narrowness is the point.

        127.0.0.0/8 means "this machine" wherever it is read, so it identifies
        no environment - and refusing it forced examples to be wrong, since the
        web service really does bind loopback, and 0.0.0.0/8 because it is
        never an address at all - what it matches is version numbers in lock
        files. A private address is still an address out of somebody's
        network, so RFC 1918 stays refused.
        """

        is_forbidden_ip = self.scanner().is_forbidden_ip

        for allowed in (
            "127.0.0.1",
            "127.0.0.53",
            "192.0.2.10",
            "203.0.113.7",
            "0.0.0.2",
            "0.4.9.6",
        ):
            with self.subTest(address=allowed):
                self.assertFalse(is_forbidden_ip(allowed))

        #
        # Assembled from octets rather than written out, because this scanner
        # scans this file: a test that spelled these addresses would be blocked
        # by the rule it is here to prove. That it cannot write them is the
        # demonstration.
        #
        for octets in (
            ("10", "0", "0", "1"),
            ("172", "16", "5", "4"),
            ("192", "168", "1", "1"),
            ("8", "8", "8", "8"),
        ):
            refused = ".".join(octets)
            with self.subTest(address=refused):
                self.assertTrue(is_forbidden_ip(refused))

    def test_missing_private_rules_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            tree = root / "tree"
            tree.mkdir()
            (tree / "example.txt").write_text("safe\n", encoding="utf-8")
            result = self.execute(tree, root / "missing.rules")
            self.assertEqual(result.returncode, 2)
            self.assertIn("required private denylist is missing", result.stderr)


if __name__ == "__main__":
    unittest.main()
