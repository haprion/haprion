from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
SCANNER = BASE / "tools" / "secret_scan.py"


class SecretScanTests(unittest.TestCase):
    def execute(self, tree: Path, rules: Path):
        return subprocess.run(
            [sys.executable, str(SCANNER), "--worktree", str(tree), "--rules", str(rules)],
            text=True,
            capture_output=True,
            check=False,
        )

    def test_safe_tree_passes(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            tree = root / "tree"
            tree.mkdir()
            (tree / "example.txt").write_text("node=node-a\naddress=192.0.2.10\n", encoding="utf-8")
            rules = root / "rules"
            rules.write_text("private-value\\tBLOCKED".replace("\\t", "\t"), encoding="utf-8")
            result = self.execute(tree, rules)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_generic_and_private_findings_block_without_echoing_values(self):
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

    def test_missing_private_rules_fails_closed(self):
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
