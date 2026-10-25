"""What the source points a reader to is there (review 26-10-24, 14-06).

A comment in `release_install` named a test that guarded its constant, and
the test was nowhere: the guard the comment promised did not exist.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCES = (ROOT / "src", ROOT / "install", ROOT / "tools", ROOT / "ui" / "src")
TESTS = (ROOT / "tests", ROOT / "ui" / "tests")
NAMED_TEST = re.compile(r"\btest_[a-z0-9_]+\.py\b")


class EveryNamedTestExists(unittest.TestCase):
    def test_a_test_the_source_names_is_one_the_suites_have(self) -> None:
        missing = set()
        for root in SOURCES:
            for path in root.rglob("*"):
                if not path.is_file() or "__pycache__" in path.parts:
                    continue
                try:
                    text = path.read_text(encoding="utf-8")
                except UnicodeDecodeError:
                    continue
                for name in NAMED_TEST.findall(text):
                    if not any((tests / name).is_file() for tests in TESTS):
                        missing.add(f"{path.relative_to(ROOT)}: {name}")
        self.assertEqual(sorted(missing), [])


if __name__ == "__main__":
    unittest.main()
