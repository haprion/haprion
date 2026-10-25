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


class NoInstallationsClusterNames(unittest.TestCase):
    """Review 26-10-24, 16-01: help texts and fixtures used a real installation's cluster IDs.

    The repository's examples use `alpha` and `beta`. The two words caught here
    were exactly one installation's pair, in four commands' help and five
    contract fixtures.
    """

    REAL = re.compile(
        r"(?:-c|--cluster) (?:internal|external)\b"
        r'|"cluster": "(?:internal|external)"'
        r"|@(?:internal|external)\.(?:timer|service)\b"
    )

    def test_no_example_or_fixture_names_them(self) -> None:
        found = []
        for root in (*SOURCES, *TESTS, ROOT / "fixtures", ROOT / "docs"):
            for path in root.rglob("*"):
                if not path.is_file() or "__pycache__" in path.parts:
                    continue
                try:
                    text = path.read_text(encoding="utf-8")
                except UnicodeDecodeError:
                    continue
                found += [
                    f"{path.relative_to(ROOT)}: {match.group()}"
                    for match in self.REAL.finditer(text)
                ]
        self.assertEqual(found, [])


if __name__ == "__main__":
    unittest.main()
