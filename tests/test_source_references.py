"""What the source points a reader to is there (review 26-10-24, 14-06).

A comment in `release_install` named a test that guarded its constant, and
the test was nowhere: the guard the comment promised did not exist.
"""

from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ("src/", "install/", "tools/", "ui/src/")
TESTS = (ROOT / "tests", ROOT / "ui" / "tests")
NAMED_TEST = re.compile(r"\btest_[a-z0-9_]+\.py\b")


def tracked(*prefixes: str) -> list[tuple[str, str]]:
    """The repository's own text files under `prefixes`, with their text.

    Not whatever a checkout holds beside them: an ignored build directory
    named tests long gone.
    """

    listed = subprocess.run(  # fixed program, the repository's own file list
        ["/usr/bin/git", "-C", str(ROOT), "ls-files", "-z", *prefixes],
        capture_output=True,
        check=True,
    ).stdout.decode()
    files = []
    for name in filter(None, listed.split("\0")):
        try:
            files.append((name, (ROOT / name).read_text(encoding="utf-8")))
        except (UnicodeDecodeError, FileNotFoundError):
            continue
    return files


class EveryNamedTestExists(unittest.TestCase):
    def test_a_test_the_source_names_is_one_the_suites_have(self) -> None:
        missing = set()
        for name, text in tracked(*SOURCES):
            for test in NAMED_TEST.findall(text):
                if not any((tests / test).is_file() for tests in TESTS):
                    missing.add(f"{name}: {test}")
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
        found = [
            f"{name}: {match.group()}"
            for name, text in tracked(*SOURCES, "tests/", "ui/tests/", "fixtures/", "docs/")
            for match in self.REAL.finditer(text)
        ]
        self.assertEqual(found, [])


if __name__ == "__main__":
    unittest.main()
