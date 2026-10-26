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


class EveryExampleClusterIsMadeUp(unittest.TestCase):
    """Review 26-10-24 16-01, 26-10-25 5-04: help texts and fixtures used a real installation's IDs.

    Held by the names that may be used rather than by the ones that may not:
    a list of real names would itself be the leak. A cluster ID given to a
    command, in a request document or in a unit instance is one of these.
    """

    MADE_UP = frozenset({"alpha", "beta", "gamma", "edge-a", "edge-demo", "service-demo", "verify"})
    NAMED = re.compile(
        r"haprion-[a-z-]+(?: [a-z][a-z-]*)?(?: --?[a-z][a-z-]*)* (?:-c|--cluster)[ =](?P<command>[a-z][a-z0-9-]*)\b"
        r'|"cluster": ?"(?P<document>[a-z][a-z0-9-]*)"'
        r"|@(?P<unit>[a-z][a-z0-9-]*)\.(?:timer|service)\b"
        r"|^\s*-?\s*cluster: (?P<yaml>[a-z][a-z0-9-]*)\s*$",
        re.MULTILINE,
    )

    def test_no_example_or_fixture_names_another(self) -> None:
        found = [
            f"{name}: {match.group()}"
            for name, text in tracked(*SOURCES, "tests/", "ui/tests/", "fixtures/", "docs/")
            # This file's own forms, below, name one on purpose.
            if name != "tests/test_source_references.py"
            for match in self.NAMED.finditer(text)
            if (match.lastgroup != "yaml" or not name.endswith(".py"))
            and match.group(match.lastgroup or "") not in self.MADE_UP
        ]
        self.assertEqual(found, [])

    def test_it_sees_each_form(self) -> None:
        for text in (
            "haprion-deploy -c delta",
            "haprion-status --cluster=delta",
            '{"cluster": "delta"}',
            "haprion-state-backup@delta.timer",
            "cluster: delta",
        ):
            with self.subTest(text=text):
                match = self.NAMED.search(text)
                assert match is not None
                self.assertEqual(match.group(match.lastgroup or ""), "delta")


if __name__ == "__main__":
    unittest.main()
