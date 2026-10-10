"""The published documentation describes the product as it is, not how it got there.

The decision log and the implementation journal are the maintainer's and are not
in this repository, so a decision number in a public document points a reader at
something they cannot open, and a dated "until"/"since" is project history a user
has no use for. Both are refused in every tracked Markdown file.
"""

from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DECISION = re.compile(r"\bB\d{2,3}\b")
DATED_HISTORY = re.compile(r"\b(?:until|since|before|after) 20\d\d-\d\d-\d\d\b", re.IGNORECASE)


def markdown_files() -> list[Path]:
    listed = subprocess.run(  # noqa: S603 - fixed argv
        ["git", "ls-files", "-z", "*.md"],  # noqa: S607 - git on PATH, as the gate's other checks
        cwd=ROOT,
        capture_output=True,
        check=True,
    ).stdout.decode()
    return [ROOT / name for name in listed.split("\0") if name]


def findings(text: str) -> list[str]:
    found = []
    for number, line in enumerate(text.splitlines(), start=1):
        for pattern in (DECISION, DATED_HISTORY):
            match = pattern.search(line)
            if match:
                found.append(f"{number}: {match.group(0)}")
    return found


class PublicDocumentationHasNoProjectHistory(unittest.TestCase):
    def test_tracked_markdown_names_no_decision_or_dated_history(self) -> None:
        files = markdown_files()
        self.assertTrue(files, "no tracked Markdown found")
        for path in files:
            with self.subTest(path=str(path.relative_to(ROOT))):
                self.assertEqual(findings(path.read_text(encoding="utf-8")), [])

    def test_the_patterns_catch_what_they_are_for(self) -> None:
        self.assertEqual(findings("fixed (B266): the accounts"), ["1: B266"])
        self.assertEqual(findings("called receivers until 2026-10-06"), ["1: until 2026-10-06"])
        self.assertEqual(findings("an archive 2026-01-01_04-00-00 and SHA-256"), [])


if __name__ == "__main__":
    unittest.main()
