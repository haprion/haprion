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


LINK = re.compile(r"\]\(([^)\s]+)\)")
HEADING = re.compile(r"^#{1,6} (.+?)\s*$")
FENCE = re.compile(r"^(```|~~~)")


def slug(heading: str) -> str:
    """GitHub's anchor for a heading: lower case, punctuation dropped, spaces as hyphens."""
    text = re.sub(r"[`*_]", "", heading).lower()
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


def anchors(text: str) -> set[str]:
    found: set[str] = set()
    fenced = False
    for line in text.splitlines():
        if FENCE.match(line):
            fenced = not fenced
            continue
        match = None if fenced else HEADING.match(line)
        if match:
            found.add(slug(match.group(1)))
    return found


def broken_links(path: Path) -> list[str]:
    broken = []
    for target in LINK.findall(path.read_text(encoding="utf-8")):
        if re.match(r"^[a-z]+:", target):
            continue
        file_part, _, anchor = target.partition("#")
        linked = (path.parent / file_part).resolve() if file_part else path
        heading_missing = (
            linked.exists()
            and bool(anchor)
            and linked.suffix == ".md"
            and anchor not in anchors(linked.read_text("utf-8"))
        )
        if not linked.exists() or heading_missing:
            broken.append(target)
    return broken


class PublicDocumentationLinksResolve(unittest.TestCase):
    def test_every_relative_link_names_a_file_and_heading_that_exist(self) -> None:
        for path in markdown_files():
            with self.subTest(path=str(path.relative_to(ROOT))):
                self.assertEqual(broken_links(path), [])

    def test_slugs_follow_github(self) -> None:
        self.assertEqual(slug("Part 1 — the management host"), "part-1--the-management-host")
        self.assertEqual(slug("The `haprion-cli` package"), "the-haprion-cli-package")
        self.assertEqual(slug("A pool's servers"), "a-pools-servers")


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


class TheContractListsEveryOperation(unittest.TestCase):
    """Every operation a schema answers for has its row in `docs/CONTRACT.md`.

    Thirteen were missing on 2026-10-12, seven of them for months: the table
    is written by hand and nothing compared it with the schemas.
    """

    def test_every_schema_operation_has_a_row(self) -> None:
        import json

        listed = set(
            re.findall(
                r"^\| [^|]+ \| `([a-z_]+)` \|",
                (ROOT / "docs" / "CONTRACT.md").read_text(encoding="utf-8"),
                re.M,
            )
        )
        answered: set[str] = set()
        for path in (ROOT / "schemas" / "v1").glob("*.schema.json"):
            for part in json.loads(path.read_text(encoding="utf-8")).get("allOf", []):
                operation = part.get("properties", {}).get("operation", {}).get("const")
                if isinstance(operation, str):
                    answered.add(operation)

        self.assertGreater(len(answered), 40)
        self.assertEqual(sorted(answered - listed), [])
