"""The published documentation describes the product as it is, not how it got there.

The decision log and the implementation journal are the maintainer's and are not
in this repository, so a decision number in a public document points a reader at
something they cannot open, and a dated "until"/"since" is project history a user
has no use for. Both are refused in every tracked Markdown file.
"""

from __future__ import annotations

import ast
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DECISION = re.compile(r"\bB\d{2,3}\b")
DATED_HISTORY = re.compile(r"\b(?:until|since|before|after) 20\d\d-\d\d-\d\d\b", re.IGNORECASE)


def markdown_files() -> list[Path]:
    listed = subprocess.run(  # fixed argv
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


def tracked_text() -> dict[str, str]:
    listed = subprocess.run(  # fixed argv
        ["git", "ls-files", "-z"],  # noqa: S607 - git on PATH, as the gate's other checks
        cwd=ROOT,
        capture_output=True,
        check=True,
    ).stdout.decode()
    found: dict[str, str] = {}
    for name in listed.split("\0"):
        try:
            found[name] = (ROOT / name).read_text(encoding="utf-8")
        except (UnicodeDecodeError, IsADirectoryError, FileNotFoundError):
            continue
    return found


class TheCodeNamesTheManualAsItIs(unittest.TestCase):
    """Review 26-10-24, 16-10: comments sent a reader to sections of an installation
    guide that is gone, by its section numbers. The manual is named by a heading it has."""

    RETIRED = re.compile(r"\bINSTALLATION \d")
    NAMED = re.compile(r"user-manual\.md, '([^']+)'")

    def test_no_document_says_every_run_makes_a_new_join_key(self) -> None:
        """Review 26-10-25, 3-03: only --again does; a leaked block was thought dead."""

        claim = re.compile(r"(?:each|every) run makes a new one-time\s+key")
        for path in sorted(ROOT.rglob("*.md")):
            if ".git" in path.parts:
                continue
            with self.subTest(path=path.relative_to(ROOT)):
                self.assertIsNone(claim.search(path.read_text(encoding="utf-8")))

    def test_nothing_names_the_old_guide_by_its_numbers(self) -> None:
        found = [
            f"{name}:{number}"
            for name, text in tracked_text().items()
            for number, line in enumerate(text.splitlines(), start=1)
            if self.RETIRED.search(line)
        ]
        self.assertEqual(found, [])

    def test_every_manual_heading_the_code_names_is_there(self) -> None:
        headings: set[str] = set()
        fenced = False
        for line in (ROOT / "docs/user-manual.md").read_text(encoding="utf-8").splitlines():
            if FENCE.match(line):
                fenced = not fenced
                continue
            match = None if fenced else HEADING.match(line)
            if match:
                headings.add(match.group(1))
        named = {
            (name, heading)
            for name, text in tracked_text().items()
            for line in text.splitlines()
            for heading in self.NAMED.findall(line)
        }
        self.assertGreater(len(named), 10)
        self.assertEqual(sorted((n, h) for n, h in named if h not in headings), [])


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


#
# A decision (B141), a plan item (C9b, D4) or a section (§4), alone or in a
# parenthesis with others.
#
REFERENCE = re.compile(
    r"\((?:[^()]*\b)?(?:B\d{1,4}|C\d{1,3}[a-z]?|D\d{1,2}|§\s?\d+)\b[^)]*\)|\bB\d{2,4}\b|§\s?\d+"
)


def _statement_strings(tree: ast.AST) -> set[int]:
    """The strings that stand as statements - docstrings, which a maintainer reads."""

    return {
        id(node.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    }


def _module_docstring_is_help(tree: ast.Module) -> bool:
    return any(
        isinstance(node, ast.keyword)
        and node.arg == "description"
        and isinstance(node.value, ast.Name)
        and node.value.id == "__doc__"
        for node in ast.walk(tree)
    )


def references_a_reader_sees() -> list[str]:
    found = []
    for path in sorted((ROOT / "src" / "haprion").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        skipped = _statement_strings(tree)
        if _module_docstring_is_help(tree) and isinstance(tree.body[0], ast.Expr):
            skipped.discard(id(tree.body[0].value))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and id(node) not in skipped
                and REFERENCE.search(node.value)
            ):
                found.append(f"{path.relative_to(ROOT)}:{node.lineno} {node.value[:60]!r}")
    return found


class TheEngineSaysNoProjectHistory(unittest.TestCase):
    """Review 26-10-24, 16-06: the same rule for what the engine says.

    Decision and plan references belong in comments and docstrings, where the
    next maintainer can look them up. In an error message or a command's help
    they reach someone who cannot - at the terminal and, by a helper's answer,
    on the interface's jobs page.
    """

    def test_no_message_or_help_text_names_a_decision(self) -> None:
        self.assertEqual(references_a_reader_sees(), [])
