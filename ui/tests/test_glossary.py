"""One word per thing on the pages (review 2026-10-22, 7-2, 7-11, 7-13 and 8-3; decided 26-10-23).

A state had up to seven names and a service four. The words are in
`haprion.labels` and the manual's table; this refuses the retired ones in what
a page shows - the templates' visible text and the strings the package hands
them - and in the manual and the quickstart.
"""

from __future__ import annotations

import ast
import re
import unittest
from pathlib import Path

from haprion_ui import labels

PACKAGE = Path(labels.__file__).parent
DOCS = PACKAGE.parents[2] / "docs"
#
# On a page a service is a proxy. *Object* stays the word of the command line,
# the YAML and the code, so only the visible text of a template is held to it.
#
SERVICE = re.compile(r"\b(?:[Oo]bjects?|[Ss]ites?)\b")


def _visible(template: str) -> list[tuple[int, str]]:
    text = re.sub(
        r"\{#.*?#\}", lambda found: "\n" * found.group(0).count("\n"), template, flags=re.S
    )
    return [
        (number, re.sub(r"<[^>]*>", " ", re.sub(r"\{%.*?%\}|\{\{.*?\}\}", " ", line)))
        for number, line in enumerate(text.split("\n"), 1)
    ]


def _strings(source: str) -> list[tuple[int, str]]:
    tree = ast.parse(source)
    docstrings = {
        id(node.body[0].value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef)
        and node.body
        and isinstance(node.body[0], ast.Expr)
        and isinstance(node.body[0].value, ast.Constant)
    }
    return [
        (node.lineno, node.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and id(node) not in docstrings
    ]


class OneWordPerThing(unittest.TestCase):
    def test_a_template_says_proxy_and_no_retired_word(self) -> None:
        found = []
        for path in sorted((PACKAGE / "templates").glob("*.html")):
            for number, line in _visible(path.read_text(encoding="utf-8")):
                if SERVICE.search(line) or any(word in line for word in labels.RETIRED):
                    found.append(f"{path.name}:{number}: {line.strip()[:80]}")
        self.assertEqual(found, [])

    def test_the_package_hands_the_pages_no_retired_word(self) -> None:
        found = [
            f"{path.relative_to(PACKAGE)}:{number}: {value[:60]}"
            for path in sorted(PACKAGE.rglob("*.py"))
            if path.name != "labels.py"
            for number, value in _strings(path.read_text(encoding="utf-8"))
            if any(word in value for word in labels.RETIRED)
        ]
        self.assertEqual(found, [])

    def test_the_manual_names_the_controls_as_the_pages_do(self) -> None:
        found = [
            f"{path.name}:{number}: {word}"
            for path in (DOCS / "user-manual.md", DOCS / "quickstart.md")
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
            for word in labels.RETIRED
            if word in line
        ]
        self.assertEqual(found, [])


if __name__ == "__main__":
    unittest.main()
