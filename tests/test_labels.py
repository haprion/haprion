"""A count says its noun in its number (review 2026-10-22, 7-2 and its cosmetic row).

"2 node(s) report a warning" stood on the dashboard, and the same bracket in
the audit list, the helpers' refusals, the tools' output and the platform
scripts' logs. Python counts with `haprion.labels`; a script with
its own `counted`.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

from haprion import labels

ROOT = Path(__file__).resolve().parents[1]
SCANNED = ("src", "install", "tools", "tests", "ui/src", "ui/migrations", "ui/tests")
# Also as a regular expression writes it, `cluster\\(s\\)`.
BRACKETED = re.compile(r"[a-z]\\{0,2}\(s\\{0,2}\)")


def _text_files() -> list[Path]:
    return [
        path
        for top in SCANNED
        for path in sorted((ROOT / top).rglob("*"))
        if path.is_file()
        and "__pycache__" not in path.parts
        and path.name != "test_labels.py"
        and path.suffix not in {".pyc", ".gpg", ".asc"}
    ]


class ACountHasItsNoun(unittest.TestCase):
    def test_one_and_any_other_number(self) -> None:
        self.assertEqual(labels.counted(1, "node"), "1 node")
        self.assertEqual(labels.counted(0, "node"), "0 nodes")
        self.assertEqual(
            labels.counted(2, "source address", "source addresses"), "2 source addresses"
        )
        self.assertEqual(labels.noun(3, "key"), "keys")

    def test_nothing_writes_a_bracketed_plural(self) -> None:
        found = []
        for path in _text_files():
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            found += [
                f"{path.relative_to(ROOT)}:{number}"
                for number, line in enumerate(text.splitlines(), 1)
                if BRACKETED.search(line) and not line.lstrip().startswith("#")
            ]
        self.assertEqual(found, [])


if __name__ == "__main__":
    unittest.main()
