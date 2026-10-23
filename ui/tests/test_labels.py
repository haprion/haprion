"""A count says its noun in its number (review 2026-10-22, 7-2 and its cosmetic row).

"2 node(s) report a warning" stood on the dashboard, and the same bracket in
the audit list, the attention list and the tools' own output.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

from haprion_ui import labels

PACKAGE = Path(labels.__file__).parent
BRACKETED = re.compile(r"[a-z]\(s\)")


class ACountHasItsNoun(unittest.TestCase):
    def test_one_and_any_other_number(self) -> None:
        self.assertEqual(labels.counted(1, "node"), "1 node")
        self.assertEqual(labels.counted(0, "node"), "0 nodes")
        self.assertEqual(
            labels.counted(2, "source address", "source addresses"), "2 source addresses"
        )
        self.assertEqual(labels.noun(3, "key"), "keys")

    def test_nothing_in_the_package_writes_a_bracketed_plural(self) -> None:
        found = [
            f"{path.relative_to(PACKAGE)}:{number}"
            for path in sorted(PACKAGE.rglob("*"))
            if path.suffix in {".py", ".html", ".js"}
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
            if BRACKETED.search(line) and not line.lstrip().startswith("#")
        ]
        self.assertEqual(found, [])


if __name__ == "__main__":
    unittest.main()
