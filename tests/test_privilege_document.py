"""PRIVILEGE.md says what the installed files do (review 26-10-24, 08-04 and 10-10).

The operators' row named the group `haprion` for the operator commands and
`sudoedit`, while the rules are granted to `%sudo` and `sudoedit` to the users
in `CONFIG_EDITORS`; an administrator following it got neither. And it said
every helper reads one line, which the helpers that read to the end do not.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
DOCUMENT = BASE / "docs" / "PRIVILEGE.md"
OPERATOR_RULES = BASE / "install" / "sudoers" / "haprion"


def _operators_row() -> str:
    [row] = [
        line for line in DOCUMENT.read_text().splitlines() if line.startswith("| human operators")
    ]
    return row


class TheOperatorsRow(unittest.TestCase):
    def test_it_names_the_group_the_rules_are_granted_to(self) -> None:
        granted = set(re.findall(r"^%(\S+)\s", OPERATOR_RULES.read_text(), re.MULTILINE))
        self.assertEqual(granted, {"sudo"})
        row = _operators_row()
        for group in granted:
            self.assertIn(f"`%{group}`", row)
        self.assertNotIn("`haprion`", row)

    def test_it_names_who_may_edit_the_declared_files(self) -> None:
        self.assertIn("`CONFIG_EDITORS`", _operators_row())


class TheHelperBoundary(unittest.TestCase):
    def test_every_helper_that_reads_to_the_end_is_named(self) -> None:
        text = " ".join(DOCUMENT.read_text().split())
        readers = sorted(
            path.stem.removesuffix("_helper").replace("_", " ")
            for path in (BASE / "src" / "haprion" / "cli").glob("*_helper.py")
            if "read_raw_request(" in path.read_text()
        )
        self.assertGreater(len(readers), 1)
        named = f"the {', '.join(readers[:-1])} and {readers[-1]} helpers"
        self.assertIn(named, text, "PRIVILEGE.md's helper boundary names how each one reads")


if __name__ == "__main__":
    unittest.main()
