"""The manual describes the product as it is (review 2026-10-22, 7-6).

It said which schema brought a feature, "(schema `0041`)", and which
installations predate a file: history for the reader to subtract. The
release notes and the migrations keep that.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

MANUAL = Path(__file__).resolve().parents[1] / "docs/user-manual.md"
HISTORY = re.compile(r"\(schema\s+`\d{4}`\)|\bpredates?\b")


class TheManualIsCurrent(unittest.TestCase):
    def test_no_feature_is_dated_by_its_schema_or_by_what_predates_it(self) -> None:
        text = MANUAL.read_text(encoding="utf-8")
        found = [
            f"{number}: {line.strip()[:80]}"
            for number, line in enumerate(text.splitlines(), 1)
            if HISTORY.search(line)
        ]
        self.assertEqual(found, [])


if __name__ == "__main__":
    unittest.main()
