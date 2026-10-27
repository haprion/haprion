"""A helper instance that answered with a refusal leaves no failed unit behind (26-10-27).

Each socket helper runs one instance per connection. An instance that ends
non-zero - a refusal, a failed step - has given its answer to the caller and
its log to the journal, yet stayed in `systemctl --failed`, and monitoring on a
manager alarmed on four of them for two weeks.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

EXAMPLES = Path(__file__).resolve().parents[1] / "install" / "platform" / "examples"


class EveryHelperInstanceIsCollected(unittest.TestCase):
    def test_every_per_connection_unit_sets_collect_mode(self) -> None:
        templates = sorted(EXAMPLES.glob("*@.service.example"))
        self.assertGreaterEqual(len(templates), 9)
        for template in templates:
            with self.subTest(template=template.name):
                text = template.read_text(encoding="utf-8")
                unit = re.search(r"^\[Unit\]\n(?P<body>.*?)^\[", text, re.MULTILINE | re.DOTALL)
                if unit is None:
                    self.fail(f"{template.name} has no [Unit] section")
                self.assertIn("CollectMode=inactive-or-failed\n", unit["body"])


if __name__ == "__main__":
    unittest.main()
