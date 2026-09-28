"""The nginx examples keep every accepted request body in memory (review 2026-09-28 F09)."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ("haproxy-ui.nginx.example", "haproxy-ui-dev.nginx.example")


def directive(text: str, name: str) -> list[str]:
    return re.findall(rf"^\s*{name}\s+(\S+);", text, re.MULTILINE)


class RequestBodiesStayInMemory(unittest.TestCase):
    def test_the_buffer_holds_the_largest_body_nginx_accepts(self) -> None:
        """A certificate import carries a private key; nginx must not spool it to disk."""

        for name in EXAMPLES:
            with self.subTest(example=name):
                text = (ROOT / "install/platform/examples" / name).read_text()
                self.assertEqual(directive(text, "client_max_body_size"), ["1m"])
                self.assertEqual(directive(text, "client_body_buffer_size"), ["1m"])
                self.assertEqual(directive(text, "client_body_in_file_only"), [])


if __name__ == "__main__":
    unittest.main()
