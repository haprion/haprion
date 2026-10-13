"""`is_digits`, and the gate that keeps a bare `isdigit()` out of the code.

Review 26-10-13, K2: `isdigit()` passed `²` to `int()` - a 500 on a query
parameter - at 13 places in the views and some 50 more across the engine, the
interface and the node scripts. Fixing them one by one leaves the next one to be
written the same way, so the pattern itself is refused here.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

from haprion.digits import MAX_DIGITS, is_digits

ROOT = Path(__file__).resolve().parents[1]

#
# The code that runs: the engine, the interface, the tools, and the scripts
# installed without a .py ending (found by their first line, as run-tests
# finds them for ruff).
#
PYTHON_TREES = ("src", "ui/src", "tools", "contract-tests")
SCRIPT_TREES = ("install", "examples")
BARE = re.compile(r"\.(isdigit|isdecimal|isnumeric)\(")
EXPLAINED = ROOT / "src" / "haprion" / "digits.py"


def _sources() -> list[Path]:
    found = [path for tree in PYTHON_TREES for path in (ROOT / tree).rglob("*.py")]
    for tree in SCRIPT_TREES:
        for path in (ROOT / tree).rglob("*"):
            if not path.is_file() or path.suffix == ".py" or "__pycache__" in path.parts:
                continue
            try:
                first = path.read_text(encoding="utf-8").split("\n", 1)[0]
            except (UnicodeDecodeError, OSError):
                continue
            if first.startswith("#!") and "python" in first:
                found.append(path)
    return sorted(path for path in found if path != EXPLAINED)


class IsDigits(unittest.TestCase):
    def test_ascii_digits_within_the_limit(self) -> None:
        for text in ("0", "7", "443", "9" * MAX_DIGITS):
            with self.subTest(text=text):
                self.assertTrue(is_digits(text))
                int(text)

    def test_what_int_refuses_or_was_never_meant(self) -> None:
        for text in ("", "²", "١٢", "１２", "-1", "+1", " 1", "1.0", "9" * (MAX_DIGITS + 1)):
            with self.subTest(text=text):
                self.assertFalse(is_digits(text))

    def test_the_limit_is_the_caller_s(self) -> None:
        self.assertTrue(is_digits("9" * 20, limit=20))
        self.assertFalse(is_digits("9" * 5000, limit=20))


class NoBareIsDigit(unittest.TestCase):
    def test_the_sources_are_found(self) -> None:
        names = {path.name for path in _sources()}
        self.assertIn("views.py", names)
        self.assertIn("haprion-node-status", names)

    def test_every_digit_check_is_ascii_bound(self) -> None:
        found = [
            f"{path.relative_to(ROOT)}:{number}: {line.strip()}"
            for path in _sources()
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
            if BARE.search(line) and ".isascii()" not in line
        ]
        self.assertEqual(found, [], "use haprion.digits.is_digits (a node script: _digits)")


if __name__ == "__main__":
    unittest.main()
