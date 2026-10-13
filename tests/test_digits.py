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
#
# The one line allowed to call `isdigit()`: the check itself, with its length
# cap. A line that merely mentions `isascii()` is not that line - ASCII without
# a cap still hands `int()` 5 000 digits, which it refuses (review 26-10-13
# r16k, F2). The node scripts carry it as `_digits`, since they cannot import
# the engine, and are held to the same line and the same limit.
#
CHECK = "return 0 < len(text) <= limit and text.isascii() and text.isdigit()"
NODE_COPY = f"def _digits(text, limit={MAX_DIGITS}):"


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
            if BARE.search(line) and line.strip() != CHECK
        ]
        self.assertEqual(found, [], "use haprion.digits.is_digits (a node script: _digits)")

    def test_the_engine_and_every_node_copy_are_the_same_check(self) -> None:
        self.assertIn(f"    {CHECK}\n", EXPLAINED.read_text(encoding="utf-8"))
        copies = [path for path in _sources() if CHECK in path.read_text(encoding="utf-8")]
        self.assertTrue(copies, "the node scripts' _digits is no longer found")
        for path in copies:
            with self.subTest(script=path.name):
                lines = path.read_text(encoding="utf-8").splitlines()
                at = next(i for i, line in enumerate(lines) if line.strip() == CHECK)
                definition = next(line for line in reversed(lines[:at]) if line.startswith("def "))
                self.assertEqual(definition, NODE_COPY)

    def test_the_gate_refuses_ascii_without_a_cap(self) -> None:
        for line in (
            "if text.isascii() and text.isdigit():",
            "    return text.isascii() and text.isdigit()",
            "ok = value.isdigit()",
        ):
            with self.subTest(line=line):
                self.assertTrue(BARE.search(line) and line.strip() != CHECK)


if __name__ == "__main__":
    unittest.main()
