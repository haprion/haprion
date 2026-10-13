"""Whether text is a number this code may hand to `int()`.

`str.isdigit()` is not that question. It is true for `²` and other Unicode
digits that `int()` refuses, and for strings longer than `int()` converts, so a
check written with it lets through exactly the input that then raises - a 500
on a query parameter (review 26-10-13, K2). `isdecimal()` has the same length
problem and accepts digits from every script. ASCII and a length cap answer the
question that was meant.

The gate refuses a bare `isdigit()`, `isdecimal()` or `isnumeric()` anywhere in
the repository (`tests/test_digits.py`); a node script, which cannot import
this, carries the same two-line check with `isascii()` beside it.
"""

from __future__ import annotations

#
# Longer than any count, port, version, PID or ID this code reads, and far
# inside what `int()` converts.
#
MAX_DIGITS = 18


def is_digits(text: str, *, limit: int = MAX_DIGITS) -> bool:
    """Text of one to `limit` ASCII digits."""

    return 0 < len(text) <= limit and text.isascii() and text.isdigit()
