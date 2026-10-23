"""The words the interface and its tools count with (review 2026-10-22, 7-2).

A count was written with a bracketed plural in a dozen places; a count says its noun
in the number it has. `tests/test_labels.py` refuses the bracketed plural.
"""

from __future__ import annotations


def noun(count: int, word: str, plural: str = "") -> str:
    """`word` for one, its plural for any other count: `plural`, or `word` with an s."""

    return word if count == 1 else plural or word + "s"


def counted(count: int, word: str, plural: str = "") -> str:
    """The count and its noun: "1 node", "2 nodes", "0 nodes"."""

    return f"{count} {noun(count, word, plural)}"
