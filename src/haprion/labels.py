"""A count in words: the number and its noun in that number (review 2026-10-22, 7-2).

The interface and the tools wrote a bracketed plural in dozens of messages;
`tests/test_labels.py` refuses it across the repository. The web interface
imports these through `haprion_ui.labels`.
"""

from __future__ import annotations


def noun(count: int, word: str, plural: str = "") -> str:
    """`word` for one, its plural for any other count: `plural`, or `word` with an s."""

    return word if count == 1 else plural or word + "s"


def counted(count: int, word: str, plural: str = "") -> str:
    """The count and its noun: "1 node", "2 nodes", "0 nodes"."""

    return f"{count} {noun(count, word, plural)}"
