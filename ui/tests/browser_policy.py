"""Fail a browser test on anything the Content-Security-Policy refused (review 26-10-13, S2).

A refused inline style or script is not an error the page raises: the browser
leaves it out and says so on the console, and the page goes on looking almost
right. So every browser test against the real app listens for that line.
"""

from __future__ import annotations

import unittest
from typing import Any


def watch(test: unittest.TestCase, page: Any) -> list[str]:
    refused: list[str] = []

    def heard(message: Any) -> None:
        if "Content Security Policy" in message.text:
            refused.append(message.text)

    page.on("console", heard)
    test.addCleanup(lambda: test.assertEqual(refused, [], "the policy refused something"))
    return refused
