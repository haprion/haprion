"""The answer to *Check HTTP-01*, drawn from the engine's own sentence.

The words are `Check.sentence()` and nothing else: the page only marks the
name and its `http://name/` address as code. A sentence the page composed
itself could drift from the terminal's.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from haprion.http01_check import Check, CheckError


@dataclass(frozen=True)
class Answer:
    """A status colour and the sentence as (text, is_code) pieces; joined, the sentence."""

    tone: str
    pieces: tuple[tuple[str, bool], ...]

    @property
    def text(self) -> str:
        return "".join(text for text, _ in self.pieces)


def _pieces(sentence: str, name: str) -> tuple[tuple[str, bool], ...]:
    """The sentence cut at the name and its address, which are the code pieces."""

    #
    # Not a name inside a longer one: `app.example.com` in the sentence is
    # the name, `x.app.example.com` in a redirect's words is not.
    #
    quoted = re.escape(name)
    pattern = re.compile(rf"(?<![\w.-])(?:http://{quoted}/|{quoted})(?!\.?[\w-])")
    pieces: list[tuple[str, bool]] = []
    position = 0
    for match in pattern.finditer(sentence):
        if match.start() > position:
            pieces.append((sentence[position : match.start()], False))
        pieces.append((match.group(), True))
        position = match.end()
    if position < len(sentence):
        pieces.append((sentence[position:], False))
    return tuple(pieces)


def of_check(check: Check) -> Answer:
    tone = "healthy" if check.answer == "reached" else "critical"
    return Answer(tone, _pieces(check.sentence(), check.name))


def of_error(error: CheckError) -> Answer:
    return Answer("critical", ((str(error), False),))
