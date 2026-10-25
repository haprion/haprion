"""Every element a page opens is closed, in order (review 26-10-24, 04-13)."""

from __future__ import annotations

from html.parser import HTMLParser

# HTML's void elements: they have no end tag.
VOID = frozenset(
    {
        "area",
        "base",
        "br",
        "col",
        "embed",
        "hr",
        "img",
        "input",
        "link",
        "meta",
        "source",
        "track",
        "wbr",
    }
)


class _Nesting(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.open: list[tuple[str, int]] = []
        self.found: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag not in VOID:
            self.open.append((tag, self.getpos()[0]))

    def handle_endtag(self, tag: str) -> None:
        if tag in VOID:
            self.found.append(f"line {self.getpos()[0]}: </{tag}> closes a void element")
            return
        if not self.open or self.open[-1][0] != tag:
            expected = (
                f"</{self.open[-1][0]}> (opened on line {self.open[-1][1]})"
                if self.open
                else "nothing"
            )
            self.found.append(f"line {self.getpos()[0]}: </{tag}> where {expected} was due")
            # Resynchronise on the nearest matching element, so one slip is one finding.
            for index in range(len(self.open) - 1, -1, -1):
                if self.open[index][0] == tag:
                    del self.open[index:]
                    break
            return
        self.open.pop()


def problems(markup: str) -> list[str]:
    nesting = _Nesting()
    nesting.feed(markup)
    nesting.close()
    return nesting.found + [
        f"<{tag}> opened on line {line} is never closed" for tag, line in nesting.open
    ]
