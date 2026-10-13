"""A state said in words is readable in both themes (review 26-10-13, U2).

The lamp colours were used for small text too, amber at about 2:1 on white.
Each state now has a `-text` colour; this keeps the words on it and the
contrast at 4.5:1 or more, computed from the stylesheet itself.
"""

from __future__ import annotations

import re
import unittest

from haprion_ui.views import STATIC_DIRECTORY

CSS = (STATIC_DIRECTORY / "app.css").read_text(encoding="utf-8")
STATES = ("healthy", "warning", "critical", "info", "unknown")
TOKEN = re.compile(r"--([a-z0-9-]+):\s*(#[0-9a-f]{6})\s*;")


def block(selector: str) -> dict[str, str]:
    start = CSS.index(selector + " {")
    return dict(TOKEN.findall(CSS[start : CSS.index("\n}", start)]))


def luminance(colour: str) -> float:
    channels = [int(colour[index : index + 2], 16) / 255 for index in (1, 3, 5)]
    linear = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def contrast(one: str, other: str) -> float:
    high, low = sorted((luminance(one), luminance(other)), reverse=True)
    return (high + 0.05) / (low + 0.05)


class StatesInWords(unittest.TestCase):
    def test_every_state_reads_on_the_panel_and_its_own_background(self) -> None:
        light = block(":root")
        dark = {**light, **block(':root[data-theme="dark"]')}
        for theme, tokens in (("light", light), ("dark", dark)):
            for state in STATES:
                text = tokens[f"{state}-text"]
                for ground in ("panel", "panel-soft", f"{state}-soft"):
                    with self.subTest(theme=theme, state=state, ground=ground):
                        self.assertGreaterEqual(contrast(text, tokens[ground]), 4.5)

    def test_no_text_is_coloured_with_a_lamp(self) -> None:
        lamp = re.compile(r"(?:^|[\s;{])color: var\(--(?:" + "|".join(STATES) + r")\)", re.M)
        self.assertEqual(lamp.findall(CSS), [])


if __name__ == "__main__":
    unittest.main()
