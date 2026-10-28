"""A button's text is readable on it, in both themes (review 2026-10-22, 2-7).

White on the brand green was 2.74:1 in the light theme and 2.24:1 in the dark;
WCAG AA asks 4.5:1 for normal text. The buttons take their colours from
`--go`/`--go-text` and `--stop`/`--stop-text`, and this reads them from the
stylesheet and measures them.
"""

from __future__ import annotations

import re
import unittest

from haprion_ui.templates import STATIC_DIRECTORY

CSS = (STATIC_DIRECTORY / "app.css").read_text(encoding="utf-8")
AA = 4.5


def _block(selector: str) -> dict[str, str]:
    start = CSS.index(selector + " {")
    body = CSS[start : CSS.index("\n}", start)]
    return dict(re.findall(r"(--[a-z-]+):\s*(#[0-9a-fA-F]{6})", body))


def _luminance(colour: str) -> float:
    def channel(value: int) -> float:
        c = value / 255
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4

    r, g, b = (int(colour[i : i + 2], 16) for i in (1, 3, 5))
    return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)


def _ratio(one: str, other: str) -> float:
    light, dark = sorted((_luminance(one), _luminance(other)), reverse=True)
    return (light + 0.05) / (dark + 0.05)


class ButtonsAreReadable(unittest.TestCase):
    def test_each_button_s_text_on_its_colour_in_each_theme(self) -> None:
        for theme, selector in (("light", ":root"), ("dark", ':root[data-theme="dark"]')):
            colours = _block(selector)
            for background, text, hover in (
                ("--go", "--go-text", "--go-hover"),
                ("--stop", "--stop-text", None),
            ):
                with self.subTest(theme, button=background):
                    self.assertGreaterEqual(
                        _ratio(colours[background], colours[text]), AA, f"{background} in {theme}"
                    )
                    if hover:
                        self.assertGreaterEqual(_ratio(colours[hover], colours[text]), AA)

    def test_the_buttons_take_those_colours(self) -> None:
        for rule, background, text in (
            (".primary-button {", "var(--go)", "var(--go-text)"),
            (".danger-button {", "var(--stop)", "var(--stop-text)"),
            (".secondary-button.deploy-due {", "var(--go)", "var(--go-text)"),
        ):
            with self.subTest(rule):
                bodies = [
                    CSS[start : CSS.index("}", start)]
                    for start in (match.start() for match in re.finditer(re.escape(rule), CSS))
                ]
                painted = [body for body in bodies if "background:" in body]
                self.assertEqual(len(painted), 1, rule)
                self.assertIn(f"background: {background}", painted[0])
                self.assertIn(f"color: {text}", painted[0])


class TheFocusRingIsSeen(unittest.TestCase):
    """Review 26-10-24, 04-12: the halo was about 1.2:1 in light and 1.7:1 in dark.

    WCAG 1.4.11 asks 3:1 for what shows a control's state.
    """

    def test_the_ring_s_colour_against_the_panel_and_the_page_in_each_theme(self) -> None:
        for theme, selector in (("light", ":root"), ("dark", ':root[data-theme="dark"]')):
            colours = _block(selector)
            for ground in ("--panel", "--bg"):
                with self.subTest(theme, ground=ground):
                    self.assertGreaterEqual(_ratio(colours["--brand-strong"], colours[ground]), 3.0)

    def test_every_focus_ring_is_drawn_in_that_colour(self) -> None:
        self.assertIn(":focus-visible { outline: 2px solid var(--brand-strong);", CSS)
        self.assertEqual(
            re.findall(r"--focus: ([^;]+);", CSS), ["0 0 0 2px var(--brand-strong)"] * 2
        )
        self.assertNotRegex(CSS, r"focus[^{]*\{[^}]*outline: 2px solid var\(--brand\)")


class EveryBadgeHasATone(unittest.TestCase):
    """Review 26-10-24, 04-14: "Off" was a pill with no colour, bold text in a frame
    of nothing. A state that is neither good nor bad is the grey `unknown` tone,
    or plain text where its neighbours are (26-10-25)."""

    def test_no_template_draws_a_status_badge_without_one(self) -> None:
        templates = STATIC_DIRECTORY.parent / "templates"
        untoned = [
            f"{path.name}: {match.group(0)}"
            for path in sorted(templates.glob("*.html"))
            for match in re.finditer(r'class="([^"]*)"', path.read_text(encoding="utf-8"))
            if re.search(r"(^| )status-badge( |$)", match.group(1))
            and "status-badge-" not in match.group(1)
        ]
        self.assertEqual(untoned, [])


if __name__ == "__main__":
    unittest.main()
