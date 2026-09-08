"""The version token on local asset URLs.

A stylesheet change that a browser does not fetch is worse than no change: the
new markup arrives against the old CSS, and the page looks broken in a way that
points at the new code rather than at the cache. The token is what makes a
release's assets a different URL from the previous release's.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from haproxy_ui.views import STATIC_DIRECTORY, asset_token


class AssetTokenTests(unittest.TestCase):
    def test_the_token_changes_when_an_asset_does(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            static = Path(directory)
            stylesheet = static / "app.css"
            stylesheet.write_text("body { color: red }", encoding="utf-8")
            before = asset_token(static)

            stylesheet.write_text("body { color: blue and wider }", encoding="utf-8")
            after = asset_token(static)

        self.assertNotEqual(before, after)
        self.assertTrue(before.isalnum())

    def test_the_token_is_stable_for_an_unchanged_directory(self) -> None:
        # A release directory does not change under a running process, so two
        # reads of it must not produce two URLs.
        with tempfile.TemporaryDirectory() as directory:
            static = Path(directory)
            (static / "app.css").write_text("body {}", encoding="utf-8")

            self.assertEqual(asset_token(static), asset_token(static))

    def test_a_missing_directory_still_renders_a_page(self) -> None:
        #
        # A static mount that is not there is a deployment fault, and the mount
        # reports it. It must not be the reason a page cannot render the
        # diagnosis.
        #
        self.assertEqual(asset_token(Path("/nonexistent-static-directory")), "0")


if __name__ == "__main__":
    unittest.main()


class ShapesTheIconRuleReaches(unittest.TestCase):
    """Every SVG shape in the app inherits the icon dressing, whether it wants it.

    `svg { fill: none; stroke: currentcolor; stroke-width: 1.8 }` is written for
    the icon set and reaches every shape in every SVG on the page. A hover
    target added to the traffic sparkline cleared its fill and not its stroke,
    and shipped as sixty vertical bars drawn over the line - a picket fence
    where an invisible rectangle was intended.

    So: a shape meant to be invisible says so about both properties. Checked as
    text because that is where the mistake lives; no test can render CSS here,
    but this one names the rule that will catch the next shape.
    """

    def stylesheet(self) -> str:
        return (STATIC_DIRECTORY / "app.css").read_text(encoding="utf-8")

    def test_the_icon_rule_still_strokes_everything(self) -> None:
        """If this fails the rule below may no longer be needed - check, do not delete."""

        self.assertIn("svg { fill: none; stroke: currentcolor;", self.stylesheet())

    def test_an_invisible_shape_clears_its_stroke_too(self) -> None:
        rule = next(
            line for line in self.stylesheet().splitlines() if line.startswith(".traffic-hit {")
        )
        self.assertIn("stroke: none", rule)
        self.assertIn("fill: transparent", rule)

    def test_a_reading_is_not_shown_in_a_floating_box(self) -> None:
        """There is nowhere on a card this size to float one.

        A box wide enough for seven figures covers either the scale beside the
        line or the line itself, and clamping it to the card put it half
        outside on every bucket wider than the card. The figure row beneath the
        line has room, holds still, and was already there.
        """

        self.assertNotIn(".traffic-tip", self.stylesheet())
        script = (STATIC_DIRECTORY / "traffic.js").read_text(encoding="utf-8")
        self.assertNotIn("traffic-tip", script)
        self.assertIn(".traffic-figures", script)

    def test_the_page_range_switch_stays_below_the_sticky_header(self) -> None:
        stylesheet = self.stylesheet()
        rule = stylesheet.split(".page-ranges-sticky {", 1)[1].split("}", 1)[0]

        self.assertIn("position: sticky", rule)
        self.assertIn("top: 97px", rule)
        self.assertIn("width: 100%", rule)
        self.assertIn("padding: 6px 0", rule)
