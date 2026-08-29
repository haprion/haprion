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

from haproxy_ui.views import asset_token


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
