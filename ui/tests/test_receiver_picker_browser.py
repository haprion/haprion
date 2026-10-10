"""The receiver chooser stays usable when the registry is no longer short."""

from __future__ import annotations

import os
import unittest
from typing import Any, ClassVar

from haprion_ui.views import STATIC_DIRECTORY

if not os.environ.get("PLAYWRIGHT_BROWSERS_PATH"):
    raise RuntimeError(
        "set PLAYWRIGHT_BROWSERS_PATH to the directory holding the Playwright browsers"
    )

from playwright.sync_api import sync_playwright  # noqa: E402


class ReceiverPickerInABrowser(unittest.TestCase):
    playwright: ClassVar[Any]
    browser: ClassVar[Any]
    page: Any

    @classmethod
    def setUpClass(cls) -> None:
        cls.playwright = sync_playwright().start()
        cls.browser = cls.playwright.chromium.launch()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.browser.close()
        cls.playwright.stop()

    def setUp(self) -> None:
        self.page = self.browser.new_page()
        self.addCleanup(self.page.close)
        options = "".join(
            f'<label data-receiver-option><input type="checkbox" value="receiver-{number:02}.example.net">'
            f"<span>receiver-{number:02}.example.net</span></label>"
            for number in range(28)
        )
        self.page.set_content(
            f"""
            <span data-receiver-count aria-live="polite">0 selected</span>
            <label data-receiver-search hidden><input type="search"></label>
            <div data-receiver-options>{options}</div>
            <span data-receiver-empty hidden>No receivers match.</span>
            """
        )
        self.page.add_script_tag(path=str(STATIC_DIRECTORY / "receiver-picker.js"))

    def test_selection_updates_the_count_without_reordering_the_list(self) -> None:
        first = self.page.locator("[data-receiver-option]").first
        last = self.page.locator("[data-receiver-option]").last
        before = first.inner_text()

        last.locator("input").check()

        self.assertEqual(self.page.locator("[data-receiver-count]").inner_text(), "1 selected")
        self.assertEqual(first.inner_text(), before)

    def test_search_filters_twenty_eight_receivers_and_can_report_no_match(self) -> None:
        search = self.page.locator("[data-receiver-search]")
        self.assertTrue(search.is_visible())

        search.locator("input").fill("receiver-17")
        self.assertEqual(self.page.locator("[data-receiver-option]:visible").count(), 1)
        self.assertIn(
            "receiver-17.example.net",
            self.page.locator("[data-receiver-option]:visible").inner_text(),
        )

        search.locator("input").fill("missing")
        self.assertEqual(self.page.locator("[data-receiver-option]:visible").count(), 0)
        self.assertTrue(self.page.locator("[data-receiver-empty]").is_visible())


if __name__ == "__main__":
    unittest.main()
