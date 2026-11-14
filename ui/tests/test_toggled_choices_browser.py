"""Groups chosen by a click and let go by a second, in Chromium (26-11-14).

With blocklists, *Denied — groups* and *Reachable from — groups* grew, and a
plain click chose one group and dropped the rest: more than one took Ctrl. A
click now toggles the group it lands on. The empty choice stands for none,
so it goes when a group is chosen, and comes back when the last one goes -
unless addresses are written beside it, where it is hidden.
"""

from __future__ import annotations

import os
import unittest
from typing import Any, ClassVar

from haprion_ui.templates import STATIC_DIRECTORY

if not os.environ.get("PLAYWRIGHT_BROWSERS_PATH"):
    raise RuntimeError(
        "set PLAYWRIGHT_BROWSERS_PATH to the directory holding the Playwright browsers"
    )

from playwright.sync_api import sync_playwright

ORIGIN = "https://manager.example.com"
PAGE = """<!doctype html>
<script src="/object-form.js"></script>
<form method="post" class="preview-form">
  <select name="deny_from" multiple size="5">
    <option value="" selected>Nobody</option>
    <option value="office">office</option>
    <option value="spamhaus-drop">spamhaus-drop</option>
    <option value="vpn">vpn</option>
  </select>
  <textarea name="deny_ranges"></textarea>
</form>"""


class ClickingAGroup(unittest.TestCase):
    playwright: ClassVar[Any]
    browser: ClassVar[Any]

    @classmethod
    def setUpClass(cls) -> None:
        cls.playwright = sync_playwright().start()
        cls.browser = cls.playwright.chromium.launch()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.browser.close()
        cls.playwright.stop()

    def page(self) -> Any:
        page = self.browser.new_page()
        self.addCleanup(page.close)
        page.route(f"{ORIGIN}/", lambda route: route.fulfill(content_type="text/html", body=PAGE))
        page.route(
            f"{ORIGIN}/object-form.js",
            lambda route: route.fulfill(
                content_type="text/javascript",
                body=(STATIC_DIRECTORY / "object-form.js").read_text(),
            ),
        )
        page.goto(f"{ORIGIN}/")
        return page

    def chosen(self, page: Any) -> list[str]:
        values: list[str] = page.evaluate(
            "() => Array.from(document.querySelector('select[name=deny_from]').selectedOptions)"
            ".map((o) => o.value)"
        )
        return values

    def click(self, page: Any, value: str) -> None:
        page.click(f"select[name=deny_from] option[value='{value}']")

    def test_clicks_add_groups_and_a_second_click_lets_one_go(self) -> None:
        page = self.page()

        self.click(page, "office")
        self.click(page, "spamhaus-drop")
        self.assertEqual(self.chosen(page), ["office", "spamhaus-drop"])

        self.click(page, "office")
        self.assertEqual(self.chosen(page), ["spamhaus-drop"])

    def test_letting_the_last_go_chooses_nobody_and_nobody_lets_all_go(self) -> None:
        page = self.page()
        self.click(page, "vpn")
        self.click(page, "vpn")
        self.assertEqual(self.chosen(page), [""])

        self.click(page, "office")
        self.click(page, "vpn")
        self.click(page, "")
        self.assertEqual(self.chosen(page), [""])

    def test_with_addresses_written_nothing_chosen_stays_nothing(self) -> None:
        page = self.page()
        page.fill("textarea[name=deny_ranges]", "198.51.100.0/24")
        self.click(page, "office")
        self.click(page, "office")
        self.assertEqual(self.chosen(page), [])


if __name__ == "__main__":
    unittest.main()
