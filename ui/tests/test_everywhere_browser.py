"""`Everywhere` and `Nobody` leave their lists while an address is written (2026-10-03)."""

from __future__ import annotations

import os
import unittest
from typing import Any, ClassVar

from haprion_ui.views import STATIC_DIRECTORY

if not os.environ.get("PLAYWRIGHT_BROWSERS_PATH"):
    raise RuntimeError(
        "set PLAYWRIGHT_BROWSERS_PATH to the directory holding the Playwright browsers"
    )

from playwright.sync_api import sync_playwright

ORIGIN = "https://manager.example.com"
PAGE = """<!doctype html>
<script src="/object-form.js"></script>
<form method="post" class="preview-form">
  <select name="allow_from" multiple size="5">
    <option value="" selected>Everywhere</option>
    <option value="office">office</option>
  </select>
  <textarea name="allow_ranges"></textarea>
  <select name="deny_from" multiple size="5">
    <option value="" selected>Nobody</option>
    <option value="office">office</option>
  </select>
  <textarea name="deny_ranges"></textarea>
</form>"""


class EmptyChoicesFollowTheAddresses(unittest.TestCase):
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

    def empty(self, page: Any, field: str = "allow_from") -> dict[str, bool]:
        state: dict[str, bool] = page.evaluate(
            "(field) => { const o = document.querySelector("
            "`select[name='${field}'] option[value='']`);"
            " return {hidden: o.hidden, selected: o.selected}; }",
            field,
        )
        return state

    def test_an_address_takes_it_away(self) -> None:
        page = self.page()

        page.fill("textarea[name=allow_ranges]", "country:SE")

        self.assertEqual(self.empty(page), {"hidden": True, "selected": False})

    def test_clearing_the_addresses_brings_it_back_chosen(self) -> None:
        page = self.page()
        page.fill("textarea[name=allow_ranges]", "country:SE")

        page.fill("textarea[name=allow_ranges]", "")

        self.assertEqual(self.empty(page), {"hidden": False, "selected": True})

    def test_a_chosen_group_keeps_it_unchosen_when_cleared(self) -> None:
        page = self.page()
        page.select_option("select[name=allow_from]", "office")
        page.fill("textarea[name=allow_ranges]", "country:SE")

        page.fill("textarea[name=allow_ranges]", "")

        self.assertEqual(self.empty(page), {"hidden": False, "selected": False})

    def test_a_denied_address_takes_nobody_away_and_leaves_everywhere(self) -> None:
        page = self.page()

        page.fill("textarea[name=deny_ranges]", "country:CN")

        self.assertEqual(self.empty(page, "deny_from"), {"hidden": True, "selected": False})
        self.assertEqual(self.empty(page), {"hidden": False, "selected": True})


if __name__ == "__main__":
    unittest.main()
