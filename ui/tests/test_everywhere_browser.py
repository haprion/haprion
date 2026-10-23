"""`Everywhere` and `Nobody` leave their lists while an address is written (2026-10-03).

And a dns listener left reachable from everywhere says so under the field (B357).
"""

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
  <select name="protocol">
    <option value="tcp" selected>TCP</option>
    <option value="dns">DNS</option>
  </select>
  <select name="allow_from" multiple size="5">
    <option value="" selected>Everywhere</option>
    <option value="office">office</option>
  </select>
  <small class="warning-text" data-open-dns-note hidden>Answers DNS queries from anywhere.</small>
  <textarea name="allow_ranges"></textarea>
  <select name="deny_from" multiple size="5">
    <option value="" selected>Nobody</option>
    <option value="office">office</option>
  </select>
  <textarea name="deny_ranges"></textarea>
</form>"""


class InTheBrowser(unittest.TestCase):
    """The page above in Chromium; no tests of its own."""

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


class EmptyChoicesFollowTheAddresses(InTheBrowser):
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


class AnOpenDnsListenerIsSaid(InTheBrowser):
    def open_note(self, page: Any) -> bool:
        return bool(page.is_visible("[data-open-dns-note]"))

    def test_only_a_dns_listener_from_everywhere_says_it(self) -> None:
        page = self.page()
        self.assertFalse(self.open_note(page))

        page.select_option("select[name=protocol]", "dns")
        self.assertTrue(self.open_note(page))

        page.fill("textarea[name=allow_ranges]", "198.51.100.0/24")
        self.assertFalse(self.open_note(page))
        page.fill("textarea[name=allow_ranges]", "")
        self.assertTrue(self.open_note(page))

        page.select_option("select[name=allow_from]", "office")
        self.assertFalse(self.open_note(page))

    def test_the_form_carries_the_note_this_page_stands_in_for(self) -> None:
        form = (STATIC_DIRECTORY.parent / "templates" / "_object-form.html").read_text()
        self.assertIn('<small class="warning-text" data-open-dns-note hidden><svg', form)
        self.assertIn("</svg>Answers DNS queries from anywhere.</small>", form)


if __name__ == "__main__":
    unittest.main()
