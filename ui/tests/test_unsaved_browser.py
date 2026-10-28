"""Leaving the editor after a change asks first, in Chromium (B336).

The page arrives right from the server; this is the script's half: a change
not sent makes leaving ask, sending the form does not, and an untouched form
lets the page go without a word.
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
<form method="post" action="/sent" class="preview-form">
  <input name="description">
  <button type="submit">Save</button>
</form>"""


class LeavingTheEditor(unittest.TestCase):
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
        page.route(
            f"{ORIGIN}/object-form.js",
            lambda route: route.fulfill(
                path=str(STATIC_DIRECTORY / "object-form.js"), content_type="text/javascript"
            ),
        )
        page.route(
            f"{ORIGIN}/editor", lambda route: route.fulfill(body=PAGE, content_type="text/html")
        )
        page.goto(f"{ORIGIN}/editor")
        self.addCleanup(page.close)
        return page

    @staticmethod
    def leaving_asks(page: Any) -> bool:
        """Whether the page holds a departure back, as the browser asks it to.

        The event the browser fires itself: headless Chromium never draws the
        dialog for a closed page, but it draws it exactly when this is true.
        """

        return bool(
            page.evaluate(
                "(() => { const event = new Event('beforeunload', {cancelable: true});"
                " window.dispatchEvent(event); return event.defaultPrevented; })()"
            )
        )

    def test_a_change_not_sent_asks_before_the_page_goes(self) -> None:
        page = self.page()
        page.fill("input[name='description']", "changed")
        self.assertTrue(self.leaving_asks(page))

    def test_sending_the_form_is_not_leaving(self) -> None:
        page = self.page()
        page.fill("input[name='description']", "changed")
        page.evaluate(
            "document.querySelector('form').addEventListener('submit', e => e.preventDefault())"
        )
        page.click("button[type='submit']")
        self.assertFalse(self.leaving_asks(page))

    def test_an_untouched_form_lets_the_page_go(self) -> None:
        page = self.page()
        page.click("input[name='description']")
        self.assertFalse(self.leaving_asks(page))
