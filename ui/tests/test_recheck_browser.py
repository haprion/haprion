"""Test health check answers in place, without reloading the form (2026-09-30)."""

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

ORIGIN = "https://manager.example.com"
PAGE = """<!doctype html>
<script src="/object-form.js"></script>
<form method="post" action="/proxies/alpha/shop/edit" class="preview-form">
  <input type="hidden" name="csrf_token" value="token">
  <input name="name" value="shop">
  <button type="submit" name="action" value="recheck">Test health check</button>
  <div class="node-health"><p>before</p></div>
</form>"""
ANSWER = """<!doctype html>
<form class="preview-form"><div class="node-health"><p>tested now</p></div></form>"""


class TheTestAnswersInPlace(unittest.TestCase):
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

    def page(self, answer: str, status: int = 200) -> tuple[Any, list[str]]:
        page = self.browser.new_page()
        self.addCleanup(page.close)
        sent: list[str] = []
        page.route(f"{ORIGIN}/", lambda route: route.fulfill(content_type="text/html", body=PAGE))
        page.route(
            f"{ORIGIN}/object-form.js",
            lambda route: route.fulfill(
                content_type="text/javascript",
                body=(STATIC_DIRECTORY / "object-form.js").read_text(),
            ),
        )

        def receive(route: Any) -> None:
            sent.append(route.request.post_data or "")
            route.fulfill(status=status, content_type="text/html", body=answer)

        page.route(f"{ORIGIN}/proxies/alpha/shop/edit", receive)
        page.goto(f"{ORIGIN}/")
        page.evaluate("window.stillHere = true")
        return page, sent

    def test_only_the_health_block_changes(self) -> None:
        page, sent = self.page(ANSWER)
        page.fill("input[name=name]", "typed")

        page.click("button")
        page.wait_for_selector("text=tested now")

        self.assertTrue(page.evaluate("window.stillHere === true"))
        self.assertEqual(page.input_value("input[name=name]"), "typed")
        self.assertEqual(len(sent), 1)
        self.assertIn("action=recheck", sent[0])
        self.assertIn("csrf_token=token", sent[0])
        self.assertIsNone(page.evaluate("sessionStorage.getItem('object-form-scroll')"))

    def test_an_answer_it_cannot_read_falls_back_to_the_ordinary_submit(self) -> None:
        page, sent = self.page("<!doctype html><p>something else</p>")

        with page.expect_navigation():
            page.click("button")

        self.assertEqual(len(sent), 2)
        self.assertFalse(page.evaluate("window.stillHere === true"))


if __name__ == "__main__":
    unittest.main()
