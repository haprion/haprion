"""page.js: what the markup asks for by attribute instead of inline script (review 26-10-13, S2)."""

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
FILTER = (
    "<!doctype html><html><head><title>WAF</title>"
    '<script defer src="/static/page.js"></script></head><body>'
    '<form method="get" action="/waf"><label>Cluster<select name="cluster" data-submit-on-change>'
    '<option value="">All clusters</option><option value="alpha">alpha</option></select></label>'
    '<input name="note" required></form></body></html>'
)


class ASelectThatSubmits(unittest.TestCase):
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

    def test_choosing_submits_the_form_as_the_inline_handler_did(self) -> None:
        # submit(), not requestSubmit(): an empty required field elsewhere in
        # the form did not stop the old handler and must not stop this one.
        tab = self.browser.new_page()
        self.addCleanup(tab.close)
        tab.route(
            f"{ORIGIN}/static/page.js",
            lambda route: route.fulfill(path=str(STATIC_DIRECTORY / "page.js")),
        )
        tab.route(
            f"{ORIGIN}/waf*",
            lambda route: route.fulfill(content_type="text/html", body=FILTER),
        )
        tab.goto(f"{ORIGIN}/waf")
        with tab.expect_navigation():
            tab.select_option("select[name=cluster]", "alpha")
        self.assertIn("cluster=alpha", tab.url)


if __name__ == "__main__":
    unittest.main()
