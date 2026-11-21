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


def _tall(form_action: str) -> str:
    """A page taller than the window, with a form far down."""

    return (
        "<!doctype html><html><head><title>Review</title>"
        '<script defer src="/static/page.js"></script></head><body>'
        '<div style="height: 3000px">top</div>'
        f'<form method="post" action="{form_action}" data-keep-place>'
        '<button type="submit">Accept</button></form>'
        '<div style="height: 3000px">bottom</div></body></html>'
    )


class AFormThatKeepsThePlace(unittest.TestCase):
    """data-keep-place (pass U): the page that comes back lands where the reader was.

    The answer is the page itself rather than a 303 to it: a fulfilled
    redirect is not routed again, and what page.js reads is only the path the
    next page loads at, which is the same either way.
    """

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

    def tab(self, action: str) -> Any:
        tab = self.browser.new_page(viewport={"width": 1280, "height": 800})
        self.addCleanup(tab.close)
        tab.route(
            f"{ORIGIN}/static/page.js",
            lambda route: route.fulfill(path=str(STATIC_DIRECTORY / "page.js")),
        )
        for path in ("/proxies/review", "/elsewhere"):
            tab.route(
                f"{ORIGIN}{path}",
                lambda route: route.fulfill(content_type="text/html", body=_tall(action)),
            )
        tab.goto(f"{ORIGIN}/proxies/review")
        tab.locator("button").scroll_into_view_if_needed()
        return tab

    def test_the_same_page_comes_back_where_it_was(self) -> None:
        tab = self.tab("/proxies/review")
        before = tab.evaluate("window.scrollY")
        self.assertGreater(before, 1000)
        with tab.expect_navigation():
            tab.click("button")
        tab.wait_for_load_state("load")
        self.assertEqual(tab.evaluate("window.scrollY"), before)

    def test_another_page_starts_at_the_top_and_nothing_is_left_over(self) -> None:
        tab = self.tab("/elsewhere")
        with tab.expect_navigation():
            tab.click("button")
        tab.wait_for_load_state("load")
        self.assertEqual(tab.url, f"{ORIGIN}/elsewhere")
        self.assertEqual(tab.evaluate("window.scrollY"), 0)
        self.assertIsNone(tab.evaluate("sessionStorage.getItem('haprion.place')"))


if __name__ == "__main__":
    unittest.main()
