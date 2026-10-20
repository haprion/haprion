"""What moved under a draft, as the browser draws it (0080, 26-10-20).

The first drawing broke an address in the middle at phone width -
`192.0.2.10:80` over `80` - which reads as two values. Measured here: every
value stays on one line, the page does not scroll sideways, and the choice is
in the box.

The server is the application itself on a loopback port, as the settings
browser suite runs it, with the editor suite's substituted readings.
"""

from __future__ import annotations

import contextlib
import threading
import unittest
from collections.abc import Iterator
from dataclasses import replace
from typing import Any, ClassVar

import uvicorn
from playwright.sync_api import Browser, Playwright

from haprion_ui.app import create_app
from tests import browser_policy
from tests.test_editor_page import SHOP, EditorTestCase, writing_configuration
from tests.test_login import PASSWORD
from tests.test_moved_under import draft
from tests.test_traffic_browser import free_port, sync_playwright

#
# Each value beside a field: how many lines it took, by its height against the
# height of one line of its text.
#
LINES = """spans => spans.map(span => {
  const style = getComputedStyle(span);
  return Math.round(span.getBoundingClientRect().height / parseFloat(style.lineHeight));
})"""


class WhatMovedFitsItsBox(EditorTestCase):
    _playwright: ClassVar[Playwright]
    _browser: ClassVar[Browser]

    @classmethod
    def setUpClass(cls) -> None:
        cls._playwright = sync_playwright().start()
        cls._browser = cls._playwright.chromium.launch()

    @classmethod
    def tearDownClass(cls) -> None:
        cls._browser.close()
        cls._playwright.stop()

    def setUp(self) -> None:
        super().setUp()
        #
        # A value pair longer than one line at phone width, each value shorter:
        # the drawing that broke inside an address.
        #
        self.draft = draft(
            base_document=SHOP.replace("shop.example.com", "storefront-archive.example.com")
        )
        self.account = replace(self.account, role="admin")
        self.port = free_port()
        server = uvicorn.Server(
            uvicorn.Config(
                create_app(writing_configuration()),
                host="127.0.0.1",
                port=self.port,
                log_level="warning",
            )
        )
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(setattr, server, "should_exit", True)
        for _ in range(200):
            if server.started:
                break
            threading.Event().wait(0.05)
        else:
            self.fail("the test server did not start")

    @contextlib.contextmanager
    def editor_at(self, width: int) -> Iterator[Any]:
        page = self._browser.new_page(viewport={"width": width, "height": 900})
        browser_policy.watch(self, page)
        try:
            page.goto(f"http://127.0.0.1:{self.port}/login")
            page.fill("input[name=username]", "operator")
            page.fill("input[name=password]", PASSWORD)
            page.click("button[type=submit]")
            page.wait_for_url(f"http://127.0.0.1:{self.port}/")
            page.goto(f"http://127.0.0.1:{self.port}/proxies/alpha/shop/edit")
            page.wait_for_selector(".moved-under")
            yield page
        finally:
            page.close()

    def test_each_value_stays_whole_and_the_choice_is_in_the_box(self) -> None:
        for width in (1280, 390):
            with self.subTest(width=width), self.editor_at(width) as page:
                lines = page.eval_on_selector_all(
                    ".moved-fields dd > span:not(.moved-arrow)", LINES
                )
                self.assertTrue(lines, "nothing moved to measure")
                self.assertEqual(set(lines), {1}, lines)
                self.assertTrue(
                    page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
                )
                box = page.locator(".moved-under").bounding_box()
                assert box is not None  # noqa: S101 - waited for above
                for button in page.locator(".moved-under button").all():
                    place = button.bounding_box()
                    assert place is not None  # noqa: S101 - drawn with the box
                    self.assertLessEqual(place["x"] + place["width"], box["x"] + box["width"])


if __name__ == "__main__":
    unittest.main()
