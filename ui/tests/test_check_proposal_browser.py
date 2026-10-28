"""A check offered as a pool takes its protocol, in Chromium (B349, review 2026-10-22, 7-3).

The page arrives from the server with the offer for a new pool; this is the
script's half: another protocol's offer, the offer following the servers'
TLS, and a check somebody chose left alone.
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
  <select name="protocol">
    <option value="https" selected>HTTPS</option>
    <option value="http">HTTP</option>
    <option value="tcp">TCP</option>
  </select>
  <select name="backend_tls">
    <option value="" selected>Plain HTTP</option>
    <option value="system">HTTPS, verify the certificate</option>
  </select>
  <select name="health_type"%s>
    <option value="disabled">disabled</option>
    <option value="http"%s>http</option>
    <option value="https">https</option>
    <option value="tcp">tcp</option>
  </select>
  <input name="health_path" value="%s">
  <input name="health_expect_status" value="%s">
</form>"""
NEW_POOL = PAGE % (' data-proposed="http"', " selected", "/", "200-499")
UNCHECKED = PAGE % ("", "", "", "")


class AnOfferedCheck(unittest.TestCase):
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

    def page(self, body: str) -> Any:
        page = self.browser.new_page()
        self.addCleanup(page.close)
        page.route(f"{ORIGIN}/", lambda route: route.fulfill(content_type="text/html", body=body))
        page.route(
            f"{ORIGIN}/object-form.js",
            lambda route: route.fulfill(
                content_type="text/javascript",
                body=(STATIC_DIRECTORY / "object-form.js").read_text(),
            ),
        )
        page.goto(f"{ORIGIN}/")
        return page

    def state(self, page: Any) -> tuple[str, str, str]:
        found: list[str] = page.evaluate(
            """() => ["health_type", "health_path", "health_expect_status"].map(
                (name) => document.querySelector(`[name=${name}]`).value)"""
        )
        return found[0], found[1], found[2]

    def test_a_new_pool_s_check_follows_its_servers_to_tls_and_back(self) -> None:
        page = self.page(NEW_POOL)

        page.select_option("select[name=backend_tls]", "system")
        self.assertEqual(self.state(page)[0], "https")

        page.select_option("select[name=backend_tls]", "")
        self.assertEqual(self.state(page)[0], "http")

    def test_an_offer_becomes_tcp_s_and_comes_back(self) -> None:
        page = self.page(NEW_POOL)

        page.select_option("select[name=protocol]", "tcp")
        self.assertEqual(self.state(page)[0], "tcp")

        page.select_option("select[name=protocol]", "http")
        self.assertEqual(self.state(page), ("http", "/", "200-499"))

    def test_a_pool_without_a_check_is_offered_one_on_the_switch(self) -> None:
        page = self.page(UNCHECKED)

        page.select_option("select[name=protocol]", "http")

        self.assertEqual(self.state(page), ("http", "/", "200-499"))

    def test_a_check_somebody_chose_stays_chosen(self) -> None:
        page = self.page(NEW_POOL)
        page.select_option("select[name=health_type]", "disabled")

        page.select_option("select[name=protocol]", "tcp")
        page.select_option("select[name=backend_tls]", "system")

        # Disabled by hand is still `disabled`, which is offered a check on a switch.
        self.assertEqual(self.state(page)[0], "tcp")
        page.select_option("select[name=health_type]", "disabled")
        page.select_option("select[name=protocol]", "http")
        self.assertEqual(self.state(page)[0], "https")

    def test_a_chosen_check_is_not_replaced(self) -> None:
        page = self.page(NEW_POOL)
        page.select_option("select[name=health_type]", "https")

        page.select_option("select[name=protocol]", "tcp")
        page.select_option("select[name=backend_tls]", "")

        self.assertEqual(self.state(page)[0], "https")


if __name__ == "__main__":
    unittest.main()
