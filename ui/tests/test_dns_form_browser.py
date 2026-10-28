"""The form following a switch to DNS and back, in Chromium (Fas 19a B5).

The page arrives right from the server; this is the script's half. A choice
the new protocol does not offer - HAProxy's `leastconn`, an http check - must
not stay chosen out of sight, and the port takes the protocol's example.
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
    <option value="tcp" selected>TCP</option>
    <option value="dns">DNS</option>
  </select>
  <label class="tcp-only" data-protocol="tcp dns" data-show-when="protocol:tcp dns">Port
    <input name="tcp_port" placeholder="5432" data-placeholders="tcp:5432 dns:53"></label>
  <select name="balance">
    <option value="roundrobin" data-show-when="protocol:http https tcp dns">roundrobin</option>
    <option value="leastconn" data-show-when="protocol:http https tcp" selected>leastconn</option>
    <option value="chashed" data-show-when="protocol:dns" hidden>chashed</option>
  </select>
  <select name="health_type">
    <option value="disabled" data-show-when="protocol:http https tcp dns">disabled</option>
    <option value="tcp" data-show-when="protocol:http https tcp" selected>tcp</option>
    <option value="dns" data-show-when="protocol:dns" hidden>dns query</option>
  </select>
  <label data-show-when="health_type:dns" hidden>Query name<input name="health_query_name"></label>
  <label data-show-when="health_type:tcp tcp-tls">Send<input name="health_send"></label>
</form>"""


class SwitchingToDns(unittest.TestCase):
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

    def state(self, page: Any) -> dict[str, Any]:
        found: dict[str, Any] = page.evaluate(
            """() => ({
                balance: document.querySelector("select[name=balance]").value,
                check: document.querySelector("select[name=health_type]").value,
                port: document.querySelector("input[name=tcp_port]").placeholder,
                portDisabled: document.querySelector("input[name=tcp_port]").disabled,
                question: document.querySelector("input[name=health_query_name]")
                    .closest("label").hidden,
                send: document.querySelector("input[name=health_send]").closest("label").hidden,
            })"""
        )
        return found

    def test_choices_dns_does_not_offer_move_to_ones_it_does(self) -> None:
        page = self.page()

        page.select_option("select[name=protocol]", "dns")

        self.assertEqual(
            self.state(page),
            {
                "balance": "roundrobin",
                "check": "disabled",
                "port": "53",
                "portDisabled": False,
                "question": True,
                "send": True,
            },
        )

    def test_a_dns_check_shows_its_question(self) -> None:
        page = self.page()
        page.select_option("select[name=protocol]", "dns")

        page.select_option("select[name=health_type]", "dns")

        self.assertFalse(self.state(page)["question"])

    def test_back_to_tcp_the_example_is_tcp_s_again(self) -> None:
        page = self.page()
        page.select_option("select[name=protocol]", "dns")

        page.select_option("select[name=protocol]", "tcp")

        self.assertEqual(self.state(page)["port"], "5432")


if __name__ == "__main__":
    unittest.main()
