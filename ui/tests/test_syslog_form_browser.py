"""The form following a switch to syslog and back, in Chromium (Fas 19b B4).

The page arrives right from the server; this is the script's half. A syslog
object is offered a udp check as it becomes one, the port takes 514 as its
example, and a tcp check's send and expect - which depend on both the check
and the protocol - follow either choice.
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
    <option value="syslog">Syslog (UDP)</option>
  </select>
  <label class="tcp-only" data-protocol="tcp dns syslog" data-show-when="protocol:tcp dns syslog">Port
    <input name="tcp_port" placeholder="5432" data-placeholders="tcp:5432 dns:53 syslog:514"></label>
  <select name="health_type">
    <option value="disabled" data-show-when="protocol:http https tcp dns syslog" selected>disabled</option>
    <option value="tcp" data-show-when="protocol:http https tcp syslog">tcp</option>
    <option value="tcp-tls" data-show-when="protocol:http https tcp">tcp, TLS handshake</option>
    <option value="udp" data-show-when="protocol:syslog" hidden>udp</option>
  </select>
  <label data-show-when="health_type:tcp tcp-tls;protocol:http https tcp" hidden>Send<input name="health_send"></label>
  <label data-show-when="protocol:http https tcp dns">Rise<input name="health_rise"></label>
</form>"""


class SwitchingToSyslog(unittest.TestCase):
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
                check: document.querySelector("select[name=health_type]").value,
                port: document.querySelector("input[name=tcp_port]").placeholder,
                send: document.querySelector("input[name=health_send]").closest("label").hidden,
                rise: document.querySelector("input[name=health_rise]").closest("label").hidden,
            })"""
        )
        return found

    def test_becoming_syslog_suggests_a_udp_check(self) -> None:
        page = self.page()

        page.select_option("select[name=protocol]", "syslog")

        self.assertEqual(
            self.state(page), {"check": "udp", "port": "514", "send": True, "rise": True}
        )

    def test_a_check_somebody_chose_stays_chosen(self) -> None:
        page = self.page()
        page.select_option("select[name=health_type]", "tcp")

        page.select_option("select[name=protocol]", "syslog")

        self.assertEqual(self.state(page)["check"], "tcp")

    def test_a_tcp_check_s_exchange_follows_the_protocol_as_well(self) -> None:
        page = self.page()
        page.select_option("select[name=health_type]", "tcp")
        self.assertFalse(self.state(page)["send"])

        page.select_option("select[name=protocol]", "syslog")
        self.assertTrue(self.state(page)["send"])

        page.select_option("select[name=protocol]", "tcp")
        self.assertFalse(self.state(page)["send"])

    def test_a_check_tcp_does_not_have_moves_to_one_it_does(self) -> None:
        page = self.page()
        page.select_option("select[name=protocol]", "syslog")

        page.select_option("select[name=protocol]", "tcp")

        self.assertEqual(self.state(page)["check"], "disabled")
        self.assertEqual(self.state(page)["port"], "5432")

    def test_a_tls_check_becomes_none_and_then_udp(self) -> None:
        """Hidden for syslog, so it moves to the first offered - and that one is suggested."""

        page = self.page()
        page.select_option("select[name=health_type]", "tcp-tls")

        page.select_option("select[name=protocol]", "syslog")

        self.assertEqual(self.state(page)["check"], "udp")


if __name__ == "__main__":
    unittest.main()
