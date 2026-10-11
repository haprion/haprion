"""waf.js opens Allow… in a dialog over the WAF page (B235, mock round 7)."""

from __future__ import annotations

import os
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, ClassVar
from unittest import mock

from haprion_ui.views import STATIC_DIRECTORY
from tests.test_editor_page import EditorTestCase
from tests.test_waf_page import CATALOG, LOGGING, finding, objects

if not os.environ.get("PLAYWRIGHT_BROWSERS_PATH"):
    raise RuntimeError(
        "set PLAYWRIGHT_BROWSERS_PATH to the directory holding the Playwright browsers"
    )

from playwright.sync_api import sync_playwright  # noqa: E402

ALLOW = "/waf/allow?cluster=alpha&object=shop&rule=942100&field=ARGS:q&path=/search"


class TheAllowDialog(EditorTestCase):
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

    def setUp(self) -> None:
        super().setUp()
        for target, value in (
            ("haprion_ui.db.waf_findings", [finding()]),
            ("haprion_ui.db.waf_verdicts", {("alpha", "shop"): (14, 3)}),
            ("haprion_ui.db.waf_request_count", 0),
            ("haprion_ui.db.waf_counted", []),
            ("haprion_ui.db.cluster_objects", objects(LOGGING)),
            ("haprion.crs.installed_catalog", CATALOG),
        ):
            patch = mock.patch(target, return_value=value)
            patch.start()
            self.addCleanup(patch.stop)
        client = self.editor()
        self.listing = client.get("/waf").text
        self.allow = client.get(ALLOW).text
        self.refused = client.post(
            "/waf/allow",
            data={
                "csrf_token": self.token(client),
                "cluster": "alpha",
                "object": "shop",
                "rule": "942100",
                "field": "ARGS:q",
                "path": ["/search"],
                "scope": "field_paths",
            },
        ).text
        self.posts: list[str] = []

    def page(self, *, refuse: bool) -> Any:
        #
        # A real server on the loopback rather than routed requests: the
        # browser does not route the request a redirect leads to, and the
        # redirect after a saved exception is what is being proved.
        #
        test = self

        class Answer(BaseHTTPRequestHandler):
            def log_message(self, *_args: Any) -> None:
                pass

            def reply(self, status: int, body: str = "", location: str = "") -> None:
                data = body.encode()
                self.send_response(status)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                if location:
                    self.send_header("Location", location)
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self) -> None:  # noqa: N802
                if self.path.startswith("/static/"):
                    self.reply(200)
                elif self.path.startswith("/waf/allow"):
                    self.reply(200, test.allow)
                else:
                    self.reply(200, test.listing)

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length", "0"))
                test.posts.append(self.rfile.read(length).decode())
                if refuse:
                    self.reply(409, test.refused)
                else:
                    self.reply(303, location="/waf?saved=shop&in=alpha")

        server = ThreadingHTTPServer(("127.0.0.1", 0), Answer)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.origin = f"http://127.0.0.1:{server.server_address[1]}"
        page = self.browser.new_page()
        self.addCleanup(page.close)
        page.goto(f"{self.origin}/waf")
        page.add_script_tag(path=str(STATIC_DIRECTORY / "waf.js"))
        return page

    def test_allow_opens_over_the_page_and_cancel_closes_it(self) -> None:
        page = self.page(refuse=False)
        page.click("[data-waf-allow]")
        page.wait_for_selector("dialog[open] form.allow-dialog")
        self.assertIn("Let this through on shop", page.inner_text("dialog[open]"))
        self.assertEqual(page.url, f"{self.origin}/waf", "the findings stay where they were")
        page.click("dialog[open] [data-allow-cancel]")
        page.wait_for_function("!document.querySelector('dialog.allow-modal').open")
        self.assertEqual(page.url, f"{self.origin}/waf")
        self.assertEqual(self.posts, [])

    def test_a_saved_exception_goes_where_the_page_would(self) -> None:
        page = self.page(refuse=False)
        page.click("[data-waf-allow]")
        page.wait_for_selector("dialog[open] form.allow-dialog")
        with page.expect_navigation():
            page.click("dialog[open] button[type=submit]")
        self.assertEqual(page.url, f"{self.origin}/waf?saved=shop&in=alpha")
        self.assertEqual(len(self.posts), 1)
        self.assertIn("scope=field_paths", self.posts[0])

    def test_a_refusal_is_answered_inside_the_dialog(self) -> None:
        page = self.page(refuse=True)
        page.click("[data-waf-allow]")
        page.wait_for_selector("dialog[open] form.allow-dialog")
        page.click("dialog[open] button[type=submit]")
        page.wait_for_selector("dialog[open] [role=alert]")
        self.assertIn("choose at least one path", page.inner_text("dialog[open] [role=alert]"))
        self.assertEqual(page.url, f"{self.origin}/waf")


if __name__ == "__main__":
    unittest.main()
