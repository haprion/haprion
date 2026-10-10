"""password-match.js holds a form whose two new passwords differ (2026-09-27)."""

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
FORM = """<!doctype html>
<form method="post" action="/sent">
  <input type="password" name="new_password">
  <input type="password" name="repeat_password">
  <button type="submit">Save</button>
</form>"""


class TwoPasswordsInABrowser(unittest.TestCase):
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

    def submit(self, first: str, repeat: str) -> tuple[list[str], str]:
        """What reached the server, and what the repeat field says."""

        page = self.browser.new_page()
        self.addCleanup(page.close)
        sent: list[str] = []
        page.route(
            f"{ORIGIN}/",
            lambda route: route.fulfill(content_type="text/html", body=FORM),
        )

        def receive(route: Any) -> None:
            sent.append(route.request.post_data or "")
            route.fulfill(content_type="text/html", body="<!doctype html><p>sent</p>")

        page.route(f"{ORIGIN}/sent", receive)
        page.goto(f"{ORIGIN}/")
        page.add_script_tag(path=str(STATIC_DIRECTORY / "password-match.js"))
        page.fill("input[name=new_password]", first)
        page.fill("input[name=repeat_password]", repeat)
        message = page.evaluate(
            "document.querySelector('input[name=repeat_password]').validationMessage"
        )
        page.click("button")
        page.wait_for_load_state()
        return sent, message

    def test_two_different_passwords_never_leave_the_browser(self) -> None:
        sent, message = self.submit("long enough one", "long enough two")

        self.assertEqual(sent, [])
        self.assertEqual(message, "The two passwords do not match.")

    def test_two_equal_passwords_are_sent(self) -> None:
        sent, message = self.submit("long enough one", "long enough one")

        self.assertEqual(len(sent), 1)
        self.assertEqual(message, "")

    def test_two_empty_fields_are_sent_for_a_save_without_a_password(self) -> None:
        sent, _message = self.submit("", "")

        self.assertEqual(len(sent), 1)


if __name__ == "__main__":
    unittest.main()
