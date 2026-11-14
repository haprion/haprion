"""*Test* on a blocklist's form, pressed in Chromium (26-11-14).

The form's buttons are named `action`, which shadows `form.action`: in 1.1.0
the script posted to `/settings/blocklists/[object RadioNodeList]`, the 404
was no JSON, and the page said the test got no answer. Nothing pressed the
button. This does, against the page's own markup and the script as shipped,
and holds the post to the form's address with the test's own fields.
"""

from __future__ import annotations

import json
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
<form method="post" action="/settings/blocklists/new" data-blocklist-form>
  <input name="name" value="drop">
  <input name="url" value="https://lists.example.com/drop.txt">
  <select name="auth" data-blocklist-auth><option value="none" selected>None</option></select>
  <p data-test-answer hidden></p>
  <button type="submit" name="action" value="test" formnovalidate data-blocklist-test>Test</button>
  <button type="submit" name="action" value="save">Save</button>
</form>
<script src="/blocklist-form.js"></script>"""


class PressingTest(unittest.TestCase):
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

    def test_it_posts_to_the_form_and_shows_the_answer(self) -> None:
        page = self.browser.new_page()
        self.addCleanup(page.close)
        posted: list[tuple[str, str]] = []

        def answer(route: Any) -> None:
            posted.append((route.request.url, route.request.post_data or ""))
            route.fulfill(
                content_type="application/json",
                body=json.dumps({"answer": "1759 addresses.", "tone": "healthy"}),
            )

        page.route(f"{ORIGIN}/", lambda route: route.fulfill(content_type="text/html", body=PAGE))
        page.route(
            f"{ORIGIN}/blocklist-form.js",
            lambda route: route.fulfill(
                content_type="text/javascript",
                body=(STATIC_DIRECTORY / "blocklist-form.js").read_text(),
            ),
        )
        page.route(f"{ORIGIN}/settings/blocklists/**", answer)
        page.goto(f"{ORIGIN}/")

        page.click("button[data-blocklist-test]")
        page.wait_for_function(
            "document.querySelector('[data-test-answer]').textContent.includes('1759')"
        )

        self.assertEqual(len(posted), 1, posted)
        url, body = posted[0]
        self.assertEqual(url, f"{ORIGIN}/settings/blocklists/new")
        self.assertIn('name="action"\r\n\r\ntest', body)
        self.assertIn("lists.example.com", body)


if __name__ == "__main__":
    unittest.main()
