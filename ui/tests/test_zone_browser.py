"""zone.js hands the browser's own time zone to the server (B190)."""

from __future__ import annotations

import os
import unittest
from typing import Any, ClassVar

from haprion_ui.views import STATIC_DIRECTORY, ZONE_COOKIE

if not os.environ.get("PLAYWRIGHT_BROWSERS_PATH"):
    raise RuntimeError(
        "set PLAYWRIGHT_BROWSERS_PATH to the directory holding the Playwright browsers"
    )

from playwright.sync_api import sync_playwright

ORIGIN = "https://manager.example.com"


class TheZoneCookieInABrowser(unittest.TestCase):
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

    def cookies_after_a_page(self, zone: str, *, before: str | None = None) -> dict[str, Any]:
        """The cookies left once a page carrying zone.js has run in `zone`."""

        context = self.browser.new_context(timezone_id=zone)
        self.addCleanup(context.close)
        if before is not None:
            context.add_cookies([{"name": ZONE_COOKIE, "value": before, "url": ORIGIN}])
        page = context.new_page()
        page.route(
            f"{ORIGIN}/",
            lambda route: route.fulfill(content_type="text/html", body="<!doctype html><p>x</p>"),
        )
        page.goto(f"{ORIGIN}/")
        page.add_script_tag(path=str(STATIC_DIRECTORY / "zone.js"))
        return {cookie["name"]: cookie for cookie in context.cookies(ORIGIN)}

    def test_the_browser_s_zone_is_written_for_the_whole_site(self) -> None:
        cookie = self.cookies_after_a_page("America/New_York")[ZONE_COOKIE]

        self.assertEqual(cookie["value"], "America/New_York")
        self.assertEqual(cookie["path"], "/")
        self.assertTrue(cookie["secure"])
        self.assertEqual(cookie["sameSite"], "Lax")

    def test_a_zone_that_changed_replaces_the_old_one(self) -> None:
        cookies = self.cookies_after_a_page("Asia/Tokyo", before="Europe/Stockholm")

        self.assertEqual(cookies[ZONE_COOKIE]["value"], "Asia/Tokyo")


if __name__ == "__main__":
    unittest.main()
