"""versions.js pages the Versions table ten at a time (Fas 14 point 8).

The page arrives whole, each row marked with its page and every page but the
first hidden by the server. Rendered through the real view and template, so
the markup the script reads is the markup the page sends.
"""

from __future__ import annotations

import os
from dataclasses import replace
from typing import Any, ClassVar
from unittest import mock

from haprion_ui.views import STATIC_DIRECTORY
from tests.test_history import reading
from tests.test_login import LoginTestCase, configuration

if not os.environ.get("PLAYWRIGHT_BROWSERS_PATH"):
    raise RuntimeError(
        "set PLAYWRIGHT_BROWSERS_PATH to the directory holding the Playwright browsers"
    )

from playwright.sync_api import sync_playwright  # noqa: E402

VERSIONS = [
    {
        "version": number,
        "hash": f"{number:040d}",
        "created_at": "2026-08-28T14:02:11+00:00",
        "comment": f"Change {number}",
        "current": number == 25,
    }
    for number in range(25, 0, -1)
]


class VersionPagesInABrowser(LoginTestCase):
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

    def shown(self, clicks: list[str]) -> tuple[list[str], str, bool, bool]:
        """Visible version numbers, the range line, and whether Newer/Older are off."""

        with mock.patch(
            "haprion_ui.db.cluster_histories",
            return_value=[reading(versions=VERSIONS, published=25)],
        ):
            client = self.client(replace(configuration(), clusters=("alpha",)))
            self.sign_in(client)
            html = client.get("/history").text

        page = self.browser.new_page()
        self.addCleanup(page.close)
        page.set_content(html)
        page.add_script_tag(path=str(STATIC_DIRECTORY / "versions.js"))
        page.evaluate("document.dispatchEvent(new Event('haprion:redrawn'))")
        for button in clicks:
            page.click(f"[data-version-page-{button}]")
        return (
            page.eval_on_selector_all(
                "[data-version-page]:not([hidden]) strong", "cells => cells.map(c => c.textContent)"
            ),
            page.inner_text("[data-version-page-range]"),
            page.is_disabled("[data-version-page-previous]"),
            page.is_disabled("[data-version-page-next]"),
        )

    def test_the_newest_ten_are_shown_first(self) -> None:
        versions, range_line, newer_off, older_off = self.shown([])

        self.assertEqual(versions, [f"v{number}" for number in range(25, 15, -1)])
        self.assertEqual(range_line, "Versions 1–10 of 25 · page 1 of 3")
        self.assertEqual((newer_off, older_off), (True, False))

    def test_older_reaches_the_last_short_page_and_newer_comes_back(self) -> None:
        versions, range_line, newer_off, older_off = self.shown(["next", "next"])
        self.assertEqual(versions, [f"v{number}" for number in range(5, 0, -1)])
        self.assertEqual(range_line, "Versions 21–25 of 25 · page 3 of 3")
        self.assertEqual((newer_off, older_off), (False, True))

        versions, _, _, _ = self.shown(["next", "next", "previous"])
        self.assertEqual(versions[0], "v15")

    def test_a_short_last_page_keeps_the_buttons_where_they_were(self) -> None:
        #
        # The last page has five rows. The table keeps the first page's height,
        # so Newer and Older stay under the pointer (2026-09-29).
        #
        with mock.patch(
            "haprion_ui.db.cluster_histories",
            return_value=[reading(versions=VERSIONS, published=25)],
        ):
            client = self.client(replace(configuration(), clusters=("alpha",)))
            self.sign_in(client)
            html = client.get("/history").text

        page = self.browser.new_page(viewport={"width": 1280, "height": 900})
        self.addCleanup(page.close)
        page.set_content(html)
        page.add_style_tag(path=str(STATIC_DIRECTORY / "app.css"))
        page.add_script_tag(path=str(STATIC_DIRECTORY / "versions.js"))
        page.evaluate("document.dispatchEvent(new Event('haprion:redrawn'))")

        def top() -> float:
            return float(
                page.evaluate(
                    "document.querySelector('[data-version-page-next]').getBoundingClientRect().top"
                )
            )

        first = top()
        for button in ("next", "next", "previous", "previous"):
            page.click(f"[data-version-page-{button}]")
            with self.subTest(after=button):
                self.assertAlmostEqual(top(), first, delta=2)
