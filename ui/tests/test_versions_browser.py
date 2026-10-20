"""versions.js pages the Versions table ten at a time (Fas 14 point 8).

The page arrives whole, each row marked with its page and every page but the
first hidden by the server. Rendered through the real view and template, so
the markup the script reads is the markup the page sends.
"""

from __future__ import annotations

import contextlib
import os
import threading
from collections.abc import Iterator
from dataclasses import replace
from typing import Any, ClassVar
from unittest import mock

import uvicorn

from haprion_ui.app import create_app
from haprion_ui.views import STATIC_DIRECTORY
from tests import browser_policy
from tests.test_editor_page import EditorTestCase, writing_configuration
from tests.test_history import reading
from tests.test_login import PASSWORD, LoginTestCase, configuration
from tests.test_package import LATER, row
from tests.test_traffic_browser import free_port

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


class PublishingAnEarlierVersionAsksFirst(LoginTestCase):
    """26-10-18: one wrong click on a row published an old version."""

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
        with mock.patch(
            "haprion_ui.db.cluster_histories",
            return_value=[reading(versions=VERSIONS, published=20)],
        ):
            client = self.client(
                replace(configuration(), clusters=("alpha",), management_writes=True)
            )
            self.sign_in(client)
            html = client.get("/history").text
        page = self.browser.new_page()
        self.addCleanup(page.close)
        page.set_content(html)
        page.add_script_tag(path=str(STATIC_DIRECTORY / "versions.js"))
        page.evaluate("document.dispatchEvent(new Event('haprion:redrawn'))")
        #
        # What reaches the server: a submit nothing held back. Kept here, not
        # sent - the page has no server behind it.
        #
        page.evaluate(
            "window.sent = []; window.addEventListener('submit', (event) => {"
            " if (!event.defaultPrevented) window.sent.push("
            " event.target.querySelector('[name=version]').value); event.preventDefault(); })"
        )
        return page

    def row_button(self, page: Any, number: int) -> Any:
        return page.locator(f"form:has(input[name=version][value='{number}']) button[type=submit]")

    def test_an_older_version_asks_and_cancel_sends_nothing(self) -> None:
        page = self.page()
        self.row_button(page, 18).click()

        dialog = page.locator("#version-confirm")
        self.assertTrue(dialog.is_visible())
        self.assertIn("18", page.inner_text("[data-confirm-title]"))
        self.assertEqual(
            page.inner_text("[data-confirm-text]"), "It is 2 versions older than the current one."
        )
        page.click("[data-confirm-cancel]")
        self.assertFalse(dialog.is_visible())
        self.assertEqual(page.evaluate("window.sent"), [])

    def test_confirming_sends_that_version(self) -> None:
        page = self.page()
        self.row_button(page, 23).click()
        self.assertEqual(
            page.inner_text("[data-confirm-text]"), "It is 3 versions newer than the current one."
        )

        page.click("[data-confirm-go]")

        self.assertEqual(page.evaluate("window.sent"), ["23"])


#
# Every cell of the pending table: how far its content reaches past its box.
#
OVERFLOW = """cells => cells.map(cell => cell.scrollWidth - cell.clientWidth)"""


class APendingChangeSavedAgainstAnOlderVersion(EditorTestCase):
    """A row saved against an older version is opened and saved again, and the
    page has to show where. Its row had an address only its name followed, and
    at phone width its badge stood out of the card (26-10-20) - neither of which
    the HTML shows. Served by the application on a loopback port, as the
    settings browser suite runs it.
    """

    _playwright: ClassVar[Any]
    _browser: ClassVar[Any]

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
        rows = [row("uptime_admin-web", base_hash=LATER)]
        for target, effect in (
            ("cluster_drafts", lambda _c, _cluster: list(rows)),
            ("cluster_changes", lambda _c, _cluster: {}),
        ):
            patch = mock.patch(f"haprion_ui.db.{target}", side_effect=effect)
            patch.start()
            self.addCleanup(patch.stop)
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
    def versions(self, width: int) -> Iterator[Any]:
        page = self._browser.new_page(viewport={"width": width, "height": 900})
        browser_policy.watch(self, page)
        try:
            page.goto(f"http://127.0.0.1:{self.port}/login")
            page.fill("input[name=username]", "operator")
            page.fill("input[name=password]", PASSWORD)
            page.click("button[type=submit]")
            page.wait_for_url(f"http://127.0.0.1:{self.port}/")
            page.goto(f"http://127.0.0.1:{self.port}/history")
            page.wait_for_selector(".pending-stale")
            yield page
        finally:
            page.close()

    def test_the_row_and_the_way_there_fit_on_one_line_each(self) -> None:
        for width in (1280, 390):
            with self.subTest(width=width), self.versions(width) as page:
                spill = page.eval_on_selector_all(".pending-stale td", OVERFLOW)
                self.assertTrue(spill, "no pending row to measure")
                self.assertTrue(all(reach <= 0 for reach in spill), spill)
                button = page.locator(".form-problem a.secondary-button")
                self.assertEqual(button.inner_text(), "Open uptime_admin-web")
                box = button.bounding_box()
                assert box is not None  # noqa: S101 - drawn, as the line above read it
                self.assertLessEqual(box["height"], 40)
                self.assertTrue(
                    page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
                )

    def test_the_row_opens_the_change_wherever_it_is_clicked(self) -> None:
        with self.versions(1280) as page:
            page.locator(".pending-stale td[data-label='Saved by']").click()
            page.wait_for_url("**/proxies/alpha/uptime_admin-web/edit")
