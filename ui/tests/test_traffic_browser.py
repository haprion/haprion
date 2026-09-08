"""The traffic chart driven by a real browser.

Everything else in this suite asks the server what it rendered. This asks the
browser what happens when somebody uses it, because the chart's behaviour is
half script: marking a range replaces part of the page instead of reloading it,
a hover writes into the figure row, and the marks live in the address so the
back button walks them back.

**A real browser rather than a stand-in DOM.** The fault this suite was written
after is the shape of the problem: `href` on an SVG `<a>` is an
`SVGAnimatedString`, not a string, so the bucket links navigated to
`/[object SVGAnimatedString]` and the page 404'd. That is valid JavaScript and
perfectly safe - a linter has nothing to say about it, and a stand-in DOM either
implements it correctly by accident or not at all. A test that passes where the
fault is is worse than no test.

The server is the application itself, on a loopback port, with the same
database substitutions the rest of the suite uses. Nothing about the page is
mocked: the figures are computed by `read_pool_totals` exactly as they are in
production, which is the point - the script must not be able to answer a
question the server has not answered.
"""

from __future__ import annotations

import contextlib
import os
import socket
import threading
import unittest
from collections.abc import Iterator
from dataclasses import replace
from typing import Any

import uvicorn

from haproxy_ui.app import create_app
from tests.test_cluster_traffic import ReadingACluster
from tests.test_login import PASSWORD, configuration

#
# Where the browser is installed is environment-specific and is read from the
# environment, never written here: this repository is meant to be public, and a
# path out of one machine is one more thing that has to be true somewhere else.
#
# Refused rather than skipped, in the same spirit as the interface gate itself.
# A suite that passes because it could not find a browser has not looked at
# anything.
#
if not os.environ.get("PLAYWRIGHT_BROWSERS_PATH"):
    raise RuntimeError(
        "set PLAYWRIGHT_BROWSERS_PATH to the directory holding the Playwright browsers; "
        "install them with `playwright install chromium` and keep them outside any home "
        "directory, which ProtectHome hides"
    )

from playwright.sync_api import sync_playwright  # noqa: E402


def free_port() -> int:
    with socket.socket() as held:
        held.bind(("127.0.0.1", 0))
        return int(held.getsockname()[1])


class TheChartInABrowser(ReadingACluster):
    """One browser for the class, one server per test.

    The database substitutions are per test and process-wide, so the server
    thread sees whatever the test set up. Starting the browser once is what
    keeps the suite to a few seconds rather than a few minutes.
    """

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
        # Not a secure cookie: the browser is talking to loopback over http, and
        # a session cookie marked secure is one the browser correctly refuses to
        # send back. The flag itself is covered where it belongs, in the login
        # suite.
        #
        config = replace(configuration(cookie_secure=False), demo_fixture=True)
        self.port = free_port()
        server = uvicorn.Server(
            uvicorn.Config(
                create_app(config), host="127.0.0.1", port=self.port, log_level="warning"
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
    def signed_in(self) -> Iterator[Any]:
        page = self._browser.new_page()
        try:
            page.goto(f"http://127.0.0.1:{self.port}/login")
            page.fill("input[name=username]", "operator")
            page.fill("input[name=password]", PASSWORD)
            page.click("button[type=submit]")
            page.wait_for_url(f"http://127.0.0.1:{self.port}/")
            page.goto(f"http://127.0.0.1:{self.port}/clusters/edge-demo/traffic")
            page.wait_for_selector(".traffic-pick")
            yield page
        finally:
            page.close()

    @staticmethod
    def stay(page: Any) -> None:
        """A mark on the window, which a page load would take with it."""

        page.evaluate("window.__stayed = true")

    @staticmethod
    def stayed(page: Any) -> bool:
        return bool(page.evaluate("window.__stayed === true"))

    @staticmethod
    def card(page: Any) -> Any:
        """The first card on the page, as the element everything else is read
        from. Selected as an element rather than by a compound selector: the
        cards are wrapped in per-section markup, so `:first-of-type` picks the
        first within each wrapper rather than the first on the page."""

        return page.query_selector(".traffic-pool")

    @classmethod
    def figures(cls, page: Any) -> list[str]:
        return [
            (value.text_content() or "").strip()
            for value in cls.card(page).query_selector_all(".traffic-figures dd")
        ]

    @classmethod
    def scope(cls, page: Any) -> str:
        return (cls.card(page).query_selector(".traffic-scope-label").text_content() or "").strip()


class MarkingARange(TheChartInABrowser):
    def test_changing_the_window_keeps_the_readers_scroll_position(self) -> None:
        with self.signed_in() as page:
            page.set_viewport_size({"width": 1000, "height": 420})
            widths = page.evaluate(
                """() => ({
                    row: document.querySelector('.page-ranges-sticky').getBoundingClientRect().width,
                    page: document.querySelector('main.page').getBoundingClientRect().width,
                    controls: document.querySelector('.page-ranges').getBoundingClientRect().width,
                })"""
            )
            self.assertAlmostEqual(widths["row"], widths["page"], delta=1)
            self.assertGreater(widths["row"], widths["controls"])
            page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            before = page.evaluate("window.scrollY")
            self.assertGreater(before, 0)
            self.stay(page)

            page.evaluate(
                "document.querySelector('.page-ranges a[title=\"the last 7 days\"]').click()"
            )
            page.wait_for_function("() => window.location.search.includes('traffic=7d')")

            self.assertTrue(self.stayed(page), "changing the window reloaded the page")
            self.assertAlmostEqual(page.evaluate("window.scrollY"), before, delta=1)

    def test_a_bucket_link_carries_a_readable_address(self) -> None:
        """The fault this suite exists for: `href` inside SVG is not a string."""

        with self.signed_in() as page:
            self.stay(page)
            page.query_selector(".traffic-pick").click()
            page.wait_for_function("() => window.location.search.includes('from=')")
            self.assertNotIn("SVGAnimatedString", page.url)
            self.assertTrue(self.stayed(page), "the page reloaded instead of replacing its regions")

    def test_two_clicks_mark_a_range_and_the_third_clears_it(self) -> None:
        with self.signed_in() as page:
            picks = page.query_selector_all(".traffic-pick")
            self.stay(page)

            picks[2].click()
            page.wait_for_function("() => window.location.search.includes('from=')")
            page.query_selector_all(".traffic-pick")[8].click()
            page.wait_for_function("() => window.location.search.includes('to=')")
            self.assertTrue(page.query_selector(".traffic-marked"))

            #
            # Outside the drawing, which is the point of it: a reader who has
            # finished with a range clicks it away somewhere on the page.
            #
            page.click(".traffic-section")
            page.wait_for_function("() => !window.location.search.includes('from=')")
            self.assertIsNone(page.query_selector(".traffic-marked"))
            self.assertTrue(self.stayed(page), "clearing reloaded the page")

    def test_the_back_button_walks_the_marks_back(self) -> None:
        with self.signed_in() as page:
            page.query_selector_all(".traffic-pick")[2].click()
            page.wait_for_function("() => window.location.search.includes('from=')")
            self.stay(page)
            page.go_back()
            #
            # Waited for on the band rather than on the address. `popstate`
            # fires with the address already changed, and fetching what the
            # server says about it comes after - so asking about the drawing a
            # moment later asks it before the answer has arrived.
            #
            page.wait_for_selector(".traffic-marked", state="detached")
            self.assertNotIn("from=", page.url)
            self.assertTrue(self.stayed(page), "going back reloaded the page")


class WhatAHoverAnswers(TheChartInABrowser):
    def test_the_browser_tooltip_is_gone_where_the_script_runs(self) -> None:
        with self.signed_in() as page:
            self.assertEqual(page.eval_on_selector_all(".traffic-pick title", "t => t.length"), 0)

    def test_a_bucket_writes_its_own_reading_into_the_row(self) -> None:
        with self.signed_in() as page:
            window = self.scope(page)
            self.card(page).query_selector_all(".traffic-pick")[3].hover()
            page.wait_for_function(
                "label => document.querySelector('.traffic-pool .traffic-scope-label')"
                ".textContent.trim() !== label",
                arg=window,
            )

    def test_a_bucket_inside_the_mark_keeps_the_range_the_reader_asked_about(self) -> None:
        """The reader marked a stretch to ask about the stretch."""

        with self.signed_in() as page:
            self.card(page).query_selector_all(".traffic-pick")[2].click()
            page.wait_for_function("() => window.location.search.includes('from=')")
            self.card(page).query_selector_all(".traffic-pick")[8].click()
            page.wait_for_function("() => window.location.search.includes('to=')")

            marked = self.figures(page)
            label = self.scope(page)
            inside = self.card(page).query_selector_all(".traffic-pick[data-selected]")
            self.assertTrue(inside, "the range marked no buckets")
            inside[0].hover()
            page.wait_for_timeout(150)

            self.assertEqual(self.figures(page), marked)
            self.assertEqual(self.scope(page), label)


if __name__ == "__main__":
    unittest.main()
