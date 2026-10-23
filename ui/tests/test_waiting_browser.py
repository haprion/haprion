"""waiting.js keeps a finished job's spinner until the poller has read it through (0068).

A job finishing and the poller reading what it did are two moments. Redrawn on
the first, the dashboard had its buttons back beside counts from before the
job - Publish & deploy offering what had just been published - and stayed so
until the next pass (26-10-11).
"""

from __future__ import annotations

import json
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
TICK = 4000


def dashboard(drawn: int, *, busy: bool) -> str:
    spinner = '<span data-busy="alpha">Deploying</span>' if busy else "<button>Deploy</button>"
    return (
        "<!doctype html><html><head><title>Dashboard</title>"
        '<script defer src="/static/live.js"></script>'
        '<script defer src="/static/waiting.js"></script></head>'
        f'<body><main><p id="drawn">{drawn}</p>{spinner}</main></body></html>'
    )


class WaitingPage(unittest.TestCase):
    """The dashboard in Chromium on a virtual clock; the cases are below."""

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

    def open(self, pages: list[bool], answers: list[dict[str, Any]]) -> Any:
        """The dashboard, drawn busy or idle per request, with `/clusters/busy` answering in turn."""

        context = self.browser.new_context()
        self.addCleanup(context.close)
        tab = context.new_page()
        tab.clock.install()
        served = {"pages": 0, "asked": 0}

        def page(route: Any) -> None:
            busy = pages[min(served["pages"], len(pages) - 1)]
            served["pages"] += 1
            route.fulfill(content_type="text/html", body=dashboard(served["pages"], busy=busy))

        def busy(route: Any) -> None:
            answer = answers[min(served["asked"], len(answers) - 1)]
            served["asked"] += 1
            route.fulfill(content_type="application/json", body=json.dumps(answer))

        def script(name: str) -> Any:
            return lambda route: route.fulfill(path=str(STATIC_DIRECTORY / name))

        for name in ("live.js", "waiting.js"):
            tab.route(f"{ORIGIN}/static/{name}", script(name))
        tab.route(f"{ORIGIN}/", page)
        tab.route(f"{ORIGIN}/clusters/busy", busy)
        tab.goto(f"{ORIGIN}/")
        self.served = served
        return tab

    def tick(self, tab: Any) -> None:
        with tab.expect_response(f"{ORIGIN}/clusters/busy"):
            tab.clock.run_for(TICK)
        # Long enough for a redraw it should not make to have reached the server.
        tab.wait_for_timeout(300)

    def drawn(self, tab: Any) -> str:
        return str(tab.locator("#drawn").text_content())


class TheSpinnerWaitsForTheReading(WaitingPage):
    def test_a_finished_job_keeps_its_spinner_until_its_cluster_is_read_through(self) -> None:
        tab = self.open(
            [True, False],
            [
                {"busy": {}, "catching_up": ["alpha"]},
                {"busy": {}, "catching_up": []},
            ],
        )

        self.tick(tab)
        self.assertEqual(self.drawn(tab), "1", "redrawn before the reading caught up")
        self.assertEqual(tab.locator("[data-busy]").count(), 1)

        self.tick(tab)
        tab.wait_for_function("document.getElementById('drawn').textContent === '2'")
        self.assertEqual(tab.locator("[data-busy]").count(), 0)

    def test_a_page_drawn_while_catching_up_redraws_once_it_has(self) -> None:
        #
        # The answer to a job that ended before the browser came back: no
        # spinner to watch, and readings from before the job.
        #
        with_settle: list[dict[str, Any]] = [
            {"busy": {}, "catching_up": ["alpha"]},
            {"busy": {}, "catching_up": ["alpha"]},
            {"busy": {}, "catching_up": []},
        ]
        tab = self.open([False], with_settle)
        tab.wait_for_function("true")
        self.assertEqual(self.served["asked"], 1, "asked once on arrival")

        self.tick(tab)
        self.assertEqual(self.drawn(tab), "1")

        self.tick(tab)
        tab.wait_for_function("document.getElementById('drawn').textContent === '2'")

        # Caught up and drawn: nothing left to ask about.
        tab.clock.run_for(TICK * 3)
        tab.wait_for_timeout(300)
        self.assertEqual(self.served["asked"], 3)

    def test_a_page_drawn_after_it_caught_up_stays_as_it_is(self) -> None:
        tab = self.open([False], [{"busy": {}, "catching_up": []}])
        tab.wait_for_timeout(300)

        tab.clock.run_for(TICK * 3)
        tab.wait_for_timeout(300)

        self.assertEqual((self.served["asked"], self.served["pages"]), (1, 1))


class AHiddenTabComesBackCurrent(WaitingPage):
    """Review 26-10-13, U1: hidden time used up the asks, and nothing restarted them."""

    STILL_BUSY: ClassVar[list[dict[str, Any]]] = [{"busy": {"alpha": "deploy"}, "catching_up": []}]

    def hide(self, tab: Any, hidden: bool) -> None:
        tab.evaluate(
            "hidden => {"
            "  Object.defineProperty(document, 'hidden', {configurable: true, get: () => hidden});"
            "  document.dispatchEvent(new Event('visibilitychange'));"
            "}",
            hidden,
        )

    def test_a_tab_hidden_for_five_minutes_asks_as_soon_as_it_is_seen(self) -> None:
        tab = self.open([True], self.STILL_BUSY)
        self.hide(tab, True)

        tab.clock.run_for(310_000)
        tab.wait_for_timeout(300)
        self.assertEqual(self.served["asked"], 0, "a hidden tab asked")

        with tab.expect_response(f"{ORIGIN}/clusters/busy"):
            self.hide(tab, False)
            tab.clock.run_for(10)
        self.assertEqual(self.served["asked"], 1)

        self.tick(tab)
        self.assertEqual(self.served["asked"], 2, "the loop did not go on")

    def test_a_job_that_outlasts_the_asks_is_asked_about_more_slowly(self) -> None:
        tab = self.open([True], self.STILL_BUSY)
        for _ in range(75):
            self.tick(tab)
        self.assertEqual(self.served["asked"], 75)

        tab.clock.run_for(TICK * 2)
        tab.wait_for_timeout(300)
        self.assertEqual(self.served["asked"], 75, "not slower after the limit")

        with tab.expect_response(f"{ORIGIN}/clusters/busy"):
            tab.clock.run_for(30_000)
        self.assertEqual(self.served["asked"], 76, "stopped at the limit")


if __name__ == "__main__":
    unittest.main()
