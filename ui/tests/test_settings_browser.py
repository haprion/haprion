"""A cluster's logs & metrics form in a real browser.

The page suite reads the HTML; this measures what the browser drew from it. The
TLS choice was a select too narrow for "Yes" - cut to "Ye" at 1280 px, seen
2026-10-05 - which no HTML assertion can see.

The server is the application itself on a loopback port, as the traffic and
certificate browser suites run it, with the page suite's substituted readings.
"""

from __future__ import annotations

import contextlib
import threading
import unittest
from collections.abc import Iterator
from dataclasses import replace
from typing import Any, ClassVar
from unittest import mock

import uvicorn
from playwright.sync_api import Browser, Playwright

from haprion_ui import demo
from haprion_ui.app import create_app
from tests.test_login import PASSWORD, configuration
from tests.test_queue_route import QueueRouteTestCase
from tests.test_settings_cluster import NOW
from tests.test_traffic_browser import free_port, sync_playwright

#
# What a select's own arrow takes beside its text. Measured in Chromium: at the
# old column width the room left for "Yes" came out 3 px short with this
# allowance and the text was visibly cut.
#
ARROW = 16

#
# For every select in the form: the room its widest option has left, in pixels.
# Negative is an option the closed select cannot show whole.
#
ROOM_LEFT = """selects => selects.map(select => {
  const style = getComputedStyle(select);
  const probe = document.createElement('span');
  probe.style.font = style.font;
  probe.style.position = 'absolute';
  probe.style.visibility = 'hidden';
  probe.style.whiteSpace = 'pre';
  document.body.append(probe);
  let widest = 0;
  for (const option of select.options) {
    probe.textContent = option.text;
    widest = Math.max(widest, probe.getBoundingClientRect().width);
  }
  probe.remove();
  return Math.floor(
    select.clientWidth - parseFloat(style.paddingLeft) - parseFloat(style.paddingRight)
    - ARROW - widest
  );
})""".replace("ARROW", str(ARROW))


class TheLogsAndMetricsForm(QueueRouteTestCase):
    _playwright: ClassVar[Playwright]
    _browser: ClassVar[Browser]

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
        patch = mock.patch(
            "haprion_ui.db.cluster_settings", return_value=list(demo.settings_rows(NOW))
        )
        patch.start()
        self.addCleanup(patch.stop)
        self.account = replace(self.account, role="admin")
        config = replace(
            configuration(cookie_secure=False),
            management_writes=True,
            clusters=("edge-demo", "service-demo"),
        )
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
    def signed_in(self, width: int) -> Iterator[Any]:
        page = self._browser.new_page(viewport={"width": width, "height": 900})
        try:
            page.goto(f"http://127.0.0.1:{self.port}/login")
            page.fill("input[name=username]", "operator")
            page.fill("input[name=password]", PASSWORD)
            page.click("button[type=submit]")
            page.wait_for_url(f"http://127.0.0.1:{self.port}/")
            page.goto(f"http://127.0.0.1:{self.port}/settings/clusters/edge-demo")
            page.wait_for_selector(".log-target-table")
            yield page
        finally:
            page.close()

    def test_every_choice_shows_whole_in_its_select(self) -> None:
        for width in (1280, 760):
            with self.subTest(width=width), self.signed_in(width) as page:
                room = page.eval_on_selector_all("form select", ROOM_LEFT)
                self.assertTrue(room, "the form has no selects to measure")
                self.assertTrue(all(left >= 0 for left in room), room)
                self.assertTrue(
                    page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
                )


if __name__ == "__main__":
    unittest.main()
