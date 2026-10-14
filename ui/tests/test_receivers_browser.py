"""The receivers page in a real browser: its table never scrolls sideways.

The actions column held *Fetch commands · New secret · in use* in a width
made for two of them, and the table scrolled sideways at every width
(26-10-14). Only a layout engine can say that, so this asks one, the way the
certificate browser suite does.
"""

from __future__ import annotations

import contextlib
import threading
from collections.abc import Iterator
from dataclasses import replace
from typing import Any, ClassVar

import uvicorn
from playwright.sync_api import Browser, Playwright, sync_playwright

from haprion_ui.app import create_app
from tests import browser_policy
from tests.test_certificate_browser import free_port
from tests.test_certificate_receivers import ReceiverRouteTestCase, record
from tests.test_login import PASSWORD, configuration


class TheTableFitsInABrowser(ReceiverRouteTestCase):
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
        #
        # The widest rows there are: an https receiver in use, with every
        # action it can have, and a long name in each column.
        #
        self.records = [
            record(
                "fetcher-with-a-long-name.example.net",
                transport="https",
                allow=("198.51.100.0/24",),
                certificates=("app.example.com", "portal.example.com"),
            ),
            record("lb-02.example.net"),
            record("backup-host.example.org", transport="sftp", certificates=("app.example.com",)),
        ]
        self.account = replace(self.account, role="admin")
        config = replace(
            configuration(cookie_secure=False), management_writes=True, clusters=("alpha",)
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
    def signed_in(self) -> Iterator[Any]:
        page = self._browser.new_page()
        browser_policy.watch(self, page)
        try:
            page.goto(f"http://127.0.0.1:{self.port}/login")
            page.fill("input[name=username]", "operator")
            page.fill("input[name=password]", PASSWORD)
            page.click("button[type=submit]")
            page.wait_for_url(f"http://127.0.0.1:{self.port}/")
            page.goto(f"http://127.0.0.1:{self.port}/certificates/receivers")
            page.wait_for_selector(".receiver-table")
            yield page
        finally:
            page.close()

    def test_no_table_scrolls_sideways_at_half_4k_nor_on_a_phone(self) -> None:
        with self.signed_in() as page:
            self.assertIn("New secret", page.content())
            for width in (1280, 390):
                with self.subTest(width=width):
                    page.set_viewport_size({"width": width, "height": 900})
                    overflow = page.evaluate(
                        "() => [...document.querySelectorAll('.table-scroll')]"
                        ".map((box) => box.scrollWidth - box.clientWidth)"
                    )
                    self.assertEqual(set(overflow), {0})
                    self.assertTrue(
                        page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
                    )
