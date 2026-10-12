"""Events -> Audit in a real browser: a row unfolds where the reader is (26-10-12).

The detail row is in the address, so opening it was a navigation, and a
navigation drew the page again from the top - a reader halfway down the record
lost their place on every click.
"""

from __future__ import annotations

import contextlib
import socket
import threading
import unittest
from collections.abc import Iterator
from dataclasses import replace
from datetime import timedelta
from typing import Any, ClassVar
from unittest import mock

import uvicorn
from playwright.sync_api import Browser, Playwright, sync_playwright

from haprion_ui.app import create_app
from haprion_ui.db import AuditEvent
from tests.test_audit import AT
from tests.test_login import PASSWORD, LoginTestCase, configuration

ROWS = [
    AuditEvent(
        id=100 - number,
        at=AT - timedelta(minutes=number),
        actor="operator",
        action="login",
        cluster=None,
        request_id=None,
        detail={"client_ip": f"192.0.2.{number + 1}", "role": "admin"},
    )
    for number in range(50)
]


def free_port() -> int:
    with socket.socket() as held:
        held.bind(("127.0.0.1", 0))
        return int(held.getsockname()[1])


class AnAuditRowInABrowser(LoginTestCase):
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
        for patch in (
            mock.patch("haprion_ui.db.audit_events", return_value=ROWS),
            mock.patch("haprion_ui.db.audit_count", return_value=len(ROWS)),
        ):
            patch.start()
            self.addCleanup(patch.stop)
        config = replace(configuration(cookie_secure=False), clusters=("alpha",))
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
        page = self._browser.new_page(viewport={"width": 1280, "height": 700})
        try:
            page.goto(f"http://127.0.0.1:{self.port}/login")
            page.fill("input[name=username]", "operator")
            page.fill("input[name=password]", PASSWORD)
            page.click("button[type=submit]")
            page.wait_for_url(f"http://127.0.0.1:{self.port}/")
            page.goto(f"http://127.0.0.1:{self.port}/jobs?view=audit&size=50")
            page.wait_for_selector(".audit-table")
            yield page
        finally:
            page.close()

    def test_a_row_far_down_opens_and_closes_where_the_reader_is(self) -> None:
        with self.signed_in() as page:
            page.evaluate("window.__stayed = true")
            row = page.locator(".audit-row").nth(40)
            row.scroll_into_view_if_needed()
            scrolled = page.evaluate("window.scrollY")
            self.assertGreater(scrolled, 0)

            row.locator("td[data-label='Where']").click()
            page.wait_for_selector(".audit-detail")

            self.assertTrue(page.evaluate("window.__stayed === true"))
            self.assertIn("open=60", page.url)
            self.assertEqual(page.evaluate("window.scrollY"), scrolled)
            self.assertIn("192.0.2.41", page.locator(".audit-detail").inner_text())

            page.go_back()
            page.wait_for_selector(".audit-detail", state="detached")
            self.assertTrue(page.evaluate("window.__stayed === true"))
            self.assertNotIn("open=", page.url)


if __name__ == "__main__":
    unittest.main()
