"""Settings -> API tokens in a real browser: one line a row at 1280 px, nothing scrolls sideways.

The page suite reads the HTML; this measures what Chromium drew. The server is
the application on a loopback port with the demo tokens in the table.
"""

from __future__ import annotations

import contextlib
import threading
from collections.abc import Iterator
from dataclasses import replace
from typing import Any, ClassVar
from unittest import mock

import uvicorn
from playwright.sync_api import Browser, Playwright

from haprion_ui import demo
from haprion_ui.app import create_app
from tests import browser_policy
from tests.test_login import PASSWORD, LoginTestCase, configuration
from tests.test_traffic_browser import free_port, sync_playwright

ROW_HEIGHTS = "Array.from(document.querySelectorAll('.api-token-table tbody tr')).map(r => r.getBoundingClientRect().height)"
NO_SIDEWAYS = "document.documentElement.scrollWidth <= window.innerWidth"
CLIPPED = """Array.from(document.querySelectorAll('.api-token-table td'))
  .filter(td => td.scrollWidth > td.clientWidth + 1).map(td => [td.dataset.label, td.scrollWidth, td.clientWidth])"""


class TheTokensPage(LoginTestCase):
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
            mock.patch(
                "haprion_ui.db.api_tokens", side_effect=lambda _c: list(demo.api_token_rows())
            ),
            mock.patch(
                "haprion_ui.external_blocking.blocking_objects", return_value=("shop", "store")
            ),
            mock.patch(
                "haprion_ui.db.create_api_token",
                side_effect=lambda _c, **values: replace(
                    demo.api_token_rows()[0], name=values["name"]
                ),
            ),
        ):
            patch.start()
            self.addCleanup(patch.stop)
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
    def signed_in(self, width: int, path: str) -> Iterator[Any]:
        page = self._browser.new_page(viewport={"width": width, "height": 900})
        browser_policy.watch(self, page)
        try:
            page.goto(f"http://127.0.0.1:{self.port}/login")
            page.fill("input[name=username]", "operator")
            page.fill("input[name=password]", PASSWORD)
            page.click("button[type=submit]")
            page.wait_for_url(f"http://127.0.0.1:{self.port}/")
            page.goto(f"http://127.0.0.1:{self.port}{path}")
            yield page
        finally:
            page.close()

    def test_a_row_is_one_line_and_nothing_is_cut_or_scrolls_at_1280(self) -> None:
        with self.signed_in(1280, "/settings/api-tokens") as page:
            heights = page.evaluate(ROW_HEIGHTS)
            self.assertEqual(len(heights), 3)
            self.assertTrue(all(height < 40 for height in heights), heights)
            self.assertEqual(page.evaluate(CLIPPED), [])
            self.assertTrue(page.evaluate(NO_SIDEWAYS))

    def test_the_rows_become_cards_below_1050_and_nothing_scrolls(self) -> None:
        for width in (900, 400):
            with self.subTest(width=width), self.signed_in(width, "/settings/api-tokens") as page:
                self.assertTrue(page.evaluate(NO_SIDEWAYS))
                self.assertTrue(page.is_visible(".api-token-table tbody tr >> nth=0"))

    def test_the_form_and_the_settings_card_fit(self) -> None:
        for path in ("/settings/api-tokens/new", "/settings"):
            for width in (1280, 760):
                with self.subTest(path=path, width=width), self.signed_in(width, path) as page:
                    self.assertTrue(page.evaluate(NO_SIDEWAYS))

    def test_proxies_show_for_a_block_token_only(self) -> None:
        with self.signed_in(1280, "/settings/api-tokens/new") as page:
            self.assertFalse(page.is_visible("[data-for-level=block]"))
            page.check("input[name=level][value=block]")
            self.assertTrue(page.is_visible("[data-for-level=block]"))
            page.check("input[name=level][value=write]")
            self.assertFalse(page.is_visible("[data-for-level=block]"))

    def test_only_these_clusters_show_their_boxes_and_only_their_proxies(self) -> None:
        def by_cluster(_readings: object, cluster: str) -> tuple[str, ...]:
            return ("shop",) if cluster == "edge-demo" else ("store",)

        with (
            mock.patch("haprion_ui.external_blocking.blocking_objects", side_effect=by_cluster),
            self.signed_in(1280, "/settings/api-tokens/new") as page,
        ):
            page.check("input[name=level][value=block]")
            self.assertFalse(page.is_visible("input[name=clusters][value=edge-demo]"))
            self.assertTrue(page.is_visible("input[name=objects][value=store]"))
            page.check("input[name=cluster_scope][value=chosen]")
            page.check("input[name=clusters][value=edge-demo]")
            self.assertTrue(page.is_visible("input[name=objects][value=shop]"))
            self.assertFalse(page.is_visible("input[name=objects][value=store]"))
            self.assertTrue(page.is_disabled("input[name=objects][value=store]"))
            page.check("input[name=cluster_scope][value=all]")
            self.assertFalse(page.is_visible("input[name=clusters][value=edge-demo]"))
            self.assertTrue(page.is_visible("input[name=objects][value=store]"))

    def test_the_secret_is_copyable_on_the_page_that_made_it(self) -> None:
        with self.signed_in(1280, "/settings/api-tokens/new") as page:
            page.fill("input[name=name]", "monitoring")
            page.click("form[action$=new] button[type=submit]")
            page.wait_for_selector(".api-token-secret code")
            self.assertTrue(page.inner_text(".api-token-secret code").startswith("hap_"))
            self.assertTrue(page.is_visible(".copy-button-beside"))
            self.assertTrue(page.evaluate(NO_SIDEWAYS))
