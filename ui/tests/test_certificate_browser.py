"""The certificate page's view switch in a real browser.

Everything else about the page asks the server what it rendered. This asks
the browser what it did with it: that the switch stays on screen while the
registry scrolls, that a segment is the same width before and after it is
chosen, and that choosing one swaps the view without a page load. All three
were asked for by the maintainer on 2026-09-12, looking at the page, and none
of the three can be read off HTML.

The server is the application itself on a loopback port, as the traffic
browser suite does it, with the same substituted readings the page suite uses.
"""

from __future__ import annotations

import contextlib
import socket
import threading
import unittest
from collections.abc import Iterator
from dataclasses import replace
from typing import Any

import uvicorn
from playwright.sync_api import sync_playwright

from haproxy_ui.app import create_app
from tests.test_certificate_page import TheCertificatePageHasTwoViews
from tests.test_login import PASSWORD, configuration


def free_port() -> int:
    with socket.socket() as held:
        held.bind(("127.0.0.1", 0))
        return int(held.getsockname()[1])


class TheSwitchInABrowser(TheCertificatePageHasTwoViews):
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
    def signed_in(self, query: str = "", *, path: str = "/certificates") -> Iterator[Any]:
        page = self._browser.new_page()
        try:
            page.goto(f"http://127.0.0.1:{self.port}/login")
            page.fill("input[name=username]", "operator")
            page.fill("input[name=password]", PASSWORD)
            page.click("button[type=submit]")
            page.wait_for_url(f"http://127.0.0.1:{self.port}/")
            page.goto(f"http://127.0.0.1:{self.port}{path}{query}")
            page.wait_for_selector(
                ".certificate-form" if path == "/certificates/new" else ".certificate-views"
            )
            yield page
        finally:
            page.close()

    @staticmethod
    def widths(page: Any) -> list[float]:
        return page.evaluate(
            "() => [...document.querySelectorAll('.certificate-views a')]"
            ".map(a => a.getBoundingClientRect().width)"
        )

    def test_choosing_a_view_swaps_it_in_place_and_moves_no_segment(self) -> None:
        with self.signed_in("?view=clusters") as page:
            page.evaluate("window.__stayed = true")
            before = self.widths(page)
            self.assertNotIn("Certificate registry", page.content())

            page.click(".certificate-views a[href='?view=registry']")
            page.wait_for_selector("text=Certificate registry")

            self.assertTrue(page.evaluate("window.__stayed === true"))
            self.assertTrue(page.url.endswith("/certificates?view=registry"))
            #
            # Bold is wider than regular, and the chosen segment is bold. The
            # widths are reserved from the label, so choosing one moves nothing.
            #
            self.assertEqual(self.widths(page), before)

            page.go_back()
            page.wait_for_selector(".certificate-cluster-list")
            self.assertTrue(page.evaluate("window.__stayed === true"))

    def test_clicking_anywhere_on_a_row_opens_its_detail_in_place(self) -> None:
        with self.signed_in("?view=registry") as page:
            page.evaluate("window.__stayed = true")
            self.assertEqual(page.locator(".registry-detail").count(), 0)

            page.click(".registry-row td[data-label='Valid from']")
            page.wait_for_selector(".registry-detail")

            self.assertTrue(page.evaluate("window.__stayed === true"))
            self.assertIn("open=", page.url)

            page.click(".registry-open td[data-label='Expires']")
            page.wait_for_selector(".registry-detail", state="detached")
            self.assertNotIn("open=", page.url)

    def test_the_switch_stays_on_screen_while_the_page_scrolls(self) -> None:
        with self.signed_in("?view=registry") as page:
            page.set_viewport_size({"width": 1000, "height": 300})
            page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            self.assertGreater(page.evaluate("window.scrollY"), 0)
            top = page.evaluate(
                "document.querySelector('.page-ranges-sticky').getBoundingClientRect().top"
            )
            header = page.evaluate(
                "document.querySelector('.page-ranges-sticky').getBoundingClientRect().height"
            )
            self.assertGreaterEqual(top, 0)
            self.assertLess(top, 300 - header)

    def test_the_new_form_guidance_stays_above_the_fields_and_wraps_without_overflow(self) -> None:
        with self.signed_in(path="/certificates/new") as page:
            page.set_viewport_size({"width": 1280, "height": 800})
            header = page.locator(".certificate-form .cluster-header").first.bounding_box()
            fields = page.locator(".certificate-form .form-grid").first.bounding_box()
            warning = page.locator(".challenge-warning").bounding_box()

            if header is None or fields is None or warning is None:
                self.fail("the certificate header, guidance and fields must have layout boxes")
            self.assertGreaterEqual(warning["y"], header["y"] + header["height"])
            self.assertLessEqual(warning["y"] + warning["height"], fields["y"])
            #
            # Three lines by design (one per statement), never a fourth.
            #
            self.assertLessEqual(warning["height"], 64)
            self.assertEqual(
                page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"), True
            )

            page.set_viewport_size({"width": 390, "height": 800})
            warning = page.locator(".challenge-warning").bounding_box()
            if warning is None:
                self.fail("the guidance must keep its layout box on a narrow screen")
            #
            # Each statement wraps on its own here: six lines, measured.
            #
            self.assertLessEqual(warning["height"], 130)
            self.assertEqual(
                page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"), True
            )

    def test_choosing_http_01_greys_the_profile_field_and_dns_01_gives_it_back(self) -> None:
        with self.signed_in(path="/certificates/new") as page:
            profile = page.locator("select[name='dns_profile']")
            self.assertFalse(profile.is_disabled())

            ndes = page.locator("select[name='ndes_profile']")
            self.assertFalse(ndes.is_visible())

            page.check("input[name='method'][value='http-01']")
            self.assertTrue(profile.is_disabled())
            self.assertTrue(profile.is_visible())
            self.assertLess(
                page.evaluate("getComputedStyle(document.querySelector('.profile-field')).opacity"),
                "1",
            )
            self.assertTrue(page.locator("[data-profile-hint='http-01']").is_visible())

            page.check("input[name='method'][value='dns-01']")
            self.assertFalse(profile.is_disabled())
            self.assertTrue(page.locator("[data-profile-hint='dns-01']").is_visible())

    def test_the_challenge_sits_midway_between_its_neighbours(self) -> None:
        with self.signed_in(path="/certificates/new") as page:
            page.set_viewport_size({"width": 1280, "height": 800})
            domain = page.locator("input[name='domain']").bounding_box()
            challenge = page.locator(".challenge-field").bounding_box()
            profile = page.locator("select[name='dns_profile']").bounding_box()
            if domain is None or challenge is None or profile is None:
                self.fail("the three fields must have layout boxes")
            left = challenge["x"] - (domain["x"] + domain["width"])
            right = profile["x"] - (challenge["x"] + challenge["width"])
            self.assertGreater(left, 16)
            self.assertAlmostEqual(left, right, delta=2)


if __name__ == "__main__":
    unittest.main()
