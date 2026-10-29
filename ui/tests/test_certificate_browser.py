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
from typing import Any, ClassVar
from unittest import mock

import uvicorn
from playwright.sync_api import Browser, Playwright, sync_playwright

from haprion_ui.app import create_app
from tests import browser_policy
from tests.test_certificate_page import TheCertificatePageHasTwoViews
from tests.test_certificates import node, status
from tests.test_login import PASSWORD, configuration
from tests.test_queue_route import queued


def free_port() -> int:
    with socket.socket() as held:
        held.bind(("127.0.0.1", 0))
        return int(held.getsockname()[1])


class TheSwitchInABrowser(TheCertificatePageHasTwoViews):
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
        browser_policy.watch(self, page)
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
        widths: list[float] = page.evaluate(
            "() => [...document.querySelectorAll('.certificate-views a')]"
            ".map(a => a.getBoundingClientRect().width)"
        )
        return widths

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

    def test_a_job_refresh_keeps_the_view_chosen_in_place(self) -> None:
        active = queued(
            operation="cert_issue",
            cluster=None,
            state="running",
            payload={"domain": "new.example.com"},
        )
        with (
            mock.patch("haprion_ui.db.recent_jobs", return_value=[active]),
            self.signed_in("?view=registry") as page,
        ):
            page.click(".certificate-views a[href='?view=clusters']")
            page.wait_for_selector(".certificate-cluster-list")
            page.wait_for_timeout(3500)

            self.assertTrue(page.url.endswith("/certificates?view=clusters"))
            self.assertEqual(page.locator(".certificate-cluster-list").count(), 1)

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

    def test_the_older_copy_action_is_below_aligned_state_text_and_owns_its_form(self) -> None:
        with (
            mock.patch(
                "haprion_ui.db.cluster_statuses",
                return_value=[status(node(("example.com", "b" * 64)))],
            ),
            self.signed_in("?view=registry&open=example.com") as page,
        ):
            values = page.locator(".registry-detail-grid > div > span")
            covers = values.nth(0).bounding_box()
            issuer = values.nth(1).bounding_box()
            state = values.nth(2).bounding_box()
            button = page.get_by_role("button", name="Deploy to nodes")
            button_box = button.bounding_box()
            if covers is None or issuer is None or state is None or button_box is None:
                self.fail("the three detail values and deploy action must have layout boxes")

            self.assertAlmostEqual(covers["y"], issuer["y"], delta=1)
            self.assertAlmostEqual(covers["y"], state["y"], delta=1)
            self.assertGreater(button_box["y"], state["y"])
            self.assertAlmostEqual(button_box["x"], state["x"], delta=1)
            self.assertTrue(button.evaluate("button => button.form.action.endsWith('/operations')"))

    def test_registry_selection_controls_keep_their_external_form_owner(self) -> None:
        with self.signed_in("?view=registry") as page:
            pick = page.locator("[data-delete-pick]").first
            submit = page.get_by_role("button", name="Delete selected…")
            self.assertEqual(pick.evaluate("pick => pick.form.id"), "certificate-selection")
            self.assertEqual(submit.evaluate("button => button.form.id"), "certificate-selection")

            pick.check()

            self.assertFalse(submit.is_disabled())
            self.assertEqual(page.locator("[data-delete-count]").inner_text(), "1 selected")

    def test_a_tick_survives_opening_a_row_to_read_it(self) -> None:
        """Review 26-10-24, 04-11: opening a row's detail took every tick away."""

        with self.signed_in("?view=registry") as page:
            page.locator("[data-delete-pick]").first.check()
            page.click(".registry-row td[data-label='Valid from']")
            page.wait_for_selector(".registry-detail")

            self.assertTrue(page.locator("[data-delete-pick]").first.is_checked())
            self.assertEqual(page.locator("[data-delete-count]").inner_text(), "1 selected")

    def test_export_wakes_at_one_external_row_and_no_other(self) -> None:
        from tests.test_certificates import reading, registered, with_registry
        from tests.test_external_certificates import external

        rows = [with_registry(reading(), registered(fingerprint="a" * 64), external())]
        with (
            mock.patch("haprion_ui.features.is_on", return_value=True),
            mock.patch("haprion_ui.db.cluster_certificates", return_value=rows),
            self.signed_in("?view=registry") as page,
        ):
            export = page.get_by_role("button", name="Export…")
            outside = page.locator("[data-delete-pick]:not([data-exportable])").first
            inside = page.locator("[data-delete-pick][data-exportable]")

            outside.check()
            self.assertTrue(export.is_disabled())
            outside.uncheck()
            inside.check()
            self.assertFalse(export.is_disabled())
            outside.check()
            self.assertTrue(export.is_disabled())

    def test_abandon_wakes_at_one_waiting_row_and_no_other(self) -> None:
        """B388: only a request the CA still holds can be given up."""

        from tests.test_certificates import reading, registered, with_registry

        waiting = registered(fingerprint="a" * 64, kind="import")
        waiting["source"]["ndes_profile"] = "certserver1"
        waiting["renewal"] = {"attempted_at": "2026-09-15T05:00:00Z", "outcome": "pending"}
        waiting["request_state"] = "pending"
        other = registered("other.example.com", fingerprint="b" * 64, kind="import")
        rows = [with_registry(reading(), waiting, other)]
        with (
            mock.patch("haprion_ui.features.is_on", return_value=True),
            mock.patch("haprion_ui.db.cluster_certificates", return_value=rows),
            self.signed_in("?view=registry") as page,
        ):
            abandon = page.get_by_role("button", name="Abandon request…")
            outside = page.locator("[data-delete-pick]:not([data-pending])").first
            inside = page.locator("[data-delete-pick][data-pending]")

            self.assertTrue(abandon.is_disabled())
            outside.check()
            self.assertTrue(abandon.is_disabled())
            outside.uncheck()
            inside.check()
            self.assertFalse(abandon.is_disabled())
            outside.check()
            self.assertTrue(abandon.is_disabled())

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
            #
            # The buttons ride in the same strip (2026-09-21): still on
            # screen at the bottom of the registry, on the switch's own row,
            # and the row does not push the page sideways.
            #
            button = page.get_by_role("link", name="New certificate").bounding_box()
            switch = page.locator(".certificate-views").bounding_box()
            if button is None or switch is None:
                self.fail("the button and the switch must have layout boxes")
            self.assertGreaterEqual(button["y"], 0)
            self.assertLess(button["y"] + button["height"], 300)
            self.assertAlmostEqual(
                button["y"] + button["height"] / 2, switch["y"] + switch["height"] / 2, delta=2
            )
            self.assertGreater(button["x"], switch["x"] + switch["width"])
            self.assertEqual(
                page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"), True
            )

    def test_the_strip_folds_rather_than_overflows_on_a_narrow_screen(self) -> None:
        with self.signed_in("?view=registry") as page:
            page.set_viewport_size({"width": 390, "height": 800})
            button = page.get_by_role("link", name="New certificate").bounding_box()
            switch = page.locator(".certificate-views").bounding_box()
            if button is None or switch is None:
                self.fail("the button and the switch must have layout boxes")
            self.assertGreater(button["y"], switch["y"] + switch["height"])
            self.assertEqual(
                page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"), True
            )

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

    def test_changing_kind_keeps_the_name_and_the_ca_and_sits_in_the_targets_header(
        self,
    ) -> None:
        with (
            mock.patch("haprion_ui.features.is_on", return_value=True),
            self.signed_in(path="/certificates/new") as page,
        ):
            self.assertEqual(page.locator(".cluster-header .certificate-kind").count(), 1)
            page.fill("input[name='domain']", "bmc01.example.com")
            page.check("input[name='method'][value='http-01']")
            page.set_viewport_size({"width": 1280, "height": 800})
            choices = page.locator(".certificate-kind .check")
            first, second = choices.nth(0).bounding_box(), choices.nth(1).bounding_box()
            if first is None or second is None:
                self.fail("both kinds must have layout boxes")
            self.assertAlmostEqual(first["y"], second["y"], delta=1)
            self.assertEqual(
                page.evaluate(
                    "[...document.querySelectorAll('.certificate-kind .check, "
                    ".challenge-field .check')].map(e => getComputedStyle(e).fontWeight)"
                    ".filter((v, i, a) => a.indexOf(v) === i).length"
                ),
                1,
            )
            page.check("input[name='certificate_kind'][value='external']")
            page.wait_for_selector("input[name='exportable']", state="attached")

            self.assertEqual(page.input_value("input[name='domain']"), "bmc01.example.com")
            self.assertTrue(page.is_checked("input[name='method'][value='http-01']"))
            self.assertEqual(page.locator(".cluster-header .certificate-kind").count(), 1)

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
