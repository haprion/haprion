"""Path limits on the object form (B517, 11; B520).

The server half posts the fields and reads the saved document, and opens an
object with limits again. The browser half loads the real page in Chromium,
adds and removes limits by clicking, saves, and hands what the browser posted
to the app unchanged - the path a person takes, from the click to the document
the draft holds.
"""

from __future__ import annotations

import os
import unittest
from typing import Any, ClassVar
from urllib.parse import parse_qsl

import yaml

from haprion_ui.editor import moved
from haprion_ui.form_groups import form_groups
from haprion_ui.preview import DEFAULTS, build_document, form_from_document
from haprion_ui.templates import STATIC_DIRECTORY
from tests.test_editor_page import EditorTestCase

if not os.environ.get("PLAYWRIGHT_BROWSERS_PATH"):
    raise RuntimeError(
        "set PLAYWRIGHT_BROWSERS_PATH to the directory holding the Playwright browsers"
    )

from playwright.sync_api import sync_playwright

ORIGIN = "https://manager.example.com"

LIMITED = """schema: 1
name: shop
hostnames: [shop.example.com]
listen:
  protocol: http
path_limits:
  - path: /login
    match: exact
    max_requests: 5
    window: 10s
  - path: /api
    match: prefix
    max_requests: 50
    window: 1m
routes:
  - path: /
    backend: web
backends:
  web:
    balance: roundrobin
    health:
      type: disabled
    servers:
      - host: 192.0.2.10
        port: 8080
"""


def saved_document(test: EditorTestCase) -> dict[str, Any]:
    document = yaml.safe_load(test.saved[-1]["yaml"])
    test.assertIsInstance(document, dict)
    return dict(document)


class TheFormWritesTheLimits(EditorTestCase):
    def test_posted_limits_become_the_document_s_limits(self) -> None:
        client = self.editor()

        answer = self.submit(
            client,
            "/proxies/alpha/shop/edit",
            action="save",
            limit_path=["/login", "/api"],
            limit_match=["exact", "prefix"],
            limit_requests=["5", "50"],
            limit_window=["10s", "1m"],
        )

        self.assertEqual(answer.status_code, 303, answer.text)
        self.assertEqual(
            saved_document(self)["path_limits"],
            [
                {"path": "/login", "match": "exact", "max_requests": 5, "window": "10s"},
                {"path": "/api", "max_requests": 50, "window": "1m"},
            ],
        )

    def test_a_limit_without_a_number_is_not_saved(self) -> None:
        client = self.editor()

        answer = self.submit(
            client,
            "/proxies/alpha/shop/edit",
            action="save",
            limit_path=["/login"],
            limit_match=["exact"],
            limit_requests=[""],
            limit_window=["10s"],
        )

        self.assertEqual(answer.status_code, 200)
        self.assertIn("needs a number of requests", answer.text)
        self.assertEqual(self.saved, [])

    def test_a_raw_port_posts_no_limits(self) -> None:
        """The list is hidden for tcp, and hidden fields still post."""

        client = self.editor()

        self.submit(
            client,
            "/proxies/alpha/new",
            action="save",
            name="db",
            protocol="tcp",
            tcp_port="5432",
            hostnames="",
            limit_path=["/x"],
            limit_match=["prefix"],
            limit_requests=["5"],
            limit_window=["10s"],
        )

        self.assertNotIn("path_limits", saved_document(self))


class AnObjectWithLimitsOpensInTheForm(unittest.TestCase):
    def test_the_round_trip_keeps_every_limit(self) -> None:
        """`match: prefix` written out is the form's unsaid prefix, not a difference."""

        fields = form_from_document(LIMITED)

        self.assertEqual(fields["limit_path"], ["/login", "/api"])
        self.assertEqual(fields["limit_match"], ["exact", "prefix"])
        self.assertEqual(fields["limit_requests"], ["5", "50"])
        self.assertEqual(fields["limit_window"], ["10s", "1m"])
        rebuilt = yaml.safe_load(build_document(fields))
        self.assertEqual(len(rebuilt["path_limits"]), 2)

    def test_the_limits_group_counts_the_limits(self) -> None:
        fields = form_from_document(LIMITED)
        limits = form_groups(fields)["limits"]

        self.assertIn("2 path limits", limits.summary)
        self.assertNotIn("path limit", form_groups(dict(DEFAULTS))["limits"].summary)

    def test_a_changed_limit_is_one_line_named_by_its_paths(self) -> None:
        after = LIMITED.replace("max_requests: 5\n", "max_requests: 9\n")

        lines = moved(LIMITED, after)

        self.assertEqual([line.label for line in lines], ["Path limits"])


@unittest.skipUnless(os.environ.get("PLAYWRIGHT_BROWSERS_PATH"), "no browser")
class AddingAndRemovingLimitsInTheBrowser(EditorTestCase):
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

    def open_form(self, client: Any, posted: list[str] | None = None) -> Any:
        form_page = client.get("/proxies/alpha/shop/edit").text
        page = self.browser.new_page()
        self.addCleanup(page.close)

        def answer(route: Any, *_: Any) -> None:
            if posted is not None and route.request.method == "POST":
                posted.append(route.request.post_data or "")
            route.fulfill(content_type="text/html", body=form_page)

        page.route(f"{ORIGIN}/proxies/alpha/shop/edit", answer)
        for asset in ("object-form.js", "app.css"):
            kind = "text/javascript" if asset.endswith(".js") else "text/css"
            body = (STATIC_DIRECTORY / asset).read_text()
            page.route(
                f"{ORIGIN}/static/{asset}*",
                lambda route, *_, kind=kind, body=body: route.fulfill(content_type=kind, body=body),
            )
        page.goto(f"{ORIGIN}/proxies/alpha/shop/edit")
        page.click("summary:has-text('Limits')")
        return page

    def test_a_limit_s_line_follows_what_is_typed(self) -> None:
        page = self.open_form(self.editor())
        page.click("[data-add-limit]")
        limit = page.locator("[data-limit]").last
        self.assertEqual(limit.locator("[data-limit-title]").inner_text(), "New limit")
        self.assertEqual(limit.locator("input[name=limit_window]").input_value(), "10s")
        limit.locator("input[name=limit_path]").fill("/login")
        limit.locator("select[name=limit_match]").select_option("exact")
        limit.locator("input[name=limit_requests]").fill("5")
        self.assertEqual(limit.locator("[data-limit-title]").inner_text(), "/login")
        self.assertEqual(
            limit.locator("[data-limit-summary]").inner_text(), "exact · at most 5 per 10s"
        )

    def test_what_the_browser_posts_is_the_limits_on_the_screen(self) -> None:
        client = self.editor()
        posted: list[str] = []
        page = self.open_form(client, posted)

        add = page.locator("[data-add-limit]")
        for _ in range(3):
            add.click()
        limits = page.locator("[data-limit]")
        self.assertEqual(limits.count(), 3)
        first, second, third = limits.nth(0), limits.nth(1), limits.nth(2)
        first.locator("input[name=limit_path]").fill("/dropped")
        first.locator("input[name=limit_requests]").fill("1")
        second.locator("input[name=limit_path]").fill("/login")
        second.locator("select[name=limit_match]").select_option("exact")
        second.locator("input[name=limit_requests]").fill("5")
        third.locator("input[name=limit_path]").fill("/api")
        third.locator("input[name=limit_requests]").fill("50")
        third.locator("input[name=limit_window]").fill("1m")
        first.locator("[data-remove-limit]").click()
        self.assertEqual(page.locator("[data-limit]").count(), 2)

        with page.expect_request(f"{ORIGIN}/proxies/alpha/shop/edit"):
            page.click("button[name=action][value=save]")

        self.assertEqual(len(posted), 1)
        fields: dict[str, list[str]] = {}
        for key, value in parse_qsl(posted[0], keep_blank_values=True):
            fields.setdefault(key, []).append(value)
        answer = client.post(
            "/proxies/alpha/shop/edit",
            data={key: values if len(values) > 1 else values[0] for key, values in fields.items()},
            follow_redirects=False,
        )

        self.assertEqual(answer.status_code, 303, answer.text)
        self.assertEqual(
            saved_document(self)["path_limits"],
            [
                {"path": "/login", "match": "exact", "max_requests": 5, "window": "10s"},
                {"path": "/api", "max_requests": 50, "window": "1m"},
            ],
        )


if __name__ == "__main__":
    unittest.main()
