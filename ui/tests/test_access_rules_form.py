"""Access rules on the object form: deny_from, deny rules and the body limit (Fas 21, B227).

The server half posts the fields and reads the saved document. The browser half
loads the real page in Chromium, adds and removes rules by clicking, saves, and
hands what the browser posted to the app unchanged - the path a person takes,
from the click to the document the draft holds.
"""

from __future__ import annotations

import os
import unittest
from typing import Any, ClassVar
from urllib.parse import parse_qsl

import yaml

from haprion_ui.templates import STATIC_DIRECTORY
from tests.test_editor_page import EditorTestCase

if not os.environ.get("PLAYWRIGHT_BROWSERS_PATH"):
    raise RuntimeError(
        "set PLAYWRIGHT_BROWSERS_PATH to the directory holding the Playwright browsers"
    )

from playwright.sync_api import sync_playwright

ORIGIN = "https://manager.example.com"


def saved_document(test: EditorTestCase) -> dict[str, Any]:
    document = yaml.safe_load(test.saved[-1]["yaml"])
    test.assertIsInstance(document, dict)
    return dict(document)


class TheFormWritesTheRules(EditorTestCase):
    def test_posted_rules_become_the_document_s_rules(self) -> None:
        client = self.editor()

        answer = self.submit(
            client,
            "/proxies/alpha/shop/edit",
            action="save",
            deny_from=["office"],
            deny_ranges="203.0.113.0/24",
            deny_mode="deny",
            max_request_body="10m",
            rule_index=["0", "3"],
            rule_name=["admin-post", "private"],
            rule_mode=["deny", "log"],
            rule_path=["/admin", "/private"],
            rule_match=["prefix", "exact"],
            rule_header=["", "User-Agent"],
            rule_header_match=["equals", "contains"],
            rule_header_value=["", "sqlmap"],
            rule_source=["", "office"],
            rule_methods=["0:POST", "0:PUT"],
            rule_negate=["3"],
        )

        self.assertEqual(answer.status_code, 303, answer.text)
        document = saved_document(self)
        self.assertEqual(
            document["deny_from"], {"mode": "deny", "sources": ["office", "203.0.113.0/24"]}
        )
        self.assertEqual(document["max_request_body"], "10m")
        self.assertEqual(
            document["deny_rules"],
            [
                {
                    "name": "admin-post",
                    "mode": "deny",
                    "path": "/admin",
                    "methods": ["POST", "PUT"],
                },
                {
                    "name": "private",
                    "mode": "log",
                    "path": "/private",
                    "match": "exact",
                    "header": {"name": "User-Agent", "contains": "sqlmap"},
                    "source": ["office"],
                    "source_negate": True,
                },
            ],
        )

    def test_a_rule_the_engine_refuses_is_not_saved(self) -> None:
        client = self.editor()

        answer = self.submit(
            client,
            "/proxies/alpha/shop/edit",
            action="save",
            rule_index=["0"],
            rule_name=["everything"],
            rule_mode=["deny"],
        )

        self.assertEqual(answer.status_code, 200)
        self.assertIn("names no condition", answer.text)
        self.assertEqual(self.saved, [])

    def test_a_raw_port_posts_no_rules(self) -> None:
        """The fields are hidden for tcp, and hidden fields still post."""

        client = self.editor()

        self.submit(
            client,
            "/proxies/alpha/new",
            action="save",
            name="db",
            protocol="tcp",
            tcp_port="5432",
            hostnames="",
            max_request_body="1m",
            rule_index=["0"],
            rule_name=["a"],
            rule_mode=["log"],
            rule_path=["/x"],
        )

        document = saved_document(self)
        self.assertNotIn("deny_rules", document)
        self.assertNotIn("max_request_body", document)


@unittest.skipUnless(os.environ.get("PLAYWRIGHT_BROWSERS_PATH"), "no browser")
class AddingAndRemovingRulesInTheBrowser(EditorTestCase):
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

    def open_form(self) -> Any:
        form_page = self.editor().get("/proxies/alpha/shop/edit").text
        page = self.browser.new_page()
        self.addCleanup(page.close)
        page.route(
            f"{ORIGIN}/proxies/alpha/shop/edit",
            lambda route, *_: route.fulfill(content_type="text/html", body=form_page),
        )
        for asset in ("object-form.js", "app.css"):
            kind = "text/javascript" if asset.endswith(".js") else "text/css"
            body = (STATIC_DIRECTORY / asset).read_text()
            page.route(
                f"{ORIGIN}/static/{asset}*",
                lambda route, *_, kind=kind, body=body: route.fulfill(content_type=kind, body=body),
            )
        page.goto(f"{ORIGIN}/proxies/alpha/shop/edit")
        page.click("summary:has-text('Access')")
        return page

    def test_add_rule_follows_the_last_rule(self) -> None:
        """26-10-30, in use: Add rule at the top put the new rule at the bottom of a long list."""

        page = self.open_form()
        add = page.locator("[data-add-rule]")
        for _ in range(3):
            add.click()
            last = page.locator("[data-rule]").last.evaluate(
                "e => e.getBoundingClientRect().bottom"
            )
            button = add.evaluate("e => e.getBoundingClientRect().top")
            self.assertGreaterEqual(button, last)

    def test_a_rule_s_line_follows_its_name_and_mode(self) -> None:
        page = self.open_form()
        page.click("[data-add-rule]")
        rule = page.locator("[data-rule]").last
        rule.locator("input[name=rule_name]").fill("authentik-admin")
        rule.locator("select[name=rule_mode]").select_option("deny")
        self.assertEqual(rule.locator("[data-rule-title]").inner_text(), "authentik-admin")
        badge = rule.locator("[data-rule-badge]")
        self.assertEqual(badge.inner_text(), "Denying")
        self.assertIn("status-badge-critical", badge.get_attribute("class") or "")
        self.assertEqual(rule.locator("[data-rule-summary]").inner_text(), "No condition")
        rule.locator("input[name=rule_path]").fill("/if/admin")
        self.assertEqual(
            rule.locator("[data-rule-summary]").inner_text(), "Changed — validate to see the result"
        )
        rule.locator("input[name=rule_name]").fill("")
        self.assertEqual(rule.locator("[data-rule-title]").inner_text(), "New rule")

    def test_what_the_browser_posts_is_the_rules_on_the_screen(self) -> None:
        client = self.editor()
        form_page = client.get("/proxies/alpha/shop/edit").text
        page = self.browser.new_page()
        self.addCleanup(page.close)
        posted: list[str] = []

        def capture(route: Any) -> None:
            if route.request.method == "POST":
                posted.append(route.request.post_data or "")
            route.fulfill(content_type="text/html", body=form_page)

        page.route(f"{ORIGIN}/proxies/alpha/shop/edit", capture)

        def serve(asset: str) -> Any:
            kind = "text/javascript" if asset.endswith(".js") else "text/css"
            body = (STATIC_DIRECTORY / asset).read_text()
            return lambda route, *_: route.fulfill(content_type=kind, body=body)

        for asset in ("object-form.js", "app.css"):
            page.route(f"{ORIGIN}/static/{asset}*", serve(asset))
        page.goto(f"{ORIGIN}/proxies/alpha/shop/edit")
        page.click("summary:has-text('Access')")

        add = page.locator("[data-add-rule]")
        for _ in range(3):
            add.click()
        rules = page.locator("[data-rule]")
        self.assertEqual(rules.count(), 3)
        first, second, third = rules.nth(0), rules.nth(1), rules.nth(2)
        first.locator("input[name=rule_name]").fill("dropped")
        first.locator("input[name=rule_path]").fill("/dropped")
        second.locator("input[name=rule_name]").fill("admin-post")
        second.locator("select[name=rule_mode]").select_option("deny")
        second.locator("input[name=rule_path]").fill("/admin")
        second.locator("input[value$=':POST']").check()
        third.locator("input[name=rule_name]").fill("private")
        third.locator("input[name=rule_path]").fill("/private")
        third.locator("input[name=rule_source]").fill("office")
        third.locator("input[name=rule_negate]").check()
        first.locator("[data-remove-rule]").click()
        self.assertEqual(page.locator("[data-rule]").count(), 2)

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
            saved_document(self)["deny_rules"],
            [
                {"name": "admin-post", "mode": "deny", "path": "/admin", "methods": ["POST"]},
                {
                    "name": "private",
                    "mode": "log",
                    "path": "/private",
                    "source": ["office"],
                    "source_negate": True,
                },
            ],
        )


if __name__ == "__main__":
    unittest.main()
