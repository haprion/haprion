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

    def test_the_denied_mode_says_log_only_and_a_tcp_object_is_offered_only_deny(self) -> None:
        client = self.editor()

        http = self.submit(client, "/proxies/alpha/shop/edit", action="check")
        tcp = self.submit(
            client, "/proxies/alpha/shop/edit", action="check", protocol="tcp", tcp_port="5432"
        )

        for page in (http.text, tcp.text):
            select = page.split('name="deny_mode"')[1].split("</select>")[0]
            self.assertIn('<option value="log"', select)
            self.assertIn(">log only</option>", select)
            self.assertIn(">deny</option>", select)
        http_select = http.text.split('name="deny_mode"')[1].split("</select>")[0]
        tcp_select = tcp.text.split('name="deny_mode"')[1].split("</select>")[0]
        self.assertNotRegex(http_select, r'value="log"[^>]*hidden')
        self.assertRegex(http_select, r'value="log"[^>]*selected')
        self.assertIn('<option value="deny" selected>', tcp_select)
        self.assertRegex(tcp_select, r'value="log"[^>]*hidden')
        self.assertNotRegex(tcp_select, r'value="log"[^>]*selected')

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

    def test_a_blocking_rule_saves_without_dynamic_blocking_and_writes_its_time(self) -> None:
        client = self.editor()

        page = self.submit(client, "/proxies/alpha/shop/edit", action="check").text
        select = page.split('name="rule_mode"')[1].split("</select>")[0]
        self.assertIn('<option value="block">deny and block the address</option>', select)
        self.assertIn('<option value="log" selected>log only</option>', select)
        answer = self.submit(
            client,
            "/proxies/alpha/shop/edit",
            action="save",
            rule_index=["0", "1"],
            rule_name=["env-probe", "peek"],
            rule_mode=["block", "deny"],
            rule_block_for=["2h", "45m"],
            rule_path=["/.env", "/peek"],
            rule_match=["prefix", "prefix"],
        )

        self.assertEqual(answer.status_code, 303, answer.text)
        rules = saved_document(self)["deny_rules"]
        self.assertEqual(rules[0]["mode"], "block")
        self.assertEqual(rules[0]["block_for"], "2h")
        self.assertNotIn("block_for", rules[1])
        self.assertNotIn("dynamic_block", saved_document(self))

    def test_a_blocking_rule_without_a_time_is_refused_naming_the_rule(self) -> None:
        """Review 26-11-21, U10: the object's own *Block for* refuses an empty time too."""

        answer = self.submit(
            self.editor(),
            "/proxies/alpha/shop/edit",
            action="save",
            rule_index=["0"],
            rule_name=["env-probe"],
            rule_mode=["block"],
            rule_block_for=[""],
            rule_path=["/.env"],
            rule_match=["prefix"],
        )

        self.assertEqual(answer.status_code, 200)
        self.assertIn("Block for needs a time, such as 30m (rule env-probe)", answer.text)
        self.assertEqual(self.saved, [])
        # Review 26-11-21, UU01: the page that refuses it leaves the field
        # empty, so the next Save does not write a time nobody chose.
        self.assertIn('name="rule_block_for" value="" ', answer.text)
        self.assertIn("data-rule-badge>Blocking</span>", answer.text)
        self.assertNotIn("data-rule-badge>Blocking 30m<", answer.text)

    def test_the_rule_card_greys_block_for_in_place_unless_the_rule_blocks(self) -> None:
        """26-11-21: a field that comes and goes moves the ones beside it; greyed, it stays."""

        from haprion_ui.preview import DEFAULTS, build_document, form_from_document

        opened = form_from_document(
            build_document(
                {
                    **DEFAULTS,
                    "name": "shop",
                    "hostnames": "shop.example.com",
                    "servers": "192.0.2.10:8080",
                    "rule_index": ["0", "1"],
                    "rule_name": ["probe", "watch"],
                    "rule_mode": ["block", "log"],
                    "rule_block_for": ["2h", "30m"],
                    "rule_path": ["/.env", "/x"],
                    "rule_match": ["prefix", "prefix"],
                    "rule_header": ["", ""],
                    "rule_header_match": ["equals", "equals"],
                    "rule_header_value": ["", ""],
                    "rule_source": ["", ""],
                }
            ),
            networks=(),
        )
        self.assertEqual(opened["rule_block_for"], ["2h", "30m"])
        client = self.editor()
        page = self.submit(
            client,
            "/proxies/alpha/shop/edit",
            action="check",
            rule_index=["0", "1"],
            rule_name=["probe", "watch"],
            rule_mode=["block", "log"],
            rule_block_for=["2h", "30m"],
            rule_path=["/.env", "/x"],
            rule_match=["prefix", "prefix"],
        ).text
        cards = [
            card for card in page.split('<details class="rule-card')[1:] if "data-rule>" in card
        ]
        self.assertGreaterEqual(len(cards), 2)
        probe = next(card for card in cards if 'value="probe"' in card)
        watch = next(card for card in cards if 'value="watch"' in card)
        self.assertIn("data-rule-badge>Blocking 2h</span>", probe)
        self.assertIn("data-rule-block-for>", probe)
        self.assertIn('name="rule_block_for" value="2h" size="10" placeholder="30m">', probe)
        # Read-only, not disabled: a disabled field is not posted, and the
        # rules' columns would no longer line up.
        self.assertIn("data-rule-block-for>", watch)
        self.assertIn(
            'name="rule_block_for" value="30m" size="10" placeholder="30m" class="field-idle"'
            ' readonly tabindex="-1">',
            watch,
        )
        self.assertNotIn("data-rule-block-for hidden", page)
        self.assertIn("data-rule-badge>Logging</span>", watch)

    def test_a_block_for_on_another_mode_is_not_written(self) -> None:
        self.submit(
            self.editor(),
            "/proxies/alpha/shop/edit",
            action="save",
            rule_index=["0"],
            rule_name=["watch"],
            rule_mode=["log"],
            rule_block_for=["2h"],
            rule_path=["/x"],
            rule_match=["prefix"],
        )

        self.assertNotIn("block_for", saved_document(self)["deny_rules"][0])

    def test_never_blocked_alone_is_saved_as_the_objects_own_key(self) -> None:
        self.submit(
            self.editor(),
            "/proxies/alpha/shop/edit",
            action="save",
            block_exempt_from=["office"],
            block_exempt_ranges="192.0.2.10",
        )

        document = saved_document(self)
        self.assertEqual(document["never_blocked"], ["office", "192.0.2.10"])
        self.assertNotIn("dynamic_block", document)

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
        # A deliberate refusal is not an alarm: grey, as the group's badge (B437).
        self.assertIn("status-badge-unknown", badge.get_attribute("class") or "")
        self.assertEqual(rule.locator("[data-rule-summary]").inner_text(), "No condition")
        rule.locator("input[name=rule_path]").fill("/if/admin")
        self.assertEqual(
            rule.locator("[data-rule-summary]").inner_text(), "Changed — validate to see the result"
        )
        rule.locator("input[name=rule_name]").fill("")
        self.assertEqual(rule.locator("[data-rule-title]").inner_text(), "New rule")
        rule.locator("select[name=rule_mode]").select_option("block")
        self.assertEqual(badge.inner_text(), "Blocking 30m")
        self.assertIn("status-badge-unknown", badge.get_attribute("class") or "")
        block_for = rule.locator("input[name=rule_block_for]")
        self.assertTrue(block_for.is_visible())
        block_for.fill("2h")
        self.assertEqual(badge.inner_text(), "Blocking 2h")
        # UU01: an emptied time names none, as the server refuses it.
        block_for.fill("")
        self.assertEqual(badge.inner_text(), "Blocking")
        self.assertTrue(block_for.is_editable())
        rule.locator("select[name=rule_mode]").select_option("log")
        self.assertTrue(block_for.is_visible())
        self.assertFalse(block_for.is_editable())
        self.assertIn("field-idle", block_for.get_attribute("class") or "")
        self.assertEqual(badge.inner_text(), "Logging")

    def test_the_access_badge_counts_denying_and_blocking_apart(self) -> None:
        page = self.open_form()
        for mode in ("deny", "deny", "block"):
            page.click("[data-add-rule]")
            page.locator("[data-rule]").last.locator("select[name=rule_mode]").select_option(mode)
        badges = page.locator(
            "details.form-group:has([data-rule-list]) > summary .form-group-badge"
        )
        self.assertIn("2 denying", badges.all_inner_texts())
        self.assertIn("1 blocking", badges.all_inner_texts())
        # The deny list counts with its own mode, as the server counts it.
        page.locator("textarea[name=deny_ranges]").fill("192.0.2.0/24")
        page.locator("select[name=deny_mode]").select_option("deny")
        self.assertIn("3 denying", badges.all_inner_texts())
        page.locator("select[name=deny_mode]").select_option("log")
        self.assertIn("1 logging", badges.all_inner_texts())

    def test_the_methods_sit_in_the_first_grid_and_nothing_scrolls_sideways(self) -> None:
        page = self.open_form()
        page.set_viewport_size({"width": 1280, "height": 900})
        page.click("[data-add-rule]")
        rule = page.locator("[data-rule]").last
        rule.locator("select[name=rule_mode]").select_option("block")
        self.assertTrue(
            rule.locator(".rule-methods").evaluate(
                "e => e.parentElement === e.closest('details').querySelector('.form-grid')"
            )
        )
        self.assertTrue(rule.locator(".rule-methods .check").first.is_visible())
        overflow = page.evaluate(
            "document.documentElement.scrollWidth - document.documentElement.clientWidth"
        )
        self.assertEqual(overflow, 0)
        # Block for sits right of Mode, on the same row.
        mode = rule.locator("select[name=rule_mode]").bounding_box()
        block = rule.locator("input[name=rule_block_for]").bounding_box()
        self.assertAlmostEqual(mode["y"], block["y"], delta=2)
        self.assertGreater(block["x"], mode["x"])

    def test_no_field_of_a_rule_moves_when_its_mode_changes(self) -> None:
        """26-11-21: Block for was hidden outside block mode, and Path, Path match and Methods moved."""

        page = self.open_form()
        page.set_viewport_size({"width": 1280, "height": 900})
        page.click("[data-add-rule]")
        rule = page.locator("[data-rule]").last
        fields = (
            "input[name=rule_block_for]",
            "input[name=rule_path]",
            "select[name=rule_match]",
            ".rule-methods",
            "input[name=rule_header]",
        )
        where: dict[str, list[tuple[float, float]]] = {}
        for mode in ("log", "deny", "block", "log"):
            rule.locator("select[name=rule_mode]").select_option(mode)
            for field in fields:
                box = rule.locator(field).bounding_box()
                if box is None:
                    self.fail(f"{field} is not drawn in {mode} mode")
                where.setdefault(field, []).append((round(box["x"]), round(box["y"])))
        for field, places in where.items():
            self.assertEqual(len(set(places)), 1, f"{field} moved: {places}")

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
