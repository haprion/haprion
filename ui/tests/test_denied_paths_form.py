"""*Denied paths* on the object form (B527): the row beside *Denied — groups*.

The server half: what the fields write, what a stored object fills them with,
that a raw port never carries them, the Access group's badges, and the form's
check generating with the lists Settings holds.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Any, ClassVar
from unittest import mock

import yaml

from haprion_ui import db, form_groups, preview
from haprion_ui.templates import STATIC_DIRECTORY
from tests.test_access_rules_form import ORIGIN, saved_document
from tests.test_editor_page import SHOP, EditorTestCase

if not os.environ.get("PLAYWRIGHT_BROWSERS_PATH"):
    raise RuntimeError(
        "set PLAYWRIGHT_BROWSERS_PATH to the directory holding the Playwright browsers"
    )

from playwright.sync_api import sync_playwright

NOW = datetime(2026, 11, 24, 8, 0, tzinfo=UTC)


def saved_list(name: str = "scanners", paths: tuple[str, ...] = ("/.env",)) -> db.PathList:
    return db.PathList(
        name=name,
        description="",
        paths=list(paths),
        revision=1,
        created_at=NOW,
        updated_at=NOW,
        updated_by="admin",
    )


def with_paths(extra: str) -> str:
    return SHOP.replace("routes:\n", f"{extra}routes:\n", 1)


class TheFieldsWriteTheDocument(EditorTestCase):
    def setUp(self) -> None:
        super().setUp()
        patch = mock.patch("haprion_ui.db.path_lists", return_value=[saved_list()])
        patch.start()
        self.addCleanup(patch.stop)

    def test_lists_paths_mode_and_time_become_deny_paths(self) -> None:
        client = self.editor()
        answer = self.submit(
            client,
            "/proxies/alpha/shop/edit",
            action="save",
            deny_path_lists=["", "scanners"],
            deny_paths="/server-info\n\n/.git\n",
            deny_paths_mode="block",
            deny_paths_block_for="1h",
        )
        self.assertIn(answer.status_code, (200, 303), answer.text[-500:])
        self.assertEqual(
            saved_document(self)["deny_paths"],
            {
                "mode": "block",
                "lists": ["scanners"],
                "paths": ["/server-info", "/.git"],
                "block_for": "1h",
            },
        )

    def test_log_only_writes_no_time(self) -> None:
        client = self.editor()
        self.submit(
            client,
            "/proxies/alpha/shop/edit",
            action="save",
            deny_path_lists=["scanners"],
            deny_paths_mode="log",
            deny_paths_block_for="1h",
        )
        self.assertEqual(saved_document(self)["deny_paths"], {"mode": "log", "lists": ["scanners"]})

    def test_nothing_chosen_writes_nothing(self) -> None:
        client = self.editor()
        self.submit(client, "/proxies/alpha/shop/edit", action="save", deny_paths_mode="deny")
        self.assertNotIn("deny_paths", saved_document(self))

    def test_a_list_settings_does_not_hold_is_refused_by_the_check(self) -> None:
        client = self.editor()
        answer = self.submit(
            client,
            "/proxies/alpha/shop/edit",
            action="check",
            deny_path_lists=["missing"],
            deny_paths_mode="deny",
        )
        self.assertIn("path list missing, which does not exist", answer.text)

    def test_the_page_offers_the_lists_and_greys_block_for_outside_block(self) -> None:
        page = self.editor().get("/proxies/alpha/shop/edit").text
        self.assertIn('<option value="scanners">scanners</option>', page)
        self.assertIn(
            'name="deny_paths_block_for" value="30m" size="10" placeholder="30m" class="field-idle" readonly',
            page,
        )


class AStoredObjectFillsTheRow(EditorTestCase):
    def test_every_field_comes_back_and_the_round_trip_holds(self) -> None:
        document = with_paths(
            "deny_paths:\n  mode: block\n  lists: [scanners]\n  paths: [/server-info]\n"
        )
        form = preview.form_from_document(document)
        self.assertEqual(
            (
                form["deny_path_lists"],
                form["deny_paths"],
                form["deny_paths_mode"],
                form["deny_paths_block_for"],
            ),
            (("scanners",), "/server-info", "block", "30m"),
        )
        rebuilt = yaml.safe_load(preview.build_document(form))
        self.assertEqual(
            rebuilt["deny_paths"],
            {"mode": "block", "lists": ["scanners"], "paths": ["/server-info"], "block_for": "30m"},
        )

    def test_a_block_without_a_time_shows_the_time_a_rule_would_take(self) -> None:
        # Review 26-11-24, PW06: the object's Dynamic blocking, not always 30m.
        document = with_paths(
            "dynamic_block:\n  max_requests: 100\n  block_for: 2h\n"
            "deny_paths:\n  mode: block\n  paths: [/x]\n"
        )
        form = preview.form_from_document(document)
        self.assertEqual(form["deny_paths_block_for"], "2h")
        rebuilt = yaml.safe_load(preview.build_document(form))
        self.assertEqual(rebuilt["deny_paths"]["block_for"], "2h")

    def test_a_raw_port_never_carries_the_row(self) -> None:
        form: dict[str, Any] = {
            **preview.DEFAULTS,
            "name": "db",
            "protocol": "tcp",
            "tcp_port": "5432",
            "servers": "192.0.2.10:5432",
            "health_type": "tcp",
            "deny_path_lists": ("scanners",),
            "deny_paths": "/x",
            "deny_paths_mode": "deny",
        }
        self.assertNotIn("deny_paths", yaml.safe_load(preview.build_document(form)) or {})


class TheAccessBadges(EditorTestCase):
    def test_denied_paths_count_by_their_mode(self) -> None:
        base = dict(preview.DEFAULTS)
        for mode, badge in (("log", "1 logging"), ("deny", "1 denying"), ("block", "1 blocking")):
            form = {**base, "deny_paths": "/.env", "deny_paths_mode": mode}
            access = form_groups.form_groups(form)["access"]
            with self.subTest(mode=mode):
                self.assertIn(badge, [b.text for b in access.badges])

    def test_a_block_by_denied_paths_alone_is_counted_on_access(self) -> None:
        """Review 26-11-24, PW05: not "Off · 3 blocked" on Dynamic blocking."""

        form = {**preview.DEFAULTS, "deny_paths": "/.env", "deny_paths_mode": "block"}
        groups = form_groups.form_groups(form, blocked=3)

        self.assertTrue(form_groups.blocks_on_match(form))
        self.assertEqual(groups["blocking"].summary, "Off")
        self.assertTrue(groups["access"].summary.endswith("· 3 blocked"))

    def test_a_block_mode_without_a_path_blocks_nothing(self) -> None:
        form = {**preview.DEFAULTS, "deny_paths_mode": "block"}

        self.assertFalse(form_groups.blocks_on_match(form))


class TheRowInTheBrowser(EditorTestCase):
    """Block for greys in place outside block, and the group's badges count the row."""

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
        with mock.patch("haprion_ui.db.path_lists", return_value=[saved_list()]):
            form_page = self.editor().get("/proxies/alpha/shop/edit").text
        page = self.browser.new_page()
        self.addCleanup(page.close)
        errors: list[str] = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        self.addCleanup(lambda: self.assertEqual(errors, []))
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

    def test_block_for_takes_input_only_in_block(self) -> None:
        page = self.open_form()
        mode = page.locator("select[name=deny_paths_mode]")
        block_for = page.locator("input[name=deny_paths_block_for]")
        self.assertTrue(block_for.evaluate("e => e.readOnly"))
        mode.select_option("block")
        self.assertFalse(block_for.evaluate("e => e.readOnly"))
        self.assertNotIn("field-idle", block_for.get_attribute("class") or "")
        mode.select_option("deny")
        self.assertTrue(block_for.evaluate("e => e.readOnly"))

    def test_a_chosen_list_is_counted_on_the_group_by_its_mode(self) -> None:
        page = self.open_form()
        page.locator("select[name=deny_path_lists]").select_option(["scanners"])
        page.locator("select[name=deny_paths_mode]").select_option("deny")
        badges = page.locator("summary:has-text('Access') .form-group-badge").all_inner_texts()
        self.assertIn("1 denying", badges)
