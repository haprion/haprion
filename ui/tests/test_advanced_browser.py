"""The advanced config dialog in a real browser (Fas 17, review F3).

The route is tested next door; this is the part only a browser can show: the
button opens the dialog, Check and Save draw their answer inside it, a Save
that went through stays open with every line's fate, and closing it lands on
the page with the draft.
"""

from __future__ import annotations

import threading
from dataclasses import replace
from types import SimpleNamespace
from typing import Any, ClassVar
from unittest import mock
from uuid import uuid4

import uvicorn
from playwright.sync_api import Browser, Playwright

from haproxy_ui.app import create_app
from haproxy_ui.db import ProxyDraft
from tests.test_editor_page import OBSERVED
from tests.test_login import PASSWORD, configuration
from tests.test_object_page import DraftReading
from tests.test_traffic_browser import free_port, sync_playwright

WRITTEN_POOL = """schema: 1
name: public-web
hostnames:
- app.demo.example
listen:
  protocol: http
routes:
- path: /
  backend: web
backends:
  web:
    servers: []
advanced: |
  balance leastconn
  option httpchk GET /health
  server app1 192.0.2.30:8080 check
"""


class TheDialogInABrowser(DraftReading):
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
        self.draft = self.stored_draft = ProxyDraft(
            cluster="edge-demo",
            object_id="public-web",
            yaml=WRITTEN_POOL,
            base_version=1,
            base_hash="a" * 40,
            revision=4,
            updated_by="operator",
            updated_at=OBSERVED,
            deleted=False,
        )
        self.saved: list[dict[str, Any]] = []
        self.queued: list[dict[str, Any]] = []
        for name, effect in (("save_draft", self._save), ("queue_job", self._queue)):
            patch = mock.patch(f"haproxy_ui.db.{name}", side_effect=effect)
            patch.start()
            self.addCleanup(patch.stop)
        config = replace(
            configuration(cookie_secure=False), demo_fixture=True, management_writes=True
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

    def _save(self, _c: object, **values: Any) -> ProxyDraft:
        self.saved.append(values)
        drafted = replace(
            self.draft or self.stored_draft,
            yaml=values["yaml"],
            revision=values["expected_revision"] + 1,
        )
        self.draft = drafted
        return drafted

    def _queue(self, _c: object, **values: Any) -> Any:
        self.queued.append(values)
        return SimpleNamespace(id=7, request_id=uuid4())

    def open_page(self) -> Any:
        page = self._browser.new_page(viewport={"width": 1280, "height": 900})
        self.addCleanup(page.close)
        page.goto(f"http://127.0.0.1:{self.port}/login")
        page.fill("input[name=username]", "operator")
        page.fill("input[name=password]", PASSWORD)
        page.click("button[type=submit]")
        page.wait_for_url(f"http://127.0.0.1:{self.port}/")
        page.goto(f"http://127.0.0.1:{self.port}/proxies/edge-demo/public-web")
        page.click("[data-advanced-open]")
        page.wait_for_selector("[data-advanced-dialog][open]")
        return page

    def test_check_draws_each_line_in_the_dialog(self) -> None:
        page = self.open_page()

        page.click("[data-advanced-form] button[value=check]")
        page.wait_for_selector("[data-advanced-answer] table")

        fates = page.eval_on_selector_all(
            "[data-advanced-answer] tbody tr td:nth-child(2)",
            "cells => cells.map(c => c.innerText)",
        )
        self.assertEqual(fates, ["placed", "placed", "placed"])
        self.assertEqual(self.saved, [])

    def test_save_goes_to_the_page_with_the_draft_as_the_editor_does(self) -> None:
        page = self.open_page()
        page.uncheck("input[name=handwritten_pool]")

        page.click("[data-advanced-form] button[value=save]")
        page.wait_for_url("**/proxies/edge-demo/public-web?saved=1")

        self.assertEqual(len(self.saved), 1)
        self.assertEqual(self.saved[0]["expected_revision"], 4)
        self.assertIn("Saved as a draft", page.inner_text("main"))

    def test_the_buttons_are_the_editors(self) -> None:
        page = self.open_page()

        labels = page.eval_on_selector_all(
            "[data-advanced-form] .form-actions button", "buttons => buttons.map(b => b.innerText)"
        )
        self.assertEqual(
            labels, ["Close", "Validate the object", "Save as draft", "Save and publish"]
        )
        page.click("[data-advanced-close]")
        self.assertFalse(page.is_visible("[data-advanced-dialog]"))

    def test_save_and_publish_lands_on_the_listing_as_the_editor_does(self) -> None:
        page = self.open_page()
        page.fill(
            "textarea[name=advanced]",
            "balance leastconn\nserver app1 192.0.2.30:8080 check\nretries 5\n",
        )

        page.click("[data-advanced-form] button[value=publish]")
        page.wait_for_url("**/proxies?published=public-web")

        self.assertEqual([job["operation"] for job in self.queued], ["objects_publish"])
