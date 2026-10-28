"""Small layout slips at 1280, measured in a browser (review 26-10-24, 04-14).

The audit filter's From and To stood 37px against the other fields' 33-34,
and the Network page's DEFAULT SOURCE heading ran past its column while
"whatever routing picks" broke over two lines. Rendered through the real
views and templates, with the real stylesheet, at the width the interface is
checked at.
"""

from __future__ import annotations

import os
from dataclasses import replace
from typing import Any
from unittest import mock

from haprion_ui.templates import STATIC_DIRECTORY
from tests.test_login import LoginTestCase, configuration

if not os.environ.get("PLAYWRIGHT_BROWSERS_PATH"):
    raise RuntimeError(
        "set PLAYWRIGHT_BROWSERS_PATH to the directory holding the Playwright browsers"
    )

from playwright.sync_api import sync_playwright

ROW = """() => Array.from(
    document.querySelectorAll(
        "form.log-filters input:not([type=hidden]), form.log-filters select,"
        + " form.log-filters > button, form.log-filters > a"),
    (element) => element.getBoundingClientRect())
    .filter((box) => box.height > 0)
    .map((box) => [Math.round(box.top), Math.round(box.bottom)])"""

VIPS = """() => ({
    headings: Array.from(document.querySelectorAll(".network-table-vips th"),
        (cell) => cell.scrollWidth - cell.clientWidth),
    empties: Array.from(document.querySelectorAll(".network-table-vips .table-empty"),
        (span) => span.getBoundingClientRect().height),
})"""


def measured(html: str, script: str) -> Any:
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page(viewport={"width": 1280, "height": 900})
        page.set_content(html)
        page.add_style_tag(path=str(STATIC_DIRECTORY / "app.css"))
        found = page.evaluate(script)
        browser.close()
    return found


class TheFilterRowIsOneLine(LoginTestCase):
    def test_every_field_and_both_actions_share_a_top_and_a_bottom(self) -> None:
        client = self.client()
        self.sign_in(client)
        with mock.patch("haprion_ui.db.audit_events", return_value=[]):
            html = client.get("/jobs?view=audit").text
        boxes = measured(html, ROW)
        self.assertGreaterEqual(len(boxes), 7)
        self.assertEqual(len(set(map(tuple, boxes))), 1, boxes)


class TheNetworkHeadingsFit(LoginTestCase):
    def test_no_heading_runs_over_and_an_empty_source_is_one_line(self) -> None:
        client = self.client(replace(configuration(), demo_fixture=True))
        self.sign_in(client)
        html = client.get("/network").text
        self.assertIn("whatever routing picks", html)
        found = measured(html, VIPS)
        self.assertTrue(found["headings"])
        self.assertEqual([over for over in found["headings"] if over > 0], [])
        self.assertTrue(found["empties"])
        self.assertLessEqual(max(found["empties"]), 20)
