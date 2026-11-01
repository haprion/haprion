"""The object page's Blocked addresses card at 1280, measured in a browser.

Its columns once took the node table's fixed widths by position, so with the
select box first the reason and the node names ran out of their cells and the
card scrolled sideways. Rendered through the real view and template, with the
real stylesheet, at the width the interface is checked at.
"""

from __future__ import annotations

import os
from dataclasses import replace
from typing import Any
from unittest import mock

from haprion_ui import demo
from haprion_ui.templates import STATIC_DIRECTORY
from tests.test_busy_clusters import BadgeReading
from tests.test_login import configuration
from tests.test_object_page import DraftReading

if not os.environ.get("PLAYWRIGHT_BROWSERS_PATH"):
    raise RuntimeError(
        "set PLAYWRIGHT_BROWSERS_PATH to the directory holding the Playwright browsers"
    )

from playwright.sync_api import sync_playwright

MEASURE = """() => {
    const scroll = document.querySelector("#blocked .table-scroll");
    const cells = Array.from(document.querySelectorAll("#blocked td"));
    return {
        page: document.documentElement.scrollWidth - document.documentElement.clientWidth,
        card: scroll.scrollWidth - scroll.clientWidth,
        cells: cells
            .filter((cell) => cell.scrollWidth > cell.clientWidth)
            .map((cell) => cell.textContent.trim()),
        rows: cells.length,
    };
}"""

BLOCKED = {
    "public-web": {
        "count": 3,
        "addresses": [
            {"address": "198.51.100.23", "expires_in_ms": 1_640_000, "reason": "manual"},
            {
                "address": "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
                "expires_in_ms": 734_000,
                "reason": "requests",
            },
            {"address": "203.0.113.9", "expires_in_ms": 90_000_000, "reason": "connections"},
        ],
    }
}


class TheBlockedCardFitsAt1280(DraftReading, BadgeReading):
    def measure(self, *, writes: bool) -> Any:
        self.account = replace(self.account, role="admin")
        client = self.client(
            replace(
                configuration(),
                demo_fixture=True,
                management_writes=writes,
                clusters=demo.CLUSTERS,
            )
        )
        self.sign_in(client)
        with mock.patch.object(demo, "BLOCKED", BLOCKED):
            html = client.get("/proxies/edge-demo/public-web").text
        self.assertIn('id="blocked"', html)
        html = html.replace("edge-a, edge-b", "node-a.example.com, node-b.example.com")
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            page = browser.new_page(viewport={"width": 1280, "height": 900})
            page.set_content(html)
            page.add_style_tag(path=str(STATIC_DIRECTORY / "app.css"))
            found = page.evaluate(MEASURE)
            browser.close()
        return found

    def check(self, found: Any) -> None:
        self.assertGreater(found["rows"], 0)
        self.assertEqual(found["cells"], [])
        self.assertLessEqual(found["card"], 0, found)
        self.assertLessEqual(found["page"], 0, found)

    def test_with_the_select_boxes(self) -> None:
        self.check(self.measure(writes=True))

    def test_read_only(self) -> None:
        self.check(self.measure(writes=False))
