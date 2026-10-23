"""Where a table becomes cards, measured in a browser with the real stylesheet.

Below 1050 px every table becomes cards, so none scrolls sideways or is cut at
the window's edge (2026-09-28). Two keep their columns: the traffic log, which
may scroll instead, and the editor tables, whose cells are fields and which
keep the phone breakpoint. None of this can be read off the HTML.
"""

from __future__ import annotations

import os
import unittest
from typing import Any, ClassVar

from haprion_ui.views import STATIC_DIRECTORY

if not os.environ.get("PLAYWRIGHT_BROWSERS_PATH"):
    raise RuntimeError(
        "set PLAYWRIGHT_BROWSERS_PATH to the directory holding the Playwright browsers"
    )

from playwright.sync_api import sync_playwright

ROW = "".join(f'<td data-label="Column {n}">value {n}</td>' for n in range(1, 9))
HEAD = "".join(f"<th>Column {n}</th>" for n in range(1, 9))


def table(classes: str) -> str:
    return (
        f'<div class="table-scroll"><table class="{classes}"><thead><tr>{HEAD}</tr></thead>'
        f"<tbody><tr>{ROW}</tr><tr>{ROW}</tr></tbody></table></div>"
    )


MARKUP = f"""
<main class="page">
  <section class="cluster-card">{table("node-table job-table")}</section>
  <section class="cluster-card">{table("node-table log-table")}</section>
  <section class="cluster-card">{table("node-table network-table editor-table")}</section>
</main>
"""


class TablesBecomeCards(unittest.TestCase):
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

    def heads(self, width: int) -> dict[str, str]:
        """Whether each table still draws its heading row at this width."""

        page = self.browser.new_page(viewport={"width": width, "height": 800})
        self.addCleanup(page.close)
        page.set_content(MARKUP)
        page.add_style_tag(path=str(STATIC_DIRECTORY / "app.css"))
        return dict(
            page.evaluate(
                """() => Object.fromEntries(['job-table', 'log-table', 'editor-table'].map(name =>
                     [name, getComputedStyle(document.querySelector(`.${name} thead`)).display]))"""
            )
        )

    def test_a_table_keeps_its_columns_from_1050(self) -> None:
        self.assertEqual(self.heads(1050)["job-table"], "table-header-group")

    def test_below_1050_a_table_is_cards_but_the_traffic_log_is_not(self) -> None:
        heads = self.heads(1049)
        self.assertEqual(heads["job-table"], "none")
        self.assertEqual(heads["log-table"], "table-header-group")
        self.assertEqual(heads["editor-table"], "table-header-group")

    def test_the_editor_tables_become_cards_on_a_phone(self) -> None:
        heads = self.heads(680)
        self.assertEqual(heads["editor-table"], "none")
        self.assertEqual(heads["log-table"], "table-header-group")


if __name__ == "__main__":
    unittest.main()
