"""The dashboard's four cards on one line each at the width people use (2026-10-06).

Each card is a figure, a label and a detail. Equal quarters of the row gave the
longest ("4/4 Nodes online · All reporting") 210 px of the 226 it needs at 1280
with a scrollbar, and broke it in two while the others had room to spare. The
cards are sized to their text now; this measures it with the real stylesheet
and the real font, which the HTML alone cannot say anything about.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import Any, ClassVar

from haprion_ui.views import STATIC_DIRECTORY

if not os.environ.get("PLAYWRIGHT_BROWSERS_PATH"):
    raise RuntimeError(
        "set PLAYWRIGHT_BROWSERS_PATH to the directory holding the Playwright browsers"
    )

from playwright.sync_api import sync_playwright  # noqa: E402


def card(figure: str, label: str, detail: str) -> str:
    return (
        '<article class="metric-card"><span class="metric-icon"></span>'
        f"<div><strong>{figure}</strong><span>{label}</span><small>{detail}</small></div></article>"
    )


#
# The dashboard's cards as `index.html` writes them, with the values a healthy
# installation of two clusters and four nodes shows.
#
MARKUP = f"""<!doctype html><html><head><meta charset="utf-8">
<link rel="stylesheet" href="app.css"></head><body><main class="page">
<section class="metric-grid">
{card("2", "Clusters", "2 healthy")}
{card("4<small>/4</small>", "Nodes online", "All reporting")}
{card("3<small>/3</small>", "Active VIPs", "Single owner")}
{card("2", "Converged", "Target release")}
</section></main></body></html>"""


class TheDashboardCards(unittest.TestCase):
    playwright: ClassVar[Any]
    browser: ClassVar[Any]
    page_path: ClassVar[Path]

    @classmethod
    def setUpClass(cls) -> None:
        directory = Path(tempfile.mkdtemp(prefix="dashboard-cards-"))
        cls.addClassCleanup(shutil.rmtree, directory)
        for name in ("app.css", "inter-var.woff2"):
            shutil.copy(STATIC_DIRECTORY / name, directory / name)
        cls.page_path = directory / "index.html"
        cls.page_path.write_text(MARKUP)
        cls.playwright = sync_playwright().start()
        cls.browser = cls.playwright.chromium.launch()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.browser.close()
        cls.playwright.stop()

    def lines(self, width: int) -> list[int]:
        """How many lines each card's text takes at this width: 2 when its detail moved under."""

        page = self.browser.new_page(viewport={"width": width, "height": 600})
        self.addCleanup(page.close)
        page.goto(self.page_path.as_uri())
        page.evaluate("() => document.fonts.ready")
        self.assertEqual(
            page.evaluate("() => document.fonts.check('14px \"Inter Var\"')"),
            True,
            "the app's font did not load, so the measurement is not the page's",
        )
        return list(
            page.evaluate(
                """() => [...document.querySelectorAll('.metric-card > div')].map(text => {
                     const label = text.querySelector(':scope > span').getBoundingClientRect();
                     const detail = text.querySelector(':scope > small').getBoundingClientRect();
                     return detail.top >= label.bottom ? 2 : 1; })"""
            )
        )

    def test_every_card_is_one_line_at_1280_with_a_scrollbar(self) -> None:
        """1265 px is what a 1280 px window leaves beside a classic scrollbar."""

        self.assertEqual(self.lines(1265), [1, 1, 1, 1])

    def test_a_wide_window_keeps_them_on_one_line(self) -> None:
        self.assertEqual(self.lines(1920), [1, 1, 1, 1])
